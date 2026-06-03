package akeyless

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ak "github.com/akeylesslabs/akeyless-go/v5"
	auth "github.com/pleme-io/auth-go"
	shikuakeyless "github.com/pleme-io/shikumi-go/akeyless"
)

// roundTripFunc is a mock http.RoundTripper so the tests exercise the real SDK
// request marshaling + response decoding fully offline (no network).
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// mockClient builds an *ak.APIClient whose transport is the given handler.
func mockClient(handler roundTripFunc) *ak.APIClient {
	cfg := ak.NewConfiguration()
	cfg.HTTPClient = &http.Client{Transport: handler}
	return ak.NewAPIClient(cfg)
}

// NewResolver validates the kind and defaults sensibly.
func TestNewResolver_KindValidation(t *testing.T) {
	if _, err := NewResolver(Credentials{Kind: auth.AuthKind("bogus")}); err == nil {
		t.Fatal("NewResolver(bogus kind) = nil err, want error")
	}
	r, err := NewResolver(Credentials{}) // empty kind → api_key
	if err != nil {
		t.Fatal(err)
	}
	if r.Kinds()[0] != auth.KindAPIKey {
		t.Errorf("default kind = %v, want api_key", r.Kinds())
	}
	if r.skew != auth.DefaultRefreshSkew {
		t.Errorf("skew = %v, want default", r.skew)
	}
}

// buildAuth requires the per-method material and errors clearly when it is
// missing — so a misconfigured tool fails before any network call.
func TestBuildAuth_RequiredMaterial(t *testing.T) {
	cases := []struct {
		name    string
		creds   Credentials
		wantErr bool
	}{
		{"api_key ok", Credentials{Kind: auth.KindAPIKey, AccessID: "p-1", AccessKey: "k"}, false},
		{"api_key no key", Credentials{Kind: auth.KindAPIKey, AccessID: "p-1"}, true},
		{"aws_iam ok", Credentials{Kind: auth.KindAWSIAM, CloudID: "cid"}, false},
		{"aws_iam empty", Credentials{Kind: auth.KindAWSIAM}, true},
		{"oidc ok", Credentials{Kind: auth.KindOIDC, JWT: "jwt"}, false},
		{"oidc empty", Credentials{Kind: auth.KindOIDC}, true},
		{"k8s ok", Credentials{Kind: auth.KindK8s, K8sServiceAccountToken: "sa"}, false},
		{"email ok", Credentials{Kind: auth.KindEmail, AdminEmail: "a@b", AdminPassword: "pw"}, false},
		{"ldap ok", Credentials{Kind: auth.KindLDAP, LDAPPassword: "pw"}, false},
		{"cert ok", Credentials{Kind: auth.KindCert, CertData: "cd"}, false},
		{"uid ok", Credentials{Kind: auth.KindUniversalIdentity, UIDToken: "u"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewResolver(c.creds)
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			_, err = r.buildAuth()
			if c.wantErr != (err != nil) {
				t.Fatalf("buildAuth err = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}
}

// Resolve → Session mints a real token by driving the SDK Auth call against the
// mock transport, and the token lives only in the Session (CFG-09).
func TestResolver_MintsViaSDK(t *testing.T) {
	var authCalls int
	exp := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	client := mockClient(func(req *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(req.URL.Path, "/auth") {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		authCalls++
		return jsonResponse(`{"token":"t-minted","expiration":"` + exp + `"}`), nil
	})

	r, err := NewResolver(Credentials{Kind: auth.KindAPIKey, AccessID: "p-1", AccessKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	r.client = client // inject mock transport

	sess, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authCalls != 0 {
		t.Fatalf("Resolve eagerly authenticated (%d calls), want lazy", authCalls)
	}
	tok, err := sess.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "t-minted" {
		t.Errorf("token = %q, want t-minted", tok.Value)
	}
	if tok.Expiry.IsZero() {
		t.Error("expiry not parsed from response")
	}
	// Cached: a second read does not re-auth.
	if _, err := sess.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authCalls != 1 {
		t.Errorf("auth calls = %d, want 1 (cached)", authCalls)
	}
	// Forced refresh re-auths.
	if _, err := sess.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authCalls != 2 {
		t.Errorf("auth calls after Refresh = %d, want 2", authCalls)
	}
}

// A missing token in the Auth response is a clear error.
func TestResolver_EmptyTokenResponse(t *testing.T) {
	client := mockClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"expiration":""}`), nil
	})
	r, _ := NewResolver(Credentials{Kind: auth.KindAPIKey, AccessID: "p-1", AccessKey: "k"})
	r.client = client
	sess, _ := r.Resolve(context.Background())
	if _, err := sess.Token(context.Background()); err == nil {
		t.Fatal("Token with empty response = nil err, want error")
	}
}

// SecretGetter satisfies shikumi-go's carrier and resolves a secret by driving
// V2Api.GetSecretValue against the mock, authenticating from the Session.
func TestSecretGetter_ResolvesSecret(t *testing.T) {
	var _ shikuakeyless.SecretGetter = (*SecretGetter)(nil)

	const path = "/prod/db/password"
	var sawToken string
	client := mockClient(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/auth"):
			return jsonResponse(`{"token":"t-sg","expiration":""}`), nil
		case strings.HasSuffix(req.URL.Path, "/get-secret-value"):
			b, _ := io.ReadAll(req.Body)
			if bytes.Contains(b, []byte("t-sg")) {
				sawToken = "t-sg"
			}
			return jsonResponse(`{"` + path + `":"super-secret"}`), nil
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})

	r, _ := NewResolver(Credentials{Kind: auth.KindAPIKey, AccessID: "p-1", AccessKey: "k"})
	r.client = client
	sess, _ := r.Resolve(context.Background())
	getter := r.NewSecretGetter(sess)

	v, err := getter.GetSecretValue(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if v != "super-secret" {
		t.Errorf("value = %q, want super-secret", v)
	}
	if sawToken != "t-sg" {
		t.Error("GetSecretValue did not carry the minted token (CFG-09 point-of-use)")
	}

	// The wrapper plugs straight into shikumi-go's two-phase resolver.
	res := shikuakeyless.FromBootstrap(getter)
	if res.Backend() != "akeyless" {
		t.Errorf("backend = %q, want akeyless", res.Backend())
	}
	got, err := res.Resolve(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "super-secret" {
		t.Errorf("shikumi resolve = %q, want super-secret", got)
	}
}

// A secret missing from the response is a clear error, not an empty string.
func TestSecretGetter_NotPresent(t *testing.T) {
	client := mockClient(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/auth") {
			return jsonResponse(`{"token":"t-x","expiration":""}`), nil
		}
		return jsonResponse(`{"/other":"v"}`), nil
	})
	r, _ := NewResolver(Credentials{Kind: auth.KindAPIKey, AccessID: "p-1", AccessKey: "k"})
	r.client = client
	sess, _ := r.Resolve(context.Background())
	getter := r.NewSecretGetter(sess)
	if _, err := getter.GetSecretValue(context.Background(), "/missing"); err == nil {
		t.Fatal("GetSecretValue(missing) = nil err, want error")
	}
}

// parseExpiry parses RFC3339 and falls back to a default TTL window.
func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	withExp := &ak.AuthOutput{}
	exp := now.Add(15 * time.Minute).Format(time.RFC3339)
	withExp.SetExpiration(exp)
	if got := parseExpiry(withExp, now); !got.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("parseExpiry(rfc3339) = %v, want +15m", got)
	}
	// Empty/absent → default TTL window.
	if got := parseExpiry(&ak.AuthOutput{}, now); !got.Equal(now.Add(DefaultTokenTTL)) {
		t.Errorf("parseExpiry(absent) = %v, want now+DefaultTokenTTL", got)
	}
}
