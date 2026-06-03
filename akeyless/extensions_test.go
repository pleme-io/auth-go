package akeyless

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	auth "github.com/pleme-io/auth-go"
)

// buildAuth sets the gcp-audience and gateway-url on the request body for the
// gcp-audience access shape and the gateway-config-URL token shape.
func TestBuildAuth_GcpAudienceAndGateway(t *testing.T) {
	r, err := NewResolver(Credentials{
		Kind:        auth.KindGCP,
		GatewayURL:  "https://gw.example",
		GcpAudience: "my-audience",
		JWT:         "jwt",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.buildAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := body.GetGcpAudienceOk(); !ok || got == nil || *got != "my-audience" {
		t.Errorf("gcp-audience not set, got %v", got)
	}
	if got, ok := body.GetGatewayUrlOk(); !ok || got == nil || *got != "https://gw.example" {
		t.Errorf("gateway-url not set, got %v", got)
	}
}

// A CloudIdentityProvider supplies the cloud-id blob at mint time (fresh each mint).
func TestBuildAuth_CloudIdentityProvider(t *testing.T) {
	var calls int
	prov := auth.NewCloudIdentityFunc(auth.CloudAWS, func(context.Context) (string, error) {
		calls++
		return "live-cloud-id-blob", nil
	})
	r, err := NewResolver(Credentials{Kind: auth.KindAWSIAM, CloudIdentity: prov})
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.buildAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := body.GetCloudIdOk(); !ok || got == nil || *got != "live-cloud-id-blob" {
		t.Errorf("cloud-id from provider not set, got %v", got)
	}
	if calls != 1 {
		t.Errorf("provider called %d times, want 1", calls)
	}
}

// UID rotation drives V2Api.UidRotateToken and advances the credential; Resolve
// installs the rotation scheduler on the Session.
func TestResolver_UIDRotation(t *testing.T) {
	var rotateCalls int
	client := mockClient(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/auth"):
			return jsonResponse(`{"token":"t-uid","expiration":""}`), nil
		case strings.HasSuffix(req.URL.Path, "/uid-rotate-token"):
			rotateCalls++
			return jsonResponse(`{"token":"uid-next"}`), nil
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})
	r, err := NewResolver(Credentials{Kind: auth.KindUniversalIdentity, UIDToken: "uid-0"})
	if err != nil {
		t.Fatal(err)
	}
	r.client = client

	sess, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sess.HasRotation() {
		t.Fatal("uid session has no rotation, want HasRotation")
	}
	if err := sess.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rotateCalls != 1 {
		t.Errorf("uid-rotate-token calls = %d, want 1", rotateCalls)
	}
	if sess.Rotated() != "uid-next" {
		t.Errorf("rotated value = %q, want uid-next", sess.Rotated())
	}
	if r.creds.UIDToken != "uid-next" {
		t.Errorf("resolver UIDToken = %q, want uid-next (advanced)", r.creds.UIDToken)
	}
}

// CredentialsFromProfile carries the per-method material the core selector omits.
func TestCredentialsFromProfile(t *testing.T) {
	prof := auth.Profile{
		Kind:              "gcp",
		AccessType:        "gcp_audience",
		GatewayURL:        "https://gw",
		AccessID:          "p-1",
		Audience:          "aud",
		K8sAuthConfigName: "k8s-cfg",
	}
	c := CredentialsFromProfile(prof)
	if c.Kind != auth.KindGCP {
		t.Errorf("kind = %q, want gcp", c.Kind)
	}
	if c.GcpAudience != "aud" {
		t.Errorf("gcp-audience = %q, want aud", c.GcpAudience)
	}
	if c.K8sAuthConfigName != "k8s-cfg" {
		t.Errorf("k8s-auth-config = %q, want k8s-cfg", c.K8sAuthConfigName)
	}
	if c.AccessKey != "" {
		t.Error("CredentialsFromProfile leaked a secret (access-key)")
	}
}

// CredentialsFromInCluster reads the SA JWT into the k8s credential material.
func TestCredentialsFromInCluster(t *testing.T) {
	// Write a real projected-SA token file and point the profile at it.
	dir := t.TempDir()
	tokenPath := dir + "/token"
	if err := os.WriteFile(tokenPath, []byte("sa-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prof := auth.InClusterProfile{TokenPath: tokenPath, K8sAuthConfigName: "k8s-cfg"}
	c, err := CredentialsFromInCluster(prof)
	if err != nil {
		t.Fatal(err)
	}
	if c.K8sServiceAccountToken != "sa-jwt" {
		t.Errorf("sa token = %q, want sa-jwt", c.K8sServiceAccountToken)
	}
	if c.K8sAuthConfigName != "k8s-cfg" {
		t.Errorf("k8s-auth-config = %q, want k8s-cfg", c.K8sAuthConfigName)
	}
	if c.Kind != auth.KindK8s {
		t.Errorf("kind = %q, want k8s", c.Kind)
	}

	// Missing token → ErrNotInCluster.
	if _, err := CredentialsFromInCluster(auth.InClusterProfile{TokenPath: dir + "/absent"}); err == nil {
		t.Fatal("CredentialsFromInCluster(absent) = nil err, want ErrNotInCluster")
	}
}

// ResolverFromProfile validates then builds the SDK resolver in one call.
func TestResolverFromProfile(t *testing.T) {
	r, err := ResolverFromProfile(auth.Profile{Kind: "api_key", AccessID: "p-1"}, "access-key")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kinds()[0] != auth.KindAPIKey {
		t.Errorf("kind = %v, want api_key", r.Kinds())
	}
	// Malformed profile fails at the bridge.
	if _, err := ResolverFromProfile(auth.Profile{Kind: "gcp", AccessType: "ca_cert"}, ""); err == nil {
		t.Fatal("ResolverFromProfile(mismatched) = nil err, want error")
	}
}

// Validator posts to the validation endpoint and maps the verdict; satisfies the
// core ProducerCredentialValidator inverse seam.
func TestValidator(t *testing.T) {
	var _ auth.ProducerCredentialValidator = (*Validator)(nil)

	cases := []struct {
		name      string
		handler   roundTripFunc
		req       auth.ValidationRequest
		wantValid bool
		wantErr   bool
	}{
		{
			name: "valid match",
			handler: func(req *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(req.Body)
				if !bytes.Contains(b, []byte("p-1")) {
					t.Error("request missing expected access-id")
				}
				return jsonResponse(`{"access_id":"p-1"}`), nil
			},
			req:       auth.ValidationRequest{Credential: "c", ExpectedAccessID: "p-1"},
			wantValid: true,
		},
		{
			name: "mismatched access id (rejected, no error)",
			handler: func(*http.Request) (*http.Response, error) {
				return jsonResponse(`{"access_id":"p-2"}`), nil
			},
			req:       auth.ValidationRequest{Credential: "c", ExpectedAccessID: "p-1"},
			wantValid: false,
		},
		{
			name: "non-200 (rejected, no error)",
			handler: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied"))}, nil
			},
			req:       auth.ValidationRequest{Credential: "c", ExpectedAccessID: "p-1"},
			wantValid: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := NewValidator(
				WithValidationURL("https://auth.example/validate"),
				WithValidatorClient(&http.Client{Transport: c.handler}),
			)
			if len(v.Kinds()) == 0 {
				t.Error("validator reports no kinds")
			}
			res, err := v.Validate(context.Background(), c.req)
			if c.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Valid != c.wantValid {
				t.Errorf("Valid = %v, want %v (reason=%q)", res.Valid, c.wantValid, res.Reason)
			}
		})
	}
}
