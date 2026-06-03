package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// StaticTokenResolver wraps a fixed token and is a valid AuthResolver.
func TestStaticTokenResolver(t *testing.T) {
	var _ AuthResolver = (*StaticTokenResolver)(nil)

	exp := time.Now().Add(time.Hour)
	r := NewStaticTokenResolver("t-static",
		WithStaticKind(KindOIDC),
		WithStaticExpiry(exp),
	)
	if kinds := r.Kinds(); len(kinds) != 1 || kinds[0] != KindOIDC {
		t.Fatalf("Kinds = %v, want [oidc]", kinds)
	}
	sess, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sess.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "t-static" {
		t.Errorf("token = %q, want t-static", tok.Value)
	}
	if !tok.Expiry.Equal(exp) {
		t.Errorf("expiry = %v, want %v", tok.Expiry, exp)
	}
}

// An empty static token fails at Resolve with ErrNoToken.
func TestStaticTokenResolver_Empty(t *testing.T) {
	r := NewStaticTokenResolver("")
	if _, err := r.Resolve(context.Background()); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Resolve(empty) err = %v, want ErrNoToken", err)
	}
}

// EnvTokenResolver reads the token from the (injected) environment at Resolve.
func TestEnvTokenResolver(t *testing.T) {
	var _ AuthResolver = (*EnvTokenResolver)(nil)

	env := map[string]string{"MY_TOKEN": "t-from-env"}
	r := NewEnvTokenResolver(
		WithEnvVar("MY_TOKEN"),
		WithEnvKind(KindK8s),
		withEnvLookup(func(k string) (string, bool) { v, ok := env[k]; return v, ok }),
	)
	if r.Kinds()[0] != KindK8s {
		t.Errorf("Kinds = %v, want [k8s]", r.Kinds())
	}
	sess, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := sess.Token(context.Background())
	if tok.Value != "t-from-env" {
		t.Errorf("token = %q, want t-from-env", tok.Value)
	}
}

// An unset env var fails at Resolve with ErrNoToken.
func TestEnvTokenResolver_Unset(t *testing.T) {
	r := NewEnvTokenResolver(
		WithEnvVar("ABSENT"),
		withEnvLookup(func(string) (string, bool) { return "", false }),
	)
	if _, err := r.Resolve(context.Background()); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Resolve(unset) err = %v, want ErrNoToken", err)
	}
}

// New with an explicit resolver returns it verbatim.
func TestNew_WithResolver(t *testing.T) {
	want := NewStaticTokenResolver("t-x")
	got, err := New(WithResolver(want))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("New(WithResolver) returned a different resolver")
	}
}

// New with a static token builds a StaticTokenResolver.
func TestNew_StaticToken(t *testing.T) {
	r, err := New(WithStaticToken("t-y"), WithKind(KindCert))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*StaticTokenResolver); !ok {
		t.Fatalf("New(WithStaticToken) = %T, want *StaticTokenResolver", r)
	}
	if r.Kinds()[0] != KindCert {
		t.Errorf("Kinds = %v, want [cert]", r.Kinds())
	}
}

// The option-free New yields an EnvTokenResolver (construction never errors;
// the failure, if any, is deferred to Resolve).
func TestNew_DefaultsToEnv(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	er, ok := r.(*EnvTokenResolver)
	if !ok {
		t.Fatalf("New() = %T, want *EnvTokenResolver", r)
	}
	if er.envVar != DefaultTokenEnv {
		t.Errorf("envVar = %q, want %q", er.envVar, DefaultTokenEnv)
	}
}

// FromConfig builds the static path from a pre-minted token.
func TestFromConfig_StaticToken(t *testing.T) {
	r, err := FromConfig(Config{Kind: "oidc", Token: "t-cfg"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*StaticTokenResolver); !ok {
		t.Fatalf("FromConfig(token) = %T, want *StaticTokenResolver", r)
	}
	sess, _ := r.Resolve(context.Background())
	tok, _ := sess.Token(context.Background())
	if tok.Value != "t-cfg" {
		t.Errorf("token = %q, want t-cfg", tok.Value)
	}
	if r.Kinds()[0] != KindOIDC {
		t.Errorf("Kinds = %v, want [oidc]", r.Kinds())
	}
}

// FromConfig builds the env path when no token is inlined.
func TestFromConfig_Env(t *testing.T) {
	r, err := FromConfig(Config{TokenEnv: "CFG_TOKEN", RefreshSkew: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	er, ok := r.(*EnvTokenResolver)
	if !ok {
		t.Fatalf("FromConfig(env) = %T, want *EnvTokenResolver", r)
	}
	if er.envVar != "CFG_TOKEN" {
		t.Errorf("envVar = %q, want CFG_TOKEN", er.envVar)
	}
	if er.skew != 30*time.Second {
		t.Errorf("skew = %v, want 30s", er.skew)
	}
}

// FromConfig rejects an unparseable kind so a typo fails loudly.
func TestFromConfig_BadKind(t *testing.T) {
	if _, err := FromConfig(Config{Kind: "not-a-method"}); err == nil {
		t.Fatal("FromConfig(bad kind) = nil err, want error")
	}
}
