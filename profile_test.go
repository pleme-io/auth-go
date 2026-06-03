package auth

import (
	"context"
	"testing"
	"time"
)

// AccessType → AuthKind mapping and Valid agree across the four shapes.
func TestAccessType(t *testing.T) {
	cases := []struct {
		at   AccessType
		kind AuthKind
	}{
		{AccessUniversalIdentity, KindUniversalIdentity},
		{AccessK8sViaGateway, KindK8s},
		{AccessGCPAudience, KindGCP},
		{AccessCACert, KindCert},
	}
	for _, c := range cases {
		t.Run(c.at.String(), func(t *testing.T) {
			if !c.at.Valid() {
				t.Errorf("%q reports !Valid", c.at)
			}
			if got := c.at.Kind(); got != c.kind {
				t.Errorf("Kind() = %q, want %q", got, c.kind)
			}
		})
	}
	if AccessType("nope").Valid() {
		t.Error(`AccessType("nope").Valid() = true, want false`)
	}
	if AccessType("nope").Kind() != "" {
		t.Error("unknown AccessType.Kind() != empty")
	}
}

// Profile.Validate accepts consistent profiles and rejects mismatches.
func TestProfile_Validate(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{"zero value (api_key)", Profile{}, false},
		{"gcp + gcp_audience", Profile{Kind: "gcp", AccessType: "gcp_audience"}, false},
		{"k8s + k8s_via_gateway", Profile{Kind: "k8s", AccessType: "k8s_via_gateway"}, false},
		{"cert + ca_cert", Profile{Kind: "cert", AccessType: "ca_cert"}, false},
		{"uid + universal_identity", Profile{Kind: "universal_identity", AccessType: "universal_identity"}, false},
		{"bad kind", Profile{Kind: "not-a-method"}, true},
		{"unknown access-type", Profile{Kind: "gcp", AccessType: "bogus"}, true},
		{"access-type does not specialize kind", Profile{Kind: "gcp", AccessType: "ca_cert"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.profile.Validate()
			if c.wantErr != (err != nil) {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}
}

// ResolvedKind picks the effective AuthKind from Kind, then AccessType, then api_key.
func TestProfile_ResolvedKind(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
		want    AuthKind
	}{
		{"explicit kind", Profile{Kind: "oidc"}, KindOIDC},
		{"from access-type", Profile{AccessType: "gcp_audience"}, KindGCP},
		{"default", Profile{}, KindAPIKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.profile.ResolvedKind(); got != c.want {
				t.Errorf("ResolvedKind = %q, want %q", got, c.want)
			}
		})
	}
}

// Profile.Config projects the credential-free selectors; FromProfile bridges to
// a core resolver (the FromConfig bridge from a tundra-profile shikumi struct).
func TestProfile_ConfigAndFromProfile(t *testing.T) {
	prof := Profile{
		Name:        "prod",
		Kind:        "oidc",
		GatewayURL:  "https://gw.example",
		AccessID:    "p-123",
		Audience:    "akeyless.io",
		RefreshSkew: 30 * time.Second,
	}
	cfg := prof.Config()
	if cfg.Kind != "oidc" || cfg.GatewayURL != "https://gw.example" || cfg.AccessID != "p-123" {
		t.Errorf("Config projection wrong: %+v", cfg)
	}
	if cfg.RefreshSkew != 30*time.Second {
		t.Errorf("RefreshSkew = %v, want 30s", cfg.RefreshSkew)
	}
	// Token/TokenEnv stay empty — a profile is a selector, not a pre-minted token.
	if cfg.Token != "" {
		t.Errorf("Config.Token = %q, want empty", cfg.Token)
	}

	// FromProfile validates then bridges. The oidc kind has no zero-dep mint,
	// so the core builds the env resolver (deferred failure), but kind is carried.
	r, err := FromProfile(prof)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kinds()[0] != KindOIDC {
		t.Errorf("Kinds = %v, want [oidc]", r.Kinds())
	}

	// A malformed profile fails at the bridge, not at mint.
	if _, err := FromProfile(Profile{Kind: "gcp", AccessType: "ca_cert"}); err == nil {
		t.Fatal("FromProfile(mismatched) = nil err, want error")
	}
}

// AllAccessTypes is non-empty and every entry is Valid (sanity, mirrors AllKinds).
func TestAllAccessTypes(t *testing.T) {
	all := AllAccessTypes()
	if len(all) == 0 {
		t.Fatal("AllAccessTypes is empty")
	}
	for _, a := range all {
		if !a.Valid() {
			t.Errorf("AllAccessTypes entry %q reports !Valid", a)
		}
	}
	_ = context.Background()
}
