package auth

import (
	"fmt"
	"time"
)

// AccessType is the fine-grained selector *within* an [AuthKind] that captures
// the deployment-shape variations a single method carries. An [AuthKind] names
// the broad method (k8s, gcp, cert, universal_identity); an AccessType names the
// specific profile a tool runs in. The recon surfaced four that recur across
// consumers and must be first-class (registry §4d) rather than per-tool flags:
//
//   - AccessUniversalIdentity — a rotating UID token (KindUniversalIdentity),
//     advanced on a schedule by the rotation scheduler (rotation.go).
//   - AccessK8sViaGateway — a Kubernetes SA-JWT presented to a gateway-side
//     configured k8s-auth method (KindK8s), as opposed to a directly-minted
//     k8s token. Pairs with [InClusterProfile.K8sAuthConfigName].
//   - AccessGCPAudience — a GCP identity token minted for a *specific audience*
//     (KindGCP), the value a gateway expects when its gcp-auth method pins an
//     audience, as opposed to the default akeyless.io audience.
//   - AccessCACert — a client X.509 cert auth where the presented material is a
//     CA-issued cert + signed challenge (KindCert).
//
// AccessType is neutral: it describes the access *shape*, not a vendor.
type AccessType string

const (
	// AccessUniversalIdentity is a rotating UID token (KindUniversalIdentity).
	AccessUniversalIdentity AccessType = "universal_identity"
	// AccessK8sViaGateway is a SA-JWT presented to a gateway k8s-auth method
	// (KindK8s).
	AccessK8sViaGateway AccessType = "k8s_via_gateway"
	// AccessGCPAudience is a GCP identity token minted for a pinned audience
	// (KindGCP).
	AccessGCPAudience AccessType = "gcp_audience"
	// AccessCACert is a CA-issued client-cert + signed-challenge auth (KindCert).
	AccessCACert AccessType = "ca_cert"
)

// String returns the wire value of the access type.
func (a AccessType) String() string { return string(a) }

// Kind maps an [AccessType] to the broad [AuthKind] it specializes. An unknown
// access type yields the empty kind (which [AuthKind.Valid] rejects).
func (a AccessType) Kind() AuthKind {
	switch a {
	case AccessUniversalIdentity:
		return KindUniversalIdentity
	case AccessK8sViaGateway:
		return KindK8s
	case AccessGCPAudience:
		return KindGCP
	case AccessCACert:
		return KindCert
	default:
		return ""
	}
}

// AllAccessTypes is the canonical ordered list of fine-grained access types.
func AllAccessTypes() []AccessType {
	return []AccessType{
		AccessUniversalIdentity, AccessK8sViaGateway, AccessGCPAudience, AccessCACert,
	}
}

// Valid reports whether a is one of the known access types.
func (a AccessType) Valid() bool {
	for _, known := range AllAccessTypes() {
		if a == known {
			return true
		}
	}
	return false
}

// Profile is the typed, yaml-tagged selector struct that picks *which gateway,
// which method, and which access-type shape* a tool authenticates with — the
// neutral, shikumi-loaded shape behind the fleet `--profile`/`--gateway-url`
// flags (BOREALIS §2.1). It carries no secret and no live token (CFG-09): it is
// the credential-free *selector* a tool resolves to a concrete resolver.
//
// # Gateway-config-URL token shape
//
// A gateway can advertise a *config URL* — a single endpoint a tool fetches its
// effective auth configuration (gateway base URL, default access-id, audience,
// k8s-auth config name) from, instead of inlining each field. [Profile.ConfigURL]
// is that shape: when set, a tool fetches the config blob, merges it under any
// explicit fields, and proceeds. The fetch itself is SDK/HTTP-bearing and so
// lives in the gated leaf; the core only models the URL and the merge precedence
// (explicit field > config-URL value > default), keeping the selector zero-dep.
type Profile struct {
	// Name is the profile's key in a `profiles:` map (the `--profile prod`
	// selector). It is informational in the core; shikumi selection happens on
	// the caller's root config.
	Name string `yaml:"name" json:"name"`
	// GatewayURL is the Akeyless API / Gateway base URL. Empty uses the public
	// endpoint. Discovery precedence (§2.1): --gateway-url > profile.GatewayURL
	// > config-URL value > public default.
	GatewayURL string `yaml:"gatewayUrl" json:"gatewayUrl"`
	// ConfigURL is the gateway-config URL token shape: a single endpoint a tool
	// fetches its effective auth config from. Empty disables config-URL fetch.
	// The fetch lives in the gated leaf; the core models the field and precedence.
	ConfigURL string `yaml:"configUrl" json:"configUrl"`
	// Kind is the broad auth method (the `--auth` value). Empty defaults to
	// KindAPIKey.
	Kind string `yaml:"kind" json:"kind"`
	// AccessType is the fine-grained access shape within Kind (one of
	// [AllAccessTypes]). Empty means "use Kind's default shape". When set, it
	// must specialize Kind ([AccessType.Kind] must equal the parsed Kind).
	AccessType string `yaml:"accessType" json:"accessType"`
	// AccessID is the Akeyless access-id (`p-…`). Not a secret.
	AccessID string `yaml:"accessId" json:"accessId"`
	// Audience is the pinned identity-token audience for AccessGCPAudience
	// (and any future audience-pinned method). Empty uses the method default.
	Audience string `yaml:"audience" json:"audience"`
	// K8sAuthConfigName is the gateway-side k8s-auth method name for
	// AccessK8sViaGateway.
	K8sAuthConfigName string `yaml:"k8sAuthConfigName" json:"k8sAuthConfigName"`
	// Region is the fleet region selector (used by multi-region tools to pick a
	// gateway). Informational in the core.
	Region string `yaml:"region" json:"region"`
	// RefreshSkew is how far before hard expiry a [Session] re-auths. Zero uses
	// [DefaultRefreshSkew].
	RefreshSkew time.Duration `yaml:"refreshSkew" json:"refreshSkew"`
}

// Validate checks the profile's internal consistency: a non-empty Kind must
// parse, a non-empty AccessType must be known *and* must specialize the parsed
// Kind. It returns a clear error so a malformed `profiles:` entry fails at load,
// not at mint. A zero-value profile is valid (defaults to api_key).
func (p Profile) Validate() error {
	kind := KindAPIKey
	if p.Kind != "" {
		k, err := ParseKind(p.Kind)
		if err != nil {
			return fmt.Errorf("auth: profile %q: %w", p.Name, err)
		}
		kind = k
	}
	if p.AccessType != "" {
		at := AccessType(p.AccessType)
		if !at.Valid() {
			return fmt.Errorf("auth: profile %q: unknown access-type %q", p.Name, p.AccessType)
		}
		if at.Kind() != kind {
			return fmt.Errorf("auth: profile %q: access-type %q does not specialize kind %q",
				p.Name, p.AccessType, kind)
		}
	}
	return nil
}

// ResolvedKind returns the profile's effective [AuthKind] (parsed Kind, or the
// AccessType's kind when Kind is empty but an AccessType is set, else
// KindAPIKey). It is total: callers should call [Profile.Validate] first to
// surface a malformed profile; a malformed Kind here falls back to KindAPIKey.
func (p Profile) ResolvedKind() AuthKind {
	if p.Kind != "" {
		if k, err := ParseKind(p.Kind); err == nil {
			return k
		}
	}
	if p.AccessType != "" {
		if k := AccessType(p.AccessType).Kind(); k.Valid() {
			return k
		}
	}
	return KindAPIKey
}

// Config projects a [Profile] onto the existing [Config] consumed by
// [FromConfig]. This is the FromConfig bridge from a tundra-profile shikumi
// struct (BOREALIS §2.1): a tool loads a `tundra-profile`-shaped [Profile]
// through shikumi (the `--profile`/`--gateway-url` selector), then bridges it to
// the auth resolver surface in one call:
//
//	// 1. one shikumi load picks the active profile from a profiles: map
//	prof := root.Profiles[*flagProfile]      // type auth.Profile
//	if err := prof.Validate(); err != nil { return err }
//	// 2. bridge to the resolver surface — never re-loads (Law 3 / §3.5)
//	resolver, err := auth.FromConfig(prof.Config())
//
// The bridge carries only the credential-free selectors the zero-dep [Config]
// models (kind, gateway URL, access-id, refresh-skew); the secret-bearing and
// per-method material (access-key, cloud-id, jwt, audience, k8s-auth config
// name) is consumed by the gated akeyless leaf's resolver, which reads the same
// [Profile] (so the audience / config-name / config-URL travel to where the SDK
// can act on them). Token/TokenEnv stay empty here — a profile is a *selector*,
// not a pre-minted token; for the pre-minted path a tool uses [Config] directly.
func (p Profile) Config() Config {
	return Config{
		Kind:        p.ResolvedKind().String(),
		GatewayURL:  p.GatewayURL,
		AccessID:    p.AccessID,
		RefreshSkew: p.RefreshSkew,
	}
}

// FromProfile is the canonical profile-to-resolver bridge: it validates the
// profile, then builds the core [AuthResolver] from its [Profile.Config]
// projection. It is the §3.5 FromConfig-shape entry point for the
// `--profile`-selected path; like [FromConfig] it MUST NOT call shikumi.Load
// (the loader lives once, at main). For an SDK-minting kind a tool then wires
// the akeyless leaf's resolver (built from the same [Profile]) via
// [WithResolver]; the core handles the zero-dep token/env paths.
func FromProfile(p Profile) (AuthResolver, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return FromConfig(p.Config())
}
