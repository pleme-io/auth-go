package akeyless

import (
	auth "github.com/pleme-io/auth-go"
)

// CredentialsFromProfile is the SDK-side half of the FromConfig bridge from a
// tundra-profile shikumi struct (BOREALIS §2.1): it projects an auth.Profile
// selector onto the leaf's [Credentials], carrying the per-method material the
// zero-dep core deliberately omits — the pinned GCP audience, the gateway-side
// k8s-auth config name, the gateway base URL. A tool loads the profile through
// shikumi (the `--profile` selector), then:
//
//	creds := akeyless.CredentialsFromProfile(prof)
//	creds.AccessKey = accessKey.Expose()        // secret, supplied at this site
//	res, _ := akeyless.NewResolver(creds)
//
// Secret-bearing fields (access-key, cloud-id, jwt, uid-token, passwords) are
// NOT projected — a profile is a credential-free selector (CFG-09); the caller
// supplies the one secret material at the resolver build site. The gateway-
// config-URL fetch (Profile.ConfigURL) is a separate, opt-in HTTP step a tool
// runs before this bridge to materialize ConfigURL-sourced fields.
func CredentialsFromProfile(p auth.Profile) Credentials {
	return Credentials{
		Kind:              p.ResolvedKind(),
		GatewayURL:        p.GatewayURL,
		AccessID:          p.AccessID,
		GcpAudience:       p.Audience,
		K8sAuthConfigName: p.K8sAuthConfigName,
		RefreshSkew:       p.RefreshSkew,
	}
}

// CredentialsFromInCluster projects an auth.InClusterProfile onto the leaf's
// [Credentials] for the k8s-via-gateway access shape: it reads the projected
// service-account JWT (applying the base64 quirk per the profile) into the
// K8sServiceAccountToken field and carries the gateway-side k8s-auth config
// name, so [NewResolver] can mint a `t-…` by presenting the SA token to
// V2Api.Auth. It returns auth.ErrNotInCluster when no SA token is mounted.
//
// The SA token is read at this call site and flows straight into Credentials for
// the immediate mint; it is not retained beyond the resolver (CFG-09). For the
// zero-dep path (forward the SA JWT without the SDK), use
// auth.NewInClusterResolver instead.
func CredentialsFromInCluster(p auth.InClusterProfile) (Credentials, error) {
	tok, err := p.InClusterToken()
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{
		Kind:                   auth.KindK8s,
		K8sServiceAccountToken: tok,
		K8sAuthConfigName:      p.K8sAuthConfigName,
	}, nil
}

// ResolverFromProfile builds the SDK-minting resolver directly from an
// auth.Profile selector plus the one secret material a tool supplies (the
// access-key for api_key; empty for credential-via-other-material kinds). It is
// the one-call profile→resolver path for tools that have already loaded a
// tundra-profile and resolved its secret. The profile is validated first so a
// malformed selector fails here, not at mint.
func ResolverFromProfile(p auth.Profile, accessKey string) (*Resolver, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	creds := CredentialsFromProfile(p)
	creds.AccessKey = accessKey
	return NewResolver(creds)
}
