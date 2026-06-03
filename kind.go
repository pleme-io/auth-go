package auth

import "fmt"

// AuthKind is the closed set of Akeyless authentication methods a resolver can
// mint a token from. It is the neutrally-named projection of Akeyless's eleven
// `access-type` values onto the fleet: one AuthResolver shape spans every kind,
// so a tool that supports several methods never branches on a stringly-typed
// access-type — it inspects Kinds() and dispatches uniformly.
//
// The constant *values* match Akeyless's `access-type` wire strings exactly
// (api_key/aws_iam/azure_ad/…), so the akeyless backend can pass an AuthKind
// straight through to V2Api.Auth without a translation table. The type itself
// lives in the zero-dep core because cli-go's `--auth` flag set is auto-wired
// from AuthResolver.Kinds() (§2.2) and must not pull in the SDK.
type AuthKind string

const (
	// KindAPIKey is the access-key / access-id pair (the default and most
	// common method). access-type=api_key.
	KindAPIKey AuthKind = "api_key"
	// KindAWSIAM authenticates with the caller's AWS IAM identity (SigV4 over
	// instance/role credentials). access-type=aws_iam.
	KindAWSIAM AuthKind = "aws_iam"
	// KindAzureAD authenticates with an Azure AD managed identity / JWT.
	// access-type=azure_ad.
	KindAzureAD AuthKind = "azure_ad"
	// KindGCP authenticates with a GCP service-account identity token.
	// access-type=gcp.
	KindGCP AuthKind = "gcp"
	// KindK8s authenticates with a Kubernetes service-account token bound to a
	// configured k8s auth method. access-type=k8s.
	KindK8s AuthKind = "k8s"
	// KindOIDC authenticates via an OIDC provider (browser/device flow JWT).
	// access-type=oidc.
	KindOIDC AuthKind = "oidc"
	// KindSAML authenticates via a SAML identity provider. access-type=saml.
	KindSAML AuthKind = "saml"
	// KindCert authenticates with a client X.509 certificate + signed
	// challenge. access-type=cert.
	KindCert AuthKind = "cert"
	// KindEmail authenticates with an admin email + password. access-type=email.
	KindEmail AuthKind = "email"
	// KindLDAP authenticates against a configured LDAP directory.
	// access-type=ldap.
	KindLDAP AuthKind = "ldap"
	// KindUniversalIdentity authenticates with a rotating UID token.
	// access-type=universal_identity.
	KindUniversalIdentity AuthKind = "universal_identity"
)

// AllKinds is the canonical ordered list of every supported method. cli-go's
// `--auth` flag set is auto-wired from a resolver's Kinds(); this is the
// fleet-wide superset for documentation and validation.
func AllKinds() []AuthKind {
	return []AuthKind{
		KindAPIKey, KindAWSIAM, KindAzureAD, KindGCP, KindK8s,
		KindOIDC, KindSAML, KindCert, KindEmail, KindLDAP,
		KindUniversalIdentity,
	}
}

// String returns the Akeyless wire value (also the user-facing `--auth` token).
func (k AuthKind) String() string { return string(k) }

// Valid reports whether k is one of the known methods.
func (k AuthKind) Valid() bool {
	for _, known := range AllKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// ParseKind parses a user-facing `--auth` token (case-insensitive on the wire
// string, with a few friendly aliases) into an AuthKind.
func ParseKind(s string) (AuthKind, error) {
	switch normalizeKind(s) {
	case "api_key", "apikey", "access_key", "accesskey":
		return KindAPIKey, nil
	case "aws_iam", "awsiam", "aws":
		return KindAWSIAM, nil
	case "azure_ad", "azuread", "azure":
		return KindAzureAD, nil
	case "gcp", "gce":
		return KindGCP, nil
	case "k8s", "kubernetes":
		return KindK8s, nil
	case "oidc":
		return KindOIDC, nil
	case "saml":
		return KindSAML, nil
	case "cert", "certificate":
		return KindCert, nil
	case "email":
		return KindEmail, nil
	case "ldap":
		return KindLDAP, nil
	case "universal_identity", "uid", "universalidentity":
		return KindUniversalIdentity, nil
	default:
		return "", fmt.Errorf("auth: unknown auth kind %q", s)
	}
}

// normalizeKind lowercases and replaces '-' with '_' without pulling strings.
func normalizeKind(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		case c == '-':
			b[i] = '_'
		default:
			b[i] = c
		}
	}
	return string(b)
}
