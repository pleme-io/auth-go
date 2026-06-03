// Package akeyless is auth-go's import-gated, SDK-backed sub-package (BOREALIS
// §2.2a / Law 6): the heavy akeylesslabs/akeyless-go SDK and all network-bearing
// auth/secret logic live HERE, so the auth-go core stays zero-dep and
// offline-buildable.
//
// It delivers two things, both built on one authenticated *akeyless.V2Api:
//
//  1. The SDK-minting [Resolver] — an auth.AuthResolver that mints a `t-…` token
//     from any of the closed set of methods (api_key/aws_iam/azure_ad/gcp/k8s/
//     oidc/saml/cert/email/ldap/universal_identity) by calling V2Api.Auth, and
//     hands back an *auth.Session that refreshes by re-calling Auth. The live
//     token lives only in that Session (CFG-09).
//
//  2. The [SecretGetter] — a thin wrapper over V2Api.GetSecretValue that
//     satisfies shikumi-go/akeyless.SecretGetter. A tool's shikumi `Secrets()`
//     chain resolves `secret://akeyless/…` refs through it AFTER auth, closing
//     the §2.1 two-phase load (bootstrap config → auth → resolve secrets).
//
// The division of ownership (per shikumi-go/akeyless's doc): auth-go owns the
// SDK + the token; shikumi-go owns resolution-into-config. This package is the
// seam where the two meet — it builds the authenticated client once and exposes
// it as both an auth.AuthResolver and a shikumi-go SecretGetter.
package akeyless

import (
	"context"
	"fmt"
	"time"

	ak "github.com/akeylesslabs/akeyless-go/v5"
	auth "github.com/pleme-io/auth-go"
	shikuakeyless "github.com/pleme-io/shikumi-go/akeyless"
)

// DefaultTokenTTL is the assumed token lifetime when the Auth response carries
// no parseable expiration. Akeyless `t-…` tokens are typically valid ~60 min;
// the Session refreshes a skew before this, so a missing expiration never causes
// a stuck token.
const DefaultTokenTTL = 60 * time.Minute

// Credentials is the typed, yaml-tagged input the SDK-minting [Resolver] needs.
// It is the akeyless-side superset of auth.Config: it adds the secret-typed
// access-key and per-method material that the zero-dep core deliberately omits
// (the core stays SDK-free). A tool loads this through shikumi and hands it here.
//
// CFG-09: AccessKey is the one secret field; supply it via a shikumi.Secret
// exposed only at this call site. It flows into V2Api.Auth and is never retained
// past the mint.
type Credentials struct {
	// Kind selects the auth method. Empty defaults to auth.KindAPIKey.
	Kind auth.AuthKind `yaml:"kind" json:"kind"`
	// GatewayURL is the Akeyless API / Gateway base URL. Empty uses the public
	// endpoint (shikumi-go/akeyless.DefaultGatewayURL).
	GatewayURL string `yaml:"gatewayUrl" json:"gatewayUrl"`
	// AccessID is the Akeyless access-id (`p-…`). Not a secret.
	AccessID string `yaml:"accessId" json:"accessId"`
	// AccessKey is the api_key access-key (the one secret). Expose a
	// shikumi.Secret[string] into this field only at the resolver build site.
	AccessKey string `yaml:"-" json:"-"`
	// CloudID is the base64 cloud-identity token for aws_iam/azure_ad/gcp
	// (produced by akeyless-go-cloud-id). Required for those kinds.
	CloudID string `yaml:"-" json:"-"`
	// JWT is the bearer JWT for oidc/k8s/gcp-style JWT auth.
	JWT string `yaml:"-" json:"-"`
	// K8sAuthConfigName is the gateway's configured k8s-auth method name (k8s).
	K8sAuthConfigName string `yaml:"k8sAuthConfigName" json:"k8sAuthConfigName"`
	// K8sServiceAccountToken is the projected SA token (k8s).
	K8sServiceAccountToken string `yaml:"-" json:"-"`
	// AdminEmail / AdminPassword are the email-method credentials.
	AdminEmail    string `yaml:"adminEmail" json:"adminEmail"`
	AdminPassword string `yaml:"-" json:"-"`
	// LDAPPassword pairs with AccessID for ldap.
	LDAPPassword string `yaml:"-" json:"-"`
	// CertData / SignedCertChallenge are the cert-method material.
	CertData            string `yaml:"-" json:"-"`
	SignedCertChallenge string `yaml:"-" json:"-"`
	// UIDToken is the rotating universal-identity token.
	UIDToken string `yaml:"-" json:"-"`
	// RefreshSkew is the Session refresh skew. Zero uses auth.DefaultRefreshSkew.
	RefreshSkew time.Duration `yaml:"refreshSkew" json:"refreshSkew"`
}

// Resolver is the SDK-backed auth.AuthResolver. It mints via V2Api.Auth and is
// the resolver a tool wires into the core via auth.WithResolver(r) (Law 8 — the
// core never imports the SDK; this leaf hands it an interface value).
type Resolver struct {
	client *ak.APIClient
	creds  Credentials
	kind   auth.AuthKind
	skew   time.Duration
}

// compile-time proof the SDK resolver satisfies the §3.5 fleet shape.
var _ auth.AuthResolver = (*Resolver)(nil)

// newClient builds an *akeyless.APIClient pointed at the gateway URL (or the
// public endpoint). It is the one place the SDK Configuration is constructed.
func newClient(gatewayURL string) *ak.APIClient {
	cfg := ak.NewConfiguration()
	url := gatewayURL
	if url == "" {
		url = shikuakeyless.DefaultGatewayURL
	}
	cfg.Servers = ak.ServerConfigurations{{URL: url}}
	return ak.NewAPIClient(cfg)
}

// NewResolver builds the SDK-minting resolver from typed [Credentials]. It does
// not authenticate eagerly — Resolve/Token mint lazily — so it can be
// constructed during offline bootstrap. The kind must be one of the known
// methods; an invalid kind is rejected here.
func NewResolver(creds Credentials) (*Resolver, error) {
	kind := creds.Kind
	if kind == "" {
		kind = auth.KindAPIKey
	}
	if !kind.Valid() {
		return nil, fmt.Errorf("akeyless: invalid auth kind %q", creds.Kind)
	}
	skew := creds.RefreshSkew
	if skew <= 0 {
		skew = auth.DefaultRefreshSkew
	}
	return &Resolver{
		client: newClient(creds.GatewayURL),
		creds:  creds,
		kind:   kind,
		skew:   skew,
	}, nil
}

// Kinds reports the single method this resolver mints from (§3.5).
func (r *Resolver) Kinds() []auth.AuthKind { return []auth.AuthKind{r.kind} }

// Resolve returns the *auth.Session that owns the live token. The Session's
// MintFunc calls [Resolver.mint], so the bearer value is produced lazily and
// re-minted at refresh time — and lives only inside the Session (CFG-09).
func (r *Resolver) Resolve(_ context.Context) (*auth.Session, error) {
	return auth.NewSession(r.kind, r.mint, auth.WithRefreshSkew(r.skew))
}

// mint performs one V2Api.Auth call for the configured method and parses the
// resulting token + expiry into an auth.Token.
func (r *Resolver) mint(ctx context.Context) (auth.Token, error) {
	body, err := r.buildAuth()
	if err != nil {
		return auth.Token{}, err
	}
	out, _, err := r.client.V2Api.Auth(ctx).Body(*body).Execute()
	if err != nil {
		return auth.Token{}, fmt.Errorf("akeyless: auth(%s): %w", r.kind, err)
	}
	tv, ok := out.GetTokenOk()
	if !ok || tv == nil || *tv == "" {
		return auth.Token{}, fmt.Errorf("akeyless: auth(%s): empty token in response", r.kind)
	}
	return auth.Token{Value: *tv, Expiry: parseExpiry(out, time.Now())}, nil
}

// buildAuth assembles the *akeyless.Auth body for the configured method, setting
// only the fields that method needs. Missing required material is a clear error
// rather than a confusing server-side 400.
func (r *Resolver) buildAuth() (*ak.Auth, error) {
	body := ak.NewAuth()
	body.SetAccessType(r.kind.String())
	if r.creds.AccessID != "" {
		body.SetAccessId(r.creds.AccessID)
	}
	switch r.kind {
	case auth.KindAPIKey:
		if r.creds.AccessKey == "" {
			return nil, fmt.Errorf("akeyless: api_key requires an access-key")
		}
		body.SetAccessKey(r.creds.AccessKey)
	case auth.KindAWSIAM, auth.KindAzureAD, auth.KindGCP:
		if r.creds.CloudID == "" && r.creds.JWT == "" {
			return nil, fmt.Errorf("akeyless: %s requires a cloud-id or jwt", r.kind)
		}
		if r.creds.CloudID != "" {
			body.SetCloudId(r.creds.CloudID)
		}
		if r.creds.JWT != "" {
			body.SetJwt(r.creds.JWT)
		}
	case auth.KindK8s:
		if r.creds.K8sServiceAccountToken == "" {
			return nil, fmt.Errorf("akeyless: k8s requires a service-account token")
		}
		body.SetK8sServiceAccountToken(r.creds.K8sServiceAccountToken)
		if r.creds.K8sAuthConfigName != "" {
			body.SetK8sAuthConfigName(r.creds.K8sAuthConfigName)
		}
		if r.creds.JWT != "" {
			body.SetJwt(r.creds.JWT)
		}
	case auth.KindOIDC, auth.KindSAML:
		if r.creds.JWT == "" {
			return nil, fmt.Errorf("akeyless: %s requires a jwt", r.kind)
		}
		body.SetJwt(r.creds.JWT)
	case auth.KindEmail:
		if r.creds.AdminEmail == "" || r.creds.AdminPassword == "" {
			return nil, fmt.Errorf("akeyless: email requires admin-email and admin-password")
		}
		body.SetAdminEmail(r.creds.AdminEmail)
		body.SetAdminPassword(r.creds.AdminPassword)
	case auth.KindLDAP:
		if r.creds.LDAPPassword == "" {
			return nil, fmt.Errorf("akeyless: ldap requires an ldap-password")
		}
		body.SetLdapPassword(r.creds.LDAPPassword)
	case auth.KindCert:
		if r.creds.CertData == "" {
			return nil, fmt.Errorf("akeyless: cert requires cert-data")
		}
		body.SetCertData(r.creds.CertData)
		if r.creds.SignedCertChallenge != "" {
			body.SetSignedCertChallenge(r.creds.SignedCertChallenge)
		}
	case auth.KindUniversalIdentity:
		if r.creds.UIDToken == "" {
			return nil, fmt.Errorf("akeyless: universal_identity requires a uid-token")
		}
		body.SetUidToken(r.creds.UIDToken)
	default:
		return nil, fmt.Errorf("akeyless: unsupported auth kind %q", r.kind)
	}
	return body, nil
}

// parseExpiry reads the Auth response's expiration into an absolute instant.
// Akeyless reports expiration as an RFC3339 timestamp; when absent or
// unparseable, a [DefaultTokenTTL] window from now is assumed so the Session
// still refreshes on schedule.
func parseExpiry(out *ak.AuthOutput, now time.Time) time.Time {
	if e, ok := out.GetExpirationOk(); ok && e != nil && *e != "" {
		if ts, err := time.Parse(time.RFC3339, *e); err == nil {
			return ts
		}
	}
	return now.Add(DefaultTokenTTL)
}
