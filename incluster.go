package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"time"
)

// DefaultServiceAccountTokenPath is the well-known in-cluster mount point of a
// Kubernetes projected service-account token. Every pod with an automounted
// (or explicitly projected) service-account gets a JWT here; it is the
// credential the k8s auth method presents to a gateway-configured k8s-auth
// method. The constant lives in the zero-dep core so an in-cluster tool never
// hardcodes the path itself.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// ErrNotInCluster is returned by [InClusterToken] / [InClusterResolver].Resolve
// when no projected service-account token is present at the mount path — i.e.
// the process is not running inside a pod (or the SA is not projected). It is a
// sentinel so a tool can branch on errors.Is(err, auth.ErrNotInCluster) and fall
// back to another resolver.
var ErrNotInCluster = errors.New("auth: not running in a kubernetes cluster (no projected service-account token)")

// InClusterProfile is the typed knob surface for reading a projected
// service-account JWT from inside a pod. Every field has a sane in-cluster
// default, so the zero-value profile reads the standard mount path and presents
// the raw JWT.
//
// # The base64 quirk
//
// Some gateway k8s-auth configurations expect the service-account JWT to be
// presented *base64-encoded* (the value is double-handled: read from the file,
// then base64-StdEncoded before it is sent as the k8s-service-account-token
// field), while others expect the raw JWT. This is a real, recurring
// deployment-shape divergence, so it is a typed knob ([InClusterProfile.Base64])
// rather than tribal per-tool knowledge — the in-cluster profile owns the quirk
// once for the whole fleet.
type InClusterProfile struct {
	// TokenPath is the file the projected SA token is read from. Empty uses
	// [DefaultServiceAccountTokenPath].
	TokenPath string `yaml:"tokenPath" json:"tokenPath"`
	// Base64 base64-StdEncodes the JWT before presenting it. Set this only when
	// the gateway's k8s-auth method expects an encoded token (the quirk above);
	// the default presents the raw JWT.
	Base64 bool `yaml:"base64" json:"base64"`
	// K8sAuthConfigName is the gateway-side configured k8s-auth method name the
	// token authenticates against. The core does not use it (it has no SDK) but
	// carries it so the one profile shape spans the zero-dep reader and the
	// SDK-backed leaf that mints with it.
	K8sAuthConfigName string `yaml:"k8sAuthConfigName" json:"k8sAuthConfigName"`
	// readFile is an injectable file reader (test-only; unexported).
	readFile func(string) ([]byte, error)
}

// InClusterToken reads the projected service-account JWT for the profile,
// applying the base64 quirk when requested. It returns [ErrNotInCluster] when
// the token file is absent (the not-in-a-pod case) so callers can fall back.
// The returned string is the credential value a k8s-auth mint presents; it is
// read at the point of use and never retained by the profile (CFG-09).
func (p InClusterProfile) InClusterToken() (string, error) {
	path := p.TokenPath
	if path == "" {
		path = DefaultServiceAccountTokenPath
	}
	read := p.readFile
	if read == nil {
		read = os.ReadFile
	}
	raw, err := read(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotInCluster
		}
		return "", err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", ErrNotInCluster
	}
	if p.Base64 {
		return base64.StdEncoding.EncodeToString([]byte(tok)), nil
	}
	return tok, nil
}

// InClusterResolver is a zero-dep [AuthResolver] for the in-cluster k8s profile.
// It reads the projected SA JWT at Resolve time and hands back a [*Session]
// whose token *is* that JWT — useful when an outer component already exchanged
// the SA token for a `t-…` bearer, or when a tool forwards the SA JWT directly
// to a k8s-via-gateway flow it drives itself. For the SDK-minting path (present
// the SA token to V2Api.Auth and receive a `t-…`), the akeyless leaf's resolver
// reads the same [InClusterProfile]; this core resolver stays SDK-free.
//
// It is the offline-friendly resolver for operators and CSI providers that run
// in a pod and need the SA identity without importing client-go (Law 6).
type InClusterResolver struct {
	profile InClusterProfile
	skew    time.Duration
}

// compile-time proof the in-cluster resolver is an AuthResolver.
var _ AuthResolver = (*InClusterResolver)(nil)

// InClusterOption configures an [InClusterResolver].
type InClusterOption func(*InClusterResolver)

// WithInClusterBase64 toggles the base64 token quirk (see [InClusterProfile]).
func WithInClusterBase64(b bool) InClusterOption {
	return func(r *InClusterResolver) { r.profile.Base64 = b }
}

// WithInClusterTokenPath overrides [DefaultServiceAccountTokenPath].
func WithInClusterTokenPath(path string) InClusterOption {
	return func(r *InClusterResolver) {
		if path != "" {
			r.profile.TokenPath = path
		}
	}
}

// WithInClusterRefreshSkew sets the [Session] refresh skew.
func WithInClusterRefreshSkew(d time.Duration) InClusterOption {
	return func(r *InClusterResolver) {
		if d >= 0 {
			r.skew = d
		}
	}
}

// withInClusterReadFile injects a file reader (test-only).
func withInClusterReadFile(f func(string) ([]byte, error)) InClusterOption {
	return func(r *InClusterResolver) {
		if f != nil {
			r.profile.readFile = f
		}
	}
}

// NewInClusterResolver builds the zero-dep in-cluster resolver. It does not read
// the token eagerly — Resolve reads it — so it can be constructed offline.
func NewInClusterResolver(opts ...InClusterOption) *InClusterResolver {
	r := &InClusterResolver{skew: DefaultRefreshSkew}
	for _, o := range opts {
		if o != nil {
			o(r)
		}
	}
	return r
}

// Kinds reports KindK8s — the in-cluster profile authenticates via a
// service-account token bound to a gateway k8s-auth method.
func (r *InClusterResolver) Kinds() []AuthKind { return []AuthKind{KindK8s} }

// Profile returns a copy of the resolved [InClusterProfile] (so the SDK leaf can
// read the same mount path / quirk / config-name).
func (r *InClusterResolver) Profile() InClusterProfile { return r.profile }

// Resolve reads the projected SA token and builds a [*Session] holding it. It
// returns [ErrNotInCluster] when not running in a pod, so a tool fails with a
// clear sentinel rather than an empty token.
func (r *InClusterResolver) Resolve(_ context.Context) (*Session, error) {
	tok, err := r.profile.InClusterToken()
	if err != nil {
		return nil, err
	}
	mint := func(context.Context) (Token, error) {
		// Re-read on refresh: projected SA tokens rotate on the kubelet's
		// schedule, so the mint reads the current file each time rather than
		// caching the first value.
		v, err := r.profile.InClusterToken()
		if err != nil {
			return Token{}, err
		}
		return Token{Value: v}, nil
	}
	_ = tok // presence already verified above; mint re-reads at use.
	return NewSession(KindK8s, mint, WithRefreshSkew(r.skew))
}
