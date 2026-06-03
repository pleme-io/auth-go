package auth

import (
	"context"
	"os"
	"time"
)

// StaticTokenResolver is a zero-dep [AuthResolver] that wraps an
// already-minted bearer token. It never touches the network and never imports
// the SDK, so the core happy path (and every test) authenticates offline.
//
// It is the right resolver when a `t-…` token has already been obtained out of
// band — by an outer `akeyless auth` call, an injected K8s secret, a sidecar, or
// a test fixture — and a tool just needs to carry it in the one sanctioned home
// (CFG-09). Because the value is fixed, the resulting [Session] re-mints to the
// same token (it does not call back out), so a zero Expiry (the default) means
// "treat as permanently valid"; supply [WithStaticExpiry] when the external
// token has a known lifetime so [Session.Snapshot] reports it accurately.
type StaticTokenResolver struct {
	token  string
	expiry time.Time
	kind   AuthKind
	skew   time.Duration
}

// StaticOption configures a [StaticTokenResolver] / [EnvTokenResolver].
type StaticOption func(*StaticTokenResolver)

// WithStaticExpiry records the external token's hard expiry so [Session.Snapshot]
// reports validity correctly. A static resolver re-mints to the same value, so
// past expiry the Session reports invalid (callers should obtain a fresh token
// out of band) rather than silently serving a stale one.
func WithStaticExpiry(t time.Time) StaticOption {
	return func(r *StaticTokenResolver) { r.expiry = t }
}

// WithStaticKind labels which auth method produced the external token (purely
// for [AuthResolver.Kinds] / status reporting; the default is [KindAPIKey]).
func WithStaticKind(k AuthKind) StaticOption {
	return func(r *StaticTokenResolver) {
		if k.Valid() {
			r.kind = k
		}
	}
}

// WithStaticRefreshSkew sets the [Session]'s refresh skew (default
// [DefaultRefreshSkew]).
func WithStaticRefreshSkew(d time.Duration) StaticOption {
	return func(r *StaticTokenResolver) {
		if d >= 0 {
			r.skew = d
		}
	}
}

// NewStaticTokenResolver wraps a fixed bearer token as a zero-dep resolver. An
// empty token is allowed at construction but yields [ErrNoToken] on Resolve, so
// a misconfigured tool fails loudly at auth time rather than minting an empty
// token.
func NewStaticTokenResolver(token string, opts ...StaticOption) *StaticTokenResolver {
	r := &StaticTokenResolver{
		token: token,
		kind:  KindAPIKey,
		skew:  DefaultRefreshSkew,
	}
	for _, o := range opts {
		if o != nil {
			o(r)
		}
	}
	return r
}

// Kinds reports the single method this resolver represents.
func (r *StaticTokenResolver) Kinds() []AuthKind { return []AuthKind{r.kind} }

// Resolve builds a [*Session] whose MintFunc returns the fixed token. It does
// not eagerly mint, matching the lazy contract; the empty-token check fires on
// first [Session.Token] via the MintFunc, but Resolve also rejects an empty
// token up front so misconfiguration surfaces immediately.
func (r *StaticTokenResolver) Resolve(_ context.Context) (*Session, error) {
	if r.token == "" {
		return nil, ErrNoToken
	}
	tok := Token{Value: r.token, Expiry: r.expiry}
	mint := func(context.Context) (Token, error) { return tok, nil }
	return NewSession(r.kind, mint, WithRefreshSkew(r.skew))
}

// EnvTokenResolver is a zero-dep [AuthResolver] that reads a bearer token from an
// environment variable at Resolve time. It is the offline-friendly resolver for
// CI and containerized contexts where an outer step (an `akeyless auth`, a
// secrets-store CSI mount writing to env, a sidecar) has already placed a token
// in the environment.
//
// CFG-09 is honoured: the env var is read once, at Resolve, and the value flows
// straight into a [Session] — it is never copied into config or a package var.
type EnvTokenResolver struct {
	envVar string
	kind   AuthKind
	skew   time.Duration
	expiry time.Time
	lookup func(string) (string, bool) // injectable for tests
}

// DefaultTokenEnv is the conventional environment variable an out-of-band auth
// step writes the bearer token to.
const DefaultTokenEnv = "AKEYLESS_TOKEN"

// EnvOption configures an [EnvTokenResolver].
type EnvOption func(*EnvTokenResolver)

// WithEnvVar overrides [DefaultTokenEnv].
func WithEnvVar(name string) EnvOption {
	return func(r *EnvTokenResolver) {
		if name != "" {
			r.envVar = name
		}
	}
}

// WithEnvKind labels which method produced the env token (default [KindAPIKey]).
func WithEnvKind(k AuthKind) EnvOption {
	return func(r *EnvTokenResolver) {
		if k.Valid() {
			r.kind = k
		}
	}
}

// WithEnvExpiry records the env token's hard expiry for accurate status.
func WithEnvExpiry(t time.Time) EnvOption {
	return func(r *EnvTokenResolver) { r.expiry = t }
}

// WithEnvRefreshSkew sets the Session's refresh skew (default
// [DefaultRefreshSkew]).
func WithEnvRefreshSkew(d time.Duration) EnvOption {
	return func(r *EnvTokenResolver) {
		if d >= 0 {
			r.skew = d
		}
	}
}

// withEnvLookup injects an environment lookup (test-only).
func withEnvLookup(f func(string) (string, bool)) EnvOption {
	return func(r *EnvTokenResolver) {
		if f != nil {
			r.lookup = f
		}
	}
}

// NewEnvTokenResolver builds a resolver that reads the token from an env var
// ([DefaultTokenEnv] unless [WithEnvVar] overrides it).
func NewEnvTokenResolver(opts ...EnvOption) *EnvTokenResolver {
	r := &EnvTokenResolver{
		envVar: DefaultTokenEnv,
		kind:   KindAPIKey,
		skew:   DefaultRefreshSkew,
		lookup: os.LookupEnv,
	}
	for _, o := range opts {
		if o != nil {
			o(r)
		}
	}
	return r
}

// Kinds reports the single method this resolver represents.
func (r *EnvTokenResolver) Kinds() []AuthKind { return []AuthKind{r.kind} }

// Resolve reads the env var and builds a [*Session] around it. It returns
// [ErrNoToken] when the variable is unset or empty, so a CI job missing the
// token fails at auth time with a clear sentinel.
func (r *EnvTokenResolver) Resolve(_ context.Context) (*Session, error) {
	v, ok := r.lookup(r.envVar)
	if !ok || v == "" {
		return nil, ErrNoToken
	}
	tok := Token{Value: v, Expiry: r.expiry}
	mint := func(context.Context) (Token, error) { return tok, nil }
	return NewSession(r.kind, mint, WithRefreshSkew(r.skew))
}
