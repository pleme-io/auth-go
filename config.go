package auth

import (
	"fmt"
	"time"
)

// Config is the typed, yaml-tagged knob surface for the auth primitive (Law 3).
// It is the sub-struct a caller's shikumi-loaded root config embeds:
//
//	type Root struct {
//	    Auth auth.Config `yaml:"auth"`
//	    // …
//	}
//
// and hands to [FromConfig]. Per BOREALIS §3.5, [FromConfig] consumes this
// already-loaded struct and MUST NOT itself call shikumi.Load — config loading
// happens once, at main, via shikumi.For[Root]; every primitive only consumes
// its sub-struct.
//
// CFG-09: Config carries NO live token. It carries the *credentials and
// selectors* needed to mint one (auth kind, access-id, gateway URL, the env var
// to read a pre-minted token from). The minted token lives only in a [Session].
// Secret-typed credential fields (access-key) belong in a shikumi.Secret[string]
// on the caller's root config, exposed at the point this resolver is built — the
// core Config deliberately models only the zero-dep Token/Env path so it stays
// SDK-free; the akeyless sub-package's config consumes the full credential set.
type Config struct {
	// Kind selects the auth method (the `--auth` value). Empty defaults to
	// [KindAPIKey]. The core [FromConfig] can only build the token-carrying
	// resolvers (Static/Env); SDK-minting kinds are built by the akeyless
	// sub-package's resolver factory, which reads this same Config.
	Kind string `yaml:"kind" json:"kind"`
	// Token is a pre-minted bearer token supplied directly (e.g. injected). When
	// non-empty the core [FromConfig] builds a [StaticTokenResolver]. Prefer
	// TokenEnv over inlining a token in config; a token here is still never
	// retained beyond resolver construction (CFG-09).
	Token string `yaml:"token" json:"token"`
	// TokenEnv names the environment variable a pre-minted token is read from
	// (default [DefaultTokenEnv]). When Token is empty and an env path is wanted,
	// the core [FromConfig] builds an [EnvTokenResolver].
	TokenEnv string `yaml:"tokenEnv" json:"tokenEnv"`
	// GatewayURL is the Akeyless API / Gateway base URL the SDK-backed resolvers
	// authenticate against (the akeyless sub-package reads it). Empty means the
	// public endpoint. Modelled in core so the one Config shape spans both the
	// zero-dep and SDK paths.
	GatewayURL string `yaml:"gatewayUrl" json:"gatewayUrl"`
	// AccessID is the Akeyless access-id (`p-…`) for the SDK-backed resolvers.
	// Not a secret. Read by the akeyless sub-package.
	AccessID string `yaml:"accessId" json:"accessId"`
	// RefreshSkew is how far before hard expiry a [Session] re-auths. Zero uses
	// [DefaultRefreshSkew].
	RefreshSkew time.Duration `yaml:"refreshSkew" json:"refreshSkew"`
}

// config is the resolved option set used by [New]. It is internal; callers
// configure it through [Option] values passed to [New], or via the yaml [Config]
// handed to [FromConfig].
type config struct {
	resolver    AuthResolver
	token       string
	tokenEnv    string
	kind        AuthKind
	refreshSkew time.Duration
}

// Option configures [New] using the functional-options pattern, matching the
// house style across the pleme-io Go libraries (shikumi-go, logging-go,
// errors-go, metrics-go).
type Option func(*config)

// WithResolver installs an explicit [AuthResolver] — the seam the akeyless
// sub-package uses to hand the core an SDK-backed resolver without the core
// importing the SDK (Law 6 / Law 8). When set, [New] returns it directly and
// ignores the token/env options.
func WithResolver(r AuthResolver) Option {
	return func(c *config) { c.resolver = r }
}

// WithStaticToken makes [New] build a [StaticTokenResolver] around a pre-minted
// token.
func WithStaticToken(token string) Option {
	return func(c *config) { c.token = token }
}

// WithTokenEnv makes [New] build an [EnvTokenResolver] reading the named env var
// (empty keeps [DefaultTokenEnv]).
func WithTokenEnv(name string) Option {
	return func(c *config) { c.tokenEnv = name }
}

// WithKind labels the auth method for status/Kinds reporting (default
// [KindAPIKey]).
func WithKind(k AuthKind) Option {
	return func(c *config) {
		if k.Valid() {
			c.kind = k
		}
	}
}

// WithRefreshSkewOption sets the [Session] refresh skew the built resolver uses.
func WithRefreshSkewOption(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.refreshSkew = d
		}
	}
}

// New is the canonical constructor (BOREALIS §3.5:
// `New(required…, opts ...Option) (*T, error)`). It returns the configured core
// [AuthResolver]. Precedence among the built-in resolvers:
//
//  1. an explicit [WithResolver] (e.g. the SDK-backed one from the akeyless
//     sub-package) wins;
//  2. else a non-empty [WithStaticToken] builds a [StaticTokenResolver];
//  3. else an [EnvTokenResolver] reads [WithTokenEnv] (or [DefaultTokenEnv]).
//
// It returns an error only when an explicitly-supplied resolver is nil. The
// option-free path never errors: it yields an [EnvTokenResolver] over
// [DefaultTokenEnv], which fails (with [ErrNoToken]) only later, at Resolve, if
// no token was placed in the environment — keeping construction offline and
// total.
func New(opts ...Option) (AuthResolver, error) {
	c := config{
		kind:        KindAPIKey,
		refreshSkew: DefaultRefreshSkew,
	}
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	if c.resolver != nil {
		return c.resolver, nil
	}
	switch {
	case c.token != "":
		return NewStaticTokenResolver(c.token,
			WithStaticKind(c.kind),
			WithStaticRefreshSkew(c.refreshSkew),
		), nil
	default:
		return NewEnvTokenResolver(
			WithEnvVar(c.tokenEnv),
			WithEnvKind(c.kind),
			WithEnvRefreshSkew(c.refreshSkew),
		), nil
	}
}

// FromConfig builds the core [AuthResolver] from an already-loaded [Config]
// (BOREALIS §3.5). It is the canonical config-consuming constructor: it takes the
// sub-struct and MUST NOT call shikumi.Load — loading happened once at main.
//
// It handles only the zero-dep paths (a pre-minted Token, or a TokenEnv to read
// one from). For an SDK-minting Kind (aws_iam/azure_ad/gcp/k8s/oidc/saml/cert/
// email/ldap/universal_identity, or api_key with an access-key), the akeyless
// sub-package owns the resolver factory (it has the SDK + the secret-typed
// access-key); a tool wires that resolver in via [WithResolver]. FromConfig
// returns an error for an unparseable Kind, so a typo in `auth.kind:` fails at
// build time rather than producing a silently-wrong resolver.
func FromConfig(cfg Config) (AuthResolver, error) {
	kind := KindAPIKey
	if cfg.Kind != "" {
		k, err := ParseKind(cfg.Kind)
		if err != nil {
			return nil, fmt.Errorf("auth: config: %w", err)
		}
		kind = k
	}
	opts := []Option{WithKind(kind), WithRefreshSkewOption(cfg.RefreshSkew)}
	switch {
	case cfg.Token != "":
		opts = append(opts, WithStaticToken(cfg.Token))
	default:
		opts = append(opts, WithTokenEnv(cfg.TokenEnv))
	}
	return New(opts...)
}
