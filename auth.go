// Package auth is the pleme-io fleet authentication primitive (BOREALIS §2.2a):
// the neutrally-named, akeyless-first auth seam that every Go tool wires the
// same shape.
//
// Every akeyless tool's first act is minting a `t-…` token from one of a closed
// set of auth methods (API-Key / AWS-IAM / Azure-AD / GCP / K8s / OIDC / SAML /
// cert / email / LDAP / universal-identity) and constructing an authenticated
// client. That is the single most akeyless-specific concern in the fleet — so
// it is a primitive, not per-tool boilerplate.
//
// # The one shape
//
// A resolver mints; a session holds. Both have exactly one shape across every
// method (BOREALIS §3.5):
//
//		type AuthResolver interface {
//		    Resolve(ctx context.Context) (*Session, error)
//		    Kinds() []AuthKind
//		}
//
//	  - [AuthResolver.Resolve] returns a [*Session] — the ONE CFG-09-sanctioned,
//	    process-scoped home for a live token. The token lives only there: never in
//	    a config struct, never in a package-level var, never in a log field.
//	  - [AuthResolver.Kinds] reports which methods this resolver can mint. cli-go
//	    auto-wires the `--auth` flag value set from a resolver's Kinds() (§2.2), so
//	    a tool never hand-maintains the list of supported methods.
//
// # Weight (BOREALIS Law 6)
//
// This core package is ZERO-DEP: it builds and tests offline. The zero-dep
// resolvers ([StaticTokenResolver] / [EnvTokenResolver]) let the core happy path
// authenticate without ever touching the network or the SDK. The akeylesslabs
// akeyless-go SDK — the heavy, network-bearing piece — is import-gated to the
// auth-go/akeyless sub-package, which is also where the
// shikumi-go/akeyless.SecretGetter seam is implemented so a tool's shikumi
// `Secrets()` chain resolves akeyless secrets post-auth.
package auth

import (
	"context"
	"errors"
	"time"
)

// errNilMint is returned by [NewSession] when given a nil [MintFunc]. A Session
// without a mint operation can never produce a token, so it is rejected at
// construction rather than failing on first use.
var errNilMint = errors.New("auth: nil mint function")

// ErrNoToken is returned when a resolver is asked to produce a Session but no
// token (nor a way to mint one) is available — e.g. an [EnvTokenResolver] whose
// environment variable is unset. It is a sentinel so callers can branch on
// errors.Is(err, auth.ErrNoToken).
var ErrNoToken = errors.New("auth: no token available")

// AuthResolver is THE fleet auth seam (BOREALIS §3.5). One shape spans every
// method: a resolver mints a token (or wraps an already-minted one) and hands
// back the [*Session] that owns it. Implementations live wherever their weight
// belongs — the zero-dep [StaticTokenResolver] / [EnvTokenResolver] here in
// core, the SDK-backed per-method resolvers in the import-gated
// auth-go/akeyless sub-package.
//
// Resolve is idempotent-friendly: it constructs the Session without eagerly
// minting (the Session mints lazily on first [Session.Token]), so a resolver can
// be Resolved during offline bootstrap and only touch the network on use.
type AuthResolver interface {
	// Resolve builds the process-scoped [*Session] that holds the live token.
	// The returned Session is the only sanctioned home for the bearer value.
	Resolve(ctx context.Context) (*Session, error)
	// Kinds reports the closed set of auth methods this resolver can mint from.
	// cli-go's `--auth` flag value set is auto-wired from this (§2.2).
	Kinds() []AuthKind
}

// Status is the redaction-safe view of a [Session]'s current state, returned by
// [Session.Snapshot]. It carries NO bearer value — only the method, whether a
// token is present, its expiry, validity, and how long until the next refresh
// fires. It is the typed value a render leaf turns into a themed report via the
// fleet's single render verb, borealis.Render(theme, status) (BOREALIS §3.5 —
// borealis owns Render; this package never imports it).
type Status struct {
	// Kind is the auth method that minted (or would mint) the session's token.
	Kind AuthKind
	// HasToken reports whether a token has been minted and cached.
	HasToken bool
	// Valid reports whether the cached token is currently usable (non-empty and
	// not past hard expiry). Meaningless when HasToken is false.
	Valid bool
	// Expiry is the cached token's hard expiry. Zero means a non-expiring token.
	Expiry time.Time
	// RefreshIn is how long until the session would re-mint (expiry minus skew),
	// from the moment Snapshot was taken. Zero when there is no token, the token
	// never expires, or a refresh is already due.
	RefreshIn time.Duration
	// RefreshSkew is how far before hard expiry the session re-auths.
	RefreshSkew time.Duration
}

// String returns a plain, redaction-safe one-line summary of the session state.
// It is a fmt.Stringer, which borealis.Render dispatches on (its `case
// fmt.Stringer`), so `borealis.Render(theme, sess.Snapshot())` yields this text
// WITHOUT auth-go ever importing borealis (Law 6 — the core stays zero-dep). A
// render leaf (auth-go/render, deferred to the wiring wave) can upgrade this to
// a themed comp.StatusList by implementing borealis.Renderable; until then the
// Stringer keeps the render verb total. It never prints the bearer value.
func (s Status) String() string {
	tok := "no token"
	if s.HasToken {
		if s.Valid {
			tok = "valid"
		} else {
			tok = "expired"
		}
	}
	exp := "never"
	if !s.Expiry.IsZero() {
		exp = s.Expiry.Format(time.RFC3339)
	}
	ref := "n/a"
	if s.RefreshIn > 0 {
		ref = s.RefreshIn.Round(time.Second).String()
	}
	return "auth: kind=" + s.Kind.String() +
		" token=" + tok +
		" expiry=" + exp +
		" refresh-in=" + ref
}
