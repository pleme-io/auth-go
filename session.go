package auth

import (
	"context"
	"sync"
	"time"
)

// Token is the immutable result of one successful authentication: a live
// Akeyless `t-…` token and the instant it stops being valid. It is the
// oauth2.Token-shaped payload a Session hands out.
//
// CFG-09: a Token only ever lives inside a *Session. It is never assigned into
// a config struct, a package-level var, or a log field. The String/GoString
// methods redact so an accidental %v never prints the bearer value.
type Token struct {
	// Value is the bearer token (the Akeyless "t-…" string). Read it only at
	// the point of use (constructing a request); never copy it elsewhere.
	Value string
	// Expiry is when Value stops being accepted. A zero Expiry means "never
	// expires" (the token is treated as permanently valid and never refreshed).
	Expiry time.Time
}

const redacted = "[REDACTED]"

// String redacts. A Token must never print its bearer value.
func (Token) String() string { return redacted }

// GoString redacts (covers %#v).
func (Token) GoString() string { return redacted }

// Valid reports whether the token is non-empty and not past expiry (with no
// skew applied — see Session for skew-aware refresh).
func (t Token) Valid() bool {
	if t.Value == "" {
		return false
	}
	return t.Expiry.IsZero() || time.Now().Before(t.Expiry)
}

// expired reports whether the token should be refreshed, applying skew so a
// refresh fires *before* the hard expiry (avoiding a 401 on the next call).
func (t Token) expired(skew time.Duration, now time.Time) bool {
	if t.Value == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return !now.Before(t.Expiry.Add(-skew))
}

// MintFunc mints a fresh Token. It is the one method-specific operation a
// backend supplies; the Session owns caching, skew, refresh, and concurrency.
// The akeyless sub-package's MintFunc calls V2Api.Auth and reads the
// AuthOutput; the no-dep stub's MintFunc returns a static token.
type MintFunc func(ctx context.Context) (Token, error)

// DefaultRefreshSkew is how far before hard expiry a Session re-auths. Akeyless
// tokens are typically valid ~60 min; refreshing a minute early keeps a
// long-running gateway from 401-ing mid-request.
const DefaultRefreshSkew = time.Minute

// Session is the single CFG-09-sanctioned, process-scoped home for a live
// Akeyless token. It is oauth2.TokenSource-shaped: callers ask for a token and
// the Session transparently re-mints it at expiry-skew. It is safe for
// concurrent use.
//
// A Session is produced by AuthResolver.Resolve. Backends never expose the
// token directly — they hand back a Session whose Token(ctx) is the only door.
type Session struct {
	kind  MintFunc
	akind AuthKind
	skew  time.Duration
	now   func() time.Time // injectable clock for tests

	mu  sync.Mutex
	cur Token
}

// SessionOption configures a Session at construction (canonical functional-option
// shape, scoped to the Session so the package-level [Option] stays the
// resolver-construction surface for [New]).
type SessionOption func(*Session)

// WithRefreshSkew overrides DefaultRefreshSkew.
func WithRefreshSkew(d time.Duration) SessionOption {
	return func(s *Session) {
		if d >= 0 {
			s.skew = d
		}
	}
}

// withClock injects a clock (test-only; unexported so it isn't part of the
// public surface).
func withClock(now func() time.Time) SessionOption {
	return func(s *Session) {
		if now != nil {
			s.now = now
		}
	}
}

// NewSession builds a Session around a MintFunc for a given AuthKind. It is the
// canonical constructor (pkg.New(required…, opts ...Option) (*T, error)) the
// backends call after wiring their method-specific MintFunc. NewSession does
// NOT mint eagerly — the first Token(ctx) call triggers the first auth, so a
// resolver can be constructed offline and only touches the network on use.
func NewSession(kind AuthKind, mint MintFunc, opts ...SessionOption) (*Session, error) {
	if mint == nil {
		return nil, errNilMint
	}
	s := &Session{
		kind:  mint,
		akind: kind,
		skew:  DefaultRefreshSkew,
		now:   time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Kind reports which auth method minted this session.
func (s *Session) Kind() AuthKind { return s.akind }

// Token returns a currently-valid token, minting or refreshing transparently
// when the cached one is empty or within skew of expiry. This is the
// oauth2.TokenSource shape; it is the ONLY way to read the bearer value.
func (s *Session) Token(ctx context.Context) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cur.expired(s.skew, s.now()) {
		return s.cur, nil
	}
	tok, err := s.kind(ctx)
	if err != nil {
		return Token{}, err
	}
	s.cur = tok
	return tok, nil
}

// Refresh forces an immediate re-auth regardless of the cached token's expiry
// and returns the new token. lifecycle.WithAuth's refresher loop calls this on
// its schedule; on-demand callers normally use Token instead.
func (s *Session) Refresh(ctx context.Context) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, err := s.kind(ctx)
	if err != nil {
		return Token{}, err
	}
	s.cur = tok
	return tok, nil
}

// Snapshot returns a redaction-safe view of the session's current state for
// status reporting — never the bearer value. The borealis-render leaf
// (auth/render) turns this into a themed report.
func (s *Session) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	st := Status{
		Kind:        s.akind,
		RefreshIn:   0,
		HasToken:    s.cur.Value != "",
		Expiry:      s.cur.Expiry,
		RefreshSkew: s.skew,
	}
	if st.HasToken && !s.cur.Expiry.IsZero() {
		st.Valid = s.cur.Valid()
		if d := s.cur.Expiry.Add(-s.skew).Sub(now); d > 0 {
			st.RefreshIn = d
		}
	} else if st.HasToken {
		st.Valid = true // non-expiring token
	}
	return st
}
