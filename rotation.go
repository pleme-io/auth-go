package auth

import (
	"context"
	"errors"
	"time"
)

// ErrNoRotation is returned by [Session.Rotate] when the session was built
// without a [RotateFunc] — e.g. an api_key session, which has no rotating
// credential. It is a sentinel so a rotation loop can branch on
// errors.Is(err, auth.ErrNoRotation) and stop scheduling for that session.
var ErrNoRotation = errors.New("auth: session has no rotation function")

// DefaultRotationInterval is how often a universal-identity (UID) token is
// rotated when no explicit interval is configured. Akeyless UID tokens are
// rotated on use (each rotation yields the next token in the chain); rotating
// well inside the configured TTL keeps the chain from lapsing while a
// long-running tool is idle.
const DefaultRotationInterval = 50 * time.Minute

// RotateFunc rotates a credential out of band of token minting and returns the
// next credential value. It is the one method-specific operation the
// universal-identity flow supplies: UID auth mints a `t-…` token *and* hands
// back a fresh UID token to use next time, so the rotating credential must be
// advanced on a schedule independent of [Session.Token]'s skew-based mint. The
// akeyless leaf's UID resolver supplies a RotateFunc that calls
// V2Api.UidRotateToken; non-rotating methods supply none.
//
// The returned string is the new credential (a UID token); the Session forwards
// it to the next mint and never logs it (CFG-09).
type RotateFunc func(ctx context.Context) (string, error)

// WithRotation installs a [RotateFunc] and the interval at which a rotation
// scheduler should advance the credential. It is the additive Session knob that
// makes universal-identity (and any other rotate-on-use credential) a
// first-class, fleet-uniform concern rather than per-tool wiring. A
// non-positive interval uses [DefaultRotationInterval].
//
// Installing rotation does not start a loop — the lifecycle owner (or a tool's
// own goroutine) calls [Session.RotateEvery] / [Session.Rotate] under its
// supervision (mirroring how lifecycle.WithAuth drives [Session.Refresh]).
func WithRotation(rotate RotateFunc, interval time.Duration) SessionOption {
	return func(s *Session) {
		if rotate != nil {
			s.rotate = rotate
			if interval > 0 {
				s.rotateEvery = interval
			} else {
				s.rotateEvery = DefaultRotationInterval
			}
		}
	}
}

// HasRotation reports whether this session was built with a [RotateFunc].
func (s *Session) HasRotation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotate != nil
}

// RotationInterval reports the configured rotation interval (zero when the
// session has no rotation).
func (s *Session) RotationInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateEvery
}

// Rotate advances the rotating credential once, calling the installed
// [RotateFunc]. It returns [ErrNoRotation] if none was installed. The new
// credential is held only inside the session (CFG-09) and is used by the next
// mint; callers never receive it.
func (s *Session) Rotate(ctx context.Context) error {
	s.mu.Lock()
	rot := s.rotate
	s.mu.Unlock()
	if rot == nil {
		return ErrNoRotation
	}
	next, err := rot(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.rotated = next
	s.mu.Unlock()
	return nil
}

// Rotated returns the most recently rotated credential value, if any. It is the
// seam the mint side reads to pick up the advanced UID token; it returns "" when
// no rotation has happened. It is unexported-adjacent in spirit (a token-bearing
// value) — callers other than a mint closure should not read it, and it never
// appears in [Status].
func (s *Session) Rotated() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotated
}

// RotateEvery drives the rotation scheduler until ctx is cancelled: it rotates
// the credential immediately, then every [Session.RotationInterval]. It is the
// "keep the UID chain fresh" loop a long-running tool registers under its
// lifecycle supervision (the rotation sibling of the mint-refresh loop). It
// returns ctx.Err() on cancellation, or [ErrNoRotation] immediately if the
// session has no rotation. A rotation error is returned (so the supervisor can
// back off and restart); the caller decides retry policy.
func (s *Session) RotateEvery(ctx context.Context) error {
	if !s.HasRotation() {
		return ErrNoRotation
	}
	interval := s.RotationInterval()
	if err := s.Rotate(ctx); err != nil {
		return err
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := s.Rotate(ctx); err != nil {
				return err
			}
		}
	}
}
