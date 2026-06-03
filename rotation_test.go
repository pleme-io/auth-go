package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A session without rotation reports HasRotation=false and Rotate → ErrNoRotation.
func TestSession_NoRotation(t *testing.T) {
	s, _ := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		return Token{Value: "t"}, nil
	})
	if s.HasRotation() {
		t.Error("api_key session reports HasRotation, want false")
	}
	if s.RotationInterval() != 0 {
		t.Errorf("RotationInterval = %v, want 0", s.RotationInterval())
	}
	if err := s.Rotate(context.Background()); !errors.Is(err, ErrNoRotation) {
		t.Errorf("Rotate err = %v, want ErrNoRotation", err)
	}
	if err := s.RotateEvery(context.Background()); !errors.Is(err, ErrNoRotation) {
		t.Errorf("RotateEvery err = %v, want ErrNoRotation", err)
	}
}

// WithRotation installs a RotateFunc; Rotate advances the credential and the
// rotated value is held in the session (never in Status).
func TestSession_Rotate(t *testing.T) {
	var n int
	rotate := func(context.Context) (string, error) {
		n++
		return "uid-" + time.Duration(n).String(), nil
	}
	s, _ := NewSession(KindUniversalIdentity,
		func(context.Context) (Token, error) { return Token{Value: "t"}, nil },
		WithRotation(rotate, 0), // 0 → DefaultRotationInterval
	)
	if !s.HasRotation() {
		t.Fatal("session reports no rotation, want HasRotation")
	}
	if s.RotationInterval() != DefaultRotationInterval {
		t.Errorf("interval = %v, want default %v", s.RotationInterval(), DefaultRotationInterval)
	}
	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Rotated(); got != "uid-1ns" {
		t.Errorf("Rotated = %q, want uid-1ns", got)
	}
	// A rotation error is surfaced.
	boom := errors.New("rotate backend down")
	s2, _ := NewSession(KindUniversalIdentity,
		func(context.Context) (Token, error) { return Token{Value: "t"}, nil },
		WithRotation(func(context.Context) (string, error) { return "", boom }, time.Minute),
	)
	if err := s2.Rotate(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Rotate err = %v, want boom", err)
	}
}

// RotateEvery rotates immediately then exits cleanly on context cancellation.
func TestSession_RotateEvery(t *testing.T) {
	var n int
	s, _ := NewSession(KindUniversalIdentity,
		func(context.Context) (Token, error) { return Token{Value: "t"}, nil },
		WithRotation(func(context.Context) (string, error) { n++; return "uid", nil }, time.Hour),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the first tick
	err := s.RotateEvery(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RotateEvery err = %v, want context.Canceled", err)
	}
	// The immediate rotation still fired once before the cancelled select.
	if n != 1 {
		t.Errorf("rotations = %d, want 1 (immediate)", n)
	}
}
