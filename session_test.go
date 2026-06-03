package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// NewSession rejects a nil mint (errNilMint) and accepts a real one.
func TestNewSession_NilMint(t *testing.T) {
	if _, err := NewSession(KindAPIKey, nil); !errors.Is(err, errNilMint) {
		t.Fatalf("NewSession(nil) err = %v, want errNilMint", err)
	}
	s, err := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		return Token{Value: "t-x"}, nil
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s.Kind() != KindAPIKey {
		t.Errorf("Kind = %q, want api_key", s.Kind())
	}
}

// Token mints lazily on first call and caches thereafter (no re-mint while
// valid). Construction must not touch the mint func.
func TestSession_TokenLazyAndCached(t *testing.T) {
	var mints int
	s, _ := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		mints++
		return Token{Value: "t-1", Expiry: time.Now().Add(time.Hour)}, nil
	})
	if mints != 0 {
		t.Fatalf("constructed eagerly minted %d times, want 0 (lazy)", mints)
	}
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "t-1" {
		t.Errorf("token = %q, want t-1", tok.Value)
	}
	// Second read must reuse the cached token.
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mints != 1 {
		t.Errorf("minted %d times, want 1 (cached)", mints)
	}
}

// Token re-mints once the cached token is within skew of expiry, using the
// injected clock so the test is deterministic and offline.
func TestSession_TokenRefreshesAtSkew(t *testing.T) {
	base := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	now := base
	var minted []string
	mint := func(context.Context) (Token, error) {
		v := "t-" + time.Duration(len(minted)+1).String()
		minted = append(minted, v)
		// Each token is valid for 10 minutes from the current clock.
		return Token{Value: v, Expiry: now.Add(10 * time.Minute)}, nil
	}
	s, _ := NewSession(KindAPIKey, mint,
		WithRefreshSkew(time.Minute),
		withClock(func() time.Time { return now }),
	)

	t1, _ := s.Token(context.Background())

	// Advance to within skew of expiry → next Token must re-mint.
	now = base.Add(9*time.Minute + 30*time.Second)
	t2, _ := s.Token(context.Background())
	if t1.Value == t2.Value {
		t.Errorf("token not refreshed at skew: both %q", t1.Value)
	}
	if len(minted) != 2 {
		t.Errorf("minted %d times, want 2", len(minted))
	}
}

// A zero Expiry means a non-expiring token: never re-minted.
func TestSession_NonExpiringTokenNeverRefreshes(t *testing.T) {
	var mints int
	s, _ := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		mints++
		return Token{Value: "t-forever"}, nil // zero Expiry
	})
	for i := 0; i < 5; i++ {
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if mints != 1 {
		t.Errorf("non-expiring token minted %d times, want 1", mints)
	}
}

// Refresh forces an immediate re-mint regardless of cached validity.
func TestSession_RefreshForcesReMint(t *testing.T) {
	var n int
	s, _ := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		n++
		return Token{Value: "t-" + time.Duration(n).String(), Expiry: time.Now().Add(time.Hour)}, nil
	})
	first, _ := s.Token(context.Background())
	forced, err := s.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if forced.Value == first.Value {
		t.Errorf("Refresh did not re-mint: still %q", forced.Value)
	}
	if n != 2 {
		t.Errorf("minted %d times, want 2", n)
	}
}

// A mint error is surfaced and not cached (next call retries).
func TestSession_MintErrorSurfaced(t *testing.T) {
	boom := errors.New("auth backend down")
	var calls int
	s, _ := NewSession(KindAPIKey, func(context.Context) (Token, error) {
		calls++
		if calls == 1 {
			return Token{}, boom
		}
		return Token{Value: "t-ok", Expiry: time.Now().Add(time.Hour)}, nil
	})
	if _, err := s.Token(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Token err = %v, want boom", err)
	}
	// The failed mint must not be cached: a retry succeeds.
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if tok.Value != "t-ok" {
		t.Errorf("token = %q, want t-ok", tok.Value)
	}
}

// Token redacts under String/GoString so an accidental %v never leaks.
func TestToken_Redacts(t *testing.T) {
	tok := Token{Value: "t-supersecret", Expiry: time.Now().Add(time.Hour)}
	if s := tok.String(); strings.Contains(s, "supersecret") {
		t.Errorf("String leaked token: %q", s)
	}
	if s := tok.GoString(); strings.Contains(s, "supersecret") {
		t.Errorf("GoString leaked token: %q", s)
	}
}

// Snapshot/Status reports a redaction-safe view: no bearer value, correct
// validity + refresh window.
func TestSession_SnapshotRedacted(t *testing.T) {
	base := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	s, _ := NewSession(KindAWSIAM, func(context.Context) (Token, error) {
		return Token{Value: "t-secret", Expiry: base.Add(time.Hour)}, nil
	},
		WithRefreshSkew(time.Minute),
		withClock(func() time.Time { return base }),
	)
	// Before minting.
	if st := s.Snapshot(); st.HasToken {
		t.Error("Snapshot before mint reports HasToken")
	}
	_, _ = s.Token(context.Background())
	st := s.Snapshot()
	if st.Kind != KindAWSIAM {
		t.Errorf("kind = %q, want aws_iam", st.Kind)
	}
	if !st.HasToken || !st.Valid {
		t.Errorf("snapshot = %+v, want HasToken && Valid", st)
	}
	// refresh-in = expiry(60m) - skew(1m) = 59m.
	if st.RefreshIn != 59*time.Minute {
		t.Errorf("RefreshIn = %v, want 59m", st.RefreshIn)
	}
	if rendered := st.String(); strings.Contains(rendered, "secret") {
		t.Errorf("Status.String leaked token: %q", rendered)
	}
	if !strings.Contains(st.String(), "aws_iam") {
		t.Errorf("Status.String missing kind: %q", st.String())
	}
}
