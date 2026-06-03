package auth

import (
	"context"
	"errors"
	"testing"
)

// FuncValidator carries validation logic and reports kinds; a nil func yields
// ErrValidationUnavailable.
func TestFuncValidator(t *testing.T) {
	var _ ProducerCredentialValidator = (*FuncValidator)(nil)

	cases := []struct {
		name      string
		fn        func(context.Context, ValidationRequest) (*ValidationResult, error)
		req       ValidationRequest
		wantValid bool
		wantErr   error
	}{
		{
			name: "valid",
			fn: func(_ context.Context, r ValidationRequest) (*ValidationResult, error) {
				return &ValidationResult{Valid: true, AccessID: r.ExpectedAccessID}, nil
			},
			req:       ValidationRequest{Credential: "c", ExpectedAccessID: "p-1"},
			wantValid: true,
		},
		{
			name: "rejected (no error)",
			fn: func(context.Context, ValidationRequest) (*ValidationResult, error) {
				return &ValidationResult{Valid: false, Reason: "mismatched access id"}, nil
			},
			req:       ValidationRequest{Credential: "c", ExpectedAccessID: "p-1"},
			wantValid: false,
		},
		{
			name:    "nil fn → unavailable",
			fn:      nil,
			req:     ValidationRequest{},
			wantErr: ErrValidationUnavailable,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := NewFuncValidator(c.fn, KindAPIKey)
			if v.Kinds()[0] != KindAPIKey {
				t.Errorf("Kinds = %v, want [api_key]", v.Kinds())
			}
			res, err := v.Validate(context.Background(), c.req)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Valid != c.wantValid {
				t.Errorf("Valid = %v, want %v", res.Valid, c.wantValid)
			}
		})
	}
}
