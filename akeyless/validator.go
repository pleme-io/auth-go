package akeyless

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	auth "github.com/pleme-io/auth-go"
)

// DefaultValidationURL is the akeyless producer-credential validation endpoint.
// A custom producer / webhook receiver posts an inbound credential here to
// confirm it belongs to the expected access-id (the inverse of login).
const DefaultValidationURL = "https://auth.akeyless.io/validate-producer-credentials"

// Validator is the HTTP-backed auth.ProducerCredentialValidator: it posts an
// inbound credential to the akeyless validation endpoint and reports whether it
// belongs to the expected access-id. It is the server-side, vendor-coupled
// implementation of the generic core auth.ProducerCredentialValidator seam —
// living in the import-gated leaf so the core names no vendor (worlds-separate).
//
// It uses a plain *http.Client (no SDK) because the validation endpoint is a
// single REST POST, not part of V2Api; supply a custom client (e.g. a
// todoku-go-backed resilient one) via [WithValidatorClient].
type Validator struct {
	url    string
	client *http.Client
}

// compile-time proof the HTTP validator satisfies the core §-inverse shape.
var _ auth.ProducerCredentialValidator = (*Validator)(nil)

// ValidatorOption configures a [Validator].
type ValidatorOption func(*Validator)

// WithValidationURL overrides [DefaultValidationURL] (e.g. to point at a private
// gateway's validation endpoint).
func WithValidationURL(u string) ValidatorOption {
	return func(v *Validator) {
		if u != "" {
			v.url = u
		}
	}
}

// WithValidatorClient installs a custom *http.Client (default http.DefaultClient).
func WithValidatorClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		if c != nil {
			v.client = c
		}
	}
}

// NewValidator builds an HTTP-backed producer-credential validator.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{url: DefaultValidationURL, client: http.DefaultClient}
	for _, o := range opts {
		if o != nil {
			o(v)
		}
	}
	return v
}

// Kinds reports the methods this validator verifies. Producer credentials are
// minted from the full method set, so it reports all kinds.
func (v *Validator) Kinds() []auth.AuthKind { return auth.AllKinds() }

// Validate posts the inbound credential to the validation endpoint and maps the
// response onto an auth.ValidationResult. Per the interface contract, a
// definitively-rejected credential yields a result with Valid=false and a nil
// error; only a transport/operational failure (unreachable service, malformed
// response) returns a non-nil error (wrapping auth.ErrValidationUnavailable).
func (v *Validator) Validate(ctx context.Context, req auth.ValidationRequest) (*auth.ValidationResult, error) {
	body, err := json.Marshal(map[string]any{
		"creds":              req.Credential,
		"expected_access_id": req.ExpectedAccessID,
		"expected_item_name": req.ExpectedItemName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %v", auth.ErrValidationUnavailable, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", auth.ErrValidationUnavailable, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrValidationUnavailable, err)
	}
	defer func() { _ = res.Body.Close() }()
	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", auth.ErrValidationUnavailable, err)
	}
	// A non-200 from the validation service is a definitive rejection (the creds
	// did not validate), not an operational outage — return an invalid result.
	if res.StatusCode != http.StatusOK {
		return &auth.ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("validation rejected (status %d)", res.StatusCode),
		}, nil
	}
	var params struct {
		AccessID string `json:"access_id"`
	}
	if err := json.Unmarshal(respBody, &params); err != nil {
		return nil, fmt.Errorf("%w: decode response: %v", auth.ErrValidationUnavailable, err)
	}
	if params.AccessID != req.ExpectedAccessID {
		return &auth.ValidationResult{
			Valid:    false,
			AccessID: params.AccessID,
			Reason:   "mismatched access id",
		}, nil
	}
	return &auth.ValidationResult{Valid: true, AccessID: params.AccessID}, nil
}
