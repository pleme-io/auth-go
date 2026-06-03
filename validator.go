package auth

import (
	"context"
	"errors"
)

// ProducerCredentialValidator is the *inverse* of [AuthResolver]: where a
// resolver mints a token to prove the local process's identity *outbound*, a
// validator checks an *inbound* credential a remote caller presented and
// reports whether it belongs to an expected identity. It is the server-side seam
// every custom-producer / webhook receiver needs — "is this request really from
// the access-id it claims?" — and is the natural home for that concern so it is
// not re-rolled per producer (PRIME DIRECTIVE).
//
// The shape mirrors [AuthResolver] exactly (one verb + one capability report),
// so a tool wires a validator the same way it wires a resolver:
//
//	type ProducerCredentialValidator interface {
//	    Validate(ctx context.Context, req ValidationRequest) (*ValidationResult, error)
//	    Kinds() []AuthKind
//	}
//
// Like the resolver, the interface is zero-dep core; the HTTP/SDK-backed
// implementation (which posts to the akeyless validate-producer-credentials
// endpoint) lives in the import-gated auth-go/akeyless leaf (Law 6 / worlds-
// separate: the core names no vendor).
type ProducerCredentialValidator interface {
	// Validate checks the inbound credential in req against the expected
	// identity. It returns a [*ValidationResult] on a definitive answer (valid or
	// invalid), and a non-nil error only on a *transport/operational* failure
	// (the validation service was unreachable, malformed response) — a credential
	// that is simply wrong yields a result with Valid=false, not an error, so a
	// caller distinguishes "we could not check" from "we checked and it failed".
	Validate(ctx context.Context, req ValidationRequest) (*ValidationResult, error)
	// Kinds reports which auth methods this validator can verify credentials for
	// (mirroring AuthResolver.Kinds so the two seams compose uniformly).
	Kinds() []AuthKind
}

// ValidationRequest is the inbound material a [ProducerCredentialValidator]
// checks: the credential a remote caller presented, plus the identity the
// receiver expects it to belong to. It is the typed request shape so a producer
// never assembles an untyped map per call.
//
// CFG-09: Credential is a secret-bearing inbound value — read it at the point of
// validation and never copy it into config, a package var, or a log field. The
// request is consumed by Validate and not retained.
type ValidationRequest struct {
	// Credential is the inbound credential the remote caller presented (the
	// opaque `creds` blob a custom producer receives in its webhook payload).
	Credential string
	// ExpectedAccessID is the access-id (`p-…`) the receiver expects the
	// credential to belong to. A mismatch is the canonical invalid result.
	ExpectedAccessID string
	// ExpectedItemName, when non-empty, additionally asserts the credential was
	// issued for the named producer item (the WithAllowedItemName assertion).
	ExpectedItemName string
}

// ValidationResult is the typed answer a [ProducerCredentialValidator] returns.
// It carries the verdict plus the resolved identity the validation service
// reported, so a producer can record *who* called (not just that the call was
// valid) without re-parsing a raw response.
type ValidationResult struct {
	// Valid reports whether the inbound credential belongs to the expected
	// identity. False with a nil error means "checked and rejected".
	Valid bool
	// AccessID is the access-id the validation service confirmed the credential
	// belongs to. On a valid result it equals the request's ExpectedAccessID.
	AccessID string
	// Reason is a short, redaction-safe explanation of an invalid verdict
	// (e.g. "mismatched access id"); empty on a valid result. It never echoes
	// the inbound credential.
	Reason string
}

// ErrValidationUnavailable is returned by a [ProducerCredentialValidator] when
// the validation service could not be reached or returned an unusable response —
// the "we could not check" case, distinct from a definitive invalid verdict. It
// is a sentinel so a receiver can fail closed (reject) on an operational outage
// rather than mistaking it for a rejected credential.
var ErrValidationUnavailable = errors.New("auth: producer credential validation unavailable")

// FuncValidator adapts a plain func into a [ProducerCredentialValidator], so a
// test fixture or the SDK leaf can supply validation logic without a named type.
// It is the carrier seam (Law 5) mirroring [CloudIdentityFunc].
type FuncValidator struct {
	kinds []AuthKind
	fn    func(ctx context.Context, req ValidationRequest) (*ValidationResult, error)
}

// compile-time proof the func adapter is a ProducerCredentialValidator.
var _ ProducerCredentialValidator = (*FuncValidator)(nil)

// NewFuncValidator wraps a func as a [ProducerCredentialValidator] reporting the
// given kinds. A nil fn yields [ErrValidationUnavailable] on Validate, so wiring
// stays total.
func NewFuncValidator(fn func(ctx context.Context, req ValidationRequest) (*ValidationResult, error), kinds ...AuthKind) *FuncValidator {
	return &FuncValidator{fn: fn, kinds: kinds}
}

// Validate calls the wrapped func, mapping a nil func to
// [ErrValidationUnavailable].
func (v *FuncValidator) Validate(ctx context.Context, req ValidationRequest) (*ValidationResult, error) {
	if v.fn == nil {
		return nil, ErrValidationUnavailable
	}
	return v.fn(ctx, req)
}

// Kinds reports the methods this validator can verify (mirrors AuthResolver).
func (v *FuncValidator) Kinds() []AuthKind { return v.kinds }
