package auth

import (
	"context"
	"errors"
)

// CloudIdentityProvider is the generic, zero-dep seam for "prove who I am to the
// cloud platform I run on, without a long-lived credential" — the shape behind
// the AWS-IAM / Azure-AD / GCP cloud-identity auth methods. It is deliberately
// neutral: it names no vendor, imports no cloud SDK, and says nothing about
// akeyless (BOREALIS §2 worlds-separate). A cloud provider produces a single
// opaque, base64-encoded identity blob that an auth backend forwards verbatim as
// the method's cloud-id material.
//
// The three production families all collapse to this one verb:
//
//   - AWS: a SigV4-signed STS GetCallerIdentity request, JSON-bundled and
//     base64-encoded — the blob proves the caller holds the role's credentials.
//   - Azure: an IMDS-issued managed-identity JWT for a resource audience,
//     base64-encoded.
//   - GCP: a metadata-server-signed identity token for a configured audience,
//     base64-encoded.
//
// Each is a different signature mechanism but the same output contract: an
// already-encoded string the backend never reinterprets. So this package owns
// the *interface*; the SDK-bearing implementations (which import the AWS / Azure
// / GCP SDKs) live in import-gated leaves a tool wires in — never here in the
// zero-dep core (Law 6).
type CloudIdentityProvider interface {
	// Identity returns the opaque, base64-encoded cloud-identity blob for the
	// current environment (instance role / managed identity / service account).
	// It is the value an auth backend forwards as its cloud-id field; callers do
	// not parse it.
	Identity(ctx context.Context) (string, error)
	// Cloud reports which cloud family this provider signs for, so a resolver can
	// pick the matching AuthKind (KindAWSIAM / KindAzureAD / KindGCP) and a
	// status view can name the platform without inspecting the blob.
	Cloud() Cloud
}

// Cloud is the closed set of cloud platforms a [CloudIdentityProvider] can sign
// for. It is the neutral projection of the three cloud-backed auth methods; a
// resolver maps a Cloud to its [AuthKind] via [Cloud.Kind].
type Cloud string

const (
	// CloudAWS is Amazon Web Services (STS GetCallerIdentity, SigV4).
	CloudAWS Cloud = "aws"
	// CloudAzure is Microsoft Azure (IMDS managed-identity token).
	CloudAzure Cloud = "azure"
	// CloudGCP is Google Cloud Platform (metadata-signed identity token).
	CloudGCP Cloud = "gcp"
)

// ErrNoCloudIdentity is returned by a [CloudIdentityProvider] when no cloud
// identity is obtainable in the current environment (not running on the cloud,
// metadata endpoint unreachable, no instance role). It is a sentinel so callers
// can branch on errors.Is(err, auth.ErrNoCloudIdentity) — e.g. to fall back to
// another resolver.
var ErrNoCloudIdentity = errors.New("auth: no cloud identity available")

// String returns the wire value of the cloud family.
func (c Cloud) String() string { return string(c) }

// Kind maps a [Cloud] to the [AuthKind] whose cloud-id material it produces.
// AWS→KindAWSIAM, Azure→KindAzureAD, GCP→KindGCP. An unknown cloud yields the
// empty kind, which [AuthKind.Valid] rejects.
func (c Cloud) Kind() AuthKind {
	switch c {
	case CloudAWS:
		return KindAWSIAM
	case CloudAzure:
		return KindAzureAD
	case CloudGCP:
		return KindGCP
	default:
		return ""
	}
}

// CloudIdentityFunc adapts a plain func into a [CloudIdentityProvider] for the
// given cloud, so a caller (or the import-gated cloud leaves) can supply an
// identity source without declaring a named type. It is the carrier seam (Law 5)
// that lets, e.g., akeyless-go-cloud-id's GetCloudId be wrapped in one line
// without the core importing it:
//
//	p := auth.CloudIdentityFunc(auth.CloudAWS, func(ctx context.Context) (string, error) {
//	    return aws.GetCloudId() // from akeyless-go-cloud-id, in the caller's module
//	})
type CloudIdentityFunc struct {
	cloud Cloud
	fn    func(ctx context.Context) (string, error)
}

// compile-time proof the func adapter is a CloudIdentityProvider.
var _ CloudIdentityProvider = (*CloudIdentityFunc)(nil)

// NewCloudIdentityFunc wraps a func as a [CloudIdentityProvider]. A nil fn or an
// unknown cloud is tolerated at construction; Identity then returns
// [ErrNoCloudIdentity] / the cloud reports as supplied, so wiring stays total.
func NewCloudIdentityFunc(cloud Cloud, fn func(ctx context.Context) (string, error)) *CloudIdentityFunc {
	return &CloudIdentityFunc{cloud: cloud, fn: fn}
}

// Identity calls the wrapped func, mapping a nil func to [ErrNoCloudIdentity].
func (p *CloudIdentityFunc) Identity(ctx context.Context) (string, error) {
	if p.fn == nil {
		return "", ErrNoCloudIdentity
	}
	return p.fn(ctx)
}

// Cloud reports the cloud family this adapter signs for.
func (p *CloudIdentityFunc) Cloud() Cloud { return p.cloud }
