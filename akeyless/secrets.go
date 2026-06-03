package akeyless

import (
	"context"
	"fmt"

	ak "github.com/akeylesslabs/akeyless-go/v5"
	auth "github.com/pleme-io/auth-go"
	shikuakeyless "github.com/pleme-io/shikumi-go/akeyless"
)

// SecretGetter is the post-auth secret-resolution seam: a thin wrapper over
// V2Api.GetSecretValue that satisfies shikumi-go/akeyless.SecretGetter. It is
// the piece that closes the §2.1 two-phase load — a tool authenticates (phase 1),
// builds a SecretGetter, then resolves `secret://akeyless/…` config refs through
// it (phase 2):
//
//	res, _ := akeyless.NewResolver(creds)
//	sess, _ := res.Resolve(ctx)
//	getter := akeyless.NewSecretGetter(sess)         // *SecretGetter
//	resolver := shikumiakeyless.FromBootstrap(getter) // shikumi.SecretResolver
//	cfg, _ := shikumi.For[Cfg]("app").Secrets(resolver).Load(ctx)
//
// CFG-09 is preserved end-to-end: the SecretGetter holds an *auth.Session, NOT a
// token, and reads the live token from the Session (refreshing transparently) at
// the moment each GetSecretValue is issued.
type SecretGetter struct {
	client  *ak.APIClient
	session *auth.Session
}

// compile-time proof the wrapper satisfies shikumi-go's carrier interface — the
// whole point of this sub-package's existence (BOREALIS §2.2a).
var _ shikuakeyless.SecretGetter = (*SecretGetter)(nil)

// NewSecretGetter builds a SecretGetter from a [*Resolver]'s own client and the
// [*auth.Session] it produced, so secret reads share the exact authenticated
// client (and gateway URL) the token was minted on.
func (r *Resolver) NewSecretGetter(session *auth.Session) *SecretGetter {
	return &SecretGetter{client: r.client, session: session}
}

// NewSecretGetter builds a SecretGetter against the public-endpoint client. Use
// [Resolver.NewSecretGetter] when you already hold the resolver, so the same
// gateway URL is reused; this free function is for callers that only have a
// Session (it builds a fresh public-endpoint client).
func NewSecretGetter(session *auth.Session) *SecretGetter {
	return &SecretGetter{client: newClient(""), session: session}
}

// GetSecretValue fetches one secret's value by path, authenticating each call
// with a fresh-or-cached token from the Session (CFG-09: the token is read at
// the point of use, never copied). It implements shikumi-go/akeyless.SecretGetter,
// so shikumi's `Secrets()` chain resolves akeyless refs through it.
//
// The Akeyless GetSecretValue response is a map keyed by the requested secret
// name; this extracts the single requested value and stringifies it.
func (g *SecretGetter) GetSecretValue(ctx context.Context, name string) (string, error) {
	if g.session == nil {
		return "", fmt.Errorf("akeyless: secret getter has no session")
	}
	tok, err := g.session.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("akeyless: get-secret-value %q: auth: %w", name, err)
	}
	body := ak.NewGetSecretValue([]string{name})
	body.SetToken(tok.Value)
	out, _, err := g.client.V2Api.GetSecretValue(ctx).Body(*body).Execute()
	if err != nil {
		return "", fmt.Errorf("akeyless: get-secret-value %q: %w", name, err)
	}
	v, ok := out[name]
	if !ok {
		return "", fmt.Errorf("akeyless: get-secret-value %q: not present in response", name)
	}
	switch s := v.(type) {
	case string:
		return s, nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}
