# auth-go

The Go representation of pleme-io's **fleet authentication primitive**
(BOREALIS **§2.2a**): the neutrally-named, akeyless-first auth seam every Go
tool wires the same shape.

Every akeyless tool's first act is the same — mint a `t-…` token from one of a
closed set of methods and construct an authenticated client. That is the single
most akeyless-specific concern in the fleet, so it is a **primitive, not
per-tool boilerplate**.

> **Zero-dep core.** This module builds and tests **offline**: the core surface
> ([`AuthResolver`](auth.go), [`Session`](session.go), the zero-dep
> [`StaticTokenResolver`](resolver.go) / [`EnvTokenResolver`](resolver.go)) carries
> no dependencies. The heavy, network-bearing
> [`akeylesslabs/akeyless-go`](https://github.com/akeylesslabs/akeyless-go) SDK
> is **import-gated** to the [`akeyless/`](akeyless) leaf module (BOREALIS Law 6),
> which is also where the `shikumi-go/akeyless.SecretGetter` seam is implemented.

## The one shape (§3.5 canonical)

A resolver **mints**; a session **holds**. Both have exactly one shape across
every method:

```go
type AuthResolver interface {
    Resolve(ctx context.Context) (*Session, error)
    Kinds() []AuthKind
}
```

| Symbol | Purpose |
| --- | --- |
| `AuthResolver` | The fleet auth seam — `Resolve` returns a `*Session`; `Kinds` reports supported methods. |
| `AuthKind` + `AllKinds` / `ParseKind` | Closed set of methods (api_key / aws_iam / azure_ad / gcp / k8s / oidc / saml / cert / email / ldap / universal_identity). cli-go auto-wires `--auth` from a resolver's `Kinds()`. |
| `Session` | The **only** CFG-09-sanctioned, process-scoped home for a live token. oauth2-`TokenSource`-shaped: `Token(ctx)` mints lazily + refreshes at `expiry-skew`; `Refresh(ctx)` forces a re-mint. |
| `Token` | Immutable `{Value, Expiry}`; **redacts** under `String`/`GoString`. |
| `Status` + `Session.Snapshot()` | Redaction-safe view (no bearer value) for status reporting; rendered via the one verb `borealis.Render(theme, status)`. |
| `StaticTokenResolver` / `EnvTokenResolver` | **Zero-dep** resolvers wrapping a pre-minted token (inline or from an env var) so the core authenticates offline. |
| `New(opts ...Option) (AuthResolver, error)` | Canonical constructor. |
| `Config` + `FromConfig(cfg) (AuthResolver, error)` | Typed yaml config → resolver (never calls `shikumi.Load`). |

## CFG-09 — the token lives in exactly one place

The minted bearer token lives **only** inside a `Session`. It is never assigned
into a `Config` struct, a package-level var, or a log field. `Token` redacts
under every `fmt` verb, and `Status`/`Snapshot` carry no bearer value — so an
accidental `%v` or status dump cannot leak it.

## Quick start (zero-dep core, offline)

```go
// A pre-minted token (injected, or from `akeyless auth`) in the one sanctioned home:
res, _ := auth.New(auth.WithTokenEnv("AKEYLESS_TOKEN"))
sess, err := res.Resolve(ctx)
if err != nil { /* ErrNoToken if the env var is unset */ }
tok, _ := sess.Token(ctx)            // refreshes transparently; the only door
fmt.Println(borealis.Render(theme, sess.Snapshot())) // redacted status
```

## SDK-backed path + secret resolution (`auth-go/akeyless`)

The gated leaf mints via the SDK **and** implements
`shikumi-go/akeyless.SecretGetter`, closing the §2.1 two-phase load
(bootstrap config → auth → resolve `secret://akeyless/…` refs):

```go
import (
    akauth "github.com/pleme-io/auth-go/akeyless"
    shikumiakeyless "github.com/pleme-io/shikumi-go/akeyless"
)

res, _ := akauth.NewResolver(akauth.Credentials{
    Kind: auth.KindAPIKey, AccessID: "p-…", AccessKey: accessKey.Expose(),
})
sess, _ := res.Resolve(ctx)               // *auth.Session (SDK-minting)

getter := res.NewSecretGetter(sess)        // shikumi-go SecretGetter
resolver := shikumiakeyless.FromBootstrap(getter)
cfg, _ := shikumi.For[Cfg]("app").Secrets(resolver).Load(ctx)
```

## License

[MIT](LICENSE) © pleme-io
