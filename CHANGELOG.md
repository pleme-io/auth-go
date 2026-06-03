# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (borealis-elevate — additive, registry §4d)
- `CloudIdentityProvider` trait (`Identity(ctx)` / `Cloud()`) — the generic,
  vendor-neutral seam behind AWS-IAM / Azure-AD / GCP cloud-identity auth (each
  produces an opaque base64 identity blob); `Cloud` enum + `Cloud.Kind()`;
  `CloudIdentityFunc` carrier adapter. The cloud SDKs stay out of the core.
- In-cluster k8s profile: `InClusterProfile` (`DefaultServiceAccountTokenPath`
  SA-JWT mount + the base64 token quirk) and the zero-dep `InClusterResolver`
  (re-reads the rotating projected token each mint).
- UID/token rotation scheduler on `Session`: `RotateFunc` + `WithRotation`,
  `Session.Rotate` / `RotateEvery` / `HasRotation` / `RotationInterval`,
  `DefaultRotationInterval` — the "keep the universal-identity chain fresh" loop.
- `ProducerCredentialValidator` (the inverse of `AuthResolver`): server-side
  inbound-credential validation. `ValidationRequest` / `ValidationResult` /
  `FuncValidator` / `ErrValidationUnavailable`.
- Full fine-grained access-types: `AccessType` (universal_identity /
  k8s_via_gateway / gcp_audience / ca_cert) with `AllAccessTypes`, `Kind`,
  `Valid`.
- `Profile` — the credential-free `--profile`/`--gateway-url` selector with the
  gateway-config-URL token shape (`ConfigURL`), `Validate`, `ResolvedKind`, and
  the `Config()` / `FromProfile()` bridge (the FromConfig bridge from a
  tundra-profile shikumi struct).
- `akeyless` leaf (gated): gcp-audience + gateway-url on the Auth body;
  `CloudIdentity` provider consulted at mint; UID rotation via
  `V2Api.UidRotateToken`; `CredentialsFromProfile` / `CredentialsFromInCluster`
  / `ResolverFromProfile`; the HTTP-backed `Validator`
  (`validate-producer-credentials`).
- GSDS scaffolding: `flake.nix` (substrate `goLibraryFlakeBuilder`),
  `caixa.lisp`, this `CHANGELOG.md`.

### Fixed
- `Session.Snapshot` now measures token validity against the session's injected
  clock (`s.now`) rather than the real wall clock, so a `Snapshot` is
  deterministic under an injected clock and consistent with the skew-aware
  refresh. No public-surface change.

## [0.1.0] - 2026-06-03

### Added
- Initial: the `AuthResolver`/`Session` akeyless-first auth seam. Zero-dep core
  (`AuthKind` + `AllKinds`/`ParseKind`, `Token` (redacting), `Session`
  (oauth2-`TokenSource`-shaped, lazy mint + skew refresh), `StaticTokenResolver`
  / `EnvTokenResolver`, `New` + `FromConfig`, redaction-safe `Status`/`Snapshot`)
  and the import-gated, SDK-backed `akeyless/` leaf (`Resolver` minting via
  `V2Api.Auth`; `SecretGetter` implementing `shikumi-go/akeyless.SecretGetter`).
