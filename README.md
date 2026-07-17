# oidc-app-auth

<!-- simit:badges:start -->

[![CI](https://img.shields.io/badge/CI-managed-2088ff)](.forgejo/workflows/ci.yaml) [![Nix](https://img.shields.io/badge/Nix-managed-5277c3)](flake.nix) [![docs](https://img.shields.io/badge/docs-enabled-6f42c1)](https://docs.rs/oidc-app-auth) [![crates.io](https://img.shields.io/badge/crates.io-ready-f46623)](https://crates.io/crates/oidc-app-auth) [![release](https://img.shields.io/badge/release-configured-2ea44f)](.forgejo/workflows/release.yml) [![artifacts](https://img.shields.io/badge/artifacts-configured-2ea44f)](.forgejo/workflows/release.yml)

<!-- simit:badges:end -->

Provider-neutral Rust primitives for browser OIDC applications.

The crate deliberately stops at protocol mechanics: bounded discovery and
token HTTP, Authorization Code + S256 PKCE, state/nonce validation, userinfo
claims, signed short-lived flow state, and opaque session-token generation.
Consumers own database persistence, cookies, access/admin groups, and product
routes. It contains no client secret, local-password flow, role registry, or
application-specific schema.

The initial consumers are Foundry Circle and Pink Raven. Keep the crate
provider-neutral so both applications share the security-sensitive protocol
code without sharing their route or persistence models.

The consumers currently use an immutable git dependency pinned to a reviewed
commit because the first crates.io publication is still pending. After release,
replace that pin with the crates.io dependency shown below.

## Integration

After the first crates.io release, add the crate to an application with:

```toml
oidc-app-auth = "0.1"
```

The main entry points are `OidcClient::discover` for provider metadata,
`OidcClient::authorization_request` and `OidcClient::complete` for the
authorization-code flow, `SignedFlowState` for short-lived signed browser
state, and `SessionToken` for opaque session identifiers. Applications remain
responsible for persistence, cookies, access policy, and secret storage.

The generated API documentation is published at
[docs.rs/oidc-app-auth](https://docs.rs/oidc-app-auth).

## Release validation

The repository's Forgejo workflows run the release checks and publish the
crate. The local equivalents are:

```bash
nix flake check --no-build --no-update-lock-file
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --locked --all-targets --all-features -- --deny warnings
nix develop -c cargo test --locked --all-features
nix develop -c cargo doc --locked --no-deps --all-features
nix develop -c cargo audit
nix develop -c cargo package --locked --list
```
