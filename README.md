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

The consumers currently use a local `path` dependency with an explicit version
so this workspace can validate the integration before publication. A release
must publish/tag `oidc-app-auth` first, then replace those local paths with the
reviewed immutable dependency pin.
