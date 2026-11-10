# oidc-app-auth vision

Provider-neutral Rust primitives for browser OIDC applications. The crate
covers protocol mechanics — bounded discovery and token HTTP, Authorization Code
with S256 PKCE, state/nonce validation, userinfo claims, signed short-lived flow
state, and opaque session-token generation — while consumers own database
persistence, cookies, access and admin groups, and product routes. Its initial
consumers are Foundry Circle and Pink Raven.

## Problem

Two applications need the same security-sensitive OIDC code. Copying it invites
silent divergence in PKCE, state, and nonce handling, but adopting a framework
would take over their route and persistence models, which differ.

## Principles

- **Protocol only.** The crate contains no client secret, local-password flow,
  role registry, or application-specific schema.
- **Bounded network work.** Discovery and token HTTP calls are bounded, not
  open-ended client construction.
- **Shared mechanism, private policy.** Applications keep persistence, cookies,
  access policy, and secret storage; the crate returns validated protocol
  results.
- **Short-lived browser state is signed.** `SignedFlowState` carries the flow
  through the redirect; sessions are opaque tokens rather than self-describing
  bearer data.
- **Release discipline.** The repository's Crow CI pipelines run formatting,
  strict Clippy, tests, docs, audit, and package listing, and publication is a
  separate step.
- **Immutable consumer pins until publication.** Consumers pin a reviewed commit
  because the first crates.io release is pending.

## Scope

`OidcClient::discover`, `OidcClient::authorization_request`, and
`OidcClient::complete` for the authorization-code flow; `SignedFlowState` for
short-lived signed browser state; `SessionToken` for opaque session identifiers;
userinfo claim handling; generated API documentation on docs.rs.

## Non-goals

- No application persistence, cookie format, or session store.
- No role or group registry and no access-policy decisions.
- No client-secret flow, local-password login, or product routes.

## Direction

The stated next step is the first crates.io publication, after which consumers
replace the immutable git dependency with `oidc-app-auth = "0.1"`.

## Place in the fleet

canix's Foundry Circle integration plan assigns the shared discovery, PKCE,
callback, identity, and signed-flow-state primitives to this crate while keeping
application routes, schemas, role policy, and secrets in the consumer; publishing
the crate and updating the Foundry/Pink Raven revisions are recorded there as
release gates. Atlas's update automation tracks the repository.
