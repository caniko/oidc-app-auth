# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Provider-neutral OIDC PKCE and opaque browser-session primitives.

### Changed

- Added crates.io metadata, dual-license texts, docs.rs configuration, and
  release validation documentation.
- Replaced `openidconnect` with `reqwest` and `jsonwebtoken` (aws-lc-rs) so the
  `rsa` crate (RUSTSEC-2023-0071) is no longer compiled. The public API is
  unchanged; ID tokens are verified against an RS256/ES256/EdDSA allowlist.
