# Changelog

All notable changes to the AXIAM C SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-release qualifier `-alpha9`).

## [1.0.0-alpha18] - 2026-07-24

### Changed

- C SDK branch coverage 70.9%→82.0% + real TLS/mTLS handshake test (#7)
- C SDK 90% → 98.8% + add gcovr regression gate (Phase D) (#6)

### Fixed

- Pin newest libcurl (8.21.0) to escape stale broken recipe revision
- Bump libcurl 8.6.0 -> 8.11.1 to unblock package-recipes CI

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info

## [Unreleased]

### Changed

- Adopt CONTRACT.md 1.3: the new gRPC-only `axiam_get_user_info` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract copy is re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Changed

- Add C examples, README badges, sync CONTRACT §5.1 (#4)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Make version string test resilient to pre-release suffix changes (#3)

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Resolve tenant_id/org_id from access-token claim for the refresh body (#2)
- Publish API docs to gh-pages branch

## [Unreleased]

### Added

- Initial greenfield C11 SDK for the AXIAM REST API.
- Client configuration (`axiam_client_config_t`) requiring a base URL and exactly
  one tenant identifier (slug or id) — no default tenant (CONTRACT §5).
- Canonical operations (CONTRACT §1): `axiam_login`, `axiam_verify_mfa`,
  `axiam_refresh`, `axiam_logout`, `axiam_check_access`, `axiam_can`,
  `axiam_batch_check`, with `(action, resource[, scope])` argument order.
- Error taxonomy `axiam_error_t` / `axiam_error_kind_t` with the three kinds
  `AXIAM_ERR_AUTH` / `AXIAM_ERR_AUTHZ` / `AXIAM_ERR_NETWORK` and the HTTP-status
  mapping (CONTRACT §2); messages never carry token material.
- Automatic CSRF forwarding: capture `X-CSRF-Token` from responses, echo on
  state-changing requests (CONTRACT §3).
- Per-client in-memory libcurl cookie engine (CONTRACT §4).
- `X-Tenant-ID` injected on every request (CONTRACT §5).
- Strict TLS always on, custom CA (PEM) as the only escape hatch (CONTRACT §6);
  in-memory client-certificate mTLS via PEM cert + key blobs (CONTRACT §6.1).
- Opaque `axiam_sensitive_t` with `[SENSITIVE]` rendering and no raw getter;
  mTLS private key held behind it (CONTRACT §7).
- Single-flight refresh guard using `pthread_mutex_t` + condition variable, with
  a concurrency test asserting exactly one refresh under load (CONTRACT §9).
- Framework-agnostic route guard `axiam_require_auth` and declarative helpers
  `axiam_require_access` / `axiam_require_role` plus `AXIAM_REQUIRE_*` macros
  (CONTRACT §10, §11), composing on top of JWKS verification.
- JWKS fetch + EdDSA/Ed25519 JWT verification (OpenSSL `EVP_DigestVerify`), 300s
  cache, non-EdDSA algorithms rejected before key lookup, `exp` not checked.
- Function-pointer HTTP transport seam (`axiam_transport_fn`) for testability;
  default libcurl implementation.
- CMake build producing static and shared `axiam` libraries, install rules,
  package config, and a CPack `.tar.gz`; vcpkg overlay port and Conan recipe.
- CI: build (gcc + clang), CTest, TLS-bypass grep gate, recipe validation,
  tag-on-main gate, release upload; Doxygen Pages; gcov/lcov → Coveralls.

### Deferred

- gRPC transport and §8 AMQP HMAC consumer are out of scope for v1.0.
