# Changelog

All notable changes to the AXIAM C SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-release qualifier `-alpha9`).

## [Unreleased]

### Added

- **ASan+UBSan and valgrind CI job (§13.4 observation 10 / §12.6.1).** `OBS-4`
  was a signed-integer overflow — undefined behaviour on the **token-decode
  path** — that survived three security passes because neither C repository had
  a sanitizer leg: the only jobs were gcc/clang builds plus coverage, and UB is
  exactly what an ordinary build does not report. The new job runs the full
  suite under ASan+UBSan with `-fno-sanitize-recover=all` (so a UBSan diagnostic
  aborts rather than printing and letting the run stay green) and then sweeps
  every test binary under valgrind with `--error-exitcode=9 --leak-check=full`.
  Verified locally before wiring: 23/23 tests pass under the sanitizers, and the
  valgrind sweep reports 0 errors and 0 definite leaks.

### Notes

- **§13.4 observation 8 was mistaken; no change was needed.** It recorded that
  this SDK's §10.1 negative-test set "looks incomplete — `tests/test_jwt_claims.c`
  covers the `exp` cases but not evidently the rest". Auditing the file against
  the mandated list shows the set is **complete**, and each case is substantive
  rather than nominal: expired, absent `exp`, non-numeric `exp`, future `nbf`,
  malformed `nbf`, foreign tenant, absent `tenant_id`, `alg: none`, and an
  HS-signed token bearing the org's EdDSA `kid` — plus issuer and audience
  mismatches, which §10.1 requires only where the SDK supports that
  configuration. The tenant and `alg` cases additionally assert at all three
  guard entry points and that the authz server is never consulted.

### Security

- **SEC-071 (HIGH) — route guards no longer accept expired or cross-tenant tokens.**
  Local verification is now strict by default: `axiam_jwt_verify()` (and therefore
  `axiam_require_auth` / `axiam_require_access` / `axiam_require_role`) enforces the
  token lifetime — `exp` is mandatory, `nbf` is honoured when present, both with a
  60s `AXIAM_JWT_CLOCK_SKEW_SECS` allowance — and asserts that the `tenant_id` claim
  equals the client's configured tenant. The JWKS trust anchor is organization-wide,
  so a valid signature alone never implied the caller's tenant. Every new check fails
  **closed** (`AXIAM_ERR_AUTH` / HTTP 401), and the authorization server is no longer
  consulted for a token the guard should have refused.
- **CONTRACT §10.1 conformance — optional `iss` / `aud` pinning on local verification.**
  The §10.1 "minimum local-verification set" is now fully satisfied by
  `axiam_jwt_verify()` and the §10/§11 guards. Rules 1–4 and 7 (EdDSA `alg` pin
  before key lookup, mandatory numeric `exp`, `nbf` when present, asserted
  `tenant_id`, the named/bounded `AXIAM_JWT_CLOCK_SKEW_SECS`) were already
  enforced by SEC-071. Rules 5 and 6 are new: `axiam_client_config_set_expected_issuer()`
  and `axiam_client_config_set_expected_audience()` configure the expectations,
  and `AXIAM_JWT_VERIFY_STRICT` now also carries `AXIAM_JWT_VERIFY_ISSUER_AUDIENCE`.
  Both checks are **conditional** — an unset expectation (the default) means the
  claim is not checked, and no issuer is ever assumed. When one *is* configured,
  a token whose claim is absent, of the wrong JSON type, or different is refused
  with `AXIAM_ERR_AUTH` / HTTP 401. `aud` is matched against both the bare-string
  and the array-of-strings forms. A resource server guarding a user-facing API
  should set the audience to `axiam:user`.
- **SEC-073 — a plaintext `http://` base URL is refused at construction** (CONTRACT §6).
  `axiam_client_config_validate()` / `axiam_client_new()` now reject a non-`https`
  base URL, with a loopback exception (`localhost`, `127.0.0.1`, `::1`) for local
  development. There is no flag to disable the check for a routable host.
- **SEC-076 — MFA challenge/setup tokens are held behind `axiam_sensitive_t`** (§7):
  they render as `[SENSITIVE]` and their memory is zeroized on release. Login and
  MFA request bodies (which carry the password and the challenge token) are also
  scrubbed before being freed, and the Sensitive scrub now uses a volatile write
  the compiler may not elide.

### Added

- **T-145 / CONTRACT §13 — webhook signature verification.** New `axiam/webhook.h`:
  `axiam_webhook_verify()`, `axiam_webhook_verify_at()` (a `now` seam for tests) and
  `axiam_webhook_verify_headers()` (which also yields the event type and the
  `X-Axiam-Delivery` dedup key). HMAC-SHA256 over `<timestamp>.<raw_body>`,
  constant-time comparison over the decoded MAC bytes (explicit volatile
  accumulator — no `memcmp`, no early return), two-sided 300s freshness window,
  typed statuses that never carry the expected signature.
- `axiam_jwt_verify_ex()` with the `AXIAM_JWT_VERIFY_*` policy flags, for callers
  that deliberately want a weaker check than the strict default.
- `axiam_verify_mfa_sensitive()`, which takes the Sensitive challenge token straight
  from `axiam_login_result_t`.

### Changed

- **Source-breaking:** `axiam_login_result_t.challenge_token` and `.setup_token` are
  now `axiam_sensitive_t *` instead of `char *`. Pass them to the new
  `axiam_verify_mfa_sensitive()`; `axiam_verify_mfa()` still accepts a raw string.
- **Behaviour-breaking:** a client used for route guarding must be configured with
  `axiam_client_config_set_tenant_id()` (the token's `tenant_id` claim is a UUID and
  a slug cannot be compared against it). A slug-only client that has not completed a
  login has no tenant binding available and refuses every token.
- **Behaviour-breaking (opt-in): configuring an expected issuer or audience tightens
  acceptance.** A client built with `axiam_client_config_set_expected_issuer()` or
  `..._set_expected_audience()` refuses tokens that previously passed — including
  tokens that carry no `iss`/`aud` claim at all, which fail closed rather than
  being treated as "nothing to check". Clients that set neither (the default)
  behave exactly as before. `AXIAM_JWT_VERIFY_STRICT`'s numeric value changed
  because it gained `AXIAM_JWT_VERIFY_ISSUER_AUDIENCE`; recompile against the new
  header rather than relying on a cached literal.
- Vendored `CONTRACT.md` re-synced with the new §13 (webhook signature verification)
  and §10.1 (minimum local-verification set).

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6

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
