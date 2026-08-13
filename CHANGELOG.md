# Changelog

All notable changes to the AXIAM C SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-release qualifier `-alpha9`).

## [Unreleased]

### Changed

- **BREAKING (contract 1.13): `axiam_token_exchange_params_t::subject_token_type` is now
  required.** It shipped optional, defaulting to `…:access_token` when NULL. That satisfied
  §15.7's "never inspect the subject token" while leaving the rule it serves unenforced: an
  optional member with a default *is* a default the SDK applies whenever the caller says
  nothing. §15.1 now makes it required.

  C cannot demand a struct member at compile time, so the demand lands at the call: a NULL or
  empty `subject_token_type` returns `AXIAM_ERR_AUTH` **client-side, with no wire call**, with a
  message naming the member and both macros. A test covers NULL and `""` — the shape a
  zero-initialised params struct actually has — and asserts zero token calls.

  **Migration** — one line, naming what you were previously getting by silence:

  ```c
  axiam_token_exchange_params_t p = {0};
  p.subject_token      = subject;
  p.subject_token_type = AXIAM_TOKEN_TYPE_ACCESS_TOKEN;  /* <- add this */
  ```

  The member stays **last** in the struct, so nothing moved and a caller who does not recompile
  gets the loud client-side refusal rather than a silently different request.

### Fixed

- **The §9 single-flight tests no longer bet on a clock.** Both burst tests spawned eight
  workers against a flight the fake transport delayed by 60 ms, then asserted `token_calls == 1`
  — that the last worker joined the flight the first one opened. The `pthread_barrier` already
  guaranteed all eight were *running*; what no fixed delay can guarantee is that they have
  reached the *guard* before the leader finishes. Under valgrind, or on a runner with fewer
  cores than threads, the leader returns first and a follower opens a second flight — a failure
  that says nothing about the guard.

  The leader now waits for arrivals instead: each worker bumps `gate_arrived` on its way into
  `axiam_oidc_refresh`, and the transport holds the leader until `gate_expect` workers have
  entered. The 60 ms delay stays as slack for a worker that has entered but not yet parked.
  Nothing weakens: if the guard were broken the followers would reach the transport and
  `token_calls` would say so; a late arrival finds the count satisfied, so nothing deadlocks;
  and the wait is bounded at 10 s so a real regression fails the assertion rather than hanging.

  Ported from the same fix in the C++ SDK (`ilpanich/axiam-cplusplus-sdk#21`), where this
  surfaced as a CI failure. It had not yet bitten here — which is the reason to fix it now
  rather than after it does. Verified with 4/4 clean runs of `test_oidc_singleflight` under
  valgrind pinned to a single core with `taskset`.

### Added

- **§15.7 external-IdP subject tokens (X4).** `axiam_token_exchange()` can now exchange a token
  minted by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token
  scoped to what the resolved AXIAM user may actually do. No new operation: the same call, plus
  `axiam_token_exchange_params_t::subject_token_type` and the new `AXIAM_TOKEN_TYPE_JWT` macro
  alongside `AXIAM_TOKEN_TYPE_ACCESS_TOKEN`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and a
  wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. NULL still sends `…:access_token`, so every existing caller is unaffected; a
  JWT-shaped subject token does **not** change what is sent, which is asserted by a test.

  The new member is **last** in the struct, so no existing member moved and a zero-initialised
  `params` struct keeps behaving exactly as before.

  Also asserted: an `actor_token` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as a
  different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* — reaches
  `err.message` intact; and nothing re-exchanges an exchanged token, which both server paths
  refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.11 → 1.12 plus
  §15.7), which also brings contract 1.12's `/oauth2/*` error rows dispatching on the `error`
  field at any status, and the `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§12 OIDC relying party, §12.7 logout, §14 device grant, §15 token exchange —
  the contract-1.11 port.** These four were deferred in this SDK through
  contract 1.10; [§12.6](CONTRACT.md) reverses that and they ship together.

  `axiam_oidc_discover/begin/exchange/refresh`, `axiam_login_client_credentials`,
  `axiam_introspect`, `axiam_revoke`, `axiam_sso_start/complete`;
  `axiam_logout_url` and `axiam_verify_logout_token`;
  `axiam_device_authorize/poll/login`; `axiam_token_exchange`. All in the new
  `axiam/oidc.h`.

  The deferral was written from persona — this is a device- and IoT-oriented
  SDK and the browser-redirect flow has no natural home in it — which covered
  `oidc_begin` and `oidc_exchange` and none of the other seven operations.
  §14 exists *because* a device cannot show a browser, and §20 had already
  given this SDK a `/oauth2/token` call, so by 1.10 it was speaking OAuth2 at
  the token endpoint without §12's discovery cache or ID-token validation. The
  port removes a divergence rather than adding one.

  What the surface deliberately does not do: it stores no `state`, `nonce` or
  `code_verifier` (§12.3 rule 1 — the caller keeps them, and the `redirect_uri`
  too); it has no way to skip ID-token validation, and §12.4 rule 7's
  all-or-nothing discard means a bad `id_token` takes the access and refresh
  tokens with it; it adopts no token as the client's own credential; and it
  does not retry a grant whose credential is single-use (§16.2).

- **`axiam_sensitive_reveal()` — §7 rule 3's single explicit accessor**, now
  public. §12 returns tokens *to* the caller, and a wrapper a §12 caller can
  never read makes §12 unusable; contract 1.11's §7 table changes the C row to
  say so. `axiam_sensitive_to_string()` is unchanged and still answers
  `"[SENSITIVE]"` whatever the content.

- **`axiam_error_t::id_token_reason`** — the §12.3 rule 3 closed seven-value
  vocabulary (`invalid_alg`, `unknown_kid`, `invalid_signature`,
  `invalid_issuer`, `invalid_audience`, `token_expired`, `nonce_mismatch`).
  A second field rather than a reuse of `oauth_error`: the two carry different
  vocabularies from different clauses, and §14.2's terminal `expired_token` is
  nearly a homograph of §12.4 rule 5's `token_expired`.

- **Config:** `axiam_client_config_set_oidc_client_id`,
  `_set_oidc_client_secret`, `_set_oidc_discovery_ttl` (raised to the
  5-minute floor), `_set_oidc_clock_skew` (clamped down to 60 s, never up).

- **Examples:** `oidc_login.c`, `device_login.c`, `token_exchange.c`.

- **§20.3 challenge emission from the §11 guard.** `axiam_require_access_uma()` takes an
  `axiam_uma_challenger_t` (realm, `as_uri`, PAT) and an out-parameter; on a denial it mints a
  permission ticket for the action that was refused and writes the formatted
  `WWW-Authenticate: UMA` value there for the caller to send and free.

  It is a **separate entry point** rather than a change to `axiam_require_access()` because
  emitting a challenge means minting a credential: a guard that did it by default would turn
  every unauthorized request into a Protection API call, which is a denial-of-service amplifier
  pointed at your own authorization server. An allow mints nothing, and neither does a NULL or
  half-configured challenger. And a **minting failure is not an escalation** — an expired PAT or
  an unreachable Protection API still yields `AXIAM_GUARD_DENIED` with the out-parameter left
  NULL, never a 503 and never an allow. Both are asserted by counting Protection API calls.

  Internally both entry points share one body, so the two cannot drift on the outcome mapping.
  The requested UMA scope is the AXIAM *action*, so the ticket asks for exactly the authority
  just refused and the engine's deny rules keep applying to whatever RPT comes back.

  Paired with the new `examples/uma_resource_server.c` and `examples/uma_client.c`, which run
  both halves — including the trust decision §20.3 keeps in the caller's hands rather than
  auto-exchanging against whatever host a 403 named.

### Changed

- **The JWKS verifier now re-fetches once per cooldown window on an unknown
  `kid`** (§12.4 rule 2), instead of failing immediately against a warm cache.
  This fixes key rotation for the §10/§11 guards as well: previously a rotated
  key was unusable until the 300-second cache TTL expired. The window (60 s)
  bounds the fetch amplification an attacker could otherwise drive by
  presenting forged `kid` values — "never re-fetch" and "always re-fetch" are
  both explicitly forbidden.

- `axiam_oidc_refresh` is governed by its own §9-conformant single-flight
  guard, keyed on the refresh token's digest. AXIAM rotates refresh tokens, so
  two threads redeeming one concurrently would produce a winner and an
  `invalid_grant` for a token that was good a millisecond earlier. Distinct
  tokens do not contend. §9 rule 5 permits this dedicated instance rather than
  reusing the §1 cookie-session guard, whose API compares an access token's
  freshness — a comparison with no meaning for a `refresh_token` grant.

### Notes

- Coverage after this change: **96.3% line, 80.2% branch** against gates of 96
  and 80. Both pass, but with materially less headroom than the pre-port
  figures the `coverage.yml` comments were written against — this subsystem
  checks every allocation, and those guards are one-sided by construction.
  Worth knowing before the next change lands on the wrong side of the line.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Conform local token verification to CONTRACT §10.1

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#15)
- Device (mTLS) tokens now carry aud=axiam:m2m (#14)
- Service accounts can use login_client_credentials (#13)
- Add ASan+UBSan and valgrind gates (§13.4 observation 10 / §12.6.1) (#12)

### Fixed

- Enforce token lifetime and tenant binding, require https, wrap MFA tokens

## [Unreleased]

### Added

- **UMA 2.0 — Protection API and ticket grant (CONTRACT §20).** New `axiam/uma.h`:
  `axiam_uma_discover`, `axiam_uma_register_resource`, `axiam_uma_read_resource`,
  `axiam_uma_update_resource`, `axiam_uma_delete_resource`, `axiam_uma_list_resources`,
  `axiam_uma_request_ticket`, `axiam_uma_exchange_ticket`, and the two local challenge
  helpers `axiam_uma_parse_challenge` / `axiam_uma_challenge_header`. Every out-parameter
  that carries heap memory has a matching `_dispose`/`_free`, and each is safe on a zeroed
  struct so a caller can dispose unconditionally on the error path.

  **This ships while §12 does not, and that is not an inconsistency.** §12.7, §14 and §15
  stay deferred because each needs an OIDC stack this SDK does not have. §20 does not: UMA
  carries its own discovery document, the Protection API is ordinary bearer-authenticated
  REST, and the ticket grant returns an opaque RPT with nothing to validate.

  The load-bearing rules, all asserted in `tests/test_uma.c`:

  - **`axiam_uma_exchange_ticket` is never retried** — not on `5xx`, not on a transport
    failure, not on `invalid_grant`. This is the one documented exception to §16, and a
    security rule rather than a performance one: the ticket is consumed *before* the
    exchange is evaluated, so a retry is a second redemption — the concurrency case whose
    measured residual `ilpanich/axiam#302` records.
  - **`axiam_uma_parse_challenge` performs no exchange.** The `as_uri` names an
    authorization server the caller has not chosen to trust.
  - **The RPT is never adopted**, and `axiam_uma_rpt_t` has no refresh-token member.
  - **`axiam_uma_update_resource` replaces the scope list rather than merging it** — no
    read-modify-write, so omitting a scope removes it.
  - **An absent PAT, ticket, `claim_token`, client secret, or a slug-only tenant is refused
    client-side**, with no wire call, so a request that could not have succeeded never
    spends a ticket.

  The grant's form body carries four secrets and is scrubbed with `axiam_secure_zero`
  before release (§7), rather than left in a freed heap block.

- **Bounded read-only retry (CONTRACT §16).** `check_access`, `can`,
  `batch_check` and the JWKS fetch now retry a transient failure: 3 attempts
  total, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`, and
  `Retry-After` honored as a **floor** — it can lengthen a wait, never shorten
  one, so a `Retry-After: 0` cannot defeat the backoff. On by default;
  `axiam_client_config_set_retry_enabled(cfg, 0)` gives exactly one attempt for
  a caller who owns their own retry layer. The attempt cap, base and cap are
  deliberately **not** settable: §16.1 permits lowering or disabling, never
  raising, and a caller who can raise them turns one client into the herd a
  backoff exists to prevent.

  Eligibility is "changes no server state", **not** "is a `GET`". The
  authorization check is a `POST` with a body and is the operation this policy
  exists for; `login`, `verify_mfa`, `logout` and `refresh` are never retried,
  both because they change state and because their credentials are single-use.
  `tests/test_d5_conformance.c` asserts that a `503` on `login` still makes
  exactly one request on the wire — the case that catches a retry wired at the
  transport layer instead of the operation layer.

- **Client-side decision memo (CONTRACT §17).** `axiam_client_config_set_decision_memo_ttl`
  enables a bounded, TTL-clamped cache of authorization decisions. **Disabled by
  default**, and `0` means disabled rather than "cache for zero milliseconds". A
  TTL above 5 s is clamped to 5 s rather than rejected, allows and denies are
  cached identically, `reason_code` comes back with the decision, failures are
  never cached, and any credential change clears it.

  **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in
  both directions — a grant just *added* can still read as denied for up to the
  TTL — which is the direction that surprises people and breaks silently.

- **Deterministic shutdown (CONTRACT §18).** `axiam_client_close()` releases the
  transport, the cookie jar and the JWKS cache, scrubs the CSRF token, and is
  idempotent. It issues **no request**: the server-side session deliberately
  outlives the client object, so a close that logged out would silently end
  every user's session on each deploy. A call on a closed client returns
  `AXIAM_ERR_NETWORK` with a message naming the cause rather than reconnecting
  or reading freed memory. `axiam_client_free()` calls it for you, so existing
  code needs no change.

- **Telemetry hooks (CONTRACT §19).** `axiam_client_config_set_telemetry_hook`
  installs a sink for `request_start`, `request_end`, `retry`, `refresh` and
  `config_clamped` events, so metrics can be wired without this library taking a
  dependency on any metrics package. One `request_start`/`request_end` pair per
  **attempt**, so a caller can count real wire calls from the events. Payloads
  cannot carry a token by construction: `axiam_telemetry_event_t` is a fixed
  struct with no free-form map, and carries the path *template* rather than a
  URL with ids substituted in.

- **Decision reason codes (CONTRACT §11 rule 9).** `axiam_check_result_t` gains
  an owned `reason_code` string, populated by `axiam_check_access`, `axiam_can`
  and every row of `axiam_batch_check`, with `AXIAM_REASON_CODE_ALLOWED`,
  `AXIAM_REASON_CODE_NO_GRANT` and `AXIAM_REASON_CODE_DENIED_BY_RULE` as
  comparison constants. The two refusals are both `allowed == 0` but mean
  opposite things to the user — *ask an admin* versus *an admin already
  decided* — and an application that cannot tell them apart sends people to
  raise tickets that will be refused.

  Deliberately a `char *` and not an enum: §11 rule 9 requires an unrecognised
  code be surfaced verbatim, so a server that adds a fourth code must not become
  a decode failure in every deployed client. A server that omits the field
  yields `NULL` (absent, not an error), and the allow/deny outcome is carried by
  `allowed` alone. Guard behaviour is unchanged — `axiam_require_access` still
  returns `AXIAM_GUARD_DENIED` (403) for both refusals — which
  `tests/test_reason_code.c` asserts alongside the reporting half.

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

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `axiam_error_t` gained `oauth_error[64]`, empty for every failure that is not an OAuth2
  protocol error. §20.4 requires dispatching on the body's `error` field rather than the
  HTTP status — `access_denied` answers `403` on the ticket grant where RFC 8628's answers
  `400` — so the code has to reach the caller. The contract models it as an
  `OAuthProtocolError` sub-type of the authentication error; C has no subtyping, so the
  kind stays `AXIAM_ERR_AUTH` and the code lands in the new field, leaving the §2 taxonomy
  at three kinds rather than gaining a fourth. **This changes `sizeof(axiam_error_t)`**, so
  callers must recompile; the struct is caller-allocated and pre-1.0, so no ABI promise is
  broken.

- **Re-vendored `CONTRACT.md` and `openapi.json`** from `ilpanich/axiam` at
  contract 1.7. Of the sections 1.7 adds, only §11 rule 9 is implemented here;
  §12.7 (logout), §14 (device grant) and §15 (token exchange) all build on a
  §12 OIDC relying-party layer this SDK does not have, and are recorded under
  Scope / follow-ups in the README rather than half-shipped.

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
