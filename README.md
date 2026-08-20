# AXIAM C SDK

[![CI](https://github.com/ilpanich/axiam-c-sdk/actions/workflows/sdk-ci-c.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-c-sdk/actions/workflows/sdk-ci-c.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-c-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-c-sdk?branch=main)
[![Docs](https://img.shields.io/badge/docs-Doxygen-blue.svg)](https://ilpanich.github.io/axiam-c-sdk/)
[![C11](https://img.shields.io/badge/C-C11-blue.svg)](https://en.cppreference.com/w/c/11)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A C11 client SDK for [AXIAM](https://github.com/ilpanich/axiam) (Access eXtended
Identity and Authorization Management). It provides authentication, token
refresh, and authorization checks over the AXIAM REST API, plus a
framework-agnostic route guard and declarative authorization helpers.

> **This SDK conforms to CONTRACT.md §1–§7, §9–§13, §14, §15, §16–§19, §20, §21 and §23 (including §6.1 mTLS, §12.7 logout, the §11 rule 9 decision reason codes, and the §23 SRP-6a login path — conditional on OpenSSL ≥ 3.2 for Argon2id, see below).**
>
> gRPC (including the gRPC-only `axiam_get_user_info` operation, CONTRACT §1.1)
> and §8 AMQP are intentionally **out of scope for v1.0** and tracked as
> follow-ups (see [Scope](#scope--follow-ups)). Per §1.1 the REST
> `/oauth2/userinfo` endpoint is not substituted for the gRPC operation.

- **Language:** C11 (public API is C, usable from C and C++).
- **HTTP / TLS / mTLS:** [libcurl](https://curl.se/libcurl/) with in-memory PEM blobs.
- **JWT/JWKS verification:** OpenSSL (Ed25519 / EdDSA only).
- **JSON:** vendored [cJSON](https://github.com/DaveGamble/cJSON) (MIT), so the build is offline-friendly.
- **Symbols:** every public symbol is prefixed `axiam_`, snake_case (CONTRACT §1).

## Requirements

- CMake ≥ 3.16, a C11 compiler (gcc/clang).
- libcurl development headers (`libcurl4-openssl-dev`).
- OpenSSL ≥ 1.1.1 / 3.x development headers (`libssl-dev`). **OpenSSL ≥ 3.2 for
  Argon2id** under §23 SRP — see below; everything else works on 1.1.1.
- POSIX threads (`pthread`).

## Install

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(axiam-c-sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-c-sdk.git
  GIT_TAG v1.0.0-alpha31)
FetchContent_MakeAvailable(axiam-c-sdk)

target_link_libraries(my_app PRIVATE axiam::axiam)
```

### find_package (after `cmake --install`)

```cmake
find_package(axiam-c-sdk CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE axiam::axiam)
```

### vcpkg overlay port

This repo ships an overlay port under `ports/axiam-c-sdk`:

```sh
vcpkg install axiam-c-sdk --overlay-ports=./ports
```

### Conan

```sh
conan create . --version=1.0.0-alpha31
```

## Quickstart

```c
#include <axiam/axiam.h>
#include <stdio.h>

int main(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");   /* §5: required */
    axiam_client_config_set_org_slug(cfg, "acme");      /* §5.1: required for login/refresh */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) { fprintf(stderr, "config error: %s\n", err.message); return 1; }

    axiam_login_result_t login = {0};
    if (axiam_login(client, "alice", "s3cret", &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login failed: %s\n", err.message);
        axiam_client_free(client);
        return 1;
    }
    if (login.mfa_required) {
        /* §7: challenge_token is an opaque axiam_sensitive_t, handed straight back. */
        axiam_verify_mfa_sensitive(client, login.challenge_token, "123456", &login, &err);
    }
    axiam_login_result_dispose(&login);

    /* Authorization check — (action, resource[, scope]) argument order (§1). */
    axiam_check_result_t res = {0};
    if (axiam_check_access(client, "users:get",
            "44444444-4444-4444-4444-444444444444", NULL, NULL, &res, &err) == AXIAM_OK) {
        printf("allowed: %d (%s)\n", res.allowed,
               res.reason_code ? res.reason_code : "no reason code");
    }
    axiam_check_result_dispose(&res);

    axiam_logout(client, &err);
    axiam_client_free(client);
    return 0;
}
```

## TLS & mTLS

Strict server verification is **always on** and cannot be disabled — there is no
`insecure`/`skip_verify` surface anywhere in this SDK (CONTRACT §6).

- **The base URL must be `https://`.** A plaintext base URL is refused at
  construction (`axiam_client_new` returns NULL with `AXIAM_ERR_NETWORK`) rather
  than silently sending credentials, session cookies, CSRF and tenant headers in
  cleartext. The single exception is a loopback host — `localhost`, `127.0.0.1`,
  `::1` — so local development against a non-TLS dev server still works. There is
  no flag to disable this for a routable host.

- **Custom CA (dev / self-signed servers).** Adds a CA to the verification chain;
  PEM only.
  ```c
  axiam_client_config_set_custom_ca(cfg, ca_pem);   /* returns AXIAM_ERR_NETWORK on non-PEM */
  ```
- **Client certificate (mTLS, §6.1).** Presents an X.509 identity for
  service-account / IoT authentication (`POST /api/v1/auth/device`). Requires a
  PEM certificate chain **and** a PEM private key. The key is held behind an
  opaque `axiam_sensitive_t` and never logged (§7); it is wired to libcurl as an
  in-memory blob (`CURLOPT_SSLCERT_BLOB` / `CURLOPT_SSLKEY_BLOB`) — no temp files.
  ```c
  axiam_client_config_set_client_cert(cfg, cert_pem, key_pem);
  ```
  Presenting a client certificate never relaxes server verification.

## Contract behaviors

| §    | Behavior | Where |
|------|----------|-------|
| §1   | Canonical ops `axiam_login/verify_mfa/refresh/logout/check_access/can/batch_check`; `(action, resource[, scope])` order | `client.h` |
| §2   | Three error kinds (`AXIAM_ERR_AUTH/AUTHZ/NETWORK`); HTTP→kind mapping; tokens never in messages | `error.h` |
| §3   | CSRF: capture `X-CSRF-Token` from responses, echo on state-changing requests | `client.c`, `transport_curl.c` |
| §4   | Per-client in-memory libcurl cookie engine (`CURLOPT_COOKIEFILE ""`) | `transport_curl.c` |
| §5   | `X-Tenant-ID` on every request; tenant required at construction (no default) | `config.c`, `client.c` |
| §6   | Strict TLS always on; plaintext base URL refused (loopback dev exception); custom CA is the only escape hatch (PEM only) | `config.c`, `transport_curl.c` |
| §6.1 | mTLS client identity (PEM cert + key, in-memory blobs) | `config.c`, `transport_curl.c` |
| §7   | Opaque `axiam_sensitive_t`, `[SENSITIVE]` rendering, and exactly one explicit accessor (`axiam_sensitive_reveal`, rule 3) | `sensitive.h` |
| §9   | Single-flight refresh (`pthread_mutex_t` + condvar); no retry loop. A second, dedicated guard covers `axiam_oidc_refresh` (§9 rule 5) | `client.c`, `oidc_refresh.c` |
| §10  | `axiam_middleware`/guard: `axiam_require_auth` extracts + verifies session | `guard.h` |
| §11  | `axiam_require_access/require_role` + `AXIAM_REQUIRE_*` macros; `axiam_require_access_uma` adds the §20.3 challenge on a denial | `guard.h` |
| §11 r9 | `reason_code` on every decision (`AXIAM_REASON_CODE_*`); guard behaviour unchanged | `client.h` |
| §13  | `axiam_webhook_verify` — HMAC-SHA256 signed-timestamp verification | `webhook.h` |
| §16  | Bounded read-only retry: 3 attempts, 200 ms base, 5 s cap, full jitter, `Retry-After` as a floor; `axiam_client_config_set_retry_enabled` | `retry.c`, `client.c` |
| §17  | Opt-in decision memo, off by default, TTL clamped to 5 s; `axiam_client_config_set_decision_memo_ttl` | `memo.c` |
| §18  | `axiam_client_close` — idempotent, issues no request, use-after-close errors | `client.c` |
| §19  | Telemetry hooks; `axiam_client_config_set_telemetry_hook` | `telemetry.h`, `telemetry.c` |
| §12  | OIDC relying party: the nine canonical operations, the discovery cache, S256 PKCE, and the §12.4 ID-token checklist | `oidc.h`, `oidc.c`, `oidc_validate.c` |
| §12.7 | `axiam_logout_url` (RP-initiated) and `axiam_verify_logout_token` (back-channel) | `oidc.h`, `oidc_logout.c` |
| §14  | RFC 8628 device grant: `axiam_device_authorize/poll/login`, with §14.2's polling rules | `oidc.h`, `oidc_device.c` |
| §15  | RFC 8693 token exchange: `axiam_token_exchange`, delegation vs impersonation | `oidc.h`, `oidc_exchange.c` |
| §20  | UMA 2.0: Protection API (`rreg` CRUD + `perm`), the ticket grant, and both halves of the `WWW-Authenticate: UMA` challenge | `uma.h`, `uma.c` |

JWKS: `GET {base}/oauth2/jwks`, EdDSA/Ed25519 only, verified with OpenSSL
`EVP_DigestVerify`, cached 300s.

### Retry, memo, shutdown and telemetry (§16–§19)

Retry is **on by default** and applies only to operations that change no server
state — `check_access`, `can`, `batch_check` and the JWKS fetch. That is not the
same as "HTTP GET": the authorization check is a `POST` with a body and is the
operation this policy exists for. `login`, `verify_mfa`, `logout` and `refresh`
are never retried automatically, both because they change state and because
their credentials are single-use.

```c
axiam_client_config_set_retry_enabled(cfg, 0);   /* one attempt, no backoff */
```

The decision memo is **disabled by default** and must be switched on
deliberately:

```c
axiam_client_config_set_decision_memo_ttl(cfg, 5000);  /* 5 s, the maximum */
```

> **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in
> *both* directions: a grant revoked on the server can still read as allowed for
> up to the TTL, and a grant just *added* can still read as denied for up to the
> TTL. An admin UI that grants a role and immediately re-checks is the case that
> breaks, and it breaks silently. A TTL above 5 s is **clamped** to 5 s, and the
> clamp is announced through the `config_clamped` telemetry event rather than
> applied in silence.

Telemetry is a plain callback; nothing is allocated and no thread is started, so
with no hook installed the cost is one `NULL` check per request. A hook is
invoked on the calling thread and must not block — buffering is yours to choose.
Event payloads carry the operation, the *path template* (never a URL with ids
substituted in) and the attempt number, and by construction cannot carry a
token: `axiam_telemetry_event_t` has a fixed field list and no free-form map.
Every `const char *` in an event is borrowed for the duration of the call, so a
sink that keeps a string must copy it.

```c
static void sink(void *ctx, const axiam_telemetry_event_t *ev) {
    if (ev->kind == AXIAM_TELEMETRY_RETRY)
        fprintf(stderr, "retry %s attempt=%d delay=%ldms\n",
                ev->operation, ev->attempt, ev->delay_ms);
}
axiam_client_config_set_telemetry_hook(cfg, sink, NULL);
```

`axiam_client_close()` releases the transport, the cookie jar and the JWKS cache
without issuing a request — it does **not** log out, because the server-side
session deliberately outlives the client object. It is idempotent, and any
operation attempted afterwards returns `AXIAM_ERR_NETWORK` with a message naming
the cause rather than silently reconnecting. `axiam_client_free()` still calls it
for you, so existing code needs no change.

### Local token verification is strict by default

`axiam_jwt_verify()` — and therefore every route guard — checks far more than
the signature. The JWKS endpoint is **organization-wide**, so a valid signature
alone does not mean the token belongs to your tenant:

- the header's `alg` is pinned to `EdDSA` **before any key lookup**, so
  `alg: none` and HS-family confusion are refused without consulting a key;
- `exp` is **required** and enforced (±`AXIAM_JWT_CLOCK_SKEW_SECS`, 60s);
- `nbf` is enforced when present;
- `tenant_id` must equal the client's configured tenant;
- `iss` and `aud` are checked **when, and only when, you configure an expected
  value** — `axiam_client_config_set_expected_issuer()` /
  `axiam_client_config_set_expected_audience()`. Both default to unset; the SDK
  never assumes an issuer. Once configured the claim becomes required, so a
  token that carries no `iss`/`aud` at all is refused rather than waved through.
  `aud` accepts both the bare-string and array-of-strings forms; a resource
  server guarding a user-facing API should expect `axiam:user`.

Anything missing, wrong-typed or mismatched fails **closed**
(`AXIAM_ERR_AUTH` / HTTP 401). This is CONTRACT §10.1's minimum
local-verification set.
Because the token's `tenant_id` claim is a UUID, a client used for route
guarding must be configured with `axiam_client_config_set_tenant_id()` (a slug
alone cannot be compared against it, and a slug-only client that has not logged
in refuses every token). `axiam_jwt_verify_ex()` exposes the policy flags —
`AXIAM_JWT_VERIFY_SIGNATURE_ONLY` reduces the check to the signature and must
never be used to admit a request.

### Decision reason codes (§11 rule 9)

Every `axiam_check_result_t` — from `axiam_check_access`, `axiam_can` and each
row of `axiam_batch_check` — carries a `reason_code` alongside `allowed`:

| `reason_code` | Meaning |
|---|---|
| `AXIAM_REASON_CODE_ALLOWED` (`"allowed"`) | an allow grant matched and no deny did |
| `AXIAM_REASON_CODE_NO_GRANT` (`"no_grant"`) | nothing matched — default deny |
| `AXIAM_REASON_CODE_DENIED_BY_RULE` (`"denied_by_rule"`) | an explicit deny rule matched and overrode any allow |

The two refusals are both `allowed == 0`, but they mean opposite things to the
person on the other end: `no_grant` says *ask an admin for access*,
`denied_by_rule` says *an admin has already decided*. Branch on the code when
you are telling a user what to do next:

```c
axiam_check_result_t res = {0};
if (axiam_check_access(client, "docs:edit", doc_id, NULL, NULL, &res, &err) == AXIAM_OK
    && !res.allowed) {
    if (res.reason_code && strcmp(res.reason_code, AXIAM_REASON_CODE_NO_GRANT) == 0)
        show_request_access_button();
    else
        show_plain_denied_message();   /* a rule, or a code we don't know */
}
axiam_check_result_dispose(&res);      /* frees reason and reason_code */
```

Three things this field deliberately is **not**:

- **Not an enum.** An unrecognised code is surfaced verbatim, so the server can
  add a fourth code without turning every deployed client into a parse failure.
  Compare with `strcmp` and let anything unknown fall through to a default.
- **Not the decision.** The outcome is carried by `allowed` alone. Never
  re-derive allow/deny from the code.
- **Not guaranteed present.** A server older than this clause omits the field
  and `reason_code` is `NULL` — that is absence, not an error.

Enforcement is unchanged: `axiam_require_access` returns `AXIAM_GUARD_DENIED`
(403) for both refusals. The clause is about reporting, and the guard must not
vary its behaviour on the code.

### Emitting a UMA challenge from the §11 guard (§20.3)

`axiam_require_access_uma()` is `axiam_require_access()` plus one thing: on a denial, with a
challenger configured, it mints a permission ticket for the pair that was refused and hands
back the formatted `WWW-Authenticate` value.

```c
axiam_uma_challenger_t challenger = { "invoices", uma_cfg.issuer, pat };

char *challenge = NULL;
axiam_guard_status_t st = axiam_require_access_uma(
    client, headers, "invoices:read", resource_id, NULL, &challenger, &challenge);

if (st == AXIAM_GUARD_DENIED && challenge) {
    /* Send it; do not log it — it carries a live ticket (§20.6). */
    add_response_header("WWW-Authenticate", challenge);
}
free(challenge);
```

Two properties are deliberate, and both are asserted by counting Protection API calls:

- **Opt-in.** Emitting a challenge means minting a credential. A guard that did that on every
  denial by default would put a Protection API call — and a live ticket — behind every
  unauthorized request, which is a denial-of-service amplifier pointed at your own
  authorization server. `axiam_require_access()` is untouched, and a NULL challenger mints
  nothing. An allow mints nothing either.
- **A minting failure is not an escalation.** An expired PAT or an unreachable Protection API
  still yields `AXIAM_GUARD_DENIED` with `*out_challenge` left NULL — never a 503, and never
  an allow.

The requested UMA scope is the AXIAM **action**, so the ticket asks for exactly the authority
that was refused and the engine's deny rules keep applying to whatever RPT comes back.

Both halves run in [`examples/uma_resource_server.c`](examples/uma_resource_server.c) and
[`examples/uma_client.c`](examples/uma_client.c).

## Webhook signature verification (§13)

AXIAM signs every webhook delivery with a Stripe-style signed timestamp
(`X-Axiam-Signature: t=<unix>,v1=<hex>`, HMAC-SHA256 over `<t>.<raw_body>`).
`axiam_webhook_verify()` checks it with a constant-time comparison over the
decoded MAC bytes and a two-sided 300s freshness window.

**Pass the raw request body bytes**, exactly as received. Re-serializing parsed
JSON changes key order and whitespace and will break the MAC.

```c
#include <axiam/axiam.h>

/* `headers` is the request's header list; `body`/`body_len` the RAW bytes. */
axiam_sensitive_t *secret = axiam_sensitive_new(getenv("AXIAM_WEBHOOK_SECRET"));

axiam_webhook_event_t ev;
axiam_webhook_status_t st =
    axiam_webhook_verify_headers(secret, headers, body, body_len,
                                 AXIAM_WEBHOOK_DEFAULT_TOLERANCE_SECS, &ev);
if (st != AXIAM_WEBHOOK_OK) {
    /* Reject with 400; the status string never contains the expected MAC. */
    fprintf(stderr, "webhook rejected: %s\n", axiam_webhook_status_str(st));
} else {
    /* Deliveries are at-least-once: de-duplicate on ev.delivery_id before
     * acting on ev.event_type / ev.body. */
    handle_event(ev.event_type, ev.body, ev.body_len);
    axiam_webhook_event_dispose(&ev);
}
axiam_sensitive_free(secret);
```

`axiam_webhook_verify()` takes the `X-Axiam-Signature` value directly, and
`axiam_webhook_verify_at()` injects `now` for deterministic tests.

## Secure Remote Password (§23)

`axiam_login_srp()` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **verifier** `v = g^x mod N` instead of a password hash, and
what travels is `A` and a proof, neither of which is useful without that
verifier.

```c
axiam_login_result_t login = {0};
axiam_error_t err;
axiam_error_kind_t kind = axiam_login_srp(client, "alice", password, &login, &err);
```

It takes the same arguments as `axiam_login()` and fills the same
`axiam_login_result_t`, MFA branch included, so switching a tenant to SRP needs
no change to how the result is handled. A runnable end-to-end example, including
the fallback and the enrolment call, is
[`examples/srp_login.c`](examples/srp_login.c).

### What this buys, and what it does not

SRP closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under SRP it sees `A` and `M1`;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- a leaked verifier database still costs a full KDF evaluation per candidate
  password, exactly as a leaked Argon2id database does.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### Conditional on your OpenSSL: Argon2id needs 3.2

The arithmetic is `BN_mod_exp`, available in every OpenSSL this SDK links
against, and PBKDF2-HMAC-SHA256 comes from `PKCS5_PBKDF2_HMAC`, likewise. But
**Argon2id arrives as an `EVP_KDF` only in OpenSSL 3.2**, and it is what a
default-configured AXIAM tenant names.

```c
if (!axiam_srp_argon2_available()) { /* this build cannot serve an argon2id tenant */ }
```

`axiam_srp_argon2_available()` fetches the KDF rather than reading a version
macro, because a macro answers for the headers this was *compiled* against
rather than the libcrypto it is *running* against, and those differ routinely
where OpenSSL is shared. When the KDF is absent, `axiam_login_srp()` returns
`AXIAM_ERR_NETWORK` naming it — it never substitutes PBKDF2, which would derive
a different `x` and surface as "invalid password", the single most misleading
failure this code could produce.

`axiam_srp_available()` is the §23.1 capability probe and is unconditional here;
the Argon2 probe is the one that can say no.

### Tenant policy, and the errors that are not credential failures

`srp_mode` is an organization baseline a tenant may tighten:

| mode | `axiam_login()` | `axiam_login_srp()` |
|---|---|---|
| `disabled` (default) | works | `AXIAM_ERR_NETWORK` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AXIAM_ERR_AUTHZ` (`srp_required`) | works |

Neither is `AXIAM_ERR_AUTH`:

- `AXIAM_ERR_NETWORK` from `axiam_login_srp()` means *this tenant does not offer
  SRP*, or *this build cannot do the KDF it named* — a property of the tenant or
  the build, never of any user. Fall back to `axiam_login()`.
- `AXIAM_ERR_AUTHZ` from `axiam_login()` means *this tenant refuses password
  login*. The credentials were never examined. Telling a user their perfectly
  good password is invalid is the failure this mapping exists to prevent.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a verifier would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a verifier needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot compute a verifier, so any request that **sets** a password
has to carry one. `axiam_srp_enrollment()` produces the `srp` object for
`POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```c
axiam_srp_enrollment_t enrolment;
axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_PBKDF2, 0, 0, 0 };  /* 0 = AXIAM's costs */
if (axiam_srp_enrollment("alice", new_password, NULL, &params, &enrolment, &err) == AXIAM_OK) {
    /* ... attach enrolment's fields as the request's `srp` member ... */
    axiam_srp_enrollment_dispose(&enrolment);   /* zeroizes salt and verifier */
}
```

The identity must be the account's **username**: `x` is derived over
`identity ":" password` using the identity the challenge endpoint hands back, so
a verifier enrolled against an email address can never satisfy a login. For the
same reason, **renaming a user invalidates their verifier** — the server clears
it, and the user re-enrols at their next password change.

The salt is 32 fresh bytes from `RAND_bytes` on every call, and
`axiam_srp_enrollment_dispose()` zeroizes both salt and verifier before freeing
them: §23.3 rule 12 keeps them out of logs, and there is no reason to leave them
in freed memory either.

### Cost

`axiam_login_srp()` runs the tenant's KDF: Argon2id at 19 MiB and t=2 by
default, which is tens to hundreds of milliseconds of CPU plus that memory, per
login attempt. That cost is the point — it is what makes a leaked verifier no
cheaper to attack than a leaked Argon2id hash. It is synchronous and blocking;
size your request handling accordingly, since `axiam_login()` has no such cost.

### Cryptographic parameters

RFC 5054 Appendix A groups `rfc5054_2048`, `rfc5054_3072` and `rfc5054_4096`
(the AXIAM default), embedded as constants. A modulus is **never** accepted from
the server — a server-supplied `N` is a server-supplied trapdoor — and a group
this SDK does not recognise is refused rather than guessed.

Two deliberate divergences from RFC 5054, both AXIAM-wide: `H` is **SHA-256**,
not SHA-1; and `x` is a **memory-hard KDF output**, not a bare hash, because RFC
5054's bare-hash `x` would make a leaked verifier *cheaper* to attack offline
than the Argon2id hashes AXIAM already stores.

### Zeroization

§23.3 rule 8 requires clearing what can be cleared, and C is a language where it
can be. `x`, `S`, `K` and the joined `identity ":" password` are
`OPENSSL_cleanse`d before release; every `BIGNUM` derived from the password uses
`BN_clear_free` rather than `BN_free`; the request bodies carrying `A`, `M1` and
`srp_session` go through the same scrubbing free the password path already used.
The suite runs clean under ASan, UBSan and valgrind with leak checking on.

The one thing this SDK cannot clear is the `const char *password` you hand it —
that memory is yours.

## Building & testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The HTTP transport is a function-pointer seam (`axiam_transport_fn`); tests drive
the whole logic layer through an in-memory fake, plus one real-libcurl
integration test against an in-process HTTP server. Test PKI is generated at
runtime (OpenSSL CLI, CTest fixture) and never committed.

Coverage:

```sh
cmake -S . -B build -DAXIAM_BUILD_TESTS=ON -DAXIAM_ENABLE_COVERAGE=ON
cmake --build build -j && ctest --test-dir build
gcov -n build/CMakeFiles/axiam_obj.dir/src/*.gcno
```

## Documentation

API reference is generated with Doxygen (`doxygen Doxyfile` → `docs/html`) and
published to GitHub Pages by CI.

## §12 OIDC, §12.7 logout, §14 device grant, §15 token exchange

These four shipped together in the contract-1.11 port ([`CONTRACT.md` §12.6](CONTRACT.md)).
They were previously deferred here, and the reasoning behind the reversal is
worth keeping: the original deferral argued from persona — this is a device- and
IoT-oriented SDK and the browser-redirect flow has no natural home in it — which
covered `oidc_begin` and `oidc_exchange` and none of the other seven operations.
`login_client_credentials` is the machine-to-machine login an embedded consumer
wants; `introspect` and `revoke` are ordinary questions a device asks about its
own credentials; §14 exists *because* a device cannot show a browser. Meanwhile
§20 had already given this SDK a `/oauth2/token` call, so it was speaking OAuth2
at the token endpoint anyway — without the shared discovery cache and ID-token
validation §12 specifies. The port removed a divergence rather than adding one.

```c
axiam_client_config_set_oidc_client_id(cfg, "example-rp");
axiam_client_config_set_oidc_client_secret(cfg, secret);  /* omit for a public client */

axiam_oidc_config_t doc;
axiam_oidc_discover(client, &doc, &err);          /* cached ≥ 5 min per client */

axiam_authorization_request_t req;
axiam_oidc_begin(client, &doc, redirect_uri, "openid profile", &req, &err);
/* No network I/O happened. Keep req.state, req.nonce, req.code_verifier AND
 * your redirect_uri — §12.3 rule 1 means the SDK stores none of them. */

axiam_oidc_exchange_params_t p = {0};
p.code = code; p.code_verifier = req.code_verifier;
p.redirect_uri = redirect_uri; p.nonce = req.nonce;

axiam_oidc_token_set_t tokens;
axiam_oidc_exchange(client, &p, &tokens, &err);
/* tokens.id_claims is non-NULL only after every §12.4 rule passed; on any
 * failure the WHOLE set is discarded (rule 7) and err.id_token_reason names
 * the rule. */
```

Three things this surface will not do, each because a section says so:

- **It stores no correlation values** (§12.3 rule 1). See above.
- **It never skips ID-token validation** and has no flag to. §12.4 rule 7 is
  all-or-nothing: a token set whose `id_token` fails any check is discarded
  whole, access and refresh tokens included.
- **It adopts nothing.** Every operation returns tokens; none becomes this
  client's own credential. §15.2 rule 5 makes that a MUST NOT for the exchanged
  token specifically, and this SDK takes one posture everywhere rather than two.

Worked examples: [`examples/oidc_login.c`](examples/oidc_login.c),
[`examples/device_login.c`](examples/device_login.c),
[`examples/token_exchange.c`](examples/token_exchange.c).

### Sender-constrained tokens and DPoP (§10.1 rule 9, §21.7.3)

A token carrying a `cnf` claim is **not** a bearer token: it names a key, and
accepting it without proving the caller holds that key converts it straight
back into one. ``axiam_jwt_verify_certificate_binding()`` applies §10.1 rule 9.

**This SDK deliberately declines §21.7.2 DPoP proof verification** (recorded in
the contract's §21.9 per-SDK table). Its role here is resource-server-side
validation, and it ships no JOSE implementation covering PS256/ES256/EdDSA that
could verify a proof without adding a dependency this contract does not
otherwise require.

Declining is a supported answer, and §21.7.3 defines it as exactly three
obligations — all three are met here:

1. **`jkt`-bound tokens are rejected**, never accepted as bearer tokens. That
   includes a `cnf` naming **both** a certificate and a DPoP key: two
   constraints is a conjunction, so a token this SDK can only half-check is
   refused outright rather than admitted on the certificate alone. "Check
   whichever we can" would let a caller holding the certificate but not the
   DPoP key through a door the operator bolted twice.
2. **This section says so** — you are reading it.
3. **The negative tests are present**: see ``tests/test_rule9_binding.c``.

What declining does *not* mean is shipping a stub that reports "verified". If
your deployment issues DPoP-bound tokens, guard those endpoints with an SDK
whose §21.9 row says it verifies proofs (Rust, Go, Python, TypeScript, …), or
verify the proof ahead of this SDK and pass only the certificate half here.

### §15.7 — external-IdP subject tokens

The same call exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation:

```c
axiam_token_exchange_params_t p = {0};
p.subject_token      = partner_token;
p.subject_token_type = AXIAM_TOKEN_TYPE_JWT;   /* required; named, never guessed */
p.audience           = "https://orders.internal";

axiam_exchanged_token_t t;
axiam_token_exchange(client, &p, &t, &err);
```

- **`subject_token_type` is yours to state, and is required** (§15.1). The SDK
  never decodes the subject token to pick it, and never overrides what you
  named. There is no default: a NULL or empty value fails client-side with no
  wire call, because a default would be the SDK choosing for you. Pass
  `AXIAM_TOKEN_TYPE_ACCESS_TOKEN` for the same-domain exchange. The member is
  last in the struct, so adding it moved nothing — and a caller who does not
  recompile gets the loud refusal rather than a silently different request.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose description is `the
  subject token's issuer is not configured for token exchange` means *fix the
  AXIAM trust configuration*. Every other `invalid_grant` means *fix your
  token*, and is deliberately generic. §2 builds `err.message` as
  `"<error>: <error_description>"`.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

**§7 rule 3 — the one explicit accessor.** §12 returns tokens *to* the caller,
so `axiam_sensitive_reveal()` is public as of contract 1.11: a wrapper a §12
caller can never read makes §12 unusable. `axiam_sensitive_to_string()` remains
what diagnostics call, and still answers `"[SENSITIVE]"` whatever the content.
Call the accessor at the point of use — building one header, one form field —
and never let the result reach a log or a serialization sink.

## Scope / follow-ups

Out of scope for v1.0, tracked as follow-ups:

- **gRPC transport** (Tonic-equivalent low-latency authz). The `check_access`
  surface is transport-agnostic and can gain a gRPC dispatcher later.
- **§8 AMQP HMAC consumer.** The contract's §8 AMQP obligations do not list C
  among the required consumer languages; no AMQP surface is shipped.
- **§22 reactor runtime.** No `reactor_serve` here, for the same reason: §22.11
  defers the *runtime helper* on Swift, C and C++ because there is no vendorable
  AMQP client for these targets. **That is a scope decision about the helper, not
  a statement that reactors are unavailable to you.** §22.1–§22.8 is a wire
  protocol, so an integrator hand-rolling a reactor against a third-party AMQP
  client MUST satisfy every normative rule in it — the §8 v2 verification set on
  the event, the signed reply shape with its omission rules (note that
  `hmac_signature` serializes as **`null`** inside a reactor body rather than
  being omitted as it is in §8's own two message types), the per-event
  mutable-field allow-lists, and §22.7's hot-path exclusion. The §22.13 vectors
  are the conformance surface and need no SDK to run against. Read
  [§22 and §22.11 of `CONTRACT.md`](CONTRACT.md) before writing one.
- **The optional `OidcStateStore`** (§12.3 rule 1). The core §12 operations are
  usable without one and the store is a MAY; a C reference implementation with
  the mandated 10-minute TTL, single-use `consume`, and lazy (never
  timer-driven) expiry is a follow-up.

## License

See [LICENSE](LICENSE). Vendored third-party code: cJSON (MIT,
`third_party/cjson/LICENSE`), Unity test framework (MIT,
`third_party/unity/LICENSE.txt`).
