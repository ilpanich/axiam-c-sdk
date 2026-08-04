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

> **This SDK conforms to CONTRACT.md §1–§7, §9–§11, §13 (including §6.1 mTLS).**
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
- OpenSSL ≥ 1.1.1 / 3.x development headers (`libssl-dev`).
- POSIX threads (`pthread`).

## Install

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(axiam-c-sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-c-sdk.git
  GIT_TAG v1.0.0-alpha24)
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
conan create . --version=1.0.0-alpha24
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
        printf("allowed: %d\n", res.allowed);
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
| §7   | Opaque `axiam_sensitive_t`, `[SENSITIVE]` rendering, no raw getter | `sensitive.h` |
| §9   | Single-flight refresh (`pthread_mutex_t` + condvar); no retry loop | `client.c` |
| §10  | `axiam_middleware`/guard: `axiam_require_auth` extracts + verifies session | `guard.h` |
| §11  | `axiam_require_access/require_role` + `AXIAM_REQUIRE_*` macros | `guard.h` |
| §13  | `axiam_webhook_verify` — HMAC-SHA256 signed-timestamp verification | `webhook.h` |

JWKS: `GET {base}/oauth2/jwks`, EdDSA/Ed25519 only, verified with OpenSSL
`EVP_DigestVerify`, cached 300s.

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

## Scope / follow-ups

Out of scope for v1.0, tracked as follow-ups:

- **gRPC transport** (Tonic-equivalent low-latency authz). The `check_access`
  surface is transport-agnostic and can gain a gRPC dispatcher later.
- **§8 AMQP HMAC consumer.** The contract's §8 AMQP obligations do not list C
  among the required consumer languages; no AMQP surface is shipped.

## License

See [LICENSE](LICENSE). Vendored third-party code: cJSON (MIT,
`third_party/cjson/LICENSE`), Unity test framework (MIT,
`third_party/unity/LICENSE.txt`).
