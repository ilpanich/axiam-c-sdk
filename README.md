# AXIAM C SDK

A C11 client SDK for [AXIAM](https://github.com/ilpanich/axiam) (Access eXtended
Identity and Authorization Management). It provides authentication, token
refresh, and authorization checks over the AXIAM REST API, plus a
framework-agnostic route guard and declarative authorization helpers.

> **This SDK conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).**
>
> gRPC and §8 AMQP are intentionally **out of scope for v1.0** and tracked as
> follow-ups (see [Scope](#scope--follow-ups)).

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
  GIT_TAG v1.0.0-alpha11)
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
conan create . --version=1.0.0-alpha11
```

## Quickstart

```c
#include <axiam/axiam.h>
#include <stdio.h>

int main(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");   /* §5: required */
    axiam_client_config_set_org_slug(cfg, "acme-org");

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
        axiam_verify_mfa(client, login.challenge_token, "123456", &login, &err);
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
| §6   | Strict TLS always on; custom CA is the only escape hatch (PEM only) | `transport_curl.c` |
| §6.1 | mTLS client identity (PEM cert + key, in-memory blobs) | `config.c`, `transport_curl.c` |
| §7   | Opaque `axiam_sensitive_t`, `[SENSITIVE]` rendering, no raw getter | `sensitive.h` |
| §9   | Single-flight refresh (`pthread_mutex_t` + condvar); no retry loop | `client.c` |
| §10  | `axiam_middleware`/guard: `axiam_require_auth` extracts + verifies session | `guard.h` |
| §11  | `axiam_require_access/require_role` + `AXIAM_REQUIRE_*` macros | `guard.h` |

JWKS: `GET {base}/oauth2/jwks`, EdDSA/Ed25519 only, verified with OpenSSL
`EVP_DigestVerify`, cached 300s. The verifier does not check `exp`.

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
