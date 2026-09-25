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

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

> **This SDK conforms to CONTRACT.md 1.52 §1–§7, §9–§13, §14, §15, §17, §19, §20, §21, §22, §23, §24, §25, §26, §27 and §28 (including §6.1 mTLS, §12.7 logout, the §11 rule 9 decision reason codes, the §23 OPAQUE login path — which binds `libaxiam_opaque_ffi` at run time, see below — and §24's eight wire operations with §24.6a's JSON bridge, but not §24.6b's ceremony helper, which has no authenticator to link on these targets).**
>
> Sections are named individually rather than folded into ranges: widening a
> range silently turns a statement that was true when written into a different
> claim. **§16 and §18 are absent by that same rule, not by omission** — the
> contract makes retry policy and deterministic shutdown MUST-level and says
> they are not named, because an SDK is either conformant on them or it is not.
> This one is.
>
> **Contract 1.51.** Two operations and one fix landed with this revision:
> `axiam_authenticate_device()` (§6.1 rules 6–10 — this SDK's README used to
> document `POST /api/v1/auth/device` while shipping no symbol that called it;
> it now does) and the acting-tenant helper
> (`axiam_client_config_set_acting_tenant()` / `axiam_client_set_acting_tenant()`,
> §5.2 rule 1). Also **Breaking**: `axiam_jwt_verify()` / `axiam_jwt_verify_ex()`
> — and so `axiam_require_auth()` — now refuse a `cnf`-bound token instead of
> silently admitting it as a bearer token (§10.1 rule 9); see
> [Sender-constrained tokens and DPoP](#sender-constrained-tokens-and-dpop-§101-rule-9-§2173).
> The §27.6.1 manifest additions (`resources[].metadata`, the resource-scoped
> role binding, `service_accounts`) are documented under
> [Declarative manifests](#declarative-manifests-§276-§277), along with two
> pre-existing manifest defects fixed in this revision: a nested resource's
> `parent_id` now reaches the wire, and `resource_type` is refused rather than
> silently defaulted to `"folder"` when a manifest leaves it unstated.

> **§22 note, and it matters at integration time:** "conforms to … §22" is the claim; **"ships an AMQP client" is not**. The reactor *protocol* — verification, canonical signing, the registry, the runtime and the §22.14 binding table — is in the library. The *transport* is caller-supplied (§22.11): this SDK vendors no AMQP dependency, and you fill in two function pointers over whichever client you already trust.
>
> gRPC (including the gRPC-only `axiam_get_user_info` operation, CONTRACT §1.1;
> `validate_token` / `introspect_token`, §1.1.1; and §10.3's `cnf`-bearing
> `ValidateToken` / `IntrospectToken` responses — this SDK's §9–§13 range names
> no gRPC transport for either) and §8 AMQP are intentionally **out of scope
> for v1.0** and tracked as follow-ups (see [Scope](#scope--follow-ups)). Per
> §1.1 the REST `/oauth2/userinfo` endpoint is not substituted for the gRPC
> operation.
>
> **§28 note:** SHOULD-level and opt-in — every part of it is off unless you
> call `axiam_client_config_set_resource_metadata_url()`. **C has no router**
> (§28.3, §28.7), so there is no `serve_protected_resource_metadata`; instead
> `axiam_protected_resource_metadata_json()`/`_path()`/`_url()` return the
> pieces a CivetWeb (or any other) handler serves, documented below.

- **Language:** C11 (public API is C, usable from C and C++).
- **HTTP / TLS / mTLS:** [libcurl](https://curl.se/libcurl/) with in-memory PEM blobs.
- **JWT/JWKS verification:** OpenSSL (Ed25519 / EdDSA only).
- **JSON:** vendored [cJSON](https://github.com/DaveGamble/cJSON) (MIT), so the build is offline-friendly.
- **Symbols:** every public symbol is prefixed `axiam_`, snake_case (CONTRACT §1).

## Requirements

- CMake ≥ 3.16, a C11 compiler (gcc/clang) — see
  [Supported C standards](#supported-c-standards).
- libcurl development headers (`libcurl4-openssl-dev`).
- OpenSSL ≥ 1.1.1 / 3.x development headers (`libssl-dev`). The §23 SRP path
  used to need **≥ 3.2 for Argon2id**; OPAQUE does not — key stretching happens
  inside `libaxiam_opaque_ffi`, so 1.1.1 now serves every tenant.
- POSIX threads (`pthread`).
- `dlopen`/`dlsym` (`${CMAKE_DL_LIBS}`, empty on glibc ≥ 2.34). Used to resolve
  the optional OPAQUE library at run time; nothing needs to be installed at
  build time.

### Supported C standards

| | Standard | Why this one |
|---|---|---|
| **Floor** | C11 | `CMAKE_C_STANDARD` in `CMakeLists.txt`, and what every consumer inherits by default. Exposed as `AXIAM_MIN_C_STANDARD`. Deliberately not newer — raising it would exclude embedded and long-lived-distro toolchains for nothing the SDK needs. |
| **Newest** | C23 | The newest published standard (ISO/IEC 9899:2024). Exposed as `AXIAM_NEWEST_TESTED_C_STANDARD`. |

C17 is a bug-fix revision of C11 and sits between the two.

**The SDK is built at the floor and additionally compiled and tested at C23**, on
**both gcc and clang** — four legs in `sdk-ci-c.yml`. In C the upper end deserves
this more than the version count suggests, because newer standards *remove* things
rather than only adding them: K&R declarations are gone in C23, `bool`/`true`/`false`
became keywords, and an implicit function declaration is an error rather than a
warning. A consumer whose own project sets `-std=c23` — entirely their prerogative —
would otherwise be the first person to compile this SDK that way.

Nothing changes for you if you build at C11: it is still the default, and
`cmake -S . -B build` with no flags produces exactly the build it always did. To
compile against a newer standard, pass it:

```bash
cmake -S . -B build -DCMAKE_C_STANDARD=23
```

`<axiam/axiam.h>` refuses a toolchain below the floor with an `#error` at the point
of inclusion, so an out-of-date compiler produces one message that names the problem
rather than a cascade of syntax errors that reads like a broken SDK.

> **`__STDC_VERSION__` is not the same on both compilers for a C23 build.** gcc 13
> has no `-std=c23` at all, so `CMAKE_C_STANDARD 23` selects `-std=c2x` and the
> compiler reports the pre-ratification `202000L`; clang 18 accepts `-std=c23` and
> reports `202311L`. Both are correct C23 builds. Compare
> `AXIAM_NEWEST_TESTED_C_STANDARD` as a lower bound, never for equality.

See [`examples/version_compatibility.c`](./examples/version_compatibility.c) for a
runnable check, and `tests/test_version_policy.c` for the gate that fails the build
when `CMakeLists.txt`, the header macros and the CI matrix stop agreeing.

## Install

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(axiam-c-sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-c-sdk.git
  GIT_TAG v1.0.0-beta17)
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
conan create . --version=1.0.0-beta17
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
  service-account / IoT authentication over `axiam_authenticate_device()`
  (`POST /api/v1/auth/device`, §6.1 rules 6–10, contract 1.51). Requires a
  PEM certificate chain **and** a PEM private key. The key is held behind an
  opaque `axiam_sensitive_t` and never logged (§7); it is wired to libcurl as an
  in-memory blob (`CURLOPT_SSLCERT_BLOB` / `CURLOPT_SSLKEY_BLOB`) — no temp files.
  ```c
  axiam_client_config_set_client_cert(cfg, cert_pem, key_pem);

  axiam_device_auth_result_t out;
  axiam_error_t err;
  if (axiam_authenticate_device(client, &out, &err) == AXIAM_OK) {
      /* client is now signed in as the service account bound to this
       * certificate; check_access(), batch_check() and the §27 management
       * surface all carry the adopted token from here on. */
      axiam_device_auth_result_dispose(&out);
  }
  ```
  Presenting a client certificate never relaxes server verification. The call
  is reachable only on a client built with a certificate — no certificate, no
  wire call, `AXIAM_ERR_AUTH` client-side (rule 7). There is no refresh token
  for the resulting session; a later `401` on it is `AXIAM_ERR_AUTH` with no
  retry, and the caller recovers by calling `axiam_authenticate_device()`
  again. Every refusal of the device POST itself is a `401` per rule 8 — an
  unknown, untrusted, expired, revoked or unbound certificate all alike — and
  maps to `AXIAM_ERR_AUTH`, except a `429` (the route's per-client-IP rate
  limit): that is not an authentication failure, so the ordinary §2 status
  mapping puts it under `AXIAM_ERR_NETWORK` instead, and this one-shot call
  retries nothing either way. The token is certificate-bound; see
  [Sender-constrained tokens and DPoP](#sender-constrained-tokens-and-dpop-§101-rule-9-§2173)
  below for how a resource server must verify it.

  **Decline (§6.1 rule 7 as a typestate, C-1's precedent).** The contract lets
  an SDK express "unreachable without a certificate" either as a client-side
  runtime check or as a type the caller cannot even construct without one.
  This SDK takes the client-side branch: making `axiam_client_t` generic (or
  splitting it into a certificate-carrying and a non-carrying variant) for the
  sake of one operation would touch every other call in the library. The rule
  itself names the client-side `AuthError` as conforming.

### RFC 8705 §5 `mtls_endpoint_aliases` (contract 1.40, CONTRACT.md §21.3 rule 2)

A TLS listener decides whether to ask for a client certificate during the
handshake, before it has seen a byte of HTTP, so "request one on
`/oauth2/token` but not on `/oauth2/authorize`" is not something a single
listener can do. A deployment that wants both runs two — and
`mtls_endpoint_aliases` in the discovery document is how the second one is
named.

Once a client is configured with `axiam_client_config_set_client_cert`, every
request it makes presents that certificate, so the §12 operations **prefer the
alias** over the top-level entry of the same name wherever the document
publishes one:

| Operation | Endpoint aliased |
|---|---|
| `axiam_oidc_exchange`, `axiam_oidc_refresh`, `axiam_login_client_credentials`, `axiam_device_poll`, `axiam_token_exchange` | `token_endpoint` |
| `axiam_introspect` | `introspection_endpoint` |
| `axiam_revoke` | `revocation_endpoint` |
| `axiam_device_authorize` | `device_authorization_endpoint` |
| `axiam_oidc_par` | `pushed_authorization_request_endpoint` |

The parsed document exposes them as `axiam_oidc_config_t.mtls_endpoint_aliases`,
guarded by `has_mtls_endpoint_aliases`. Three things this deliberately does
**not** do:

- **`has_mtls_endpoint_aliases == 0` is not an error.** It means "this
  deployment terminates mutual TLS on the issuer's own host", so the
  conventional endpoints keep being used. A deployment running
  `client_auth = optional` on one listener serves both populations there and
  correctly publishes nothing. The same holds one level in: every member of the
  alias struct may be `NULL`, and an endpoint the object does not name falls
  back rather than failing the document.
- **No alias is ever synthesised.** Only the six endpoints RFC 8705 §5 lists
  can be aliased — never `authorization_endpoint`, `end_session_endpoint` or
  `jwks_uri`. The first two are front-channel and the third is public key
  material; sending a browser to an mTLS host raises a native
  certificate-chooser dialog most users cannot answer.
- **`issuer` does not move.** It is an identifier, not an endpoint. §12.4
  rule 3 still requires a token's `iss` to equal the document's `issuer` by
  exact string comparison, including for a token minted at an alias endpoint —
  the expected issuer is never derived from the host that was called.

A client without a certificate keeps using the top-level endpoints even when the
document publishes aliases: the alias exists for the handshake, and there is no
handshake to make.

#### A malformed alias is refused, never fallen back from (contract 1.43)

An alias that is *present* and cannot carry a certificate returns
`AXIAM_ERR_AUTH` rather than reverting to the top-level endpoint. Falling back
looks like the safe answer and is the dangerous one: the caller asked to
authenticate with a certificate, the operator published something unusable, and
sending the certificate to the front-channel host authenticates nothing while
appearing to work.

Two defects, each a refusal on its own — **not an absolute URL**, and **a scheme
weaker than the top-level endpoint the alias replaces**. The second compares like
with like: an alias substitutes for exactly one endpoint, so `https` → `http` is
a downgrade, while `http` → `http` is a development deployment and is accepted.

It is `AXIAM_ERR_AUTH`, not `AXIAM_ERR_NETWORK`, and that is not cosmetic: §16.3
retries `AXIAM_ERR_NETWORK` and only that, so the other choice would have
attempted a permanent, deterministic misconfiguration three times and reported it
as transient.

The refusal is per endpoint, like the fallback itself: one malformed alias stops
the calls that would have used it and leaves every other endpoint working. And a
client without a certificate never reads the member at all, not even to validate
it, so a deployment whose aliases are malformed cannot break the clients that
never use them.

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
| §12  | OIDC relying party: the **thirteen** canonical operations (nine at contract 1.11, the four login-provider operations at 1.37, rule 12a at 1.38), the discovery cache, S256 PKCE, and the §12.4 ID-token checklist | `oidc.h`, `oidc.c`, `oidc_validate.c` |
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

### The session-revocation feed (§10.4, contract 1.44, opt-in)

§10.2 records the gap this narrows: local verification proves a token was issued
and has not expired, never that the session behind it still exists. A logout or a
role removal does not reach a token already in a caller's hands until it expires
— up to fifteen minutes. The documented answer has been "route the decision
through gRPC introspection instead", which is correct and costs a round trip
**per request**.

A deployment can publish `GET /oauth2/revocations`: the hashed ids of the
sessions revoked within the last access-token lifetime. Turn the poller on and
`axiam_jwt_verify()` rejects a revoked session within **one poll interval**
instead, for one cacheable fetch per interval:

```c
axiam_client_enable_revocation_feed(client, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
```

**It is not a control, and every property follows from that.** It is off unless
you make that call — every existing client is unchanged and never fetches the
feed at all. It is never fetched on the request path once warm, and a feed that
is *down* is not retried on every request either, because the interval is
measured from the last *attempt*. And it **never fails closed**: an unreachable
feed, a non-`200`, a body that does not parse, or an `alg` this build does not
know all behave exactly as no feed at all — and specifically not as an empty
list, which would assert that nothing has been revoked and is a guard silently
honouring no revocations while appearing to honour them. Every rule above runs
first and still decides; the feed can only ever turn an accept into a reject, and
the error it sets names the session rather than the credential — "the session is
gone" is not "this token was never valid".

A token with no `sid` — a client-credentials token, an RPT, a token exchange — is
never matched against it, and asks the feed no question at all. There is no
session behind one, and hashing `jti` instead would match nothing while looking
like it worked.

`AXIAM_REVOCATION_DEFAULT_POLL_SECS` is 30 and `AXIAM_REVOCATION_MIN_POLL_SECS`
clamps anything shorter to 15; the cached set is bounded at
`AXIAM_REVOCATION_MAX_ENTRIES`, and a document larger than the bound is treated
as unusable rather than truncated — a truncated set is a guard that admits some
revoked sessions and reports none. `axiam_revocation_entry_for()` computes the
same entry the server publishes, for a caller that wants to check a feed
document by hand.

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

## OPAQUE — RFC 9807 (§23)

`axiam_login_opaque()` proves the password to the server without the password —
or anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **registration record** sealed under a tenant-scoped oblivious
PRF instead of a password hash, and what travels is a blinded group element and
a MAC, neither of which is useful without that record *and* the tenant's OPRF
seed.

```c
axiam_login_result_t login = {0};
axiam_error_t err;
axiam_error_kind_t kind = axiam_login_opaque(client, "alice", password, &login, &err);
```

It takes the same arguments as `axiam_login()` and fills the same
`axiam_login_result_t`, MFA branch included, so switching a tenant to OPAQUE
needs no change to how the result is handled. A runnable end-to-end example,
including the fallback and the enrolment call, is
[`examples/opaque_login.c`](examples/opaque_login.c).

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the
  substantive gain over the SRP-6a this replaces. An SRP verifier is
  `g^x mod N` with a public salt: anyone holding the database can grind
  candidate passwords locally, at one KDF evaluation each. An OPAQUE record is
  sealed under the tenant's OPRF seed, so an attacker who takes the records and
  not the seed has nothing to grind against at all. The property is called
  pre-computation resistance and SRP does not have it.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### This SDK does not implement OPAQUE, and that is the design

CONTRACT.md §23.1 forbids it. OPAQUE needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message authenticated
key exchange; eleven independent implementations of that is eleven chances to be
subtly and silently wrong, in a way test vectors do not catch because the wrong
answer is still a well-formed group element.

So this SDK binds **`libaxiam_opaque_ffi`**, the C ABI of the same audited
`opaque-ke` core the AXIAM server runs. There is no cryptography in
`src/opaque.c`.

The library is a **per-platform release asset** of
[`ilpanich/axiam-opaque`](https://github.com/ilpanich/axiam-opaque), resolved
with `dlopen()` at **run time** rather than linked. A consumer who never uses
OPAQUE therefore needs nothing extra — and `axiam_opaque_available()` can
honestly answer `0`. Install the library where the dynamic loader looks, or
point `AXIAM_OPAQUE_LIBRARY` at it:

```sh
export AXIAM_OPAQUE_LIBRARY=/usr/local/lib/libaxiam_opaque_ffi.so
```

```c
if (!axiam_opaque_available()) { /* ask BEFORE collecting a password */ }
```

### Your OpenSSL version no longer decides which tenants work

SRP was **conditional** here, and awkwardly so. The arithmetic was `BN_mod_exp`,
available everywhere, but **Argon2id arrives as an `EVP_KDF` only in OpenSSL
3.2** — and it is what a default-configured AXIAM tenant names. A build against
an older libcrypto had to refuse such a tenant outright (substituting PBKDF2
would derive a different `x` and surface as "invalid password"), so operators
either upgraded OpenSSL or weakened the tenant to `pbkdf2_sha256`.

That is gone. Key stretching happens inside `libaxiam_opaque_ffi`, so this SDK
serves `argon2id` and `scrypt` tenants against any OpenSSL it links, and
`axiam_srp_argon2_available()` has no successor because it has no question left
to answer.

One condition remains, and it is honest rather than hidden:
`axiam_opaque_available()` reports whether the shared library is present. Unlike
the `axiam_srp_available()` it replaces — which returned `1` unconditionally
while an `argon2id` tenant still failed at login — a `1` here **is** a promise
that every tenant will work.

### The server names the cost, every time

The `*_/start` response names the key-stretching function and its parameters for
**that exchange**. This SDK never caches them across exchanges and never
defaults them locally:

| rule | what it means here |
|---|---|
| §23.4 rule 2 | costs come from the server per exchange — a credential enrolled under one cost keeps working after a tenant raises its policy, so a client that guessed would derive a different randomized password and report "invalid password" for a correct one |
| §23.4 rule 3 | an unrecognised `ksf` is **refused**, never substituted |
| §23.4 rule 5 | a cost field that does not apply to the named function is **absent, not zero** — which is why every cost in `axiam_opaque_ksf_params_t` carries a `has_` flag rather than using `0` as a sentinel |
| §23.4 rule 7 | nothing is sent to `login/finish` once the envelope fails to open, and what happens next is decided by the `login/start` response's `mode` — see below |

Costs are additionally range-checked here, so a refusal names the field:

| field | accepted band |
|---|---|
| `memory_kib` | 8192 – 1048576 (8 MiB – 1 GiB) |
| `iterations` | 1 – 10 |
| `parallelism` | 1 – 16 |
| `log_n` | 14 – 20 |
| `r`, `p` | 1 – 16 |

A server is trusted to name its own policy, not to name a cost that would wedge
every device an account owns. The library range-checks too; doing it here as
well means the error says which field.

### One round trip, and no server-proof step

SRP had to guess a group before the server named one, and restart the exchange
if it guessed wrong. `KE1` does not depend on the key-stretching function, so
there is no such dance.

And where the old §23.3 rule 6 had to mandate an `M2` check **in capitals** —
because an SDK that skipped it implemented only half the protocol and no test
would notice — RFC 9807's AKE authenticates the server during the handshake.
Opening `KE2` *is* the proof that the server holds the record. Mutual
authentication is no longer something a client can forget.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `axiam_login()` | `axiam_login_opaque()` |
|---|---|---|
| `disabled` (default) | works | `AXIAM_ERR_NETWORK` — the start endpoints answer `404` |
| `optional` | works | works |
| `required` | `AXIAM_ERR_AUTHZ` (`opaque_required`) | works |

Neither is `AXIAM_ERR_AUTH`:

- `AXIAM_ERR_NETWORK` from `axiam_login_opaque()` means *this tenant does not
  offer OPAQUE*, *`libaxiam_opaque_ffi` is not installed*, *the server named a
  key-stretching function this SDK cannot ask for*, or *the response was not the
  shape §23 defines* — a property of the tenant, the build or the deployment,
  never of any user. Fall back to `axiam_login()`.
- `AXIAM_ERR_AUTHZ` from `axiam_login()` means *this tenant refuses password
  login*. The credentials were never examined. Telling a user their perfectly
  good password is invalid is the failure this mapping exists to prevent.

`AXIAM_ERR_AUTH` from `axiam_login_opaque()` means the envelope did not open: a
wrong password, an account that does not exist, an account with no registration
record, or a hostile endpoint — indistinguishable by design, and the whole
credential check now that both halves of mutual authentication live in it.

### `mode`, and the one fallback the SDK performs for you (§23.4 rule 7)

The `login/start` response carries an optional `mode` field — the tenant's
`opaque_mode`, `"optional"` or `"required"` (never `"disabled"`, which answers
`404`). It is the **only** thing that decides what follows a failure to open
`KE2`, and `axiam_login_opaque()` acts on it for you:

| `mode` in the response | what `axiam_login_opaque()` does |
|---|---|
| `"optional"` | retries over `POST /api/v1/auth/login` with the same credentials **before reporting anything**, and returns that call's outcome verbatim — its success on success, its error on failure |
| `"required"` | `AXIAM_ERR_AUTH`, exchange over. Nothing is retried |
| absent (a server older than the field) | as `"required"` — fails closed |
| a value this SDK does not recognise | as `"required"` — fails closed |

The `optional` clause is not decoration. `optional` is the state a tenant lives
in for as long as its migration takes: every account has **no** registration
record the moment an operator enables OPAQUE, and acquires one only when its
password is next set. An SDK that reported the failed exchange as final would
lock out every user of the tenant, making `optional` indistinguishable from
`required` with nobody enrolled.

Note what `mode` is **not**. It is **not downgrade protection**, and this SDK
does not treat it as any: a hostile server that wanted the plaintext could
simply answer `404` to `login/start` and get the fallback whatever it wrote
there. What closes that is `required`, enforced server-side — it refuses
`/auth/login` for every principal in the tenant, before any credential is
examined.

Only the credential check falls back. An `AXIAM_ERR_NETWORK` out of the
exchange — a key-stretching function this SDK cannot ask for, a cost outside
the accepted band — gets no plaintext retry under any `mode`: it is a client or
configuration fault, and there is no reason to believe a password on the wire
would fare better.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a record would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a record needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a
password has to carry one. `axiam_opaque_enrollment()` produces the `opaque`
object for `POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm`
and `/admin/bootstrap`:

```c
axiam_opaque_enrollment_t enrolment;
if (axiam_opaque_enrollment(client, new_password, &enrolment, &err) == AXIAM_OK) {
    /* ... attach opaque_session + registration_record as the `opaque` member ... */
    axiam_opaque_enrollment_dispose(&enrolment);   /* zeroizes the record */
}
```

Three things differ from the `axiam_srp_enrollment()` it replaces, and all three
are improvements:

- **It takes a client and performs I/O** — one `register/start` round trip.
  OPAQUE's envelope is sealed under the server's oblivious PRF, so there is no
  offline computation that produces a valid record. The SRP version was pure.
- **There is no `identity` argument.** SRP derived `x` over
  `identity ":" password` using the identity the challenge endpoint handed back,
  so passing an email where a username was wanted produced a verifier no login
  could ever satisfy — and **renaming a user invalidated their verifier**, which
  the server had to clear. An OPAQUE record binds to a credential identifier the
  server chooses. A rename is now just a rename.
- **There is no `group` and no `params`.** Those come from the `register/start`
  response, so a caller cannot pick a cost the server will not honour.

`registration_record` is credential material: never log it.
`axiam_opaque_enrollment_dispose()` `OPENSSL_cleanse`s it before freeing.

### Cost

`axiam_login_opaque()` runs the tenant's key-stretching function: Argon2id at
19 MiB and t=2 by default, which is tens to hundreds of milliseconds of CPU plus
that memory, per login attempt. That cost is the point — it is what makes a
stolen record expensive to attack even by someone holding the OPRF seed. It is
synchronous and blocking; size your request handling accordingly, since
`axiam_login()` has no such cost.

### Cryptographic parameters

`OPAQUE-3DH` over **ristretto255**, with **SHA-512**, **HKDF-SHA-512** and
**HMAC-SHA-512**. The ciphersuite is fixed in `libaxiam_opaque_ffi`; it is not
negotiated and is deliberately **not** read from the server, because a
server-selected ciphersuite is a downgrade channel.

The bundled RFC 5054 group constants are gone with the arithmetic, and so is the
"never accept a modulus from the server" rule they needed.

### Handle lifetime

An exchange owns one native allocation. It is single-use — a finish spends it —
and `axiam_opaque_exchange_close()` is idempotent, so calling it on every path
is a no-op on success and the thing that prevents a leak on every failure path:
a refused key-stretching function, a malformed response, a non-200 start.

The key-stretching handle is built **before** the exchange state is spent, and
the order is load-bearing: built the other way round, a server that names a cost
outside the accepted band would leave the state unreachable — a leaked native
allocation once per login attempt, and the steady state for a misconfigured
tenant. Two tests pin the ordering.

### Zeroization

§23.4 rule 8 requires clearing what can be cleared, and C is a language where it
can be. `KE1`, the `RegistrationRequest`, `KE3` and the registration record are
`OPENSSL_cleanse`d before release, and the request bodies carrying them go
through the same scrubbing free the password path already used. The sensitive
derivations themselves happen and are cleared on the Rust side of the ABI. The
suite runs clean under ASan, UBSan and valgrind with leak checking on.

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

The §23 OPAQUE binding gets the same treatment twice over. `tests/opaque_fake.h`
substitutes a vtable through an internal seam to exercise the exchange
lifecycle, the key-stretching selection and the error taxonomy; and
`tests/opaque_stub.c` is built as a **real shared library** exporting the twelve
`libaxiam_opaque_ffi` symbols and loaded through `AXIAM_OPAQUE_LIBRARY`, so the
`dlopen`/`dlsym` resolution itself runs against a genuine dynamic object. Most
SDKs cannot cover that path at all without shipping a per-platform binary; C
can, so `src/opaque.c` measures 100% of lines with no exclusion. Neither
artifact performs any cryptography — §23.1 puts all of it in the shared
library — and no `libaxiam_opaque_ffi` is needed to run the suite.

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

**The ID token no longer carries `tenant_id`, `org_id` or `email` (contract
1.42, OIDC Core §5.4).** AXIAM mints all three as absent — an ID token is an
authentication receipt, and OIDC Core §5.4 puts the standard claims in UserInfo
and in an ID token whose request asked for them. `tokens.id_claims->email` and
`tokens.id_claims->tenant_id` therefore read `NULL` against AXIAM. The members
are kept, and still parsed, because a non-AXIAM OP may legitimately send them
and §12.1 forbids discarding a claim the SDK was handed.

Where those identifiers actually are:

| Want | Read |
|---|---|
| tenant / organization UUID | the **access token's** claims — `axiam_jwt_verify()` hands back the verified payload as JSON with `tenant_id` and `org_id` on it. This is the pair the SDK uses itself. |
| tenant, after a §3 login | `axiam_login_result_t.tenant_id` / `.principal_tenant_id` |
| tenant a §27 call would address | `axiam_mgmt_resolved_tenant_id()` |
| e-mail address | `axiam_login_result_t.email` |

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

### The four public login-provider operations (contract 1.37; rule 12a at 1.38)

Contract 1.37 added the operations a login *page* needs — which buttons to
render, and how to finish the two flows that cannot set a `SameSite=Strict`
cookie on their own response. They bring §12 to thirteen operations.

| Canonical | C | Endpoint |
|---|---|---|
| `sso_providers` | `axiam_sso_providers()` | `GET /api/v1/auth/federation/providers` |
| `sso_start_oauth2` | `axiam_sso_start_oauth2()` | `POST /api/v1/auth/federation/oauth2/start` |
| `sso_complete_oauth2` | `axiam_sso_complete_oauth2()` | `POST /api/v1/auth/federation/oauth2/callback` |
| `sso_complete_handoff` | `axiam_sso_complete_handoff()` | `POST /api/v1/auth/federation/handoff` |

```c
axiam_federation_provider_list_t list;
if (axiam_sso_providers(client, NULL, typed_by_the_user, NULL, NULL, &list, &err) != AXIAM_OK)
    return handle(&err);

for (size_t i = 0; i < list.count; i++) {
    const axiam_federation_provider_t *p = &list.items[i];
    /* §12.1 note 10: `protocol` selects the start operation. NEVER
     * provider_kind — a SAML config can carry provider_kind "google", and
     * guessing sends it to an endpoint the server refuses with 400. */
    if (strcmp(p->protocol, AXIAM_FEDERATION_PROTOCOL_OIDC_CONNECT) == 0)
        axiam_sso_start(client, p->id, callback_uri, &start, &err);
    else if (strcmp(p->protocol, AXIAM_FEDERATION_PROTOCOL_OAUTH2) == 0)
        axiam_sso_start_oauth2(client, p->id, callback_uri, &start, &err);
    else if (strcmp(p->protocol, AXIAM_FEDERATION_PROTOCOL_SAML) == 0)
        begin_saml_login(p->id);      /* not a §12 vocabulary operation */
    /* anything else is a protocol this build predates — skip the button */
}
axiam_federation_provider_list_dispose(&list);
```

- **An empty list is a success, and the only success there is** (§12.1 note 9).
  An unknown organization, a known one with no providers, and a request naming
  no organization at all all answer `200` with `count == 0`. This SDK never
  turns that into a not-found error and never refuses the call client-side for
  missing workspace context — the endpoint is shaped so it cannot enumerate org
  or tenant slugs, and restoring the distinction would restore the oracle. A
  caller learns it named the workspace wrongly at the start operations, where
  every failure is a uniform `401`.
- **`protocol` is the wire string, not an enum.** A closed enum would fail the
  parse of the whole list over one provider this build predates. An entry with
  no `id` or no `protocol` is dropped rather than failing the listing, so the
  buttons that *are* usable still render.
- **PKCE on the OAuth2 path is mandatory and entirely server-side** (note 11).
  This SDK computes no verifier and no challenge and sends neither. That path
  also carries **reduced assurance** — no ID token, so no signature, no `nonce`,
  no `aud`.
- **A handoff code is single-use and lives `AXIAM_HANDOFF_CODE_TTL_SECONDS`
  seconds** (note 12). It arrives on the SPA callback in the
  `AXIAM_HANDOFF_QUERY_PARAM` (`axiam_handoff`) query parameter; redeem it from
  the same origin. Unknown, expired and already-redeemed all answer the same
  `401`, so a `401` is **terminal** — the code is gone either way, and this SDK
  issues the redemption exactly once.
- **A `400` is a configuration error, not a retry** (§12.1 rule 12a). On the
  SAML and Apple flows the `redirect_uri` must be on an origin the deployment
  accepts. §2 maps `400` to `AXIAM_ERR_NETWORK` — this taxonomy's
  configuration/programming-error member, as distinct from the `AXIAM_ERR_AUTH`
  a `401` gets. Never build a `redirect_uri` from a value the identity provider
  supplied.
- **Inheritance is resolved server-side** (note 13). `inherited` tells you a
  provider belongs to the organization rather than the tenant; pass the `id` you
  were handed and let the server work out the rest.

### Sender-constrained tokens and DPoP (§10.1 rule 9, §21.7.3)

A token carrying a `cnf` claim is **not** a bearer token: it names a key, and
accepting it without proving the caller holds that key converts it straight
back into one.

**The DEFAULT verify entry points now refuse a `cnf`-bound token (contract
1.51, Breaking).** `axiam_jwt_verify()` / `axiam_jwt_verify_ex()` — and so
`axiam_require_auth()` and every `AXIAM_REQUIRE_*` macro, which call them —
have no transport evidence to check a sender constraint against, and used to
accept such a token anyway: a device token lifted off a device opened every
guarded route. They now refuse it (`AXIAM_ERR_AUTH`), the same defect found
and fixed in this port wave in the Rust, TypeScript, Go, Python, C# and Java
SDKs. A resource server that DOES have the peer certificate calls
`axiam_jwt_verify_with_evidence()` / `axiam_jwt_verify_ex_with_evidence()`
instead, passing the connection's certificate thumbprint
(`axiam_certificate_thumbprint_s256()` from `SSL_get_peer_certificate()` +
`i2d_X509()` — never from a request header, which would make the mechanism
decorative). `axiam_jwt_verify_certificate_binding()` remains the standalone
building block both paths share, and is what to reach for when layering rule
9 onto claims already verified some other way.

**The framework-agnostic guards never accept a bound token, and there is no
evidence form of them.** `axiam_require_auth()`, `axiam_require_access()`,
`axiam_require_role()`, every `AXIAM_REQUIRE_*` macro, and the MCP entry
points `axiam_require_auth_mcp()` / `axiam_require_access_mcp()` all call
`axiam_jwt_verify_ex()` under `AXIAM_JWT_VERIFY_STRICT` — they have no
framework connection object to pull a peer-certificate thumbprint from, so
they cannot obtain transport evidence and, per CONTRACT.md §10.1 rule 9
(contract 1.52 N-1, C-12), refuse **every** `cnf`-bound token: a device
credential and a DPoP-bound access token behind any of these guards both get
`AXIAM_ERR_AUTH`, unconditionally. A resource server that must accept one
does its own local verification with `axiam_jwt_verify_with_evidence()` /
`axiam_jwt_verify_ex_with_evidence()`, outside the guard helpers, and applies
its authorization decision itself.

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

## §24 WebAuthn / passkeys

The six relying-party wire operations plus [§24.6a](CONTRACT.md)'s JSON bridge.
What is **not** here is §24.6b's linked-API ceremony helper, and the reason is
not effort: a C program has no authenticator. There is no platform API to link
on the targets this SDK serves, and §24.6b rule 2 forbids emulating one in
software — a "credential" held in process memory is not a second factor.

That is a statement about convenience, not capability. The bridge is the whole
interface, and it is enough for every integration this SDK actually sees: an
embedded gateway fronting a browser, a native app talking to a C service, a test
harness driving a virtual authenticator.

```c
axiam_webauthn_challenge_t challenge;
axiam_webauthn_register_start(client, &challenge, &err);   /* needs a session */

/* §24.6a rule 1: the INNER options object. The `publicKey` wrapper belongs to
 * the DOM's CredentialCreationOptions; the platform JSON APIs do not want it. */
char *request_json = axiam_webauthn_request_json(&challenge);
char *response = your_platform_runs_the_ceremony(request_json);   /* verbatim */
free(request_json);

axiam_webauthn_credential_t credential;
axiam_webauthn_register_finish(client, challenge.state_token, "Ada's laptop",
                               response, &credential, &err);
```

**The server owns the options, and the SDK owns nothing (§24.0).** Nothing in
this surface defaults a field, validates one, or re-encodes a buffer. The
challenge arrives as JSON text and leaves as JSON text; the authenticator's
response is spliced into the request body without being parsed into a model and
printed back out. A signed buffer that makes a round trip through a JSON model is
a signed buffer that can come out different — member order shifts, large integers
round through a double — and the server's signature check is what notices. The
one thing checked client-side is that the response IS a JSON object, because the
SDK will not POST a body it already knows the server cannot verify.

**Two ceremonies, not one with a flag (§24.2).**
`axiam_webauthn_authenticate_start()` is a *second factor*: it continues a login
that answered `mfa_required`, so it requires that login's challenge token.
`axiam_webauthn_discoverable_start()` is a *primary factor*: nothing precedes it,
`allowCredentials` comes back empty, and the assertion itself identifies the
user — which is why it is the one WebAuthn endpoint carrying the workspace
explicitly, and why it accepts slugs where the five `/oauth2` operations of §12.1
rule 2 do not. Both `*_finish` calls sign the client in and clear the §17
decision memo (§24.3).

**Two error cases are not the generic §2 mapping (§24.4).** A `403` on
`register/finish` carries the tenant's attestation-policy message, and that
message is surfaced — "register/finish failed" tells the person holding the key
nothing they can act on. A `503` on `register/start` is **not retried**: it means
the policy needs FIDO metadata the server cannot reach, which is a configuration
state, not a transient one.

**The failure classification is required even without a ceremony helper**
(§24.6b rule 5). Whatever *did* run the ceremony reports its failure as one
opaque type whose only machine-readable part is a name;
`axiam_webauthn_classify()` translates it once, and never fails — an
unrecognised name, including `NULL`, is `AXIAM_WEBAUTHN_UNKNOWN`. Note that
`AXIAM_WEBAUTHN_CANCELLED` covers **both** an explicit refusal and a silent
timeout: the spec deliberately refuses to distinguish them, because telling a
website which one happened leaks whether an authenticator was present. Copy that
says "you cancelled" is wrong half the time it is shown, and
`axiam_webauthn_failure_message()` does not say it.

Worked example: [`examples/webauthn_passkeys.c`](examples/webauthn_passkeys.c).

## §25 Account lifecycle and MFA enrolment

Ten operations covering voluntary and forced TOTP enrolment, email
verification, the two resends, and the password-reset triple.

**Six of the ten are deliberately unauthenticated.** A user who cannot log in
is the entire audience for a password reset, and a user whose email is unverified
may have no session at all.

```c
axiam_mfa_enrollment_t enrollment;
axiam_mfa_enroll(client, &enrollment, &err);
/* BOTH halves are Sensitive (§25.3) — see below. */
render_qr(axiam_sensitive_reveal(enrollment.totp_uri));

int enabled = 0;
axiam_mfa_confirm(client, code_the_user_typed, &enabled, &err);
```

**The otpauth URI is the field that actually leaks (§25.3).** It *contains* the
secret, so wrapping `secret_base32` and leaving `totp_uri` a plain string wraps
nothing: the URI is the one you hand to a QR renderer, and therefore the one that
ends up in a log. Both are `axiam_sensitive_t`.

**`axiam_mfa_enroll()` does not clear the decision memo (§25.2 rule 3).** The
subject has not changed — offering a factor is a profile action — and discarding
a warm §17 memo over it costs a round trip on every authorization check that
follows. `axiam_mfa_setup_confirm()` *does* clear it, because that call **is** the
completion of a login (§25.2 rule 2) and adopts credentials exactly as
`axiam_login()` does.

**Login has three outcomes now, not two.** `axiam_login_result_t` already carried
`mfa_setup_required` and `setup_token`; §25.2 rule 1 is what makes them
reachable. When the tenant requires MFA and the account has none, the setup token
**is** the credential for `axiam_mfa_setup_enroll()` and
`axiam_mfa_setup_confirm()` — there is no session yet.

**There is no one-call enrolment helper, and there must not be** (§25.2 rule 4).
The human step in the middle — read the QR code, type six digits — is not
something a helper can wait for.

**Where the tenant goes.** `verify_email`, `resend_verification` and
`confirm_password_reset` take it as a **body** field. These are not `/oauth2`
endpoints, so §12.1 rule 2's query-parameter convention does not reach them, and
putting it in the query earns a `400` that reads exactly like a bad token.

**Password reset discloses nothing (§25.4).**
`axiam_request_password_reset()` returns `AXIAM_OK` whether or not the address
exists, and this SDK exposes no way to tell the two apart. Call
`axiam_password_reset_context()` before choosing a password path: a tenant in
`opaque_mode: required` refuses a plaintext password, and refuses it *late* — by
which point the user has typed one. A `404` from that call means unknown, expired
**or** already-consumed, deliberately indistinguishable; do not invent a
distinction the server refused to make.

### Two resends, and why neither replaces the other (§25.7)

```c
/* No session — a sign-up screen. Returns AXIAM_OK whatever happened; that is the point. */
axiam_resend_verification(client, "alice@example.com", tenant_id, &err);

/* Signed in — a profile page. Says what happened, and names no address. */
switch (axiam_resend_own_verification(client, &err)) {
case AXIAM_OK:          /* enqueued — delivery is asynchronous */          break;
case AXIAM_ERR_AUTHZ:   /* 409: already verified, or a state that must not be sent */ break;
case AXIAM_ERR_NETWORK: /* 429: the daily resend limit */                  break;
case AXIAM_ERR_AUTH:    /* no session — refused here, with no wire call */ break;
default: break;
}
```

They look like one operation and are not. `axiam_resend_verification()` takes an address
from an **anonymous** caller, so it must answer identically whether the address exists, is
already verified, or is rate-limited — anything else is an oracle for which addresses have
accounts. `axiam_resend_own_verification()` is asked by a caller already signed in to the
account it is asking about, so none of those outcomes discloses anything it did not bring
with it, and this one tells the truth.

**Neither is routed to the other**, in either direction, and this SDK does not fall back
from the authenticated one to the public one on a `409` or a `429`: that fallback turns
both failures back into a silent success and restores the exact bug §25.7 describes, with
an extra round trip. The signed-in one takes **no address parameter and sends no address
field** — a parameter here would let an authenticated session mail an arbitrary one.

`AXIAM_OK` means the mail was **enqueued**, not delivered. Delivery is asynchronous and
can still fail at the provider.

### Organization-level principals (§5.2)

`axiam_login_result_t` gained `organization_level`. It is `1` when the account that just
signed in is an **organization-level** principal — one whose record lives in its
organization's reserved tenant, so its global grants apply in every tenant of that
organization and it can act on a different one by sending `X-Axiam-Tenant` on the
next request (§5.2 rule 1, contract 1.51 — see the acting-tenant helper below), with no
re-login.

An ordinary tenant principal is a principal of exactly one tenant; the same header change
produces a `403` for it. The flag is therefore what an application checks *before*
offering a tenant switch, rather than discovering the answer from a failed request.

#### The acting-tenant helper (§5.2 rule 1, contract 1.51)

`X-Axiam-Tenant` is a **different header from `X-Tenant-ID`** (§5 rule 2, sent
unconditionally on every request and never the acting-tenant switch). Construction-time
form:

```c
axiam_error_t err;
if (axiam_client_config_set_acting_tenant(cfg, other_tenant_uuid) != AXIAM_OK) {
    /* not a UUID -- the server would silently drop it and act on the caller's own
     * tenant instead, so this SDK refuses before any wire call. */
}
```

On-client rebind, once signed in:

```c
if (axiam_client_set_acting_tenant(client, other_tenant_uuid, &err) == AXIAM_OK) {
    /* every subsequent REST call this client makes carries X-Axiam-Tenant. */
}
axiam_client_clear_acting_tenant(client); /* back to none -- no header at all */
```

Gated on what THIS client knows, before any wire call: refused when a held login result
is not `organization_level`, or when `reachable_tenant_ids` is present and does not name
the tenant (§5.2.3 rule 4). A client holding no login result — a service account from
`axiam_authenticate_device()`, or an injected token — sends the header as asked and lets
the server's `403` decide.

**Exactly which calls "hold a login result," and which don't.** The gate's "does this
client have one" question is not answered per-*flow*, it is answered per-*response
shape*: a call **records** it when the response body carries a `LoginUserInfo`-shaped
`user` object, and **resets** it to unknown when the call establishes a session some
other way. Recording: `axiam_login()`, `axiam_verify_mfa()`, `axiam_login_opaque()`, the
MFA setup completion (`axiam_mfa_setup_confirm()`), and the WebAuthn *registration*
(setup) completion (`axiam_webauthn_setup_register_finish()`) — all five parse a
response of that same login shape. Resetting: the WebAuthn *authentication* ceremonies
(`axiam_webauthn_authenticate_finish()` and the discoverable/passkey variant
`axiam_webauthn_discoverable_finish()`, both via `axiam_client_adopt_session()`),
`axiam_authenticate_device()` (§6.1), and all three SSO/federation completions
(`axiam_sso_complete()`, `axiam_sso_complete_oauth2()`, `axiam_sso_complete_handoff()`)
— none of these responses carries a `user` object at
all (§12.1 note 6, §24.3), so each resets the gate to "unknown" rather than let a
PREVIOUS session's `organization_level`/`reachable_tenant_ids` leak into a new one
that never asserted anything about itself. `axiam_logout()` goes further: a logged-out
client holds no session to gate an acting tenant on, so **`axiam_logout()` also clears
the acting tenant itself** (back to "none — no header at all"), not only the gate.

This differs from the reference (Rust) SDK, which resets for OPAQUE and both setup
completions too. The two choices read the same contract text two ways: Rust treats
"was this call a ceremony completion" as the question: this SDK instead asks "did the
response carry a `LoginUserInfo`" — and for OPAQUE and the setup completions, contract
1.51's response shape answers yes. Both are conforming; this SDK's choice matches the
TypeScript, Go, Python, C#, Java, Kotlin and PHP ports.

**Design note.** Where the reference (Rust) SDK's on-client form returns a new handle
sharing the underlying session, this SDK mutates the existing `axiam_client_t` in place,
under the same lock that already guards its other mutable session state (the CSRF token,
the resolved tenant/org ids). A caller running two tenants concurrently constructs two
`axiam_client_t` (`axiam_client_config_clone()` is cheap) rather than sharing one — the
granularity every other piece of mutable per-request state in this SDK already uses.
`axiam_client_config_clone()` copies only construction-time configuration (base URL,
tenant/org, TLS material); it carries no session, so **each cloned client still needs
its own `axiam_login()`** (or other session-establishing call) — there is no single
login the two share.

The §17 decision memo key (when the memo is enabled) includes the acting tenant: since
one session can now ask the same authorization question of two tenants, a memoized
decision for tenant A must not answer for tenant B within the TTL.

It is **derived, never asserted** (§5.2 rule 2): resolved server-side from the caller's own
tenant record, and never sent by this SDK. It is `0` when the login response omits it —
what a server older than contract 1.31 answers — and `0` on the two pending outcomes,
where no principal has been established yet. Both are the safe direction. The member is
appended **last** to the struct, so every existing initializer still compiles and `{0}`
still means "no claim".

#### Signing one in (§5.2.1)

The reserved tenant has a fixed slug, `organization`, the same in every deployment — so
signing in as an organization-level principal needs no new surface, only the ordinary
config:

```c
axiam_client_config_t *cfg = axiam_client_config_new();
axiam_client_config_set_base_url(cfg, "https://iam.example.com");
axiam_client_config_set_tenant_slug(cfg, "organization");
axiam_client_config_set_org_slug(cfg, "globex");
```

Prefer that form. The server also reads a login body naming *no* tenant as "the
organization's own scope", but §5 rule 2 still requires a tenant on the `X-Tenant-ID`
header of every request after the login, so the client needs one either way.

What §5.2.1 forbids is the third possibility: an empty-string slug. Nothing can carry one,
so `tenant_slug: ""` resolves nothing — and on `/auth/opaque/login/start` it fails on the
workspace *before* the tenant's OPAQUE mode is read, so the `404` that means "OPAQUE is not
offered here" never arrives and this SDK has no fallback to take. Sign-in then fails even
against a tenant with OPAQUE disabled.

`axiam_client_config_validate` rejects a blank `tenant_slug` or `org_slug`, whitespace
included. A **NULL** pointer stays fine — that is what "not named" looks like, and it is
the difference between an unset optional and a blank one.

Worked example: [`examples/account_lifecycle.c`](examples/account_lifecycle.c).

## §26 Pushed Authorization Requests (RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`,
`redirect_uri`, `state` and the PKCE challenge into a URL the user agent
carries, the client POSTs them straight to AXIAM over an authenticated back
channel and puts an opaque handle in the redirect. What travels through the
browser is then a random string that cannot be edited into meaning something
else. **Required for a FAPI 2.0 client**: `profile: "fapi2"` refuses a
registration that does not set `require_par` (§21.1).

```c
axiam_oidc_config_t doc;
axiam_oidc_discover(client, &doc, &err);
if (!doc.pushed_authorization_request_endpoint) { /* this server has no PAR */ }

axiam_authorization_request_t req;
axiam_oidc_begin(client, &doc, redirect_uri, "openid profile", &req, &err);

axiam_pushed_authorization_request_t pushed;
axiam_oidc_par(client, &doc, &req, redirect_uri, "openid profile", NULL, &pushed, &err);
/* pushed.url carries exactly client_id and request_uri — nothing else. */
```

**The server answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and a
success predicate written `== 200` treats every successful push as a failure
while passing every other check.

**The redirect carries exactly the two parameters, plus the tenant when the
server published one (§26.2 rule 2; corrected in contract 1.42).** AXIAM
refuses a request that mixes a `request_uri` with inline *authorization*
parameters rather than merging them, because merging is where parameter
confusion lives: an attacker supplies the inline value they want and lets the
pushed copy satisfy whichever check reads the other one. Re-adding `scope`
"for compatibility" restores the attack — which is why any query the
*discovered* authorization endpoint carried is dropped rather than merged.

`tenant_id` is the one exception, and dropping it was a bug. It is not a member
of `PushedAuthorizationRequest`, it is never pushed, so no pushed copy exists
for an inline value to disagree with — it is routing, selecting whose
`/oauth2/authorize` is being addressed. AXIAM publishes it inside
`authorization_endpoint` whenever the discovery request named a tenant or the
deployment sets `oauth2_default_tenant_id`, and a browser that arrives without
it has no session to match: the server answers `401` rather than rendering the
login page. The redirect therefore carries `tenant_id` when — and only when —
the discovered endpoint carried one, holding the tenant the push was actually
made against, since a `request_uri` is only valid for the tenant that minted it.

**RFC 9449 §10.1 `dpop_jkt` (contract 1.42).** `axiam_oidc_par_ex()` takes one
extra argument, the base64url RFC 7638 thumbprint of the DPoP public key the
eventual token request will be signed with; pushing it binds the authorization
code to that key. It goes on the form only when set (`NULL` and `""` are both
"absent"). `axiam_oidc_par()` is that call with `NULL`, so nothing existing
changes. **The caller computes the thumbprint** — CONTRACT.md §21.9 records
this SDK as declining §21.7.2, so it generates no DPoP proofs and verifies
none, and this parameter does not change that.

`request_uri` is **not** on this SDK's PAR surface even though contract 1.42
adds it to `PushedAuthorizationRequest`. RFC 9126 §2.1 makes it the one
authorization parameter a client MUST NOT push; the server models it in order
to refuse it, and a client able to send it is a client able to build the
chained-request attack.

**One generator, not two (§26.2 rule 1).** The push sends the `state`, `nonce`
and PKCE pair `axiam_oidc_begin()` produced, and hands them back out on the
result so the caller has one object to persist. Two sources for those values are
two things that can disagree, and when they do the failure surfaces at the
exchange as an opaque `invalid_grant` a long way from the code that caused it.

**Never retried (§26.2 rule 4).** It is a POST that creates server state, so it
falls outside §16.2's read-only eligibility exactly as `oidc_exchange` does. The
safe recovery is a fresh push: one round trip, and it cannot double-consume
anything. The `request_uri` is single-use, short-lived (`expires_in` is not
advisory) and `Sensitive` — between the push and the redirect it is a bearer
handle to a fully-formed authorization request.

**Never synthesised.** A server that does not advertise
`pushed_authorization_request_endpoint` does not have it;
`axiam_oidc_par()` refuses client-side with no wire call rather than guessing
`/oauth2/par` and producing a 404 that reads like a broken request.

Worked example: [`examples/par_login.c`](examples/par_login.c).

## §22 Reactors — the protocol core over your own transport

A **reactor** is an external service AXIAM consults synchronously at five points
in its own flows: it may veto a login, enrich a token, or adjust a user before
creation. This SDK ships §22.1–§22.8 and §22.14 in full — the §8 v2 verification
set on the event, the canonical serialization and MAC in both directions, the
§22.5 registry and its allow-lists, §22.8's strictest-wins default, the runtime,
and the declarative binding table.

**What it does not ship is a connection.** §22.11 defers the transport, and only
the transport:

> the convenience that genuinely needed a vendored dependency was the
> **connection**, and the runtime around it needed none.

Until contract 1.28 this SDK shipped nothing from §22 at all while the section
still bound an integrator to §22.1–§22.8. The half deferred for want of a
*dependency* was the transport; the half every integrator was left to hand-roll
from prose was the **protocol** — v2 HMAC over a canonical serialization with a
`null` signature placeholder, freshness in both directions, nonce and correlation
binding, the per-event allow-lists. That is the half with the sharp edges, none
of them AMQP-shaped, and asking every integrator to reimplement it is how a
signing bug ships.

```c
/* §8b rules 1–5, BEFORE anything opens a socket. A public, tested function
 * rather than a doc comment — §22.11 rule 3. */
axiam_amqps_endpoint_t endpoint;
axiam_amqps_endpoint(broker_url, ca_pem, NULL, NULL, &endpoint, &err);

/* §22.14: one handler per event. An unregistered name is refused AT BIND TIME. */
axiam_reactor_router_t *router = axiam_reactor_router_new();
axiam_reactor_router_on(router, AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH, on_login, NULL, &err);

axiam_reactor_config_t config = {0};
config.tenant_id = tenant_id;
config.reactor_id = reactor_id;
config.signing_key = subkey;   /* the §8.1 derived AMQP subkey, RAW BYTES */
axiam_reactor_serve(&config, &your_transport, axiam_reactor_router_handler(), router, &err);
```

**The transport seam has exactly two capabilities** (§22.11 rule 1): take the
next delivery, and publish a reply to a named destination. It is not wider than
that on purpose — a struct that also exposed declare, bind or queue-name
derivation would hand you the tools §22.1 forbids using. A reactor that can bind
is a reactor that can bind itself to `*.token.pre_issue` and read another
tenant's issuance events.

**It fails closed on its own errors** (§22.10 rule 2). A body it cannot verify, a
window that has closed, or a reply it cannot build all produce **no reply**, and
the registration's `failure_policy` decides. A runtime that answered `allow` on
behalf of a handler that did not would have overridden the operator's
`fail_closed` setting from inside the library — which is exactly the defect
§22.14 exists to keep out of *user* code too, where a `default:` arm returning
allow does the same thing from a file nobody reads. An unbound event abstains,
and `AXIAM_REACTOR_ABSTAIN` is the **zero value** so a handler that returned
without filling a decision in abstains rather than allowing.

**It does not filter a patch** (§22.4 rule 1). One forbidden key rejects the
whole patch server-side, including the fields that would have been fine — and
dropping the offender to rescue the rest would leave the author believing a field
was set when it was dropped. `axiam_reactor_patch_field_allowed()` will *tell*
you what the registry admits; nothing in this SDK calls it to prune anything.

**The three hot-path decision operations are not hookable** (§22.7), and they
appear in no constant here. A reactor round trip is milliseconds; the check path's
budget is microseconds. An application needing external input on an authorization
decision writes a **deny grant**, which the engine evaluates in the hot path at
hot-path cost.

Correctness is not asserted against this implementation's own opinion: the suite
runs the committed **§22.13 reference vectors** in both directions, generated by
the server's own sign path and vendored at
[`tests/reactor_v2_reference_vectors.json`](tests/reactor_v2_reference_vectors.json).
Worked example, including a transport skeleton:
[`examples/reactor.c`](examples/reactor.c).

## §27 Management API

158 administrative operations across 24 namespaces, as **flat symbols** —
`axiam_<namespace>_<operation>()`, the exact shape CONTRACT.md **§27.3's** per-language
table gives C (its row reads `axiam_service_accounts_rotate_secret(client, id, &out)`).
C is the only SDK that takes it; every other language in that table, C++ included, gets a
namespace handle. It is not a
shortcut: §27.2's namespace-handle shape needs a value carrying both a receiver and a
method table, and C has no such thing that would not amount to hand-rolling a vtable for
24 structs to spell one dot differently. So the namespace lives in the name, and a
completion list sorted alphabetically groups exactly the way handles would.

The models and operations are generated by `scripts/gen_management.py` from the vendored
`management-registry.json` and `openapi.json`; the output is committed, so building this
library needs no Python. CI re-runs the generator with `--check` on every pull request.

```c
/* §27.4 rule 4: `total` is the SERVER's count across all pages -- NOT `count`. */
axiam_mgmt_page_req_t page = { 0, 50 };
axiam_mgmt_user_response_page_t *users = NULL;
if (axiam_users_list(c, &page, &users, &err) == AXIAM_OK) {
    printf("%zu of %ld\n", users->count, users->total);
    axiam_mgmt_user_response_page_free(users);   /* frees the items too */
}

/* §27.4 rule 5: set only what you mean to change. memset first -- an unset member is
 * OMITTED from the request, and an optional SCALAR says so with its has_ flag, because
 * 0 and -1 are both values the server can legitimately send. */
axiam_mgmt_update_user_request_t update;
memset(&update, 0, sizeof update);
update.status = AXIAM_MGMT_USER_STATUS_LOCKED;
update.has_status = 1;

/* §27.4 rule 3: {org_id}/{tenant_id} come from the client; a per-call scope overrides
 * them. Because the override is an ARGUMENT rather than state on a handle, one call's
 * scope cannot leak into the next. */
axiam_mgmt_call_scope_t scope = { other_org_id, NULL };
axiam_ca_certificates_list(c, &scope, NULL, &cas, &err);
```

**Searching a list (§27.4 rule 4).** All twenty paginated operations take an optional
free-text term, matched case-insensitively by the **server** against the identifying
fields of whatever is being listed — a name or username, plus the record id, so a UUID
pasted out of a log line finds its row. `total` then counts *matches*, not rows.

```c
const char *term = "ada";                       /* BORROWED — see below */
axiam_mgmt_page_req_t page = { 0, 50, term };
axiam_mgmt_user_response_page_t *matches = NULL;
axiam_users_list(c, &page, &matches, &err);

/* The whole filtered set: axiam_mgmt_page_next() carries the term, so every request of
 * the walk asks the same question. */
for (;;) {
    axiam_mgmt_user_response_page_t *p = NULL;
    if (axiam_users_list(c, &page, &p, &err) != AXIAM_OK || !p) break;
    if (p->count == 0) { axiam_mgmt_user_response_page_free(p); break; }
    /* ... */
    axiam_mgmt_user_response_page_free(p);
    page = axiam_mgmt_page_next(page);
}
```

The term lives on `axiam_mgmt_page_req_t`, beside `offset` and `limit`, rather than as an
extra argument on twenty operations. That is what makes the walk above work at all: an
argument has nowhere to live between one request and the next, so a walk built on one
would return the matches followed by the unfiltered tail.

`search` is **borrowed, never owned** — nothing copies it and nothing frees it, so it must
outlive every request derived from it. In the loop above that means declaring the term
outside the loop, not inside it.

`NULL` sends no `search` parameter, and an empty or all-whitespace term is the **same
request** — a search box that fires on every keystroke sends one the moment it is cleared,
and "rows containing the empty string" is a different question from "all rows".
`axiam_mgmt_page_search()` is that normalisation, exposed because it is the one piece a
caller can observe going wrong. The term is never **truncated**: the server caps its
length, and a client-side cap the server would not have applied is a silently different
query.

**Enums are open (§27.11 rule 1).** Every generated enum carries a trailing `_UNKNOWN`
constant, and `_from_wire()` returns `0` and yields it for a value this SDK's copy of the
spec does not list. Reporting a failure there would make the caller drop the whole record
— or the whole page — over one field it did not ask about.

It is never read as one of the **known** constants: reading a new value as whichever
constant happens to be first turns a new server state into a wrong one, and on this
surface these values gate access. `_UNKNOWN` is appended **last**, so it is not the zero
value a `calloc`'d struct starts at either, and `_to_wire()` spells it as the empty string
— which no server value is, so carrying an unrecognised value back into an update is
refused by the server rather than written as a spelling it never used. `_from_wire()`
still returns `-1` for a NULL argument, which is a caller error rather than a server one.

`axiam_mgmt_certificate_t::bound_service_account_id` is a **projection**, not a member of
the certificate: the server resolves it for a whole page in one query, so
`axiam_certificates_list()` populates it and `axiam_certificates_get()` leaves it `NULL`.
`NULL` there means "this read does not carry it", not "there is nothing bound" — the SDK
does not issue a second request to fill it in, because a `get` that silently costs two
round trips is the behaviour §27.4 rule 3 forbids for slug resolution, for the same reason
(§27.11 rule 4).

**Errors (§27.4 rule 7).** The §2 taxonomy here is an enum, and C has no subtyping — so
the sub-type is a classification *beside* the error rather than a hierarchy inside it,
the same accommodation `axiam_error_t::oauth_error` already makes for §12's
`OAuthProtocolError`. `kind` keeps the parent rule 7 names:

| status | `kind` | `axiam_mgmt_error_class()` | why |
|---|---|---|---|
| `404` | `AXIAM_ERR_AUTHZ` | `AXIAM_MGMT_ERR_NOT_FOUND` | A multi-tenant server answers `404` for another tenant's object *precisely so* a probing caller cannot enumerate it. Re-drawing that line client-side would undo the protection. |
| `409` | `AXIAM_ERR_AUTHZ` | `AXIAM_MGMT_ERR_CONFLICT` | §2 already maps `409` there; rule 7 keeps it. |
| `400`, `422` | `AXIAM_ERR_NETWORK` | `AXIAM_MGMT_ERR_VALIDATION` | Inherited from §2's `400` row. |

`axiam_error_kind_from_http_status()` is deliberately **unchanged** — mapping a bare
`404` to `AXIAM_ERR_NETWORK` is right for every non-management call in this SDK.

**Memory.** Every model has a `_free()` that walks it *and* frees the struct itself, so
it pairs with whatever allocated it and there is never a question of which half you own.
Free-form JSON members (`metadata`) are raw JSON **text**, not a parsed tree: every other
public header here keeps the bundled cJSON internal, and exposing it would put a
third-party type in the installed ABI.

**Secrets (§27.5).** A one-time secret is an `axiam_sensitive_t`: it stringifies as
`[SENSITIVE]`, and `axiam_sensitive_reveal()` is the single explicit way to obtain it.
The one place the SDK reveals one is on the way to the wire.

### Declarative manifests (§27.6, §27.7)

```c
axiam_mgmt_manifest_entity_t entities[] = { /* ... */ };
axiam_mgmt_manifest_t manifest = { entities, 5 };

axiam_mgmt_plan_t *plan = NULL;
axiam_mgmt_plan(c, &manifest, &plan, &err);   /* writes NOTHING */
if (plan->pending) {
    axiam_mgmt_apply_report_t report;
    axiam_mgmt_apply(c, &manifest, &report, &err);
}
axiam_mgmt_plan_free(plan);
```

- **`plan()` writes nothing.** Safe against production, safe in CI, safe on a schedule.
- **`apply()` stops at the first failure and does NOT roll back** (§27.7). The report
  names what landed, which change failed and what was never attempted — a partial apply
  is a state you resume from, and an automatic rollback would fire a second wave of
  writes exactly when the server is saying something is wrong.
- **Ordering is derived**, by kind then dependency then key. The tie-break on key is what
  makes a plan stable across runs.
- **Omission is never deletion.** There is no delete action in the enum at all, so an
  incomplete manifest cannot become a destructive one.

An incoherent manifest — a dangling reference, a cycle, a duplicate key, one role bound
twice to one subject, or `inherit: false` with no resource or on a role the manifest
itself declares `is_global: true` — is refused *before* the first request.

#### What this manifest covers, and what it declines (§27.10, flat-entity tier)

| Kind | Covered | Notes |
|---|---|---|
| `resources` | yes, nested (`depends_on` names the parent, sent as `parent_id`) | `metadata` (contract 1.51, §27.6.1 item 1): JSON value equality of the whole object, never a key-by-key merge |
| `permissions` | yes | |
| `roles` | yes | |
| `groups` | yes | `roles[]` bindings (contract 1.51, §27.6.1 item 2): both shapes — a bare role key, or `{role_key, resource_key, inherit_false}` |
| `service_accounts` | yes (contract 1.51, §27.6.1 item 3) | reconciled by `name`; takes the same `roles[]` bindings as `groups` (contract 1.51, §27.6.1 item 2); an ambiguous name fails `plan` before any write; `Create`'s one-time `client_secret` is on the apply report, never rotated |
| role → permission grants | **no** | a tier gap this port did not close (§27.10's table; not one of the three defects C-10 was assigned) — a role's permissions are managed imperatively (`axiam_roles_grant_permission` / `_revoke_permission`) |
| `users`, `scopes` | **no** | the flat-entity tier (§7.2 of the dogfooding remediation plan): deferred until a consumer needs them, same as PHP and Swift |
| `webhooks` | **no** | §27.6 leaves it "listed and unspecified" for every SDK — a webhook's `secret` is caller-supplied, not minted, so nothing forbids adding it, but no consumer has asked |

**A failed rebind (`AXIAM_MGMT_BINDING_UPDATE`) leaves the subject in one of two
states, reported as data, not only a message.** The wire form of a changed
binding is unassign-then-assign; when the assign half fails after the unassign
already landed, `apply()` attempts to restore the previous binding and reports
the outcome on `axiam_mgmt_apply_report_t`: `restore_attempted` is `1` once that
restore was tried, and, of those, `restore_succeeded` is `1` again if it worked.
Both are `0` when no rebind failed this way. Either the restore succeeded (the
subject holds the previous binding) or both calls failed (the subject holds
neither) — the report tells you which, rather than leaving you to re-`plan()`
to find out.

See `examples/management_basics.c`, `examples/management_manifest.c` and
`examples/device_mtls_provisioning.c` — the last a full operator/device split that mints
a `Device` certificate from the tenant's signing CA, binds it to a service account,
writes the one-time private key at `0600`, then authenticates as the device over §6.1
mutual TLS with no password anywhere.

## §28 MCP Resource-Server Helpers (RFC 9728)

The resource-server half of the Model Context Protocol authorization
handshake: publishing the RFC 9728 protected-resource metadata document that
tells an MCP client which AXIAM deployment guards this resource, and emitting
the `WWW-Authenticate` challenge that starts the client's discovery. AXIAM is
the authorization server here and implements none of this — §28 is the *MCP
server's* side, and this SDK implements exactly that middle row.

**SHOULD-level and entirely opt-in.** Nothing in this section runs until you
call `axiam_client_config_set_resource_metadata_url()`. With it unset, every
guard behaves byte-for-byte as it did before this section existed — no
`WWW-Authenticate` header on any response, no status changed, no path
exempted. `tests/test_mcp_guard.c`'s off-by-default suite asserts the header's
**absence**, not the status, because a 401 that quietly grew a header is still
a 401.

**No network I/O.** `axiam_protected_resource_metadata_json()`, `_path()`,
`_url()` and `axiam_bearer_challenge()` are pure local computation, like
`axiam_oidc_begin()` and `axiam_uma_parse_challenge()` — §16 retry and §9
single-flight refresh do not apply to any of them.

### The three operations, and the ownership contract

```c
#include <axiam/mcp.h>

axiam_protected_resource_metadata_options_t opts = {0};
opts.resource = "https://mcp.example.com/mcp";
static const char *servers[] = { "https://axiam.example.com" };
opts.authorization_servers = servers;
opts.authorization_server_count = 1;
static const char *scopes[] = { "mcp:read", "mcp:tools" };
opts.scopes_supported = scopes;
opts.scopes_supported_count = 2;

axiam_error_t err;
char *document = axiam_protected_resource_metadata_json(&opts, &err);
char *path     = axiam_protected_resource_metadata_path(&opts, &err);
char *url      = axiam_protected_resource_metadata_url(&opts, &err);
/* document/path/url are each malloc'd on success, NULL on a §28.2 validation
 * refusal or OOM — free every non-NULL one with free(). */

axiam_client_config_set_expected_audience(cfg, opts.resource);   /* §28.5 rule 2 */
axiam_client_config_set_resource_metadata_url(cfg, url);         /* turns §28 on */

free(document);
free(path);
free(url);
```

**Ownership, explicitly.** All three functions follow the ownership contract
this SDK already uses for every other malloc'd-string return (see
`axiam_uma_challenge_header()`, `axiam_reactor_routing_key()`): on success,
you get back a malloc'd, NUL-terminated string, freed with plain `free()` —
this SDK has no separate `axiam_string_free()`. On a §28.2 validation refusal
or an allocation failure, the function returns `NULL` and, when `err` is
non-`NULL`, fills it with `AXIAM_ERR_NETWORK` and a message naming the field
and rule — the same kind this SDK already uses for every other client-side
configuration mistake caught with no wire call (`axiam_client_config_validate()`,
`oidc_client_unusable()`). §28 has no `ValidationError` type of its own to
port; this SDK had none to begin with, and `AXIAM_ERR_NETWORK` is the one it
already uses for exactly this situation. Nothing is partially built: a refused
call touches nothing else.

**Validation refuses; it never repairs.** A relative `resource`, one with a
query or a fragment, an `http://` scheme on anything but `127.0.0.1`/`[::1]`/
`localhost`, an empty `authorization_servers`, a duplicate scope, a
`bearer_methods_supported` other than exactly `["header"]` — every one of
these is a `NULL` return, not a silently corrected document.

**Why three functions, not two.** CONTRACT.md §28.7's C row names only
`axiam_protected_resource_metadata_json` and `_path`; §28.1 separately
requires an SDK to expose **both** `metadata_path` and `metadata_url`, so an
integrator feeds the guard's `resource_metadata_url` from the value this SDK
derived rather than hand-concatenating scheme + authority + path a second
time. This SDK ships `axiam_protected_resource_metadata_url()` for that MUST
— a divergence from §28.7's literal naming table, not from §28.1's own rule.

### The challenge

```c
axiam_bearer_challenge_options_t ch = {0};
ch.resource_metadata_url = url;                 /* always present */
ch.error = AXIAM_BEARER_ERROR_INSUFFICIENT_SCOPE;
ch.scope = "mcp:tools";
char *value = axiam_bearer_challenge(&ch, &err);
/* Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="..." */
free(value);
```

Returns the header **value**, never the whole `WWW-Authenticate:` line — you
set the header. Every parameter is quoted; none is ever escaped: RFC 6750 §3
already excludes `"` and `\` from every parameter's character set, so a value
that needs escaping is refused rather than escaped, truncated or stripped.

### Guarded requests: `axiam_require_auth_mcp` / `axiam_require_access_mcp`

Two additive entry points, over `axiam_require_auth()` and
`axiam_require_access()` exactly the way `axiam_require_access_uma()` is
additive over `axiam_require_access()` for §20.3 — the originals are
untouched, and these differ only in an extra `char **out_challenge`:

```c
char *challenge = NULL;
axiam_guard_status_t st = axiam_require_auth_mcp(client, headers, &challenge);
if (st == AXIAM_GUARD_UNAUTHENTICATED) {
    /* challenge is "Bearer resource_metadata=\"...\""            (no credential)
     *           or "Bearer error=\"invalid_token\", resource_metadata=\"...\""
     *              (a credential was presented and rejected — expired, wrong
     *              tenant, wrong audience, bad signature: all indistinguishable,
     *              deliberately — §28.4, §28.8)
     */
}
free(challenge); /* NULL on ALLOW/UNAVAILABLE, or when §28 is off */
```

`axiam_require_access_mcp()` additionally attaches `insufficient_scope` (with
the route's own `scope`, verbatim, never synthesised) on **exactly one** class
of `AXIAM_GUARD_DENIED`: a `scope` argument was given, and the decision's
`reason_code` was `AXIAM_REASON_CODE_NO_GRANT`. A `denied_by_rule` denial, an
absent/unrecognised `reason_code`, or a denial with no `scope` argument all
carry **no** challenge — an administrator already decided, and re-authorizing
cannot change that (§28.5 rule 5).

Both gates — `resource_metadata_url` configured, and a non-`NULL`
`out_challenge` — must be open before either function differs at all from its
un-suffixed counterpart; `tests/test_mcp_guard.c` proves the off state is
byte-for-byte identical.

### `axiam_mcp_check_resource_metadata` — the `serve_`-less cross-check

Other languages' `serve_protected_resource_metadata(app, metadata, guard?)`
takes an optional `guard` argument and, when given, refuses at startup unless
the guard's `resource_metadata_url`/`expected_audience` agree with the
document's own `metadata_url`/`resource` (§28.5 rule 3). **C has no
`serve_` function** (§28.3, §28.7 — no router), so there is nothing to hang
that argument on. `axiam_mcp_check_resource_metadata(cfg, &opts, &err)` is the
same check as a standalone call — run it once at startup, after configuring
both:

```c
if (axiam_mcp_check_resource_metadata(cfg, &opts, &err) != AXIAM_OK) {
    fprintf(stderr, "%s\n", err.message);
    exit(1);
}
```

It returns `AXIAM_OK` immediately when the config's `resource_metadata_url` is
unset (§28 is off — nothing to check).

### CivetWeb adapter (documented, not implemented)

This SDK vendors no HTTP server, so there is no `axiam_mcp_serve_civetweb()`
in the library — the six §28.3 response rules bind whatever handler you write,
and this is that handler:

```c
#include <civetweb.h>
#include <axiam/axiam.h>

typedef struct { char *body; size_t len; char *metadata_path; } mcp_metadata_ctx_t;

/* §28.3 rule 2: served WITHOUT authentication — register this handler on
 * metadata_path and make sure your own auth callback exempts it explicitly
 * when it runs globally (mg_set_auth_handler / a per-request check ahead of
 * this one). A document that answers 401 cannot start the handshake it
 * exists to start. */
static int serve_metadata(struct mg_connection *conn, void *cbdata) {
    mcp_metadata_ctx_t *ctx = cbdata;
    /* §28.3 rule 1, 5, 6: 200, application/json, Cache-Control, CORS *,
     * no Access-Control-Allow-Credentials. Rule 4: identical for every
     * caller — nothing here reads the request. */
    mg_printf(conn,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Cache-Control: public, max-age=3600\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %zu\r\n\r\n", ctx->len);
    mg_write(conn, ctx->body, ctx->len);
    return 200;
}

/* A protected route's 401/403 path, using axiam_require_access_mcp(): */
static int serve_tool(struct mg_connection *conn, void *cbdata) {
    axiam_client_t *client = cbdata;
    axiam_headers_t *headers = /* populate from mg_get_header(...) */ NULL;

    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_access_mcp(
        client, headers, "mcp:invoke", "tool-1", "mcp:tools", &challenge);

    if (st != AXIAM_GUARD_ALLOW) {
        if (challenge) {
            mg_printf(conn, "HTTP/1.1 %d %s\r\nWWW-Authenticate: %s\r\n"
                            "Content-Type: application/json\r\n\r\n"
                            "{\"error\":\"%s\"}",
                      (int)st, st == AXIAM_GUARD_UNAUTHENTICATED ? "Unauthorized" : "Forbidden",
                      challenge,
                      st == AXIAM_GUARD_UNAUTHENTICATED ? "authentication_failed"
                                                        : "authorization_denied");
            free(challenge);
        } else {
            mg_send_http_error(conn, (int)st, "%s",
                st == AXIAM_GUARD_UNAUTHENTICATED ? "authentication_failed"
                                                  : "authorization_denied");
        }
        return (int)st;
    }
    axiam_kv_free(headers);
    /* ... serve the tool ... */
    return 200;
}

/* Wiring, once at startup: */
axiam_protected_resource_metadata_options_t opts = { /* ... */ };
char *document = axiam_protected_resource_metadata_json(&opts, &err);
char *path     = axiam_protected_resource_metadata_path(&opts, &err);
char *url      = axiam_protected_resource_metadata_url(&opts, &err);
axiam_client_config_set_expected_audience(cfg, opts.resource);
axiam_client_config_set_resource_metadata_url(cfg, url);
/* axiam_mcp_check_resource_metadata(cfg, &opts, &err) here, per above */

mcp_metadata_ctx_t ctx = { document, strlen(document), path };
mg_set_request_handler(mg_ctx, path, serve_metadata, &ctx);
mg_set_request_handler(mg_ctx, "/tool", serve_tool, client);
```

### What this port found in §28

Two things worth recording for the cross-SDK review (T21.9's plan explicitly
asks a REST-only port to look for exactly this):

1. **§28.7's C row is incomplete against §28.1's own MUST.** It names
   `axiam_protected_resource_metadata_json`/`_path` but not a `metadata_url`
   accessor, while §28.1 requires an SDK to expose both `metadata_path` *and*
   `metadata_url`. This port adds `axiam_protected_resource_metadata_url()` to
   satisfy the MUST rather than leave the integrator to hand-concatenate the
   resource's scheme and authority onto the path a second time — exactly the
   duplication §28.1 says is "the surface on which the two disagree."
2. **§28.2's "validation refuses at construction" and §28.4's "raises the
   SDK's `ValidationError`" both assume a value type and an exception
   mechanism.** C has neither. The document has nowhere to "be constructed"
   except a local struct the caller supplies per call, and a refusal is a
   `NULL` return plus an out-parameter, not a thrown type. Neither is a defect
   in §28 so much as a reminder that "returns … or raises …" is a two-outcome
   contract that a language without exceptions has to spell as two return
   channels — which is exactly what §28.7's own C row already anticipates by
   saying the operations "return the SDK's validation error rather than a
   string when it fails."

## Scope / follow-ups

Out of scope for v1.0, tracked as follow-ups:

- **gRPC transport** (Tonic-equivalent low-latency authz). The `check_access`
  surface is transport-agnostic and can gain a gRPC dispatcher later.
- **§8 AMQP HMAC consumer.** The contract's §8 AMQP obligations do not list C
  among the required consumer languages; no AMQP surface is shipped.
- **A bundled AMQP client**, and only that. §22.11 keeps the transport deferred:
  there is no maintained AMQP client for these targets this project is willing to
  vendor, which is the same reason §8 has never listed C among the SDKs that
  speak AMQP. The **protocol** is no longer deferred with it — see
  [§22 Reactors](#22-reactors--the-protocol-core-over-your-own-transport) — so
  what remains is filling in `axiam_reactor_transport_t`'s two function pointers
  over the client you choose. Revisit when a vendorable client exists; the wire
  protocol will not need to change for it, and now neither will the runtime.
- **The optional `OidcStateStore`** (§12.3 rule 1). The core §12 operations are
  usable without one and the store is a MAY; a C reference implementation with
  the mandated 10-minute TTL, single-use `consume`, and lazy (never
  timer-driven) expiry is a follow-up.

## License

See [LICENSE](LICENSE). Vendored third-party code: cJSON (MIT,
`third_party/cjson/LICENSE`), Unity test framework (MIT,
`third_party/unity/LICENSE.txt`).
