/*
 * AXIAM C SDK — JWKS fetch + Ed25519 (EdDSA) JWT verification.
 *
 * GET {base}/oauth2/jwks. Only EdDSA/Ed25519 keys are accepted; any other
 * `alg` is rejected before key lookup. Signatures are verified with OpenSSL
 * EVP_DigestVerify over a raw Ed25519 public key. The key set is cached for
 * 300 seconds.
 *
 * Verification is STRICT by default (SEC-071, CONTRACT §10.1): on top of the
 * signature, axiam_jwt_verify() enforces the `exp`/`nbf` lifetime, binds the
 * token's `tenant_id` claim to the client's configured tenant, and checks
 * `iss`/`aud` whenever the client was configured with an expected value. The
 * JWKS endpoint is organization-wide, so a valid signature alone does NOT
 * imply the token was minted for this client's tenant.
 *
 * axiam_jwt_verify_ex() exposes the policy flags for callers deliberately
 * implementing their own policy; AXIAM_JWT_VERIFY_SIGNATURE_ONLY names the
 * omission at the call site and MUST NOT be used to admit a request.
 */
#ifndef AXIAM_JWKS_H
#define AXIAM_JWKS_H

#include "axiam/client.h"
#include "axiam/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** JWKS cache TTL in seconds (CONTRACT). */
#define AXIAM_JWKS_CACHE_TTL_SECS 300

/**
 * Clock-skew allowance, in seconds, applied to the `exp` and `nbf` checks.
 * A token is accepted up to this long after `exp` (and this long before
 * `nbf`) to tolerate small clock differences between the SDK host and the
 * AXIAM server.
 */
#define AXIAM_JWT_CLOCK_SKEW_SECS 60

/* --- Verification policy flags for axiam_jwt_verify_ex(). --- */

/** Signature + `alg` pin only. UNSAFE for route guards: accepts expired and
 *  cross-tenant tokens. Use only when a caller enforces those itself. */
#define AXIAM_JWT_VERIFY_SIGNATURE_ONLY 0u
/** Enforce `exp` (required) and `nbf` (when present), with clock skew. */
#define AXIAM_JWT_VERIFY_EXPIRY (1u << 0)
/** Require the `tenant_id` claim to equal the client's configured tenant. */
#define AXIAM_JWT_VERIFY_TENANT (1u << 1)
/**
 * Check `iss` / `aud` against the expectations configured on the client
 * (axiam_client_config_set_expected_issuer / _audience). Each check is
 * CONDITIONAL: an unset expectation means that claim is not checked. A set
 * expectation makes the claim required — absent, wrong-typed or mismatched
 * fails closed.
 */
#define AXIAM_JWT_VERIFY_ISSUER_AUDIENCE (1u << 2)
/** The default policy: signature + lifetime + tenant binding + configured
 *  issuer/audience (§10.1). */
#define AXIAM_JWT_VERIFY_STRICT                                              \
    (AXIAM_JWT_VERIFY_EXPIRY | AXIAM_JWT_VERIFY_TENANT |                     \
     AXIAM_JWT_VERIFY_ISSUER_AUDIENCE)

/**
 * Verify a compact JWS (header.payload.signature) using the client's cached
 * JWKS (fetched/refreshed as needed), under the AXIAM_JWT_VERIFY_STRICT
 * policy. On success returns AXIAM_OK and, if out_claims_json is non-NULL,
 * sets *out_claims_json to a heap JSON string of the payload (caller frees
 * with free()).
 *
 * Strict means, in addition to the EdDSA signature: `exp` must be present,
 * numeric and not in the past (± AXIAM_JWT_CLOCK_SKEW_SECS); `nbf`, when
 * present, must not be in the future; `tenant_id` must be present and equal to
 * the client's configured tenant; and `iss` / `aud` must match whenever the
 * client was configured with an expected issuer / audience. Tenant binding
 * requires the client to know its tenant UUID — configure `tenant_id` (or
 * complete a login, which resolves it from the session claims); a slug-only
 * client cannot bind and fails closed.
 *
 * Failure modes: AXIAM_ERR_AUTH (malformed token, non-EdDSA alg, unknown kid,
 * bad signature, expired/not-yet-valid token, missing or foreign tenant,
 * issuer/audience mismatch when configured), AXIAM_ERR_NETWORK (JWKS could not
 * be fetched).
 */
axiam_error_kind_t axiam_jwt_verify(axiam_client_t *client,
                                    const char *token,
                                    char **out_claims_json,
                                    axiam_error_t *err);

/**
 * As axiam_jwt_verify(), with an explicit policy: a bitwise OR of the
 * AXIAM_JWT_VERIFY_* flags. AXIAM_JWT_VERIFY_STRICT is what the route guards
 * (§10/§11) always use; AXIAM_JWT_VERIFY_SIGNATURE_ONLY reduces the check to
 * the signature and `alg` pin and must not be used to admit a request.
 */
axiam_error_kind_t axiam_jwt_verify_ex(axiam_client_t *client,
                                       const char *token,
                                       unsigned flags,
                                       char **out_claims_json,
                                       axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_JWKS_H */
