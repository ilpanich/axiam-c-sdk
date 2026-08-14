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

#include <stddef.h>  /* size_t, for the §10.1 rule 9 thumbprint helper */

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

/**
 * CONTRACT.md §10.1 rule 9 — enforce a token's sender constraint against the
 * certificate the caller presented on THIS connection (RFC 8705 §3 / RFC 7800,
 * contract 1.15).
 *
 * A token carrying `cnf` is NOT a bearer token. Accepting one without proving
 * the caller holds the named key converts it straight back into one,
 * discarding the whole protection the operator turned on.
 *
 * `claims_json` is the payload axiam_jwt_verify() handed back.
 * `presented_thumbprint` is the RFC 8705 §3.1 `x5t#S256` of the peer
 * certificate on this connection, or NULL when there is none;
 * axiam_certificate_thumbprint_s256() computes it from DER bytes.
 *
 *   token's cnf              presented              result
 *   absent                   anything               AXIAM_OK (a bearer token)
 *   x5t#S256                 equal                  AXIAM_OK
 *   x5t#S256                 different, or NULL     AXIAM_ERR_AUTH
 *   present, no x5t#S256     anything               AXIAM_ERR_AUTH
 *
 * The first row is why adopting this rule breaks nothing: an UNBOUND token is
 * still accepted whether or not a certificate is present. Rule 9 constrains
 * tokens that claim a constraint; it does not make certificates mandatory.
 *
 * The last row is the one that is easy to get wrong. A `cnf` naming a
 * confirmation method this SDK cannot check is an UNVERIFIABLE constraint,
 * never NO constraint — read the other way, a sender-constrained token
 * silently degrades to a bearer token the day a newer AXIAM issues a
 * confirmation this SDK predates.
 *
 * The thumbprint must come from the transport — SSL_get_peer_certificate() and
 * i2d_X509(), or a value a TRUSTED terminating proxy forwarded over a channel
 * the application controls. Never from a caller-settable request header: a
 * forgeable input makes the whole mechanism decorative.
 *
 * axiam_jwt_verify() deliberately does NOT apply this rule: it has no
 * transport to ask. A resource server accepting bound tokens must call both.
 */
axiam_error_kind_t axiam_jwt_verify_certificate_binding(
    const char *claims_json,
    const char *presented_thumbprint,
    axiam_error_t *err);

/**
 * Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of a DER client
 * certificate: base64url-encoded SHA-256, WITHOUT padding.
 *
 * Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as
 * omitting `=`, and a padded value will not compare equal to what AXIAM put in
 * the token.
 *
 * Returns a heap string the caller frees with free(), or NULL on allocation or
 * digest failure.
 */
char *axiam_certificate_thumbprint_s256(const unsigned char *der,
                                        size_t der_len);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_JWKS_H */
