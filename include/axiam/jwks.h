/*
 * AXIAM C SDK — JWKS fetch + Ed25519 (EdDSA) JWT verification.
 *
 * GET {base}/oauth2/jwks. Only EdDSA/Ed25519 keys are accepted; any other
 * `alg` is rejected before key lookup. Signatures are verified with OpenSSL
 * EVP_DigestVerify over a raw Ed25519 public key. The key set is cached for
 * 300 seconds. The verifier does NOT check token expiry (exp).
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
 * Verify a compact JWS (header.payload.signature) using the client's cached
 * JWKS (fetched/refreshed as needed). On success returns AXIAM_OK and, if
 * out_claims_json is non-NULL, sets *out_claims_json to a heap JSON string of
 * the payload (caller frees with free()). Signature (not exp) is checked.
 *
 * Failure modes: AXIAM_ERR_AUTH (malformed token, non-EdDSA alg, unknown kid,
 * bad signature), AXIAM_ERR_NETWORK (JWKS could not be fetched).
 */
axiam_error_kind_t axiam_jwt_verify(axiam_client_t *client,
                                    const char *token,
                                    char **out_claims_json,
                                    axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_JWKS_H */
