/* Runtime JWT/JWKS fixture — generates an Ed25519 key, a signed EdDSA JWT and a
 * matching JWKS document in-process. No key material is ever written to disk. */
#ifndef AXIAM_JWT_FIXTURE_H
#define AXIAM_JWT_FIXTURE_H

#include <stddef.h>

/* base64url-encode without padding. Caller frees. */
char *jwt_b64url_encode(const unsigned char *data, size_t len);

/* Generate an Ed25519 key, sign header+payload as an EdDSA JWT, and emit a
 * JWKS document containing the public key under `kid`. Returns 0 on success.
 * *out_token and *out_jwks are heap strings (caller frees). */
int jwt_make(const char *kid, const char *payload_json,
             char **out_token, char **out_jwks);

#endif /* AXIAM_JWT_FIXTURE_H */
