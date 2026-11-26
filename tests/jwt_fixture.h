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

/* As jwt_make(), but the JOSE header is the caller's: `kid_header` and `typ` are each omitted
 * from the header when NULL. The emitted JWKS always holds exactly ONE key, under kid "k1" --
 * so a token with no `kid` is the shape the single-key fallback (CONTRACT 10.1 rule 12)
 * used to admit. */
int jwt_make_hdr(const char *kid_header, const char *typ, const char *payload_json,
                 char **out_token, char **out_jwks);

/* A rotation: the JWKS holds TWO Ed25519 keys -- an unrelated one, kid "rotated-out", FIRST, and
 * the signing key under `signing_kid` second -- so a verifier that takes the first or only key
 * fails. The JOSE header carries exactly `alg` EdDSA plus `typ` and `kid` when they are non-NULL
 * (the server's logout token is `typ: logout+jwt` with a `kid`; nothing else is added). */
int jwt_make_rotation(const char *kid_header, const char *signing_kid, const char *typ,
                      const char *payload_json, char **out_token, char **out_jwks);

/* Mint an algorithm-confusion token: the header declares `alg` (e.g. "none" or
 * "HS256") while the emitted JWKS still publishes a genuine Ed25519 key under
 * `kid`. CONTRACT §10.1 rule 1 requires both shapes to be refused before any
 * key is consulted.
 *
 *   - "none"  -> the signature part is empty ("header.payload.").
 *   - "HS256" -> a real HMAC-SHA256 over the signing input, keyed with the
 *                Ed25519 PUBLIC key bytes (the classic HS/EdDSA confusion: the
 *                attacker's "secret" is the published verification key).
 *   - anything else -> the Ed25519 signature, so only the header's `alg` lies.
 *
 * Returns 0 on success; *out_token and *out_jwks are heap strings. */
int jwt_make_confused(const char *kid, const char *alg, const char *payload_json,
                      char **out_token, char **out_jwks);

#endif /* AXIAM_JWT_FIXTURE_H */
