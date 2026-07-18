#include "jwt_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

char *jwt_b64url_encode(const unsigned char *data, size_t len) {
    size_t out_cap = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_cap);
    if (!out) return NULL;
    size_t o = 0, i = 0;
    while (i + 3 <= len) {
        unsigned v = (unsigned)data[i] << 16 | (unsigned)data[i + 1] << 8 | data[i + 2];
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
        out[o++] = B64URL[(v >> 6) & 0x3f];
        out[o++] = B64URL[v & 0x3f];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        unsigned v = (unsigned)data[i] << 16;
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
    } else if (rem == 2) {
        unsigned v = (unsigned)data[i] << 16 | (unsigned)data[i + 1] << 8;
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
        out[o++] = B64URL[(v >> 6) & 0x3f];
    }
    out[o] = '\0';
    return out;
}

static char *concat3(const char *a, const char *b, const char *c) {
    size_t n = strlen(a) + strlen(b) + strlen(c) + 1;
    char *s = malloc(n);
    if (s) snprintf(s, n, "%s%s%s", a, b, c);
    return s;
}

int jwt_make(const char *kid, const char *payload_json,
             char **out_token, char **out_jwks) {
    int rc = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    char *hdr_b64 = NULL, *pl_b64 = NULL, *sig_b64 = NULL, *x_b64 = NULL;
    char *signing_input = NULL, *token = NULL, *jwks = NULL;
    unsigned char *sig = NULL;

    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0)
        goto done;

    unsigned char pub[32];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &publen) <= 0 || publen != 32)
        goto done;
    x_b64 = jwt_b64url_encode(pub, 32);

    char header[128];
    snprintf(header, sizeof(header), "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"%s\"}", kid);
    hdr_b64 = jwt_b64url_encode((const unsigned char *)header, strlen(header));
    pl_b64 = jwt_b64url_encode((const unsigned char *)payload_json, strlen(payload_json));
    if (!hdr_b64 || !pl_b64 || !x_b64) goto done;

    signing_input = concat3(hdr_b64, ".", pl_b64);
    if (!signing_input) goto done;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t siglen = 0;
    if (!md ||
        EVP_DigestSignInit(md, NULL, NULL, NULL, pkey) <= 0 ||
        EVP_DigestSign(md, NULL, &siglen, (const unsigned char *)signing_input,
                       strlen(signing_input)) <= 0) {
        if (md) EVP_MD_CTX_free(md);
        goto done;
    }
    sig = malloc(siglen);
    if (!sig || EVP_DigestSign(md, sig, &siglen,
                               (const unsigned char *)signing_input,
                               strlen(signing_input)) <= 0) {
        EVP_MD_CTX_free(md);
        goto done;
    }
    EVP_MD_CTX_free(md);
    sig_b64 = jwt_b64url_encode(sig, siglen);
    if (!sig_b64) goto done;

    token = concat3(signing_input, ".", sig_b64);
    if (!token) goto done;

    {
        size_t jn = strlen(x_b64) + strlen(kid) + 256;
        jwks = malloc(jn);
        if (!jwks) goto done;
        snprintf(jwks, jn,
                 "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\","
                 "\"use\":\"sig\",\"kid\":\"%s\",\"x\":\"%s\"}]}",
                 kid, x_b64);
    }

    *out_token = token;
    *out_jwks = jwks;
    token = NULL;
    jwks = NULL;
    rc = 0;

done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    free(hdr_b64);
    free(pl_b64);
    free(sig_b64);
    free(x_b64);
    free(signing_input);
    free(sig);
    free(token);
    free(jwks);
    return rc;
}
