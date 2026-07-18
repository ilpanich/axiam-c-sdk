#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "cJSON.h"
#include "internal.h"

/* Parse a JwksDocument into the client's key cache (EdDSA/Ed25519 only). */
static int parse_jwks(axiam_client_t *c, const char *json) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return 0;
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(root, "keys");
    if (!cJSON_IsArray(keys)) { cJSON_Delete(root); return 0; }

    struct axiam_jwk *head = NULL, *tail = NULL;
    const cJSON *k = NULL;
    cJSON_ArrayForEach(k, keys) {
        const cJSON *kty = cJSON_GetObjectItemCaseSensitive(k, "kty");
        const cJSON *crv = cJSON_GetObjectItemCaseSensitive(k, "crv");
        const cJSON *alg = cJSON_GetObjectItemCaseSensitive(k, "alg");
        const cJSON *x = cJSON_GetObjectItemCaseSensitive(k, "x");
        const cJSON *kid = cJSON_GetObjectItemCaseSensitive(k, "kid");
        if (!cJSON_IsString(kty) || !cJSON_IsString(crv) || !cJSON_IsString(x))
            continue;
        /* Only Ed25519 / EdDSA keys are usable. */
        if (strcmp(kty->valuestring, "OKP") != 0) continue;
        if (strcmp(crv->valuestring, "Ed25519") != 0) continue;
        if (cJSON_IsString(alg) && alg->valuestring &&
            strcmp(alg->valuestring, "EdDSA") != 0)
            continue;
        size_t xlen = 0;
        unsigned char *xb = axiam_b64url_decode(x->valuestring,
                                                strlen(x->valuestring), &xlen);
        if (!xb) continue;
        if (xlen != 32) { free(xb); continue; }
        struct axiam_jwk *node = calloc(1, sizeof(*node));
        if (!node) { free(xb); continue; }
        memcpy(node->x, xb, 32);
        node->x_len = 32;
        node->kid = (cJSON_IsString(kid) && kid->valuestring)
                        ? axiam_strdup0(kid->valuestring) : NULL;
        free(xb);
        if (!tail) head = tail = node;
        else { tail->next = node; tail = node; }
    }
    cJSON_Delete(root);

    /* Swap into cache. */
    struct axiam_jwk *old = c->jwks;
    c->jwks = head;
    c->jwks_fetched_at = time(NULL);
    c->jwks_valid = 1;
    while (old) {
        struct axiam_jwk *n = old->next;
        free(old->kid);
        free(old);
        old = n;
    }
    return 1;
}

static axiam_error_kind_t ensure_jwks(axiam_client_t *c, axiam_error_t *err) {
    time_t now = time(NULL);
    pthread_mutex_lock(&c->jwks_mtx);
    int fresh = c->jwks_valid &&
                (now - c->jwks_fetched_at) < AXIAM_JWKS_CACHE_TTL_SECS;
    pthread_mutex_unlock(&c->jwks_mtx);
    if (fresh) return AXIAM_OK;

    char *body = NULL;
    axiam_error_kind_t kind = axiam_client_raw_get(c, "/oauth2/jwks", &body, err);
    if (kind != AXIAM_OK) return kind;

    pthread_mutex_lock(&c->jwks_mtx);
    int ok = parse_jwks(c, body ? body : "");
    pthread_mutex_unlock(&c->jwks_mtx);
    free(body);
    if (!ok) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid JWKS document");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* Find a cached key by kid; if kid is NULL and exactly one key exists, use it. */
static const struct axiam_jwk *find_key(axiam_client_t *c, const char *kid) {
    const struct axiam_jwk *only = NULL;
    int count = 0;
    for (const struct axiam_jwk *j = c->jwks; j; j = j->next) {
        count++;
        only = j;
        if (kid && j->kid && strcmp(j->kid, kid) == 0) return j;
    }
    if (!kid && count == 1) return only;
    return NULL;
}

axiam_error_kind_t axiam_jwt_verify(axiam_client_t *client, const char *token,
                                    char **out_claims_json, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_claims_json) *out_claims_json = NULL;
    if (!client || !token) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "missing token");
        return AXIAM_ERR_AUTH;
    }

    /* Split into header.payload.signature. */
    const char *dot1 = strchr(token, '.');
    if (!dot1) { axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token"); return AXIAM_ERR_AUTH; }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) { axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token"); return AXIAM_ERR_AUTH; }
    size_t hlen = (size_t)(dot1 - token);
    size_t plen = (size_t)(dot2 - (dot1 + 1));
    const char *sig_b64 = dot2 + 1;
    size_t slen = strlen(sig_b64);

    /* Decode + inspect header: reject non-EdDSA BEFORE key lookup. */
    size_t hdr_len = 0;
    unsigned char *hdr = axiam_b64url_decode(token, hlen, &hdr_len);
    if (!hdr) { axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token header"); return AXIAM_ERR_AUTH; }
    cJSON *hjson = cJSON_ParseWithLength((const char *)hdr, hdr_len);
    free(hdr);
    if (!hjson) { axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token header"); return AXIAM_ERR_AUTH; }
    const cJSON *alg = cJSON_GetObjectItemCaseSensitive(hjson, "alg");
    const cJSON *kid = cJSON_GetObjectItemCaseSensitive(hjson, "kid");
    char *kid_copy = NULL;
    int alg_ok = cJSON_IsString(alg) && alg->valuestring &&
                 strcmp(alg->valuestring, "EdDSA") == 0;
    if (cJSON_IsString(kid) && kid->valuestring) kid_copy = axiam_strdup0(kid->valuestring);
    cJSON_Delete(hjson);
    if (!alg_ok) {
        free(kid_copy);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "unsupported token alg (EdDSA only)");
        return AXIAM_ERR_AUTH;
    }

    axiam_error_kind_t kk = ensure_jwks(client, err);
    if (kk != AXIAM_OK) { free(kid_copy); return kk; }

    pthread_mutex_lock(&client->jwks_mtx);
    const struct axiam_jwk *key = find_key(client, kid_copy);
    unsigned char pub[32];
    int have_key = 0;
    if (key) { memcpy(pub, key->x, 32); have_key = 1; }
    pthread_mutex_unlock(&client->jwks_mtx);
    free(kid_copy);
    if (!have_key) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "no matching signing key");
        return AXIAM_ERR_AUTH;
    }

    /* Signing input = header_b64 "." payload_b64 (ASCII bytes of the token). */
    size_t signing_len = hlen + 1 + plen;

    size_t sig_len = 0;
    unsigned char *sig = axiam_b64url_decode(sig_b64, slen, &sig_len);
    if (!sig) { axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed signature"); return AXIAM_ERR_AUTH; }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pkey) { free(sig); axiam_error_set(err, AXIAM_ERR_AUTH, 0, "key load failed"); return AXIAM_ERR_AUTH; }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int verified = 0;
    if (mdctx &&
        EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, sig_len,
                         (const unsigned char *)token, signing_len) == 1) {
        verified = 1;
    }
    if (mdctx) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    free(sig);

    if (!verified) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "signature verification failed");
        return AXIAM_ERR_AUTH;
    }

    if (out_claims_json) {
        size_t pdec_len = 0;
        unsigned char *pdec = axiam_b64url_decode(dot1 + 1, plen, &pdec_len);
        if (pdec) {
            *out_claims_json = malloc(pdec_len + 1);
            if (*out_claims_json) {
                memcpy(*out_claims_json, pdec, pdec_len);
                (*out_claims_json)[pdec_len] = '\0';
            }
            free(pdec);
        }
    }
    return AXIAM_OK;
}
