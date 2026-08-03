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

/* The tenant identifier local verification binds a token to (SEC-071).
 * Preference order: the explicitly configured tenant UUID, then the UUID
 * resolved from the access-token claims at login (D-14). A slug is never a
 * valid comparand for the token's `tenant_id` claim, so a slug-only client
 * has no binding available and must fail closed. Returns a heap copy (caller
 * frees) or NULL when no UUID is known. */
static char *expected_tenant_id(axiam_client_t *c) {
    char *out = NULL;
    pthread_mutex_lock(&c->state_mtx);
    if (c->cfg->tenant_id && c->cfg->tenant_id[0])
        out = axiam_strdup0(c->cfg->tenant_id);
    else if (c->resolved_tenant_id && c->resolved_tenant_id[0])
        out = axiam_strdup0(c->resolved_tenant_id);
    pthread_mutex_unlock(&c->state_mtx);
    return out;
}

/* §10.1 rule 6: `aud` may be a bare string or an array of strings; the token is
 * acceptable when the expected audience appears among them. Any other JSON
 * shape (absent, number, object, array without a matching string) is a
 * mismatch and fails closed. */
static int audience_contains(const cJSON *aud, const char *expected) {
    if (cJSON_IsString(aud) && aud->valuestring)
        return strcmp(aud->valuestring, expected) == 0;
    if (cJSON_IsArray(aud)) {
        const cJSON *e = NULL;
        cJSON_ArrayForEach(e, aud) {
            if (cJSON_IsString(e) && e->valuestring &&
                strcmp(e->valuestring, expected) == 0)
                return 1;
        }
    }
    return 0;
}

/* Post-signature claim validation (SEC-071). A signature-valid token is NOT
 * yet an authenticated caller: the lifetime must still be inside its window
 * and the token must belong to this client's tenant (the JWKS trust anchor is
 * organization-wide). Every failure path here fails CLOSED. */
static axiam_error_kind_t check_claims(axiam_client_t *client, const char *claims_json,
                                       unsigned flags, axiam_error_t *err) {
    cJSON *root = claims_json ? cJSON_Parse(claims_json) : NULL;
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token claims");
        return AXIAM_ERR_AUTH;
    }
    axiam_error_kind_t kind = AXIAM_OK;

    if (flags & AXIAM_JWT_VERIFY_EXPIRY) {
        double now = (double)time(NULL);
        const cJSON *exp = cJSON_GetObjectItemCaseSensitive(root, "exp");
        if (!cJSON_IsNumber(exp)) {
            /* Missing or unparseable expiry: an unbounded token is refused. */
            axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token has no usable exp claim");
            kind = AXIAM_ERR_AUTH;
            goto done;
        }
        if (now > exp->valuedouble + (double)AXIAM_JWT_CLOCK_SKEW_SECS) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token has expired");
            kind = AXIAM_ERR_AUTH;
            goto done;
        }
        /* `nbf` is optional (AXIAM access tokens omit it) but honoured when
         * present — including when it is present but not a number. */
        const cJSON *nbf = cJSON_GetObjectItemCaseSensitive(root, "nbf");
        if (nbf) {
            if (!cJSON_IsNumber(nbf)) {
                axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token has a malformed nbf claim");
                kind = AXIAM_ERR_AUTH;
                goto done;
            }
            if (now + (double)AXIAM_JWT_CLOCK_SKEW_SECS < nbf->valuedouble) {
                axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token is not yet valid");
                kind = AXIAM_ERR_AUTH;
                goto done;
            }
        }
    }

    if (flags & AXIAM_JWT_VERIFY_TENANT) {
        char *expected = expected_tenant_id(client);
        if (!expected) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "cannot bind token to a tenant: configure tenant_id "
                            "(UUID) on the client");
            kind = AXIAM_ERR_AUTH;
            goto done;
        }
        const cJSON *tid = cJSON_GetObjectItemCaseSensitive(root, "tenant_id");
        int ok = cJSON_IsString(tid) && tid->valuestring &&
                 strcmp(tid->valuestring, expected) == 0;
        free(expected);
        if (!ok) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "token tenant_id does not match the configured tenant");
            kind = AXIAM_ERR_AUTH;
            goto done;
        }
    }

    if (flags & AXIAM_JWT_VERIFY_ISSUER_AUDIENCE) {
        /* §10.1 rules 5/6 are CONDITIONAL: an unset expectation means the claim
         * is not checked. A configured expectation makes it required — absent,
         * wrong-typed or mismatched all fail closed. The expectations are
         * config-only and never mutated after client construction, so no lock
         * is needed here. */
        const char *want_iss = client && client->cfg ? client->cfg->expected_issuer : NULL;
        if (want_iss && want_iss[0]) {
            const cJSON *iss = cJSON_GetObjectItemCaseSensitive(root, "iss");
            if (!cJSON_IsString(iss) || !iss->valuestring ||
                strcmp(iss->valuestring, want_iss) != 0) {
                axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                                "token iss does not match the expected issuer");
                kind = AXIAM_ERR_AUTH;
                goto done;
            }
        }
        const char *want_aud = client && client->cfg ? client->cfg->expected_audience : NULL;
        if (want_aud && want_aud[0]) {
            const cJSON *aud = cJSON_GetObjectItemCaseSensitive(root, "aud");
            if (!audience_contains(aud, want_aud)) {
                axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                                "token aud does not contain the expected audience");
                kind = AXIAM_ERR_AUTH;
                goto done;
            }
        }
    }

done:
    cJSON_Delete(root);
    return kind;
}

axiam_error_kind_t axiam_jwt_verify(axiam_client_t *client, const char *token,
                                    char **out_claims_json, axiam_error_t *err) {
    /* Safe by default: the guards' policy is also the plain entry point's. */
    return axiam_jwt_verify_ex(client, token, AXIAM_JWT_VERIFY_STRICT,
                               out_claims_json, err);
}

axiam_error_kind_t axiam_jwt_verify_ex(axiam_client_t *client, const char *token,
                                       unsigned flags, char **out_claims_json,
                                       axiam_error_t *err) {
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

    /* The payload is needed whenever the caller wants the claims OR a claim
     * policy is in force — decode it once. */
    char *claims = NULL;
    if (out_claims_json || flags) {
        size_t pdec_len = 0;
        unsigned char *pdec = axiam_b64url_decode(dot1 + 1, plen, &pdec_len);
        if (pdec) {
            claims = malloc(pdec_len + 1);
            if (claims) {
                memcpy(claims, pdec, pdec_len);
                claims[pdec_len] = '\0';
            }
            free(pdec);
        }
        if (!claims && flags) {
            /* Undecodable payload under a claim policy: fail closed. */
            axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token claims");
            return AXIAM_ERR_AUTH;
        }
    }

    if (flags) {
        axiam_error_kind_t ck = check_claims(client, claims, flags, err);
        if (ck != AXIAM_OK) {
            free(claims);
            return ck;
        }
    }

    if (out_claims_json) *out_claims_json = claims;
    else free(claims);
    return AXIAM_OK;
}
