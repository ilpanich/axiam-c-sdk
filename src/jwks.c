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

static axiam_error_kind_t ensure_jwks(axiam_client_t *c, int force, axiam_error_t *err) {
    time_t now = time(NULL);
    pthread_mutex_lock(&c->jwks_mtx);
    int fresh = !force && c->jwks_valid &&
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

/* Record a §12.3 rule 3 reason code, when the caller asked for one. */
static void set_reason(char *reason, size_t cap, const char *code) {
    if (reason && cap) snprintf(reason, cap, "%s", code);
}

/*
 * §12.4 rule 2's unknown-`kid` handling, shared by the §10 guards and the §12
 * ID-token path.
 *
 * "One re-fetch then fail", taken literally against a warm cache, is
 * unimplementable without handing an attacker one JWKS fetch per forged `kid`.
 * The rule is per WINDOW: the first unknown `kid` triggers exactly one re-fetch
 * and opens a cooldown; another unknown `kid` inside that window re-consults the
 * cached set with NO network call and fails immediately. Neither weakening is
 * permitted — "never re-fetch" breaks key rotation, "always re-fetch" is a
 * fetch-amplification vector.
 *
 * Returns 1 and fills `pub` when a key was found.
 */
static int lookup_key(axiam_client_t *c, const char *kid, unsigned char pub[32],
                      axiam_error_t *err) {
    pthread_mutex_lock(&c->jwks_mtx);
    const struct axiam_jwk *key = find_key(c, kid);
    if (key) { memcpy(pub, key->x, 32); pthread_mutex_unlock(&c->jwks_mtx); return 1; }

    time_t now = time(NULL);
    int may_refetch = now >= c->jwks_refetch_cooldown_until;
    if (may_refetch) c->jwks_refetch_cooldown_until = now + AXIAM_OIDC_JWKS_REFETCH_COOLDOWN_S;
    pthread_mutex_unlock(&c->jwks_mtx);
    if (!may_refetch) return 0;

    if (ensure_jwks(c, 1, err) != AXIAM_OK) return 0;

    pthread_mutex_lock(&c->jwks_mtx);
    key = find_key(c, kid);
    if (key) memcpy(pub, key->x, 32);
    pthread_mutex_unlock(&c->jwks_mtx);
    return key != NULL;
}

static axiam_error_kind_t verify_core(axiam_client_t *client, const char *token,
                                      unsigned flags, char **out_claims_json,
                                      char *reason, size_t reason_cap,
                                      axiam_error_t *err);

axiam_error_kind_t axiam_jwt_verify(axiam_client_t *client, const char *token,
                                    char **out_claims_json, axiam_error_t *err) {
    /* Safe by default: the guards' policy is also the plain entry point's. */
    return axiam_jwt_verify_ex(client, token, AXIAM_JWT_VERIFY_STRICT,
                               out_claims_json, err);
}

axiam_error_kind_t axiam_jwt_verify_ex(axiam_client_t *client, const char *token,
                                       unsigned flags, char **out_claims_json,
                                       axiam_error_t *err) {
    return verify_core(client, token, flags, out_claims_json, NULL, 0, err);
}

axiam_error_kind_t axiam_jwt_verify_reasoned(axiam_client_t *client, const char *token,
                                             char **out_claims_json,
                                             char *out_reason, size_t reason_cap,
                                             axiam_error_t *err) {
    /*
     * §12.4 says to EXTEND this verifier, never fork it — so §12's ID-token path
     * enters here, at the same key cache, the same EdDSA pin and the same
     * unknown-`kid` cooldown the §10 middleware uses, and layers rules 3 to 6 on
     * top. The flags are 0 because §12.4's claim rules are not §10.1's: an ID
     * token's `aud` is the RP's client_id rather than `axiam:user`, and it
     * carries no `tenant_id` claim to bind.
     */
    if (out_reason && reason_cap) out_reason[0] = '\0';
    return verify_core(client, token, AXIAM_JWT_VERIFY_SIGNATURE_ONLY, out_claims_json,
                       out_reason, reason_cap, err);
}

static axiam_error_kind_t verify_core(axiam_client_t *client, const char *token,
                                      unsigned flags, char **out_claims_json,
                                      char *reason, size_t reason_cap,
                                      axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_claims_json) *out_claims_json = NULL;
    if (!client || !token) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "missing token");
        return AXIAM_ERR_AUTH;
    }

    /* Split into header.payload.signature. A token that is not three
     * dot-separated parts cannot even have its algorithm established, which is
     * why §12.3 rule 3 folds that case into `invalid_alg`. */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_ALG);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token");
        return AXIAM_ERR_AUTH;
    }
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_ALG);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token");
        return AXIAM_ERR_AUTH;
    }
    size_t hlen = (size_t)(dot1 - token);
    size_t plen = (size_t)(dot2 - (dot1 + 1));
    const char *sig_b64 = dot2 + 1;
    size_t slen = strlen(sig_b64);

    /* Decode + inspect header: reject non-EdDSA BEFORE key lookup. §12.4 rule 1
     * is explicit that the `alg` is read from the header and checked first — an
     * SDK must not let the token select its own verification algorithm, and the
     * discovery document's `id_token_signing_alg_values_supported` cannot widen
     * this either. */
    size_t hdr_len = 0;
    unsigned char *hdr = axiam_b64url_decode(token, hlen, &hdr_len);
    if (!hdr) {
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_ALG);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token header");
        return AXIAM_ERR_AUTH;
    }
    cJSON *hjson = cJSON_ParseWithLength((const char *)hdr, hdr_len);
    free(hdr);
    if (!hjson) {
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_ALG);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token header");
        return AXIAM_ERR_AUTH;
    }
    const cJSON *alg = cJSON_GetObjectItemCaseSensitive(hjson, "alg");
    const cJSON *kid = cJSON_GetObjectItemCaseSensitive(hjson, "kid");
    char *kid_copy = NULL;
    int alg_ok = cJSON_IsString(alg) && alg->valuestring &&
                 strcmp(alg->valuestring, "EdDSA") == 0;
    if (cJSON_IsString(kid) && kid->valuestring) kid_copy = axiam_strdup0(kid->valuestring);
    cJSON_Delete(hjson);
    if (!alg_ok) {
        free(kid_copy);
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_ALG);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "unsupported token alg (EdDSA only)");
        return AXIAM_ERR_AUTH;
    }

    axiam_error_kind_t kk = ensure_jwks(client, 0, err);
    if (kk != AXIAM_OK) {
        free(kid_copy);
        /* §12.3 rule 3: a JWKS transport failure during the rule-2 re-fetch MAY
         * surface as `unknown_kid` rather than `invalid_signature`, and does —
         * "the key could not be established" is what both mean here. */
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_UNKNOWN_KID);
        return kk;
    }

    unsigned char pub[32];
    int have_key = lookup_key(client, kid_copy, pub, err);
    free(kid_copy);
    if (!have_key) {
        /* Covers "no kid in the header at all" as well as "no key matches it",
         * which §12.3 rule 3 folds into the one code deliberately. */
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_UNKNOWN_KID);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "no matching signing key");
        return AXIAM_ERR_AUTH;
    }

    /* Signing input = header_b64 "." payload_b64 (ASCII bytes of the token). */
    size_t signing_len = hlen + 1 + plen;

    size_t sig_len = 0;
    unsigned char *sig = axiam_b64url_decode(sig_b64, slen, &sig_len);
    if (!sig) {
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_SIGNATURE);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed signature");
        return AXIAM_ERR_AUTH;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pkey) {
        free(sig);
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_SIGNATURE);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "key load failed");
        return AXIAM_ERR_AUTH;
    }

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
        set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_SIGNATURE);
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
        if (!claims && (flags || reason)) {
            /* Undecodable payload: fail closed, whether a §10.1 claim policy is
             * in force or a §12.4 caller is about to apply its own. */
            set_reason(reason, reason_cap, AXIAM_OIDC_REASON_INVALID_SIGNATURE);
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

/* ------------------------------------------------------------------------
 * CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) tokens
 * (contract 1.15, RFC 8705 §3 / RFC 7800).
 *
 * A token carrying `cnf` is NOT a bearer token. Accepting one without proving
 * the caller holds the named key converts it straight back into one,
 * discarding the whole protection the operator turned on — which is why this
 * is a rule and not a recommendation.
 * ---------------------------------------------------------------------- */

/* Constant-time string comparison.
 *
 * The thumbprint is usually public — it derives from a certificate sent in the
 * clear during the handshake — so this is defence in depth. It matters most
 * for a self-signed client, where the registered thumbprint is the whole
 * credential. Length inequality short-circuits, leaking only the length; both
 * operands are fixed-length base64url SHA-256 digests when well-formed. */
static int ct_streq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++)
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

axiam_error_kind_t axiam_jwt_verify_certificate_binding(
    const char *claims_json, const char *presented_thumbprint,
    axiam_error_t *err) {
    if (!claims_json) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "no claims to check");
        return AXIAM_ERR_AUTH;
    }

    cJSON *root = cJSON_Parse(claims_json);
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "malformed token claims");
        return AXIAM_ERR_AUTH;
    }

    const cJSON *cnf = cJSON_GetObjectItemCaseSensitive(root, "cnf");
    if (!cnf || cJSON_IsNull(cnf)) {
        /* An ordinary bearer token. Accepted with or without a certificate —
         * rule 9 constrains tokens that CLAIM a constraint; it does not make
         * certificates mandatory, and treating it otherwise would break every
         * deployment that does not use mTLS. */
        cJSON_Delete(root);
        return AXIAM_OK;
    }

    if (!cJSON_IsObject(cnf)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token cnf claim is malformed");
        return AXIAM_ERR_AUTH;
    }

    const cJSON *x5t = cJSON_GetObjectItemCaseSensitive(cnf, "x5t#S256");
    if (!cJSON_IsString(x5t) || !x5t->valuestring || !x5t->valuestring[0]) {
        /* A confirmation naming a method this SDK cannot check — a DPoP `jkt`,
         * say. That is an UNVERIFIABLE constraint, never NO constraint. Read
         * the other way, a sender-constrained token silently degrades to a
         * bearer token the day a newer AXIAM issues a confirmation this SDK
         * predates. Fail closed. */
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "token carries a cnf confirmation naming a method this "
                        "SDK cannot verify");
        return AXIAM_ERR_AUTH;
    }

    if (!presented_thumbprint || !presented_thumbprint[0]) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "token is certificate-bound but no client certificate "
                        "was presented");
        return AXIAM_ERR_AUTH;
    }

    int ok = ct_streq(x5t->valuestring, presented_thumbprint);
    cJSON_Delete(root);
    if (!ok) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "token is bound to a different client certificate than "
                        "the one presented");
        return AXIAM_ERR_AUTH;
    }
    return AXIAM_OK;
}

/* Base64URL WITHOUT padding (RFC 4648 §5 alphabet, RFC 7515 §2 rules).
 *
 * Unpadded is not a style choice: RFC 7515 §2 defines base64url in JOSE as
 * omitting `=`, and a padded value will not compare equal to what AXIAM put in
 * the token. Written here rather than reused from oidc.c's PKCE helper, which
 * is `static` to that translation unit — duplicating twelve lines beats
 * widening an internal helper's linkage across the library.
 *
 * Specialised to a 32-byte SHA-256 digest — which encodes to exactly 43
 * characters — rather than written as a general encoder.
 *
 * That is deliberate. The only caller is the x5t#S256 thumbprint, so `len % 3
 * == 2` is invariant, and a general encoder's "one trailing byte" branch would
 * be PERMANENTLY unreachable: dead code that a branch-coverage gate correctly
 * declines to count as covered, and that no test could ever honestly reach.
 * Fixing the size removes every conditional from the hot loop as a bonus. */
#define THUMBPRINT_DIGEST_LEN 32u
#define THUMBPRINT_B64URL_LEN 43u

static char *thumbprint_b64url(const unsigned char digest[THUMBPRINT_DIGEST_LEN]) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    char *out = malloc(THUMBPRINT_B64URL_LEN + 1);
    if (!out) return NULL;

    size_t o = 0;
    /* 30 of the 32 bytes are ten whole 3-byte groups -> 40 characters. */
    for (size_t i = 0; i < 30; i += 3) {
        unsigned v = ((unsigned)digest[i] << 16) | ((unsigned)digest[i + 1] << 8) |
                     (unsigned)digest[i + 2];
        out[o++] = alphabet[(v >> 18) & 0x3f];
        out[o++] = alphabet[(v >> 12) & 0x3f];
        out[o++] = alphabet[(v >> 6) & 0x3f];
        out[o++] = alphabet[v & 0x3f];
    }
    /* The trailing 2 bytes -> 3 characters, and no '=' padding. */
    unsigned v = ((unsigned)digest[30] << 16) | ((unsigned)digest[31] << 8);
    out[o++] = alphabet[(v >> 18) & 0x3f];
    out[o++] = alphabet[(v >> 12) & 0x3f];
    out[o++] = alphabet[(v >> 6) & 0x3f];

    out[o] = '\0';
    return out;
}

char *axiam_certificate_thumbprint_s256(const unsigned char *der,
                                        size_t der_len) {
    if (!der) return NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, der, der_len) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != THUMBPRINT_DIGEST_LEN) return NULL;
    return thumbprint_b64url(digest);
}
