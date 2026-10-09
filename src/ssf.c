/*
 * AXIAM C SDK — the SSF receiver helper (CONTRACT.md §32.7, contract 1.56).
 *
 * See include/axiam/ssf.h. Three things are worth repeating where the code lives:
 *
 *  - The nine steps of axiam_ssf_verify_set() run in the contract's order and stop at the
 *    first failure, and the replay store is consulted LAST: a SET that fails any earlier
 *    step must not burn its `jti`, or a forged copy of a genuine SET would make the
 *    genuine one read as a replay.
 *  - A key comes only from the configured JWKS. The `jwk`, `jku` and `x5c` header members
 *    are never read, so a SET cannot nominate the key that verifies it.
 *  - An unknown `kid` forces one refetch, and forced refetches happen at most once a
 *    minute: an attacker presenting made-up kids must not be able to drive one JWKS fetch
 *    per SET. The initial fetch is not a forced one and does not start that window.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/evp.h>

#include "axiam/ssf.h"
#include "cJSON.h"
#include "internal.h"
#include "management_internal.h"

/* ------------------------------------------------------------------ */
/* Reason codes                                                       */
/* ------------------------------------------------------------------ */

const char *axiam_ssf_reason_code(axiam_ssf_reason_t reason) {
    switch (reason) {
        case AXIAM_SSF_REASON_MALFORMED: return "malformed";
        case AXIAM_SSF_REASON_INVALID_TYPE: return "invalid_type";
        case AXIAM_SSF_REASON_INVALID_KEY: return "invalid_key";
        case AXIAM_SSF_REASON_INVALID_ISSUER: return "invalid_issuer";
        case AXIAM_SSF_REASON_INVALID_AUDIENCE: return "invalid_audience";
        case AXIAM_SSF_REASON_INVALID_REQUEST: return "invalid_request";
        case AXIAM_SSF_REASON_REPLAYED: return "replayed";
        case AXIAM_SSF_REASON_NONE: break;
    }
    return "";
}

const char *axiam_ssf_push_error_code(axiam_ssf_reason_t reason) {
    switch (reason) {
        case AXIAM_SSF_REASON_INVALID_KEY:
        case AXIAM_SSF_REASON_INVALID_ISSUER:
        case AXIAM_SSF_REASON_INVALID_AUDIENCE:
            return axiam_ssf_reason_code(reason);
        /* `malformed`, `invalid_type` and `replayed` are not RFC 8935 §2.4 codes, so a
         * push endpoint answering with them would send a non-standard `err`. They are
         * answered as `invalid_request`, which is what each of them is. */
        default:
            return "invalid_request";
    }
}

axiam_ssf_set_err_t axiam_ssf_set_err_from_reason(const char *jti, axiam_ssf_reason_t reason) {
    axiam_ssf_set_err_t e;
    e.jti = jti;
    e.err = axiam_ssf_push_error_code(reason);
    e.description = NULL;
    return e;
}

/* ------------------------------------------------------------------ */
/* The receiver                                                       */
/* ------------------------------------------------------------------ */

struct ssf_key {
    char *kid;
    unsigned char x[32];
    struct ssf_key *next;
};

struct ssf_seen {
    char *jti;
    time_t expires;
    struct ssf_seen *next;
};

struct axiam_ssf_receiver {
    axiam_client_t *client; /* borrowed */
    char *issuer;
    char *audience;
    char *jwks_uri;      /* resolved from discovery on first use when NULL */
    char *discovery_url;
    axiam_ssf_token_fn token_fn;
    void *token_ctx;
    long window_s;
    axiam_ssf_replay_check_fn store_fn;
    void *store_ctx;

    pthread_mutex_t keys_mtx; /* held across a fetch: single-flight */
    struct ssf_key *keys;
    int keys_loaded;
    time_t last_forced_refetch; /* 0 = never */

    pthread_mutex_t seen_mtx;
    struct ssf_seen *seen;
};

static time_t receiver_now(const axiam_ssf_receiver_t *r) {
    return r->client->clock_fn(r->client->clock_ctx);
}

static void free_keys(struct ssf_key *k) {
    while (k) {
        struct ssf_key *next = k->next;
        free(k->kid);
        free(k);
        k = next;
    }
}

void axiam_ssf_receiver_free(axiam_ssf_receiver_t *r) {
    if (!r) return;
    free(r->issuer);
    free(r->audience);
    free(r->jwks_uri);
    free(r->discovery_url);
    free_keys(r->keys);
    for (struct ssf_seen *s = r->seen; s;) {
        struct ssf_seen *next = s->next;
        free(s->jti);
        free(s);
        s = next;
    }
    pthread_mutex_destroy(&r->keys_mtx);
    pthread_mutex_destroy(&r->seen_mtx);
    free(r);
}

axiam_ssf_receiver_t *axiam_ssf_receiver_new(axiam_client_t *client,
                                             const axiam_ssf_receiver_config_t *config,
                                             axiam_error_t *err) {
    axiam_error_reset(err);
    const char *op = "ssf.receiver";
    if (!client || !config) {
        axiam_local_refusal(err, op, "config", "a client and a configuration are required");
        return NULL;
    }
    if (!config->issuer || !config->issuer[0] || !config->audience || !config->audience[0]) {
        axiam_local_refusal(err, op, "issuer",
                            "issuer and audience are required (CONTRACT.md \xc2\xa7" "32.7)");
        return NULL;
    }
    int has_jwks = config->jwks_uri && config->jwks_uri[0];
    int has_discovery = config->discovery_url && config->discovery_url[0];
    if (has_jwks == has_discovery) {
        axiam_local_refusal(err, op, "jwks_uri",
                            "set exactly one of jwks_uri and discovery_url "
                            "(CONTRACT.md \xc2\xa7" "32.7)");
        return NULL;
    }
    if (!axiam_url_is_secure(has_jwks ? config->jwks_uri : config->discovery_url)) {
        axiam_local_refusal(err, op, has_jwks ? "jwks_uri" : "discovery_url",
                            "must be an https URL (CONTRACT.md \xc2\xa7" "6)");
        return NULL;
    }
    long window = config->replay_window_s == 0 ? AXIAM_SSF_MIN_REPLAY_WINDOW_S
                                               : config->replay_window_s;
    if (window < AXIAM_SSF_MIN_REPLAY_WINDOW_S) {
        axiam_local_refusal(err, op, "replay_window",
                            "must be at least seven days, the transmitter's buffer retention "
                            "(CONTRACT.md \xc2\xa7" "32.7)");
        return NULL;
    }

    axiam_ssf_receiver_t *r = calloc(1, sizeof(*r));
    if (!r) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    pthread_mutex_init(&r->keys_mtx, NULL);
    pthread_mutex_init(&r->seen_mtx, NULL);
    r->client = client;
    r->issuer = axiam_strdup0(config->issuer);
    r->audience = axiam_strdup0(config->audience);
    r->jwks_uri = has_jwks ? axiam_strdup0(config->jwks_uri) : NULL;
    r->discovery_url = has_discovery ? axiam_strdup0(config->discovery_url) : NULL;
    r->token_fn = config->access_token_provider;
    r->token_ctx = config->access_token_ctx;
    r->window_s = window;
    r->store_fn = config->replay_store;
    r->store_ctx = config->replay_ctx;
    if (!r->issuer || !r->audience || (has_jwks ? !r->jwks_uri : !r->discovery_url)) {
        axiam_ssf_receiver_free(r);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Fetching the keys                                                  */
/* ------------------------------------------------------------------ */

/* One GET, not as the client's session. On a 2xx returns the parsed JSON object;
 * otherwise NULL with `err` set to AXIAM_ERR_NETWORK. */
static cJSON *fetch_json(axiam_ssf_receiver_t *r, const char *url, const char *what,
                         axiam_error_t *err) {
    axiam_kv_t *headers = axiam_kv_append(NULL, "Accept", "application/json");
    axiam_http_response_t resp;
    int rc = headers ? axiam_client_send_bare(r->client, "GET", url, headers, NULL, &resp) : -1;
    if (!headers) memset(&resp, 0, sizeof(resp));
    cJSON *doc = NULL;
    char msg[160];
    if (rc != 0 || resp.status == 0) {
        snprintf(msg, sizeof msg, "%s fetch failed: %s", what,
                 resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err, msg);
    } else if (resp.status < 200 || resp.status >= 300) {
        snprintf(msg, sizeof msg, "%s fetch failed (HTTP %ld)", what, resp.status);
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status, msg);
    } else {
        doc = resp.body ? cJSON_Parse(resp.body) : NULL;
        if (!cJSON_IsObject(doc)) {
            cJSON_Delete(doc);
            doc = NULL;
            snprintf(msg, sizeof msg, "%s is not a JSON object", what);
            axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status, msg);
        }
    }
    axiam_http_response_dispose(&resp);
    return doc;
}

/* Resolve `jwks_uri` from the SSF configuration document. Called with keys_mtx held. */
static axiam_error_kind_t resolve_jwks_uri(axiam_ssf_receiver_t *r, axiam_error_t *err) {
    if (r->jwks_uri) return AXIAM_OK;
    cJSON *doc = fetch_json(r, r->discovery_url, "SSF configuration", err);
    if (!doc) return AXIAM_ERR_NETWORK;
    const cJSON *iss = cJSON_GetObjectItemCaseSensitive(doc, "issuer");
    const cJSON *jwks = cJSON_GetObjectItemCaseSensitive(doc, "jwks_uri");
    axiam_error_kind_t kind = AXIAM_OK;
    if (!cJSON_IsString(iss) || strcmp(iss->valuestring, r->issuer) != 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "the SSF configuration's issuer is not the configured issuer");
        kind = AXIAM_ERR_NETWORK;
    } else if (!cJSON_IsString(jwks) || !axiam_url_is_secure(jwks->valuestring)) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "the SSF configuration carries no https jwks_uri");
        kind = AXIAM_ERR_NETWORK;
    } else {
        r->jwks_uri = axiam_strdup0(jwks->valuestring);
        if (!r->jwks_uri) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            kind = AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(doc);
    return kind;
}

/* Fetch the JWKS and replace the key set. Only Ed25519 keys are kept. Called with
 * keys_mtx held. */
static axiam_error_kind_t fetch_keys(axiam_ssf_receiver_t *r, axiam_error_t *err) {
    axiam_error_kind_t kind = resolve_jwks_uri(r, err);
    if (kind != AXIAM_OK) return kind;
    cJSON *doc = fetch_json(r, r->jwks_uri, "JWKS", err);
    if (!doc) return AXIAM_ERR_NETWORK;
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(doc, "keys");
    struct ssf_key *head = NULL;
    for (const cJSON *k = cJSON_IsArray(keys) ? keys->child : NULL; k; k = k->next) {
        const cJSON *kty = cJSON_GetObjectItemCaseSensitive(k, "kty");
        const cJSON *crv = cJSON_GetObjectItemCaseSensitive(k, "crv");
        const cJSON *x = cJSON_GetObjectItemCaseSensitive(k, "x");
        const cJSON *kid = cJSON_GetObjectItemCaseSensitive(k, "kid");
        if (!cJSON_IsString(kty) || strcmp(kty->valuestring, "OKP") != 0) continue;
        if (!cJSON_IsString(crv) || strcmp(crv->valuestring, "Ed25519") != 0) continue;
        if (!cJSON_IsString(x) || !cJSON_IsString(kid)) continue;
        size_t len = 0;
        unsigned char *raw = axiam_b64url_decode(x->valuestring, strlen(x->valuestring), &len);
        struct ssf_key *node = (raw && len == 32) ? calloc(1, sizeof(*node)) : NULL;
        if (node) {
            memcpy(node->x, raw, 32);
            node->kid = axiam_strdup0(kid->valuestring);
            if (node->kid) {
                node->next = head;
                head = node;
            } else {
                free(node);
            }
        }
        free(raw);
    }
    cJSON_Delete(doc);
    free_keys(r->keys);
    r->keys = head;
    r->keys_loaded = 1;
    return AXIAM_OK;
}

static int find_key(const axiam_ssf_receiver_t *r, const char *kid, unsigned char out[32]) {
    for (const struct ssf_key *k = r->keys; k; k = k->next) {
        if (strcmp(k->kid, kid) == 0) {
            memcpy(out, k->x, 32);
            return 1;
        }
    }
    return 0;
}

/* Step 4: the key for `kid`, fetching on first use and refetching ONCE on a miss, at
 * most once per AXIAM_SSF_JWKS_REFETCH_INTERVAL_S. Returns AXIAM_OK with *found set, or
 * AXIAM_ERR_NETWORK when a fetch failed. */
static axiam_error_kind_t key_for_kid(axiam_ssf_receiver_t *r, const char *kid,
                                      unsigned char out[32], int *found, axiam_error_t *err) {
    *found = 0;
    pthread_mutex_lock(&r->keys_mtx);
    axiam_error_kind_t kind = AXIAM_OK;
    if (!r->keys_loaded) kind = fetch_keys(r, err);
    if (kind == AXIAM_OK) *found = find_key(r, kid, out);
    if (kind == AXIAM_OK && !*found) {
        time_t now = receiver_now(r);
        if (r->last_forced_refetch == 0 ||
            now - r->last_forced_refetch >= AXIAM_SSF_JWKS_REFETCH_INTERVAL_S) {
            r->last_forced_refetch = now;
            kind = fetch_keys(r, err);
            if (kind == AXIAM_OK) *found = find_key(r, kid, out);
        }
    }
    pthread_mutex_unlock(&r->keys_mtx);
    return kind;
}

/* ------------------------------------------------------------------ */
/* The replay store                                                   */
/* ------------------------------------------------------------------ */

/* The in-memory store: 1 recorded, 0 already held, -1 out of memory. */
static int memory_check_and_record(axiam_ssf_receiver_t *r, const char *jti) {
    time_t now = receiver_now(r);
    pthread_mutex_lock(&r->seen_mtx);
    int result = 1;
    struct ssf_seen **link = &r->seen;
    while (*link) {
        struct ssf_seen *s = *link;
        if (s->expires <= now) {
            *link = s->next;
            free(s->jti);
            free(s);
            continue;
        }
        if (strcmp(s->jti, jti) == 0) result = 0;
        link = &s->next;
    }
    if (result == 1) {
        struct ssf_seen *s = calloc(1, sizeof(*s));
        char *copy = s ? axiam_strdup0(jti) : NULL;
        if (!copy) {
            free(s);
            result = -1;
        } else {
            s->jti = copy;
            s->expires = now + (time_t)r->window_s;
            s->next = r->seen;
            r->seen = s;
        }
    }
    pthread_mutex_unlock(&r->seen_mtx);
    return result;
}

/* ------------------------------------------------------------------ */
/* verify_set                                                         */
/* ------------------------------------------------------------------ */

void axiam_security_event_dispose(axiam_security_event_t *e) {
    if (!e) return;
    free(e->jti);
    free(e->iss);
    free(e->aud);
    free(e->txn);
    free(e->event_type);
    free(e->event);
    free(e->sub_id);
    memset(e, 0, sizeof(*e));
}

static cJSON *b64_json_object(const char *part, size_t len) {
    size_t n = 0;
    unsigned char *raw = axiam_b64url_decode(part, len, &n);
    if (!raw) return NULL;
    cJSON *obj = cJSON_ParseWithLength((const char *)raw, n);
    free(raw);
    if (!cJSON_IsObject(obj)) {
        cJSON_Delete(obj);
        return NULL;
    }
    return obj;
}

static int ed25519_verify(const unsigned char pub[32], const char *signing_input, size_t input_len,
                          const unsigned char *sig, size_t sig_len) {
    if (sig_len != 64) return 0;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pkey) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
             EVP_DigestVerify(ctx, sig, sig_len, (const unsigned char *)signing_input,
                              input_len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* Refuse with `reason`. The message names the step, never a claim's value. */
static axiam_error_kind_t refuse(axiam_ssf_reason_t reason, const char *detail,
                                 axiam_ssf_reason_t *out_reason, axiam_error_t *err) {
    char msg[192];
    snprintf(msg, sizeof msg, "SET refused (%s): %s", axiam_ssf_reason_code(reason), detail);
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
    if (out_reason) *out_reason = reason;
    return AXIAM_ERR_AUTH;
}

static axiam_error_kind_t oom(axiam_error_t *err) {
    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    return AXIAM_ERR_NETWORK;
}

static axiam_error_kind_t verify_inner(axiam_ssf_receiver_t *r, const char *set,
                                       const char *expected_jti, axiam_security_event_t *out,
                                       axiam_ssf_reason_t *out_reason, axiam_error_t *err) {
    /* 1. Three base64url parts, a JSON object header and payload. */
    const char *dot1 = set ? strchr(set, '.') : NULL;
    const char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    if (!dot2 || strchr(dot2 + 1, '.'))
        return refuse(AXIAM_SSF_REASON_MALFORMED, "not three base64url parts", out_reason, err);
    size_t sig_len = 0;
    unsigned char *sig = axiam_b64url_decode(dot2 + 1, strlen(dot2 + 1), &sig_len);
    if (!sig)
        return refuse(AXIAM_SSF_REASON_MALFORMED, "not three base64url parts", out_reason, err);
    cJSON *header = b64_json_object(set, (size_t)(dot1 - set));
    cJSON *claims = b64_json_object(dot1 + 1, (size_t)(dot2 - dot1 - 1));
    axiam_error_kind_t kind = AXIAM_OK;
    if (!header || !claims) {
        kind = refuse(AXIAM_SSF_REASON_MALFORMED, "header or payload is not a JSON object",
                      out_reason, err);
        goto done;
    }

    /* 2. typ */
    {
        const cJSON *typ = cJSON_GetObjectItemCaseSensitive(header, "typ");
        if (!cJSON_IsString(typ) || (strcasecmp(typ->valuestring, "secevent+jwt") != 0 &&
                                     strcasecmp(typ->valuestring, "application/secevent+jwt") != 0)) {
            kind = refuse(AXIAM_SSF_REASON_INVALID_TYPE, "typ is not secevent+jwt", out_reason, err);
            goto done;
        }
    }
    /* 3. alg, exactly. */
    {
        const cJSON *alg = cJSON_GetObjectItemCaseSensitive(header, "alg");
        if (!cJSON_IsString(alg) || strcmp(alg->valuestring, "EdDSA") != 0) {
            kind = refuse(AXIAM_SSF_REASON_INVALID_KEY, "alg is not EdDSA", out_reason, err);
            goto done;
        }
    }
    /* 4. The key named by kid, from the configured JWKS only. */
    unsigned char pub[32];
    {
        const cJSON *kid = cJSON_GetObjectItemCaseSensitive(header, "kid");
        if (!cJSON_IsString(kid)) {
            kind = refuse(AXIAM_SSF_REASON_INVALID_KEY, "no kid", out_reason, err);
            goto done;
        }
        int found = 0;
        kind = key_for_kid(r, kid->valuestring, pub, &found, err);
        if (kind != AXIAM_OK) goto done; /* a fetch failure: not a verdict on the SET */
        if (!found) {
            kind = refuse(AXIAM_SSF_REASON_INVALID_KEY, "no key for kid in the JWKS", out_reason, err);
            goto done;
        }
    }
    /* 5. The signature. */
    if (!ed25519_verify(pub, set, (size_t)(dot2 - set), sig, sig_len)) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_KEY, "signature does not verify", out_reason, err);
        goto done;
    }
    /* 6. iss */
    const cJSON *iss = cJSON_GetObjectItemCaseSensitive(claims, "iss");
    if (!cJSON_IsString(iss) || strcmp(iss->valuestring, r->issuer) != 0) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_ISSUER, "iss is not the configured issuer",
                      out_reason, err);
        goto done;
    }
    /* 7. aud: equal, or an array containing it. */
    const cJSON *aud = cJSON_GetObjectItemCaseSensitive(claims, "aud");
    {
        int ok = cJSON_IsString(aud) && strcmp(aud->valuestring, r->audience) == 0;
        for (const cJSON *a = cJSON_IsArray(aud) ? aud->child : NULL; a && !ok; a = a->next)
            ok = cJSON_IsString(a) && strcmp(a->valuestring, r->audience) == 0;
        if (!ok) {
            kind = refuse(AXIAM_SSF_REASON_INVALID_AUDIENCE, "aud does not name this receiver",
                          out_reason, err);
            goto done;
        }
    }
    /* 8. A SET's claims. */
    if (cJSON_GetObjectItemCaseSensitive(claims, "exp") ||
        cJSON_GetObjectItemCaseSensitive(claims, "sub")) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "a SET carries no exp and no sub",
                      out_reason, err);
        goto done;
    }
    const cJSON *jti = cJSON_GetObjectItemCaseSensitive(claims, "jti");
    const cJSON *iat = cJSON_GetObjectItemCaseSensitive(claims, "iat");
    const cJSON *sub_id = cJSON_GetObjectItemCaseSensitive(claims, "sub_id");
    const cJSON *events = cJSON_GetObjectItemCaseSensitive(claims, "events");
    if (!cJSON_IsString(jti) || !jti->valuestring[0]) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "no jti", out_reason, err);
        goto done;
    }
    if (!cJSON_IsNumber(iat)) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "no numeric iat", out_reason, err);
        goto done;
    }
    if (!cJSON_IsObject(sub_id)) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "no sub_id", out_reason, err);
        goto done;
    }
    if (!cJSON_IsObject(events) || !events->child || events->child->next) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "events must have exactly one member",
                      out_reason, err);
        goto done;
    }
    if (expected_jti && strcmp(expected_jti, jti->valuestring) != 0) {
        kind = refuse(AXIAM_SSF_REASON_INVALID_REQUEST, "the poll key is not the SET's jti",
                      out_reason, err);
        goto done;
    }

    /* Build the result BEFORE recording the jti, so an allocation failure here cannot
     * leave a SET recorded that the caller never received. */
    out->jti = axiam_strdup0(jti->valuestring);
    out->iat = (long)iat->valuedouble;
    out->iss = axiam_strdup0(iss->valuestring);
    out->aud = cJSON_PrintUnformatted(aud);
    const cJSON *txn = cJSON_GetObjectItemCaseSensitive(claims, "txn");
    out->txn = cJSON_IsString(txn) ? axiam_strdup0(txn->valuestring) : NULL;
    out->event_type = axiam_strdup0(events->child->string);
    out->event = cJSON_PrintUnformatted(events->child);
    out->sub_id = cJSON_PrintUnformatted(sub_id);
    if (!out->jti || !out->iss || !out->aud || !out->event_type || !out->event || !out->sub_id ||
        (cJSON_IsString(txn) && !out->txn)) {
        axiam_security_event_dispose(out);
        kind = oom(err);
        goto done;
    }

    /* 9. Not seen within the window -- recorded only now that 1-8 passed. */
    {
        int fresh = r->store_fn ? r->store_fn(r->store_ctx, jti->valuestring, r->window_s)
                                : memory_check_and_record(r, jti->valuestring);
        if (fresh <= 0) {
            axiam_security_event_dispose(out);
            if (fresh < 0) {
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "the SSF replay store failed");
                kind = AXIAM_ERR_NETWORK;
            } else {
                kind = refuse(AXIAM_SSF_REASON_REPLAYED, "jti already seen", out_reason, err);
            }
            goto done;
        }
    }

done:
    free(sig);
    cJSON_Delete(header);
    cJSON_Delete(claims);
    return kind;
}

axiam_error_kind_t axiam_ssf_verify_set(axiam_ssf_receiver_t *receiver, const char *set,
                                        axiam_security_event_t *out,
                                        axiam_ssf_reason_t *out_reason, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_reason) *out_reason = AXIAM_SSF_REASON_NONE;
    if (!receiver || !out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    return verify_inner(receiver, set, NULL, out, out_reason, err);
}

/* ------------------------------------------------------------------ */
/* poll                                                               */
/* ------------------------------------------------------------------ */

void axiam_ssf_poll_result_dispose(axiam_ssf_poll_result_t *result) {
    if (!result) return;
    for (size_t i = 0; i < result->events_count; i++) axiam_security_event_dispose(&result->events[i]);
    free(result->events);
    for (size_t i = 0; i < result->refused_count; i++) free(result->refused[i].jti);
    free(result->refused);
    memset(result, 0, sizeof(*result));
}

/* The RFC 8936 request body: exactly the members `o` sets. NULL on OOM. */
static char *poll_body(const axiam_ssf_poll_options_t *o) {
    cJSON *body = cJSON_CreateObject();
    if (!body) return NULL;
    int ok = 1;
    if (o && o->has_max_events) ok = ok && cJSON_AddNumberToObject(body, "maxEvents", (double)o->max_events);
    if (o && o->has_return_immediately)
        ok = ok && cJSON_AddBoolToObject(body, "returnImmediately", o->return_immediately);
    if (ok && o && o->ack) {
        cJSON *ack = cJSON_AddArrayToObject(body, "ack");
        ok = ack != NULL;
        for (size_t i = 0; ok && i < o->ack_count; i++) {
            cJSON *s = cJSON_CreateString(o->ack[i] ? o->ack[i] : "");
            ok = s != NULL;
            if (s) cJSON_AddItemToArray(ack, s);
        }
    }
    if (ok && o && o->set_errs) {
        cJSON *errs = cJSON_AddObjectToObject(body, "setErrs");
        ok = errs != NULL;
        for (size_t i = 0; ok && i < o->set_errs_count; i++) {
            const axiam_ssf_set_err_t *e = &o->set_errs[i];
            cJSON *entry = cJSON_CreateObject();
            ok = entry && cJSON_AddStringToObject(entry, "err", e->err ? e->err : "") &&
                 (!e->description || cJSON_AddStringToObject(entry, "description", e->description));
            ok = ok && cJSON_AddItemToObject(errs, e->jti ? e->jti : "", entry);
            if (entry && !ok) cJSON_Delete(entry);
        }
    }
    char *json = ok ? cJSON_PrintUnformatted(body) : NULL;
    cJSON_Delete(body);
    return json;
}

static axiam_kv_t *poll_headers(const axiam_sensitive_t *token) {
    const char *raw = axiam_sensitive_reveal(token);
    size_t n = strlen("Bearer ") + strlen(raw ? raw : "") + 1;
    char *value = malloc(n);
    if (!value) return NULL;
    snprintf(value, n, "Bearer %s", raw ? raw : "");
    axiam_kv_t *h = axiam_kv_append(NULL, "Authorization", value);
    axiam_secure_zero(value, n);
    free(value);
    if (!h) return NULL;
    h = axiam_kv_append(h, "Content-Type", "application/json");
    h = axiam_kv_append(h, "Accept", "application/json");
    return h;
}

/* Verify each SET of a 2xx reply into `out`. */
static axiam_error_kind_t collect(axiam_ssf_receiver_t *r, const char *reply,
                                  axiam_ssf_poll_result_t *out, axiam_error_t *err) {
    cJSON *doc = reply ? cJSON_Parse(reply) : NULL;
    if (!cJSON_IsObject(doc)) {
        cJSON_Delete(doc);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "ssf.poll: the response is not a JSON object");
        return AXIAM_ERR_NETWORK;
    }
    out->more_available = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(doc, "moreAvailable"));
    const cJSON *sets = cJSON_GetObjectItemCaseSensitive(doc, "sets");
    size_t n = 0;
    for (const cJSON *s = cJSON_IsObject(sets) ? sets->child : NULL; s; s = s->next) n++;
    axiam_error_kind_t kind = AXIAM_OK;
    if (n > 0) {
        out->events = calloc(n, sizeof(*out->events));
        out->refused = calloc(n, sizeof(*out->refused));
        if (!out->events || !out->refused) kind = oom(err);
    }
    for (const cJSON *s = n ? sets->child : NULL; s && kind == AXIAM_OK; s = s->next) {
        axiam_ssf_reason_t reason = AXIAM_SSF_REASON_MALFORMED;
        if (cJSON_IsString(s)) {
            axiam_error_t one;
            axiam_error_reset(&one);
            axiam_security_event_t *slot = &out->events[out->events_count];
            reason = AXIAM_SSF_REASON_NONE;
            axiam_error_kind_t k = verify_inner(r, s->valuestring, s->string, slot, &reason, &one);
            if (k == AXIAM_OK) {
                out->events_count++;
                continue;
            }
            if (reason == AXIAM_SSF_REASON_NONE) { /* a JWKS fetch or store failure */
                if (err) *err = one;
                kind = k;
                break;
            }
        }
        out->refused[out->refused_count].jti = axiam_strdup0(s->string);
        out->refused[out->refused_count].reason = reason;
        if (!out->refused[out->refused_count].jti) {
            kind = oom(err);
            break;
        }
        out->refused_count++;
    }
    cJSON_Delete(doc);
    return kind;
}

axiam_error_kind_t axiam_ssf_poll(axiam_ssf_receiver_t *r, const char *stream_id,
                                  const axiam_ssf_poll_options_t *options,
                                  axiam_ssf_poll_result_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!r || !out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    axiam_client_t *c = r->client;
    if (axiam_client_is_shut(c)) return axiam_client_shut_error(err);
    if (!r->token_fn) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "ssf.poll needs an access_token_provider (a client-credentials token "
                        "with ssf.manage)");
        return AXIAM_ERR_AUTH;
    }
    if (!stream_id || !stream_id[0]) {
        axiam_local_refusal(err, "ssf.poll", "stream_id", "a stream id is required");
        return AXIAM_ERR_NETWORK;
    }

    char *escaped = axiam_url_encode(stream_id);
    size_t plen = escaped ? strlen("/ssf/v1/poll/") + strlen(escaped) + 1 : 0;
    char *path = escaped ? malloc(plen) : NULL;
    if (path) snprintf(path, plen, "/ssf/v1/poll/%s", escaped);
    free(escaped);
    char *url = path ? axiam_client_url(c, path) : NULL;
    free(path);
    char *body = url ? poll_body(options) : NULL;
    if (!body) {
        free(url);
        return oom(err);
    }

    axiam_sensitive_t *token = NULL;
    axiam_error_kind_t kind = r->token_fn(r->token_ctx, &token, err);
    if (kind != AXIAM_OK || !token) {
        axiam_sensitive_free(token);
        free(url);
        free(body);
        if (kind == AXIAM_OK) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0, "the access_token_provider returned no token");
            kind = AXIAM_ERR_AUTH;
        }
        return kind;
    }

    /* §32.7: §16 on a transport failure or a 5xx (and 408/429, per §16.3) -- never on
     * another 4xx, which is the server's decided answer. */
    int budget = c->retry_enabled ? AXIAM_RETRY_MAX_ATTEMPTS : 1;
    axiam_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int rc = -1;
    for (int attempt = 1; attempt <= budget; attempt++) {
        axiam_kv_t *headers = poll_headers(token);
        if (!headers) {
            memset(&resp, 0, sizeof(resp));
            rc = -1;
            break;
        }
        rc = axiam_client_send_bare(c, "POST", url, headers, body, &resp);
        if (attempt == budget || !axiam_retry_should_retry(rc != 0, resp.status)) break;
        long retry_after = axiam_retry_after_ms(axiam_kv_get(resp.headers, "Retry-After"));
        long delay = axiam_retry_delay_ms(attempt, retry_after, c->jitter_fn(c->jitter_ctx));
        axiam_http_response_dispose(&resp);
        c->sleep_fn(c->sleep_ctx, delay);
    }
    axiam_sensitive_free(token);
    free(url);
    free(body);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        kind = AXIAM_ERR_NETWORK;
    } else if (resp.status < 200 || resp.status >= 300) {
        axiam_mgmt_classify(err, resp.status, "ssf.poll", resp.body);
        kind = err ? err->kind : axiam_error_kind_from_http_status(resp.status);
    } else {
        kind = collect(r, resp.body, out, err);
        if (kind != AXIAM_OK) axiam_ssf_poll_result_dispose(out);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}
