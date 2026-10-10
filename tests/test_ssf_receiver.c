/*
 * CONTRACT.md §32.7 (contract 1.56) — the SSF receiver helper: §32.8's eight helper
 * tests, plus the discovery key source, a JWKS fetch failure, the RFC 8935 code mapping,
 * a pluggable replay store and the poll refusals.
 *
 * The Ed25519 keys are generated here and every SET is signed here: no key literal.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management.h"
#include "axiam/ssf.h"
#include "cJSON.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define BASE "https://tx.example.com"
#define ISSUER "https://tx.example.com/t/11111111-1111-4111-8111-111111111111"
#define AUDIENCE "https://rp.example/ssf"
#define JWKS_URI ISSUER "/oauth2/jwks"
#define DISCOVERY_URL BASE "/.well-known/ssf-configuration?tenant_id=11111111-1111-4111-8111-111111111111"

/* ------------------------------------------------------------------ */
/* Keys and SETs                                                      */
/* ------------------------------------------------------------------ */

static EVP_PKEY *new_key(void) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    TEST_ASSERT_NOT_NULL(k);
    return k;
}

static char *b64(const char *s) { return jwt_b64url_encode((const unsigned char *) s, strlen(s)); }

/* `{"keys":[...]}` with one OKP entry per (key, kid). */
static char *jwks_of(EVP_PKEY **keys, const char **kids, int n) {
    cJSON *doc = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(doc, "keys");
    for (int i = 0; i < n; i++) {
        unsigned char raw[32];
        size_t len = sizeof raw;
        TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(keys[i], raw, &len));
        char *x = jwt_b64url_encode(raw, len);
        cJSON *k = cJSON_CreateObject();
        cJSON_AddStringToObject(k, "kty", "OKP");
        cJSON_AddStringToObject(k, "crv", "Ed25519");
        cJSON_AddStringToObject(k, "x", x);
        cJSON_AddStringToObject(k, "kid", kids[i]);
        cJSON_AddItemToArray(arr, k);
        free(x);
    }
    /* Keys of other types are ignored, not fatal. */
    cJSON *rsa = cJSON_CreateObject();
    cJSON_AddStringToObject(rsa, "kty", "RSA");
    cJSON_AddStringToObject(rsa, "kid", "rsa-1");
    cJSON_AddItemToArray(arr, rsa);
    char *text = cJSON_PrintUnformatted(doc);
    cJSON_Delete(doc);
    return text;
}

/* header.payload.signature, signed by `key` (EdDSA). */
static char *sign_set(EVP_PKEY *key, const char *header, const char *payload) {
    char *h = b64(header), *p = b64(payload);
    size_t n = strlen(h) + strlen(p) + 2;
    char *input = malloc(n);
    snprintf(input, n, "%s.%s", h, p);
    unsigned char sig[64];
    size_t sig_len = sizeof sig;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit(ctx, NULL, NULL, NULL, key));
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *) input, strlen(input)));
    EVP_MD_CTX_free(ctx);
    char *s = jwt_b64url_encode(sig, sig_len);
    size_t m = strlen(input) + strlen(s) + 2;
    char *set = malloc(m);
    snprintf(set, m, "%s.%s", input, s);
    free(h);
    free(p);
    free(input);
    free(s);
    return set;
}

static void random_jti(char *out) {
    unsigned char raw[16];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    for (int i = 0; i < 16; i++) snprintf(out + 2 * i, 3, "%02x", raw[i]);
}

#define HEADER(kid) "{\"alg\":\"EdDSA\",\"typ\":\"secevent+jwt\",\"kid\":\"" kid "\"}"
#define SUB_ID "{\"format\":\"iss_sub\",\"iss\":\"" ISSUER "\",\"sub\":\"u-1\"}"

/* A payload with every claim a SET carries; `extra` appended verbatim. */
static void payload(char *out, size_t cap, const char *jti, const char *aud_json, const char *extra) {
    snprintf(out, cap,
             "{\"iss\":\"" ISSUER "\",\"aud\":%s,\"iat\":1760000000,\"jti\":\"%s\","
             "\"sub_id\":" SUB_ID ",\"events\":{\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\":"
             "{\"event_timestamp\":1760000000,\"initiating_entity\":\"admin\"}}%s}",
             aud_json, jti, extra ? extra : "");
}

/* ------------------------------------------------------------------ */
/* The fake transmitter                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    long status;
    const char *body;
    int transport_fails;
} answer_t;

typedef struct {
    char *jwks;            /* served at the jwks_uri */
    long jwks_status;      /* 0 = 200 */
    int jwks_fail_from;    /* when > 0, fetch number N and later answer 503 */
    int jwks_fetches;
    int discovery_fetches;
    const char *discovery; /* served at the discovery URL */
    answer_t poll[8];
    int poll_len;
    int poll_calls;
    char poll_url[512];
    char poll_body[2048];
    char poll_auth[256];
    int poll_had_cookie_signal;
    int poll_had_csrf;
    int other_calls;
    time_t now;
    long sleeps;
} fake_t;

static fake_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req, axiam_http_response_t *resp) {
    (void) ctx;
    memset(resp, 0, sizeof *resp);
    const char *url = req->url ? req->url : "";
    if (strstr(url, "/oauth2/jwks")) {
        g.jwks_fetches++;
        resp->status = g.jwks_status ? g.jwks_status : 200;
        if (g.jwks_fail_from > 0 && g.jwks_fetches >= g.jwks_fail_from) resp->status = 503;
        if (g.jwks) resp->body = strdup(g.jwks);
        return 0;
    }
    if (strstr(url, "/.well-known/ssf-configuration")) {
        g.discovery_fetches++;
        resp->status = 200;
        if (g.discovery) resp->body = strdup(g.discovery);
        return 0;
    }
    if (strstr(url, "/ssf/v1/poll/")) {
        int i = g.poll_calls < g.poll_len ? g.poll_calls : g.poll_len - 1;
        g.poll_calls++;
        snprintf(g.poll_url, sizeof g.poll_url, "%s", url);
        snprintf(g.poll_body, sizeof g.poll_body, "%s", req->body ? req->body : "");
        const char *auth = axiam_kv_get(req->headers, "Authorization");
        snprintf(g.poll_auth, sizeof g.poll_auth, "%s", auth ? auth : "");
        const char *cookie = axiam_kv_get(req->headers, "Cookie");
        g.poll_had_cookie_signal = cookie && !cookie[0];
        g.poll_had_csrf = axiam_kv_get(req->headers, "X-CSRF-Token") != NULL;
        if (i < 0) {
            resp->status = 200;
            resp->body = strdup("{\"sets\":{},\"moreAvailable\":false}");
            return 0;
        }
        if (g.poll[i].transport_fails) {
            resp->transport_err = 7;
            resp->transport_msg = strdup("connection reset");
            return 1;
        }
        resp->status = g.poll[i].status;
        if (g.poll[i].body) resp->body = strdup(g.poll[i].body);
        return 0;
    }
    g.other_calls++;
    resp->status = 404;
    return 0;
}

static time_t fake_clock(void *ctx) {
    (void) ctx;
    return g.now;
}

static void fake_sleep(void *ctx, long ms) {
    (void) ctx;
    (void) ms;
    g.sleeps++;
}

static double fake_jitter(void *ctx) {
    (void) ctx;
    return 0.0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, BASE);
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-4111-8111-111111111111");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    c->clock_fn = fake_clock;
    c->sleep_fn = fake_sleep; /* retry stays ENABLED; only the wait is faked */
    c->jitter_fn = fake_jitter;
    return c;
}

static char g_token[65];

static axiam_error_kind_t token_provider(void *ctx, axiam_sensitive_t **out, axiam_error_t *err) {
    (void) ctx;
    (void) err;
    *out = axiam_sensitive_new(g_token);
    return AXIAM_OK;
}

static axiam_ssf_receiver_t *make_receiver(axiam_client_t *c, int with_provider) {
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    if (with_provider) cfg.access_token_provider = token_provider;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);
    return r;
}

static EVP_PKEY *g_key;

void setUp(void) {
    memset(&g, 0, sizeof g);
    g.now = 1760000000;
    g_key = new_key();
    const char *kids[] = {"k1"};
    g.jwks = jwks_of(&g_key, kids, 1);
    unsigned char raw[24];
    RAND_bytes(raw, (int) sizeof raw);
    for (int i = 0; i < 24; i++) snprintf(g_token + 2 * i, 3, "%02x", raw[i]);
}

void tearDown(void) {
    free(g.jwks);
    EVP_PKEY_free(g_key);
}

/* Verify `set`; return the kind and the reason. */
static axiam_error_kind_t verify(axiam_ssf_receiver_t *r, const char *set, axiam_ssf_reason_t *reason) {
    axiam_security_event_t ev;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_ssf_verify_set(r, set, &ev, reason, &err);
    axiam_security_event_dispose(&ev);
    return k;
}

static void expect_refused(axiam_ssf_receiver_t *r, const char *header, const char *body,
                           axiam_ssf_reason_t expected) {
    char *set = sign_set(g_key, header, body);
    axiam_ssf_reason_t reason = AXIAM_SSF_REASON_NONE;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_STRING(axiam_ssf_reason_code(expected), axiam_ssf_reason_code(reason));
    free(set);
}

/* ---- 1. A valid SET verifies, and every field is the claim's ---------------------- */

static void test_a_valid_set_verifies_and_every_field_is_the_claims(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", ",\"txn\":\"t-9\"");
    char *set = sign_set(g_key, HEADER("k1"), body);
    axiam_security_event_t ev;
    axiam_ssf_reason_t reason;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_verify_set(r, set, &ev, &reason, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
    TEST_ASSERT_EQUAL_STRING(jti, ev.jti);
    TEST_ASSERT_EQUAL_INT(1760000000, (int) ev.iat);
    TEST_ASSERT_EQUAL_STRING(ISSUER, ev.iss);
    TEST_ASSERT_EQUAL_STRING("\"" AUDIENCE "\"", ev.aud);
    TEST_ASSERT_EQUAL_STRING("t-9", ev.txn);
    TEST_ASSERT_EQUAL_STRING(AXIAM_SSF_EVENT_SESSION_REVOKED, ev.event_type);
    TEST_ASSERT_EQUAL_STRING("{\"event_timestamp\":1760000000,\"initiating_entity\":\"admin\"}", ev.event);
    TEST_ASSERT_EQUAL_STRING(SUB_ID, ev.sub_id);
    axiam_security_event_dispose(&ev);
    free(set);

    /* An array aud containing ours, the long typ in another case, and no txn. */
    random_jti(jti);
    payload(body, sizeof body, jti, "[\"https://other.example\",\"" AUDIENCE "\"]", NULL);
    set = sign_set(g_key, "{\"alg\":\"EdDSA\",\"typ\":\"Application/SecEvent+JWT\",\"kid\":\"k1\"}", body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_verify_set(r, set, &ev, &reason, &err));
    TEST_ASSERT_EQUAL_STRING("[\"https://other.example\",\"" AUDIENCE "\"]", ev.aud);
    TEST_ASSERT_NULL(ev.txn);
    axiam_security_event_dispose(&ev);
    free(set);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);
    TEST_ASSERT_EQUAL_INT(0, g.other_calls);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 2. typ and alg --------------------------------------------------------------- */

static void test_typ_and_alg_are_pinned(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    expect_refused(r, "{\"alg\":\"EdDSA\",\"kid\":\"k1\"}", body, AXIAM_SSF_REASON_INVALID_TYPE);
    expect_refused(r, "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"k1\"}", body,
                   AXIAM_SSF_REASON_INVALID_TYPE);
    expect_refused(r, "{\"alg\":\"none\",\"typ\":\"secevent+jwt\",\"kid\":\"k1\"}", body,
                   AXIAM_SSF_REASON_INVALID_KEY);
    expect_refused(r, "{\"alg\":\"HS256\",\"typ\":\"secevent+jwt\",\"kid\":\"k1\"}", body,
                   AXIAM_SSF_REASON_INVALID_KEY);
    expect_refused(r, "{\"alg\":\"EdDSA\",\"typ\":\"secevent+jwt\"}", body, AXIAM_SSF_REASON_INVALID_KEY);
    /* An unsigned `alg: none` token, in its usual shape: an empty signature. */
    char *h = b64("{\"alg\":\"none\",\"typ\":\"secevent+jwt\",\"kid\":\"k1\"}");
    char *p = b64(body);
    char unsigned_set[2048];
    snprintf(unsigned_set, sizeof unsigned_set, "%s.%s.", h, p);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, unsigned_set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    /* ... and what step 1 refuses. */
    static const char *const malformed[] = {"a.b", "a.b.c.d", "!!!.e30.AA", NULL};
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, malformed[i], &reason));
        TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_MALFORMED, reason);
    }
    char not_object[256];
    char *arr = b64("[1]");
    snprintf(not_object, sizeof not_object, "%s.%s.AA", h, arr);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, not_object, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_MALFORMED, reason);
    snprintf(not_object, sizeof not_object, "%s.%s.!!", h, p);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, not_object, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_MALFORMED, reason);
    free(h);
    free(p);
    free(arr);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 3. Another key, a tampered payload ------------------------------------------- */

static void test_another_key_and_a_tampered_payload_are_invalid_key(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    EVP_PKEY *other = new_key();
    char *forged = sign_set(other, HEADER("k1"), body);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, forged, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    free(forged);
    EVP_PKEY_free(other);

    char *genuine = sign_set(g_key, HEADER("k1"), body);
    /* Swap the payload for another one under the genuine signature. */
    char other_body[1024];
    payload(other_body, sizeof other_body, jti, "\"https://attacker.example\"", NULL);
    char *p = b64(other_body);
    char *dot1 = strchr(genuine, '.');
    char *dot2 = strchr(dot1 + 1, '.');
    char tampered[2048];
    snprintf(tampered, sizeof tampered, "%.*s.%s%s", (int) (dot1 - genuine), genuine, p, dot2);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, tampered, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    /* A truncated signature too. */
    genuine[strlen(genuine) - 4] = '\0';
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, genuine, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    free(p);
    free(genuine);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 4. iss and aud --------------------------------------------------------------- */

static void test_another_issuer_and_another_audience(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    snprintf(body, sizeof body,
             "{\"iss\":\"https://tx.example.com\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"%s\","
             "\"sub_id\":{},\"events\":{\"e\":{}}}", jti);
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_ISSUER);
    payload(body, sizeof body, jti, "\"https://other.example\"", NULL);
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_AUDIENCE);
    payload(body, sizeof body, jti, "[\"https://other.example\",7]", NULL);
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_AUDIENCE);
    payload(body, sizeof body, jti, "null", NULL);
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_AUDIENCE);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 5. A SET's claims -------------------------------------------------------------- */

static void test_claims_a_set_must_and_must_not_carry(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", ",\"exp\":1760000600");
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_REQUEST);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", ",\"sub\":\"u-1\"");
    expect_refused(r, HEADER("k1"), body, AXIAM_SSF_REASON_INVALID_REQUEST);
    static const char *const shapes[] = {
        /* two events */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"j1\",\"sub_id\":{},"
        "\"events\":{\"a\":{},\"b\":{}}}",
        /* no events member at all */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"j1\",\"sub_id\":{},"
        "\"events\":{}}",
        /* no jti */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"sub_id\":{},\"events\":{\"a\":{}}}",
        /* an empty jti */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"\",\"sub_id\":{},"
        "\"events\":{\"a\":{}}}",
        /* no iat */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"jti\":\"j1\",\"sub_id\":{},\"events\":{\"a\":{}}}",
        /* no sub_id */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"j1\",\"events\":{\"a\":{}}}",
        /* events not an object */
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"iat\":1,\"jti\":\"j1\",\"sub_id\":{},"
        "\"events\":[1]}",
    };
    for (size_t i = 0; i < sizeof shapes / sizeof shapes[0]; i++)
        expect_refused(r, HEADER("k1"), shapes[i], AXIAM_SSF_REASON_INVALID_REQUEST);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 6. Replay -------------------------------------------------------------------- */

static void test_the_same_set_twice_is_replayed_and_the_window_has_a_floor(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    char *set = sign_set(g_key, HEADER("k1"), body);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_REPLAYED, reason);
    /* Still a replay just inside the window; new again once it has passed. */
    g.now += AXIAM_SSF_MIN_REPLAY_WINDOW_S - 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    g.now += 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    free(set);

    /* A SET refused at an earlier step does not burn its jti. */
    char jti2[33];
    random_jti(jti2);
    payload(body, sizeof body, jti2, "\"https://other.example\"", NULL);
    set = sign_set(g_key, HEADER("k1"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_AUDIENCE, reason);
    free(set);
    payload(body, sizeof body, jti2, "\"" AUDIENCE "\"", NULL);
    set = sign_set(g_key, HEADER("k1"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    free(set);
    axiam_ssf_receiver_free(r);

    /* A window below seven days is refused at configuration. */
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.replay_window_s = AXIAM_SSF_MIN_REPLAY_WINDOW_S - 1;
    axiam_error_t err;
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, &cfg, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "replay_window"));
    cfg.replay_window_s = AXIAM_SSF_MIN_REPLAY_WINDOW_S * 2;
    r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 7. Unknown kid: one refetch, at most once a minute --------------------------- */

static void test_an_unknown_kid_forces_one_refetch_at_most_once_a_minute(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    char jti[33], body[1024];
    axiam_ssf_reason_t reason;
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    char *set = sign_set(g_key, HEADER("k1"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason)); /* primes the JWKS */
    free(set);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);

    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    set = sign_set(g_key, HEADER("k-unknown"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g.jwks_fetches, "exactly one refetch");
    free(set);

    set = sign_set(g_key, HEADER("k-other"), body);
    g.now += 30;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g.jwks_fetches, "no second refetch within the minute");
    free(set);

    /* A key rotated in: after the minute, the refetch finds it. */
    EVP_PKEY *keys[2] = {g_key, new_key()};
    const char *kids[2] = {"k1", "k2"};
    free(g.jwks);
    g.jwks = jwks_of(keys, kids, 2);
    g.now += 30;
    set = sign_set(keys[1], HEADER("k2"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(3, g.jwks_fetches);
    free(set);
    EVP_PKEY_free(keys[1]);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- 8. poll ---------------------------------------------------------------------- */

static void test_poll_passes_ack_and_set_errs_through_and_returns_verified_and_refused_apart(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    char good_jti[33], bad_jti[33], key_jti[33], body[1024];
    random_jti(good_jti);
    random_jti(bad_jti);
    random_jti(key_jti);
    payload(body, sizeof body, good_jti, "\"" AUDIENCE "\"", NULL);
    char *good = sign_set(g_key, HEADER("k1"), body);
    payload(body, sizeof body, bad_jti, "\"https://other.example\"", NULL);
    char *bad = sign_set(g_key, HEADER("k1"), body);
    payload(body, sizeof body, good_jti, "\"" AUDIENCE "\"", NULL);
    char *mismatched = sign_set(g_key, HEADER("k1"), body); /* returned under another key */
    char reply[8192];
    snprintf(reply, sizeof reply,
             "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"x-not-a-string\":7},"
             "\"moreAvailable\":true}",
             good_jti, good, bad_jti, bad, key_jti, mismatched);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll[1] = (answer_t){200, "{\"sets\":{},\"moreAvailable\":false}", 0};
    g.poll_len = 2;

    const char *ack[] = {"a1", "a2"};
    axiam_ssf_set_err_t errs[2];
    errs[0] = axiam_ssf_set_err_from_reason("r1", AXIAM_SSF_REASON_REPLAYED);
    errs[1].jti = "r2";
    errs[1].err = "invalid_key";
    errs[1].description = "rotated";
    axiam_ssf_poll_options_t opts;
    memset(&opts, 0, sizeof opts);
    opts.max_events = 10;
    opts.has_max_events = 1;
    opts.return_immediately = 1;
    opts.has_return_immediately = 1;
    opts.ack = ack;
    opts.ack_count = 2;
    opts.set_errs = errs;
    opts.set_errs_count = 2;

    axiam_ssf_poll_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "stream 1/x", &opts, &res, &err));
    TEST_ASSERT_EQUAL_STRING(BASE "/ssf/v1/poll/stream%201%2Fx", g.poll_url);
    TEST_ASSERT_EQUAL_STRING("{\"maxEvents\":10,\"returnImmediately\":true,\"ack\":[\"a1\",\"a2\"],"
                             "\"setErrs\":{\"r1\":{\"err\":\"invalid_request\"},"
                             "\"r2\":{\"err\":\"invalid_key\",\"description\":\"rotated\"}}}",
                             g.poll_body);
    char expected_auth[96];
    snprintf(expected_auth, sizeof expected_auth, "Bearer %s", g_token);
    TEST_ASSERT_TRUE_MESSAGE(strcmp(g.poll_auth, expected_auth) == 0, "the provider's bearer");
    TEST_ASSERT_TRUE(g.poll_had_cookie_signal);
    TEST_ASSERT_FALSE(g.poll_had_csrf);

    TEST_ASSERT_TRUE(res.more_available);
    TEST_ASSERT_EQUAL_INT(1, (int) res.events_count);
    TEST_ASSERT_EQUAL_STRING(good_jti, res.events[0].jti);
    TEST_ASSERT_EQUAL_INT(3, (int) res.refused_count);
    TEST_ASSERT_EQUAL_STRING(bad_jti, res.refused[0].jti);
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_AUDIENCE, res.refused[0].reason);
    TEST_ASSERT_EQUAL_STRING(key_jti, res.refused[1].jti);
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_REQUEST, res.refused[1].reason);
    TEST_ASSERT_EQUAL_STRING("x-not-a-string", res.refused[2].jti);
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_MALFORMED, res.refused[2].reason);
    axiam_ssf_poll_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.poll_calls, "nothing acknowledged on its own");

    /* No options: an empty body. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_STRING("{}", g.poll_body);
    TEST_ASSERT_EQUAL_INT(0, (int) res.events_count);
    TEST_ASSERT_FALSE(res.more_available);
    axiam_ssf_poll_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(2, g.poll_calls);

    /* Empty-but-present arrays are sent, not dropped. */
    memset(&opts, 0, sizeof opts);
    opts.ack = ack;
    opts.set_errs = errs;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", &opts, &res, &err));
    TEST_ASSERT_EQUAL_STRING("{\"ack\":[],\"setErrs\":{}}", g.poll_body);
    axiam_ssf_poll_result_dispose(&res);

    free(good);
    free(bad);
    free(mismatched);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* §32.8 helper test 8 (contract 1.59, P1): a batch of two SETs whose second names an
 * unknown kid while the refetch fails. `poll` MUST NOT keep a jti it does not return: the
 * first SET is returned, the second is neither returned nor refused nor recorded, and is
 * listed as unjudged. */
static void test_poll_returns_the_judged_set_when_a_later_set_of_the_batch_cannot_be_judged(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    char first_jti[33], second_jti[33], body[1024];
    random_jti(first_jti);
    random_jti(second_jti);
    payload(body, sizeof body, first_jti, "\"" AUDIENCE "\"", NULL);
    char *first = sign_set(g_key, HEADER("k1"), body);
    EVP_PKEY *rotated = new_key();
    payload(body, sizeof body, second_jti, "\"" AUDIENCE "\"", NULL);
    char *second = sign_set(rotated, HEADER("k9"), body); /* a kid the cached JWKS lacks */
    char reply[8192];
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\"}}", first_jti, first,
             second_jti, second);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    g.jwks_fail_from = 2; /* the cold fetch succeeds; the refetch for k9 fails */

    axiam_ssf_poll_result_t res;
    axiam_error_t err;
    axiam_error_kind_t kind = axiam_ssf_poll(r, "s1", NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_fetches);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_OK, kind,
                                  "the judged SET is returned, not discarded with the batch");
    TEST_ASSERT_EQUAL_INT(1, (int) res.events_count);
    TEST_ASSERT_EQUAL_STRING(first_jti, res.events[0].jti);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) res.refused_count, "an unjudged SET is not refused");
    TEST_ASSERT_EQUAL_INT(1, (int) res.unjudged_count);
    TEST_ASSERT_EQUAL_STRING(second_jti, res.unjudged[0]);
    axiam_ssf_poll_result_dispose(&res);
    TEST_ASSERT_NULL(res.unjudged);

    /* The first SET was recorded AND returned; the second was not recorded: once the
     * JWKS carries its key, it verifies rather than reading `replayed`. */
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, first, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_REPLAYED, reason);
    EVP_PKEY *both[] = {g_key, rotated};
    const char *kids[] = {"k1", "k9"};
    free(g.jwks);
    g.jwks = jwks_of(both, kids, 2);
    g.jwks_fail_from = 0;
    g.now += AXIAM_SSF_JWKS_REFETCH_INTERVAL_S;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, second, &reason));

    free(first);
    free(second);
    EVP_PKEY_free(rotated);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* P1 with a store that cannot answer on the second SET: the same outcome. */
static int g_failing_second_calls;
static int store_failing_on_second(void *ctx, const char *jti, long window_s) {
    (void) ctx;
    (void) jti;
    (void) window_s;
    return ++g_failing_second_calls == 1 ? 1 : -1;
}

static void test_poll_returns_the_judged_set_when_the_store_fails_on_a_later_set(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.access_token_provider = token_provider;
    cfg.replay_store = store_failing_on_second;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);
    char jti[3][33], body[1024], reply[12288];
    char *sets[3];
    for (int i = 0; i < 3; i++) {
        random_jti(jti[i]);
        payload(body, sizeof body, jti[i], "\"" AUDIENCE "\"", NULL);
        sets[i] = sign_set(g_key, HEADER("k1"), body);
    }
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}}",
             jti[0], sets[0], jti[1], sets[1], jti[2], sets[2]);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    g_failing_second_calls = 0;
    axiam_ssf_poll_result_t res;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(1, (int) res.events_count);
    TEST_ASSERT_EQUAL_STRING(jti[0], res.events[0].jti);
    TEST_ASSERT_EQUAL_INT(0, (int) res.refused_count);
    /* The batch stops at the failure: the SET after it is not judged either. */
    TEST_ASSERT_EQUAL_INT(2, (int) res.unjudged_count);
    TEST_ASSERT_EQUAL_STRING(jti[1], res.unjudged[0]);
    TEST_ASSERT_EQUAL_STRING(jti[2], res.unjudged[1]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_failing_second_calls, "nothing judged past the failure");
    axiam_ssf_poll_result_dispose(&res);

    /* A failure on the FIRST SET judges nothing: the failure is raised, nothing recorded. */
    g_failing_second_calls = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_STRING("the SSF replay store failed", err.message);
    TEST_ASSERT_EQUAL_INT(0, (int) res.events_count);
    TEST_ASSERT_EQUAL_INT(0, (int) res.unjudged_count);
    for (int i = 0; i < 3; i++) free(sets[i]);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

static void test_poll_is_not_retried_on_a_4xx_and_is_on_a_5xx(void) {
    axiam_client_t *c = make_client(); /* retry ENABLED */
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    axiam_ssf_poll_result_t res;
    axiam_error_t err;

    g.poll[0] = (answer_t){400, "{\"error\":\"validation_error\",\"message\":\"maxEvents\"}", 0};
    g.poll[1] = (answer_t){200, "{\"sets\":{}}", 0};
    g.poll_len = 2;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.poll_calls, "a 400 is not retried");

    g.poll_calls = 0;
    g.poll[0] = (answer_t){404, NULL, 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(1, g.poll_calls);

    g.poll_calls = 0;
    g.poll[0] = (answer_t){503, NULL, 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g.poll_calls, "a 503 is retried");
    axiam_ssf_poll_result_dispose(&res);

    g.poll_calls = 0;
    g.poll[0] = (answer_t){0, NULL, 1};
    g.poll[1] = (answer_t){0, NULL, 1};
    g.poll[2] = (answer_t){0, NULL, 1};
    g.poll_len = 3;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(3, g.poll_calls);

    g.poll_calls = 0;
    g.poll[0] = (answer_t){200, "not json", 0};
    g.poll_len = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    axiam_ssf_receiver_free(r);

    /* No provider: a local AuthError, no request. */
    r = make_receiver(c, 0);
    g.poll_calls = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g.poll_calls);
    axiam_ssf_receiver_free(r);
    r = make_receiver(c, 1);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, NULL, NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(NULL, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g.poll_calls);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- beyond the eight -------------------------------------------------------------- */

static void test_a_jwks_fetch_failure_is_a_network_error_not_a_verdict(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    char *set = sign_set(g_key, HEADER("k1"), body);
    g.jwks_status = 503;
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);

    /* ... and it aborts a poll rather than refusing SETs it could not judge. */
    char reply[4096];
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\"}}", jti, set);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    axiam_ssf_poll_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, (int) res.events_count);

    /* The SET was never recorded: once the keys are back it verifies -- after the
     * minute a failed fetch starts (P6, contract 1.60), inside which nothing is fetched. */
    g.jwks_status = 0;
    g.now += AXIAM_SSF_JWKS_REFETCH_INTERVAL_S;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    g.jwks_status = 200;
    free(g.jwks);
    g.jwks = strdup("[]");
    axiam_ssf_receiver_free(r);
    r = make_receiver(c, 0);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify(r, set, &reason));
    free(set);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

static void test_keys_from_a_discovery_document_whose_issuer_matches(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.discovery_url = DISCOVERY_URL;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);
    g.discovery = "{\"spec_version\":\"1_0\",\"issuer\":\"" ISSUER "\",\"jwks_uri\":\"" JWKS_URI "\"}";
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    char *set = sign_set(g_key, HEADER("k1"), body);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(1, g.discovery_fetches);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);
    axiam_ssf_receiver_free(r);

    /* A document naming another issuer, or no https jwks_uri, is refused. */
    static const char *const docs[] = {
        "{\"issuer\":\"https://evil.example\",\"jwks_uri\":\"" JWKS_URI "\"}",
        "{\"issuer\":\"" ISSUER "\",\"jwks_uri\":\"http://tx.example.com/jwks\"}",
        "{\"issuer\":\"" ISSUER "\"}",
        "[]",
        NULL,
    };
    for (int i = 0; i < 5; i++) {
        g.discovery = docs[i];
        r = axiam_ssf_receiver_new(c, &cfg, &err);
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify(r, set, &reason));
        TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
        axiam_ssf_receiver_free(r);
    }
    free(set);
    axiam_client_free(c);
}

static void test_configuration_refusals(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(NULL, &cfg, &err));
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, NULL, &err));
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, &cfg, &err)); /* no issuer */
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, &cfg, &err)); /* no key source */
    cfg.jwks_uri = JWKS_URI;
    cfg.discovery_url = DISCOVERY_URL;
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, &cfg, &err)); /* both */
    cfg.discovery_url = NULL;
    cfg.jwks_uri = "http://tx.example.com/jwks";
    TEST_ASSERT_NULL(axiam_ssf_receiver_new(c, &cfg, &err)); /* plaintext */
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    axiam_ssf_receiver_free(NULL);
    axiam_security_event_dispose(NULL);
    axiam_ssf_poll_result_dispose(NULL);
    axiam_security_event_t ev;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_verify_set(NULL, "x", &ev, NULL, &err));
    axiam_client_free(c);
}

static void test_reason_codes_and_their_rfc_8935_answers(void) {
    static const struct {
        axiam_ssf_reason_t reason;
        const char *code;
        const char *push;
    } table[] = {
        {AXIAM_SSF_REASON_MALFORMED, "malformed", "invalid_request"},
        {AXIAM_SSF_REASON_INVALID_TYPE, "invalid_type", "invalid_request"},
        {AXIAM_SSF_REASON_INVALID_KEY, "invalid_key", "invalid_key"},
        {AXIAM_SSF_REASON_INVALID_ISSUER, "invalid_issuer", "invalid_issuer"},
        {AXIAM_SSF_REASON_INVALID_AUDIENCE, "invalid_audience", "invalid_audience"},
        {AXIAM_SSF_REASON_INVALID_REQUEST, "invalid_request", "invalid_request"},
        {AXIAM_SSF_REASON_REPLAYED, "replayed", "invalid_request"},
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
        TEST_ASSERT_EQUAL_STRING(table[i].code, axiam_ssf_reason_code(table[i].reason));
        TEST_ASSERT_EQUAL_STRING(table[i].push, axiam_ssf_push_error_code(table[i].reason));
        axiam_ssf_set_err_t e = axiam_ssf_set_err_from_reason("j", table[i].reason);
        TEST_ASSERT_EQUAL_STRING(table[i].push, e.err);
        TEST_ASSERT_NULL(e.description);
    }
    TEST_ASSERT_EQUAL_STRING("", axiam_ssf_reason_code(AXIAM_SSF_REASON_NONE));
}

/* A shared store: it sees the jti, and its answer decides. */
static int g_store_calls;
static int g_store_answer;
static int shared_store(void *ctx, const char *jti, long window_s) {
    (void) ctx;
    (void) jti;
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_MIN_REPLAY_WINDOW_S, (int) window_s);
    g_store_calls++;
    return g_store_answer;
}

static void test_a_pluggable_replay_store_decides(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.replay_store = shared_store;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    char *set = sign_set(g_key, HEADER("k1"), body);
    axiam_ssf_reason_t reason;
    g_store_calls = 0;
    g_store_answer = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, set, &reason));
    g_store_answer = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_REPLAYED, reason);
    g_store_answer = -1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
    TEST_ASSERT_EQUAL_INT(3, g_store_calls);
    free(set);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

static axiam_error_kind_t failing_provider(void *ctx, axiam_sensitive_t **out, axiam_error_t *err) {
    (void) ctx;
    *out = NULL;
    axiam_error_set(err, AXIAM_ERR_AUTH, 401, "no token today");
    return AXIAM_ERR_AUTH;
}

static axiam_error_kind_t empty_provider(void *ctx, axiam_sensitive_t **out, axiam_error_t *err) {
    (void) ctx;
    (void) err;
    *out = NULL;
    return AXIAM_OK;
}

static void test_a_failing_token_provider_stops_the_poll(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.access_token_provider = failing_provider;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    axiam_ssf_poll_result_t res;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_STRING("no token today", err.message);
    axiam_ssf_receiver_free(r);
    cfg.access_token_provider = empty_provider;
    r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g.poll_calls);
    axiam_ssf_receiver_free(r);
    /* A closed client polls nothing. */
    r = make_receiver(c, 1);
    axiam_client_close(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g.poll_calls);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- §32.8 helper test 6, the store-failure case (contract 1.60 B1; P4) ------------
 *
 * A replay store that cannot answer gives NO verdict. This store's answer is a bare int
 * the SDK's interface already makes fallible (a negative return), so B1 is a *verify* row:
 * the failure sets the failure channel (AXIAM_ERR_NETWORK, no reason code) and is never
 * read as `replayed`; the SET is in neither `events` nor `refused`, is not recorded (the
 * store, once it answers again, finds it fresh) and is not acknowledged. C's poll never
 * acknowledges on its own; the observable is that the SET is listed `unjudged` and nowhere
 * else, which is what keeps the caller from acknowledging or refusing it. */
static char g_b1_down_jti[40];
static int g_b1_down;
static int g_b1_calls_for_down_jti;
static int store_that_can_be_down(void *ctx, const char *jti, long window_s) {
    (void) ctx;
    (void) window_s;
    if (g_b1_down && strcmp(jti, g_b1_down_jti) == 0) {
        g_b1_calls_for_down_jti++;
        return -1; /* cannot answer */
    }
    return 1; /* recorded */
}

static void test_6_a_store_that_cannot_answer_gives_no_verdict_B1(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.access_token_provider = token_provider;
    cfg.replay_store = store_that_can_be_down;
    axiam_error_t err;
    axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);

    char jti[2][33], body[1024], reply[8192];
    char *sets[2];
    for (int i = 0; i < 2; i++) {
        random_jti(jti[i]);
        payload(body, sizeof body, jti[i], "\"" AUDIENCE "\"", NULL);
        sets[i] = sign_set(g_key, HEADER("k1"), body);
    }
    snprintf(g_b1_down_jti, sizeof g_b1_down_jti, "%s", jti[1]);

    /* verify_set: the failure channel is set, and it is not a verdict. */
    g_b1_down = 1;
    g_b1_calls_for_down_jti = 0;
    axiam_security_event_t ev;
    axiam_ssf_reason_t reason = AXIAM_SSF_REASON_REPLAYED; /* must be reset, not left */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_verify_set(r, sets[1], &ev, &reason, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_SSF_REASON_NONE, reason,
                                  "a store failure carries no reason code, least of all replayed");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_NULL(ev.jti);
    axiam_security_event_dispose(&ev);

    /* poll, a batch of two whose SECOND the store cannot answer for: the first is judged,
     * the second is in neither `events` nor `refused` -- it is `unjudged`. */
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\"}}", jti[0], sets[0],
             jti[1], sets[1]);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    axiam_ssf_poll_result_t res;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(1, (int) res.events_count);
    TEST_ASSERT_EQUAL_STRING(jti[0], res.events[0].jti);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) res.refused_count, "never refused, least of all replayed");
    TEST_ASSERT_EQUAL_INT(1, (int) res.unjudged_count);
    TEST_ASSERT_EQUAL_STRING(jti[1], res.unjudged[0]);
    axiam_ssf_poll_result_dispose(&res);

    /* Not recorded: once the store answers again the same SET is judged fresh (a recorded
     * jti would read `replayed`), and the first SET -- recorded -- is the replay. */
    g_b1_down = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, sets[1], &reason));
    axiam_ssf_receiver_free(r);

    /* The same with the default in-memory store: it cannot fail, and records only a verdict. */
    r = make_receiver(c, 0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(r, sets[0], &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, sets[0], &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_REPLAYED, reason);
    axiam_ssf_receiver_free(r);
    for (int i = 0; i < 2; i++) free(sets[i]);
    axiam_client_free(c);
}

/* ---- §34.2 P6 (contract 1.60): the key cache's lifetime and the counted fetches ---- */

/* A fresh SET signed with k1, for the cases below. */
static char *fresh_k1_set(void) {
    char jti[33], body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    return sign_set(g_key, HEADER("k1"), body);
}

static axiam_error_kind_t verify_fresh(axiam_ssf_receiver_t *r, axiam_ssf_reason_t *reason) {
    char *set = fresh_k1_set();
    axiam_error_kind_t k = verify(r, set, reason);
    free(set);
    return k;
}

static void test_p6_the_key_cache_expires_within_ten_minutes(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_TRUE(AXIAM_SSF_JWKS_CACHE_TTL_S <= 600);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);

    g.now += AXIAM_SSF_JWKS_CACHE_TTL_S - 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.jwks_fetches, "served from the cache while it lives");

    /* Expired: the next SET fetches again, and a key the transmitter removed stops
     * verifying -- the expired copy is not read. */
    g.now += 1;
    EVP_PKEY *replacement = new_key();
    const char *kids[] = {"k2"};
    free(g.jwks);
    g.jwks = jwks_of(&replacement, kids, 1);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_INVALID_KEY, reason);
    /* The refresh, then the one unknown-kid refetch (a successful refresh is not counted). */
    TEST_ASSERT_EQUAL_INT(3, g.jwks_fetches);
    EVP_PKEY_free(replacement);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

static void test_p6_a_failed_fill_counts_and_a_set_inside_the_minute_makes_no_fetch(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    axiam_ssf_reason_t reason;
    g.jwks_status = 503;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);

    /* Inside the minute: no fetch, the same no-verdict failure -- even with the JWKS back. */
    g.jwks_status = 0;
    g.now += AXIAM_SSF_JWKS_REFETCH_INTERVAL_S - 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.jwks_fetches, "no fetch within the minute of a failed one");

    /* ... and in `poll` the SET is unjudged, never refused: the first SET failing, the
     * failure is raised with nothing recorded. */
    char *set = fresh_k1_set();
    char jti[33], reply[4096];
    random_jti(jti);
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\"}}", jti, set);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    axiam_ssf_poll_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, (int) res.refused_count);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);
    free(set);

    /* After the minute the fill runs, succeeds, and is not counted: an unknown kid right
     * after it is refetched once. */
    g.now += 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(2, g.jwks_fetches);
    char body[1024];
    random_jti(jti);
    payload(body, sizeof body, jti, "\"" AUDIENCE "\"", NULL);
    set = sign_set(g_key, HEADER("k-unknown"), body);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, verify(r, set, &reason));
    TEST_ASSERT_EQUAL_INT(3, g.jwks_fetches);
    free(set);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

static void test_p6_a_failed_refresh_of_an_expired_cache_counts(void) {
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_t *r = make_receiver(c, 0);
    axiam_ssf_reason_t reason;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_fetches);

    g.now += AXIAM_SSF_JWKS_CACHE_TTL_S;
    g.jwks_status = 503;
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK, verify_fresh(r, &reason),
                                  "an expired cache is not a fallback");
    TEST_ASSERT_EQUAL_INT(AXIAM_SSF_REASON_NONE, reason);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_fetches);

    g.jwks_status = 0;
    g.now += 30;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g.jwks_fetches, "the failed refresh started the minute");

    g.now += 30;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify_fresh(r, &reason));
    TEST_ASSERT_EQUAL_INT(3, g.jwks_fetches);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

/* ---- §19.1 `ssf_unjudged` (contract 1.60, SHOULD) ----------------------------------- */

static int g_unjudged_events;
static size_t g_unjudged_count;
static char g_unjudged_category[32];
static char g_unjudged_operation[32];

static void record_unjudged(void *ctx, const axiam_telemetry_event_t *ev) {
    (void) ctx;
    if (ev->kind != AXIAM_TELEMETRY_SSF_UNJUDGED) return;
    g_unjudged_events++;
    g_unjudged_count = ev->unjudged_count;
    snprintf(g_unjudged_category, sizeof g_unjudged_category, "%s",
             ev->failure_category ? ev->failure_category : "");
    snprintf(g_unjudged_operation, sizeof g_unjudged_operation, "%s",
             ev->operation ? ev->operation : "");
}

static void test_a_poll_leaving_sets_unjudged_emits_ssf_unjudged(void) {
    axiam_client_t *c = make_client();
    c->telemetry.fn = record_unjudged;
    c->telemetry.ctx = NULL;
    g_unjudged_events = 0;

    /* key_fetch: the second SET names a kid the cache lacks and the refetch fails. */
    axiam_ssf_receiver_t *r = make_receiver(c, 1);
    char jti[3][33], body[1024], reply[12288];
    char *sets[3];
    EVP_PKEY *rotated = new_key();
    for (int i = 0; i < 3; i++) {
        random_jti(jti[i]);
        payload(body, sizeof body, jti[i], "\"" AUDIENCE "\"", NULL);
        sets[i] = i == 0 ? sign_set(g_key, HEADER("k1"), body) : sign_set(rotated, HEADER("k9"), body);
    }
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}}",
             jti[0], sets[0], jti[1], sets[1], jti[2], sets[2]);
    g.poll[0] = (answer_t){200, reply, 0};
    g.poll_len = 1;
    g.jwks_fail_from = 2;
    axiam_ssf_poll_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(2, (int) res.unjudged_count);
    TEST_ASSERT_EQUAL_INT(1, g_unjudged_events);
    TEST_ASSERT_EQUAL_STRING("ssf.poll", g_unjudged_operation);
    TEST_ASSERT_EQUAL_INT(2, (int) g_unjudged_count);
    TEST_ASSERT_EQUAL_STRING("key_fetch", g_unjudged_category);
    axiam_ssf_poll_result_dispose(&res);
    axiam_ssf_receiver_free(r);
    g.jwks_fail_from = 0;

    /* replay_store: the store cannot answer on the second SET. */
    axiam_ssf_receiver_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.issuer = ISSUER;
    cfg.audience = AUDIENCE;
    cfg.jwks_uri = JWKS_URI;
    cfg.access_token_provider = token_provider;
    cfg.replay_store = store_failing_on_second;
    r = axiam_ssf_receiver_new(c, &cfg, &err);
    TEST_ASSERT_NOT_NULL(r);
    for (int i = 0; i < 3; i++) {
        free(sets[i]);
        random_jti(jti[i]);
        payload(body, sizeof body, jti[i], "\"" AUDIENCE "\"", NULL);
        sets[i] = sign_set(g_key, HEADER("k1"), body);
    }
    snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}}",
             jti[0], sets[0], jti[1], sets[1], jti[2], sets[2]);
    g.poll[0] = (answer_t){200, reply, 0};
    g_failing_second_calls = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(2, g_unjudged_events);
    TEST_ASSERT_EQUAL_INT(2, (int) g_unjudged_count);
    TEST_ASSERT_EQUAL_STRING("replay_store", g_unjudged_category);
    axiam_ssf_poll_result_dispose(&res);

    /* A poll that judges every SET, or raises, emits nothing. */
    g.poll[0] = (answer_t){200, "{\"sets\":{},\"moreAvailable\":false}", 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_poll(r, "s1", NULL, &res, &err));
    axiam_ssf_poll_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(2, g_unjudged_events);

    for (int i = 0; i < 3; i++) free(sets[i]);
    EVP_PKEY_free(rotated);
    axiam_ssf_receiver_free(r);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_valid_set_verifies_and_every_field_is_the_claims);
    RUN_TEST(test_typ_and_alg_are_pinned);
    RUN_TEST(test_another_key_and_a_tampered_payload_are_invalid_key);
    RUN_TEST(test_another_issuer_and_another_audience);
    RUN_TEST(test_claims_a_set_must_and_must_not_carry);
    RUN_TEST(test_the_same_set_twice_is_replayed_and_the_window_has_a_floor);
    RUN_TEST(test_an_unknown_kid_forces_one_refetch_at_most_once_a_minute);
    RUN_TEST(test_poll_passes_ack_and_set_errs_through_and_returns_verified_and_refused_apart);
    RUN_TEST(test_poll_returns_the_judged_set_when_a_later_set_of_the_batch_cannot_be_judged);
    RUN_TEST(test_poll_returns_the_judged_set_when_the_store_fails_on_a_later_set);
    RUN_TEST(test_poll_is_not_retried_on_a_4xx_and_is_on_a_5xx);
    RUN_TEST(test_a_jwks_fetch_failure_is_a_network_error_not_a_verdict);
    RUN_TEST(test_keys_from_a_discovery_document_whose_issuer_matches);
    RUN_TEST(test_configuration_refusals);
    RUN_TEST(test_reason_codes_and_their_rfc_8935_answers);
    RUN_TEST(test_a_pluggable_replay_store_decides);
    RUN_TEST(test_a_failing_token_provider_stops_the_poll);
    RUN_TEST(test_6_a_store_that_cannot_answer_gives_no_verdict_B1);
    RUN_TEST(test_p6_the_key_cache_expires_within_ten_minutes);
    RUN_TEST(test_p6_a_failed_fill_counts_and_a_set_inside_the_minute_makes_no_fetch);
    RUN_TEST(test_p6_a_failed_refresh_of_an_expired_cache_counts);
    RUN_TEST(test_a_poll_leaving_sets_unjudged_emits_ssf_unjudged);
    return UNITY_END();
}
