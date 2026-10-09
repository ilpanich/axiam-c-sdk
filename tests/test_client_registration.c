/*
 * CONTRACT.md §28.12 (contract 1.53) — RFC 7592 client configuration:
 * axiam_read_client_registration(), axiam_update_client_registration(),
 * axiam_delete_client_registration().
 *
 * §28.12.6's five required tests, plus the http-loopback half of rule 1, the §16 read
 * retry (and its refusal to retry a 4xx), and the tolerant decoder.
 *
 * Every token and secret here is generated at run time: a literal would be a credential
 * in the repository, and would let a redaction test pass by coincidence. A failing
 * redaction assertion reports an offset, never the secret or the rendering it was found
 * in.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management.h"
#include "cJSON.h"
#include "internal.h"
#include "test_util.h"

#define BASE "https://iam.example.com"
#define REG_PATH "/oauth2/register/7d0c1b8e-4b0c-4a43-9a3c-1f2e3d4c5b6a"
#define REG_URI BASE REG_PATH "?tenant_id=11111111-1111-1111-1111-111111111111"

/* ------------------------------------------------------------------ */
/* A recording fake transport with a short queue of answers           */
/* ------------------------------------------------------------------ */

#define MAX_CALLS 16

typedef struct {
    long status;
    const char *body;
    int transport_fails;
} answer_t;

typedef struct {
    answer_t queue[MAX_CALLS];
    int queue_len;
    int served;
    int calls;
    char methods[MAX_CALLS][8];
    char urls[MAX_CALLS][512];
    char bodies[MAX_CALLS][4096];
    char authorization[MAX_CALLS][512];
    int has_cookie[MAX_CALLS];
    char cookie[MAX_CALLS][256];
    int has_csrf[MAX_CALLS];
    int has_tenant[MAX_CALLS];
    int has_content_type[MAX_CALLS];
    int refresh_calls;
    long sleeps[MAX_CALLS];
    int n_sleeps;
} fake_t;

static fake_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void) ctx;
    int i = g.calls < MAX_CALLS ? g.calls : MAX_CALLS - 1;
    g.calls++;
    snprintf(g.methods[i], sizeof g.methods[i], "%s", req->method ? req->method : "");
    snprintf(g.urls[i], sizeof g.urls[i], "%s", req->url ? req->url : "");
    snprintf(g.bodies[i], sizeof g.bodies[i], "%s", req->body ? req->body : "");
    const char *auth = axiam_kv_get(req->headers, "Authorization");
    snprintf(g.authorization[i], sizeof g.authorization[i], "%s", auth ? auth : "");
    const char *cookie = axiam_kv_get(req->headers, "Cookie");
    g.has_cookie[i] = cookie != NULL;
    snprintf(g.cookie[i], sizeof g.cookie[i], "%s", cookie ? cookie : "");
    g.has_csrf[i] = axiam_kv_get(req->headers, "X-CSRF-Token") != NULL;
    g.has_tenant[i] = axiam_kv_get(req->headers, "X-Tenant-ID") != NULL;
    g.has_content_type[i] = axiam_kv_get(req->headers, "Content-Type") != NULL;
    if (req->url && strstr(req->url, "/auth/refresh")) g.refresh_calls++;

    memset(resp, 0, sizeof *resp);
    answer_t a = {204, NULL, 0};
    if (g.served < g.queue_len) a = g.queue[g.served++];
    if (a.transport_fails) {
        resp->transport_err = 7;
        resp->transport_msg = strdup("connection reset");
        return 1;
    }
    resp->status = a.status;
    if (a.body) resp->body = strdup(a.body);
    /* A login answer hands out a CSRF token, so a session is genuinely present. */
    if (req->url && strstr(req->url, "/auth/login"))
        resp->headers = axiam_kv_append(resp->headers, "X-CSRF-Token", "csrf-from-login");
    return 0;
}

static void queue(long status, const char *body) {
    g.queue[g.queue_len].status = status;
    g.queue[g.queue_len].body = body;
    g.queue[g.queue_len].transport_fails = 0;
    g.queue_len++;
}

static void queue_transport_failure(void) {
    g.queue[g.queue_len].transport_fails = 1;
    g.queue_len++;
}

static void fake_sleep(void *ctx, long ms) {
    (void) ctx;
    if (g.n_sleeps < MAX_CALLS) g.sleeps[g.n_sleeps++] = ms;
}

static double fake_jitter(void *ctx) {
    (void) ctx;
    return 0.0;
}

static axiam_client_t *make_client_at(const char *base) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    /* Retry stays ENABLED (the default): a "not retried" assertion on a client that
     * never retries would prove nothing. Only the wait is faked. */
    c->sleep_fn = fake_sleep;
    c->jitter_fn = fake_jitter;
    return c;
}

static axiam_client_t *make_client(void) { return make_client_at(BASE); }

/* A client with a REAL logged-in session: a password login through the same transport,
 * which captures a CSRF token and marks the client authenticated. */
static axiam_client_t *make_signed_in_client(void) {
    axiam_client_t *c = make_client();
    queue(200, "{\"authenticated\":true,\"mfa_required\":false}");
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "admin@example.com", "pw", &res, &err));
    axiam_login_result_dispose(&res);
    return c;
}

/* 32 random bytes, hex: a token nobody wrote down. */
static void random_token(char *out, size_t cap) {
    unsigned char raw[24];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    for (size_t i = 0; i < sizeof raw && n + 2 < cap; i++) {
        out[n++] = hex[raw[i] >> 4];
        out[n++] = hex[raw[i] & 0xF];
    }
    out[n] = '\0';
}

/* No 8-character substring of `secret` appears in `haystack`. On failure the message
 * names an offset only: a failing redaction test must not print what it caught. */
static void assert_no_fragment(const char *haystack, const char *secret) {
    size_t n = strlen(secret);
    for (size_t i = 0; i + 8 <= n; i++) {
        char frag[9];
        memcpy(frag, secret + i, 8);
        frag[8] = '\0';
        if (haystack && strstr(haystack, frag)) {
            char msg[96];
            snprintf(msg, sizeof msg, "an 8-character fragment of a secret (offset %zu) leaked", i);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

void setUp(void) { memset(&g, 0, sizeof g); }
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* 1. Origin refusal (rule 1)                                         */
/* ------------------------------------------------------------------ */

static void test_a_uri_at_another_origin_is_refused_before_any_request(void) {
    axiam_client_t *c = make_client();
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    static const char *const elsewhere[] = {
        "https://evil.example.com" REG_PATH,       /* another host */
        "https://iam.example.com:8443" REG_PATH,   /* another port */
        "http://iam.example.com" REG_PATH,         /* http against an https base */
        "https://user@iam.example.com" REG_PATH,   /* userinfo */
        "ftp://iam.example.com" REG_PATH,          /* not http(s) */
        "ftp://iam.example.com:21" REG_PATH,       /* not http(s), with an explicit port */
        "/oauth2/register/relative",               /* not absolute */
        NULL,                                      /* no URI at all */
    };
    for (size_t i = 0; i < sizeof elsewhere / sizeof elsewhere[0]; i++) {
        axiam_error_t err;
        axiam_client_registration_t *out = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_read_client_registration(c, elsewhere[i], token, &out, &err));
        TEST_ASSERT_NULL(out);
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));
        /* The message names no part of the URI and none of the token. */
        TEST_ASSERT_NULL(strstr(err.message, "evil"));
        TEST_ASSERT_NULL(strstr(err.message, "8443"));
        assert_no_fragment(err.message, tok);

        axiam_client_registration_t meta = {0};
        meta.client_id = (char *) "client-1";
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_update_client_registration(c, elsewhere[i], token, &meta,
                                                               &out, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_delete_client_registration(c, elsewhere[i], token, &err));
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g.calls, "the mock must record no request");
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

static void test_http_is_accepted_only_against_an_http_loopback_base(void) {
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    axiam_error_t err;
    axiam_client_registration_t *out = NULL;

    /* An http base on loopback: the same-origin http URI goes out (default port too). */
    axiam_client_t *c = make_client_at("http://127.0.0.1:8080/");
    queue(200, "{\"client_id\":\"c1\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_read_client_registration(
                                        c, "http://127.0.0.1:8080/oauth2/register/c1", token,
                                        &out, &err));
    TEST_ASSERT_EQUAL_INT(1, g.calls);
    axiam_client_registration_free(out);
    axiam_client_free(c);

    /* An http base NOT on loopback (the transport guard would refuse it later; rule 1
     * refuses it first, with no request). */
    memset(&g, 0, sizeof g);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "http://iam.internal.example");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (c) {
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_read_client_registration(
            c, "http://iam.internal.example/oauth2/register/c1", token, &out, &err));
        TEST_ASSERT_EQUAL_INT(0, g.calls);
        axiam_client_free(c);
    }

    /* A base URL whose origin cannot be parsed (the constructor only checks the
     * scheme): nothing can be at its origin, so every URI is refused. */
    memset(&g, 0, sizeof g);
    c = make_client_at("https://iam.example.com:notaport/");
    if (c) {
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_read_client_registration(
            c, "https://iam.example.com/oauth2/register/c1", token, &out, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_EQUAL_INT(0, g.calls);
        axiam_client_free(c);
    }

    /* A port spelled out as the scheme default is the same origin. */
    memset(&g, 0, sizeof g);
    c = make_client();
    queue(200, "{\"client_id\":\"c1\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_read_client_registration(
        c, "https://IAM.example.com:443/oauth2/register/c1", token, &out, &err));
    axiam_client_registration_free(out);
    axiam_client_free(c);
    axiam_sensitive_free(token);
}

static void test_a_missing_token_is_refused_locally(void) {
    axiam_client_t *c = make_client();
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_delete_client_registration(c, REG_URI, empty, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_delete_client_registration(c, REG_URI, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(0, g.calls);
    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* 2. Header only (rules 2 and 3), with a real session present        */
/* ------------------------------------------------------------------ */

static void test_read_and_delete_send_only_the_bearer(void) {
    axiam_client_t *c = make_signed_in_client();
    int login_calls = g.calls;
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    char expected_auth[128];
    snprintf(expected_auth, sizeof expected_auth, "Bearer %s", tok);

    queue(200, "{\"client_id\":\"c1\",\"client_name\":\"Agent\"}");
    queue(204, NULL);
    axiam_error_t err;
    axiam_client_registration_t *out = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_delete_client_registration(c, REG_URI, token, &err));
    TEST_ASSERT_EQUAL_INT(login_calls + 2, g.calls);

    static const char *const methods[] = {"GET", "DELETE"};
    for (int k = 0; k < 2; k++) {
        int i = login_calls + k;
        TEST_ASSERT_EQUAL_STRING(methods[k], g.methods[i]);
        /* The URI verbatim, its query (tenant_id) kept and nothing added. */
        TEST_ASSERT_EQUAL_STRING(REG_URI, g.urls[i]);
        TEST_ASSERT_TRUE_MESSAGE(strcmp(g.authorization[i], expected_auth) == 0,
                                 "Authorization is not exactly the registration bearer");
        TEST_ASSERT_EQUAL_STRING("", g.bodies[i]);
        /* Not the SDK's session: no CSRF token, no tenant header, and the cookie jar
         * withheld (the empty Cookie entry is that signal to the default transport). */
        TEST_ASSERT_FALSE(g.has_csrf[i]);
        TEST_ASSERT_FALSE(g.has_tenant[i]);
        TEST_ASSERT_TRUE(g.has_cookie[i]);
        TEST_ASSERT_EQUAL_STRING("", g.cookie[i]);
        TEST_ASSERT_FALSE(g.has_content_type[i]);
    }
    TEST_ASSERT_EQUAL_STRING("c1", out->client_id);
    axiam_client_registration_free(out);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

static void test_a_device_bearer_is_never_attached(void) {
    /* A client holding a §6.1 device credential sends it as a bearer on every SESSION
     * request; the registration requests carry the registration's bearer instead. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, BASE);
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_client_cert(
        cfg, "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        "-----BEGIN TEST KEY-----\nZmFrZQ==\n-----END TEST KEY-----\n"));
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    char device_tok[64], reg_tok[64], device_body[256];
    random_token(device_tok, sizeof device_tok);
    random_token(reg_tok, sizeof reg_tok);
    snprintf(device_body, sizeof device_body,
             "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":900}",
             device_tok);
    queue(200, device_body);
    axiam_device_auth_result_t dev;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_authenticate_device(c, &dev, &err));
    axiam_device_auth_result_dispose(&dev);

    axiam_sensitive_t *token = axiam_sensitive_new(reg_tok);
    queue(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_delete_client_registration(c, REG_URI, token, &err));
    assert_no_fragment(g.authorization[1], device_tok);
    TEST_ASSERT_NOT_NULL(strstr(g.authorization[1], reg_tok));
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* 3. Update body (rule 4) and no retry (rule 5)                      */
/* ------------------------------------------------------------------ */

static void test_update_drops_the_server_stated_members_and_returns_the_rotated_token(void) {
    axiam_client_t *c = make_client();
    char old_tok[64], new_tok[64], secret[64];
    random_token(old_tok, sizeof old_tok);
    random_token(new_tok, sizeof new_tok);
    random_token(secret, sizeof secret);

    /* What a registration response carries: all five server-stated members, a JWKS, an
     * unknown member and a CIBA member the struct does not name. */
    char read_body[1536];
    snprintf(read_body, sizeof read_body,
             "{\"client_id\":\"c1\",\"client_id_issued_at\":1700000000,"
             "\"client_name\":\"Agent\",\"redirect_uris\":[\"https://app.example/cb\"],"
             "\"grant_types\":[\"authorization_code\",\"urn:openid:params:grant-type:ciba\"],"
             "\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"private_key_jwt\","
             "\"scope\":\"openid\",\"registration_client_uri\":\"%s\","
             "\"client_secret_expires_at\":0,\"jwks\":{\"keys\":[]},"
             "\"jwks_uri\":\"https://app.example/jwks\",\"client_secret\":\"%s\","
             "\"registration_access_token\":\"%s\","
             "\"backchannel_token_delivery_mode\":\"poll\",\"x_vendor\":{\"a\":1}}",
             REG_URI, secret, old_tok);
    axiam_error_t err;
    axiam_client_registration_t *meta = axiam_client_registration_parse(read_body, &err);
    TEST_ASSERT_NOT_NULL(meta);
    TEST_ASSERT_NOT_NULL(meta->registration_access_token);
    TEST_ASSERT_NOT_NULL(meta->client_secret);
    TEST_ASSERT_TRUE(meta->has_client_id_issued_at);
    TEST_ASSERT_TRUE(meta->has_client_secret_expires_at);

    char updated[512];
    snprintf(updated, sizeof updated,
             "{\"client_id\":\"c1\",\"client_name\":\"Agent 2\",\"registration_access_token\":\"%s\"}",
             new_tok);
    queue(200, updated);
    axiam_sensitive_t *token = axiam_sensitive_new(old_tok);
    axiam_client_registration_t *out = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_update_client_registration(c, REG_URI, token, meta, &out, &err));
    TEST_ASSERT_EQUAL_INT(1, g.calls);
    TEST_ASSERT_EQUAL_STRING("PUT", g.methods[0]);
    TEST_ASSERT_EQUAL_STRING(REG_URI, g.urls[0]);
    TEST_ASSERT_TRUE(g.has_content_type[0]);

    cJSON *sent = cJSON_Parse(g.bodies[0]);
    TEST_ASSERT_NOT_NULL(sent);
    static const char *const dropped[] = {
        "registration_access_token", "registration_client_uri", "client_secret_expires_at",
        "client_id_issued_at", "client_secret",
    };
    for (size_t i = 0; i < 5; i++)
        TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, dropped[i]), dropped[i]);
    TEST_ASSERT_EQUAL_STRING("c1", cJSON_GetObjectItemCaseSensitive(sent, "client_id")->valuestring);
    /* Everything else round-trips, the members this SDK does not model included. */
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(sent, "jwks"));
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(sent, "jwks_uri"));
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(sent, "backchannel_token_delivery_mode"));
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(sent, "x_vendor"));
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(sent, "grant_types")));
    cJSON_Delete(sent);
    /* Neither the old token nor the secret is anywhere in the body. */
    assert_no_fragment(g.bodies[0], old_tok);
    assert_no_fragment(g.bodies[0], secret);

    /* The rotated token is returned. */
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE_MESSAGE(strcmp(axiam_sensitive_reveal(out->registration_access_token), new_tok) == 0,
                             "the update did not return the rotated token");
    TEST_ASSERT_EQUAL_STRING("Agent 2", out->client_name);

    axiam_client_registration_free(out);
    axiam_client_registration_free(meta);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

static void test_writes_are_never_retried_and_the_read_is(void) {
    axiam_client_t *c = make_client(); /* retry ENABLED */
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    axiam_client_registration_t meta = {0};
    meta.client_id = (char *) "c1";
    axiam_error_t err;
    axiam_client_registration_t *out = NULL;

    queue(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.calls, "update: exactly one request on a 503");

    memset(&g, 0, sizeof g);
    queue_transport_failure();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.calls, "update: exactly one request on a dropped connection");

    memset(&g, 0, sizeof g);
    queue(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_delete_client_registration(c, REG_URI, token, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.calls, "delete: exactly one request on a 503");

    /* The read MAY retry per §16: a 503 then a 200 succeeds in two requests. */
    memset(&g, 0, sizeof g);
    queue(503, NULL);
    queue(200, "{\"client_id\":\"c1\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_EQUAL_INT(2, g.calls);
    TEST_ASSERT_EQUAL_INT(1, g.n_sleeps);
    axiam_client_registration_free(out);

    /* ... but never on a 4xx other than 408/429: a bodiless 400 is one request. */
    memset(&g, 0, sizeof g);
    queue(400, NULL);
    queue(200, "{\"client_id\":\"c1\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_EQUAL_INT(1, g.calls);
    TEST_ASSERT_NULL(out);

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* 4. Errors (§28.12.3)                                               */
/* ------------------------------------------------------------------ */

static void test_oauth_errors_at_any_status_and_no_refresh(void) {
    axiam_client_t *c = make_signed_in_client();
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    axiam_error_t err;
    axiam_client_registration_t *out = NULL;

    /* 401 invalid_token: OAuthProtocolError, and §9 is not entered. */
    queue(401, "{\"error\":\"invalid_token\",\"error_description\":\"bad token\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_token", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(401, (int) err.transport_cause);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g.refresh_calls, "a 401 here must not refresh the session");
    assert_no_fragment(err.message, tok);

    /* 400 invalid_client_metadata, with no error_description (optional). */
    axiam_client_registration_t meta = {0};
    meta.client_id = (char *) "c1";
    queue(400, "{\"error\":\"invalid_client_metadata\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_client_metadata", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(0, g.refresh_calls);
    assert_no_fragment(err.message, tok);

    /* A 401 with no error body is §2's AuthError -- still no refresh. */
    queue(401, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_delete_client_registration(c, REG_URI, token, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(0, g.refresh_calls);

    /* 204 on delete returns normally. */
    queue(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_delete_client_registration(c, REG_URI, token, &err));

    /* 429 without an error body is §2's NetworkError. */
    memset(&g, 0, sizeof g);
    queue(429, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_delete_client_registration(c, REG_URI, token, &err));
    TEST_ASSERT_EQUAL_INT(1, g.calls);

    /* A 200 whose body is not a registration is a NetworkError. */
    queue(200, "[]");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    queue(200, "{\"client_name\":\"no id\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_NULL(out);

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* 5. Redaction                                                       */
/* ------------------------------------------------------------------ */

static void test_neither_the_token_nor_the_secret_reaches_any_rendering(void) {
    char tok[64], secret[64];
    random_token(tok, sizeof tok);
    random_token(secret, sizeof secret);
    char body[512];
    snprintf(body, sizeof body,
             "{\"client_id\":\"c1\",\"client_secret\":\"%s\",\"registration_access_token\":\"%s\"}",
             secret, tok);
    axiam_error_t err;
    axiam_client_registration_t *reg = axiam_client_registration_parse(body, &err);
    TEST_ASSERT_NOT_NULL(reg);
    /* The only rendering a Sensitive member has. */
    assert_no_fragment(axiam_sensitive_to_string(reg->registration_access_token), tok);
    assert_no_fragment(axiam_sensitive_to_string(reg->client_secret), secret);
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(reg->client_secret));
    /* Neither lands among the extra members, which a caller may well log. */
    TEST_ASSERT_NULL(reg->extra);
    axiam_client_registration_free(reg);

    /* An error raised by an operation given the token names none of it. */
    axiam_client_t *c = make_client();
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    axiam_client_registration_t *out = NULL;
    queue(400, "{\"error\":\"invalid_request\",\"error_description\":\"refused\"}");
    axiam_read_client_registration(c, REG_URI, token, &out, &err);
    assert_no_fragment(err.message, tok);
    queue_transport_failure();
    axiam_delete_client_registration(c, REG_URI, token, &err);
    assert_no_fragment(err.message, tok);
    axiam_delete_client_registration(c, "https://evil.example.com/x", token, &err);
    assert_no_fragment(err.message, tok);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

static void test_decoding_is_tolerant(void) {
    axiam_error_t err;
    /* Mistyped members are KEPT in `extra` rather than dropped; nulls are absent. */
    axiam_client_registration_t *reg = axiam_client_registration_parse(
        "{\"client_id\":\"c1\",\"client_name\":42,\"scope\":null,\"redirect_uris\":\"x\","
        "\"grant_types\":null,\"client_id_issued_at\":\"soon\",\"client_secret_expires_at\":null,"
        "\"jwks\":null,\"response_types\":[\"code\",7]}",
        &err);
    TEST_ASSERT_NOT_NULL(reg);
    TEST_ASSERT_NULL(reg->client_name);
    TEST_ASSERT_NULL(reg->scope);
    TEST_ASSERT_NULL(reg->jwks);
    TEST_ASSERT_FALSE(reg->has_client_id_issued_at);
    TEST_ASSERT_FALSE(reg->has_client_secret_expires_at);
    TEST_ASSERT_EQUAL_size_t(1, reg->response_types_count);
    TEST_ASSERT_NOT_NULL(reg->extra);
    cJSON *extra = cJSON_Parse(reg->extra);
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(extra, "client_name"));
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(extra, "redirect_uris"));
    TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(extra, "client_id_issued_at"));
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(extra, "scope"));
    cJSON_Delete(extra);
    axiam_client_registration_free(reg);

    TEST_ASSERT_NULL(axiam_client_registration_parse(NULL, &err));
    TEST_ASSERT_NULL(axiam_client_registration_parse("not json", &err));
    TEST_ASSERT_NULL(axiam_client_registration_parse("{\"client_id\":7}", &err));
    axiam_client_registration_free(NULL);
}

static void test_an_unserializable_metadata_value_is_refused_locally(void) {
    axiam_client_t *c = make_client();
    char tok[64];
    random_token(tok, sizeof tok);
    axiam_sensitive_t *token = axiam_sensitive_new(tok);
    axiam_error_t err;
    axiam_client_registration_t *out = NULL;
    axiam_client_registration_t meta = {0};

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, NULL, &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    meta.client_id = (char *) "c1";
    meta.extra = (char *) "[1,2]";
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    meta.extra = NULL;
    meta.jwks = (char *) "{not json";
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, &out, &err));
    TEST_ASSERT_EQUAL_INT(0, g.calls);

    /* A hand-built value with lists and no extras serializes. */
    char *uris[] = {(char *) "https://app.example/cb"};
    meta.jwks = NULL;
    meta.redirect_uris = uris;
    meta.redirect_uris_count = 1;
    meta.jwks = (char *) "{\"keys\":[]}";
    queue(200, "{\"client_id\":\"c1\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_update_client_registration(c, REG_URI, token, &meta, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[0], "\"redirect_uris\":[\"https://app.example/cb\"]"));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[0], "\"jwks\":{\"keys\":[]}"));

    /* A closed client refuses before anything else. */
    axiam_client_close(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_read_client_registration(c, REG_URI, token, &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_read_client_registration(NULL, REG_URI, token, &out, &err));
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_uri_at_another_origin_is_refused_before_any_request);
    RUN_TEST(test_http_is_accepted_only_against_an_http_loopback_base);
    RUN_TEST(test_a_missing_token_is_refused_locally);
    RUN_TEST(test_read_and_delete_send_only_the_bearer);
    RUN_TEST(test_a_device_bearer_is_never_attached);
    RUN_TEST(test_update_drops_the_server_stated_members_and_returns_the_rotated_token);
    RUN_TEST(test_writes_are_never_retried_and_the_read_is);
    RUN_TEST(test_oauth_errors_at_any_status_and_no_refresh);
    RUN_TEST(test_neither_the_token_nor_the_secret_reaches_any_rendering);
    RUN_TEST(test_decoding_is_tolerant);
    RUN_TEST(test_an_unserializable_metadata_value_is_refused_locally);
    return UNITY_END();
}
