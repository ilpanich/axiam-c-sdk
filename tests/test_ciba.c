/*
 * CONTRACT.md §33 (contract 1.58) — CIBA: §33.8's sixteen required tests (nine
 * initiation and polling, four ping, three signed request), one-to-one with the Rust
 * reference's t01–t16, plus the unsupported server, the four discovery members and the
 * mTLS alias host.
 *
 * No credential, key or token literal: the client secret, every auth_req_id, the
 * notification token and every signing key are generated at run time. A failing
 * redaction assertion names an offset, never the value.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/ciba.h"
#include "axiam/management.h"
#include "cJSON.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define BASE "https://api.test"
#define ISSUER "https://issuer.test"
#define CLIENT_ID "ciba-client"
#define TENANT AXIAM_TEST_TENANT_ID
#define KID "ciba-kid"

#define DISCOVERY                                                                           \
    "{\"issuer\":\"" ISSUER "\",\"authorization_endpoint\":\"" BASE "/oauth2/authorize\","  \
    "\"token_endpoint\":\"" BASE "/oauth2/token\",\"jwks_uri\":\"" BASE "/oauth2/jwks\","   \
    "\"backchannel_authentication_endpoint\":\"" BASE "/oauth2/bc-authorize\","             \
    "\"backchannel_token_delivery_modes_supported\":[\"poll\",\"ping\"],"                   \
    "\"backchannel_authentication_request_signing_alg_values_supported\":[\"PS256\",\"ES256\",\"EdDSA\"]," \
    "\"backchannel_user_code_parameter_supported\":false}"

#define DISCOVERY_WITHOUT_CIBA                                                              \
    "{\"issuer\":\"" ISSUER "\",\"authorization_endpoint\":\"" BASE "/oauth2/authorize\","  \
    "\"token_endpoint\":\"" BASE "/oauth2/token\",\"jwks_uri\":\"" BASE "/oauth2/jwks\"}"

/* ------------------------------------------------------------------ */
/* Random values, redaction                                           */
/* ------------------------------------------------------------------ */

static void random_hex(char *out, size_t bytes) {
    unsigned char raw[64];
    TEST_ASSERT_TRUE(bytes <= sizeof raw);
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) bytes));
    for (size_t i = 0; i < bytes; i++) snprintf(out + 2 * i, 3, "%02x", raw[i]);
}

static void assert_no_fragment(const char *haystack, const char *secret) {
    size_t n = strlen(secret);
    for (size_t i = 0; haystack && i + 8 <= n; i++) {
        char frag[9];
        memcpy(frag, secret + i, 8);
        frag[8] = '\0';
        if (strstr(haystack, frag)) {
            char msg[96];
            snprintf(msg, sizeof msg, "an 8-character fragment of a secret (offset %zu) leaked", i);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

/* ------------------------------------------------------------------ */
/* The fake authorization server                                      */
/* ------------------------------------------------------------------ */

#define MAX 16

typedef struct {
    long status;
    const char *body;
    int transport_fails;
} answer_t;

typedef struct {
    const char *discovery;
    char *jwks;
    answer_t bc[MAX];
    int bc_len;
    answer_t token[MAX];
    int token_len;
    int bc_calls, token_calls, discovery_calls, jwks_calls, other_calls;
    char urls[MAX * 2][512];
    char bodies[MAX * 2][4096];
    char tenant_headers[MAX * 2][64];
    long at[MAX * 2];      /* the ciba clock's reading at each request */
    int n;
    long clock_s;          /* the injected ciba clock */
    long sleeps[MAX];
    int n_sleeps;
} fake_t;

static fake_t g;

static void record(const axiam_http_request_t *req) {
    if (g.n >= MAX * 2) return;
    snprintf(g.urls[g.n], sizeof g.urls[0], "%s", req->url ? req->url : "");
    snprintf(g.bodies[g.n], sizeof g.bodies[0], "%s", req->body ? req->body : "");
    const char *t = axiam_kv_get(req->headers, "X-Tenant-ID");
    snprintf(g.tenant_headers[g.n], sizeof g.tenant_headers[0], "%s", t ? t : "");
    g.at[g.n] = g.clock_s;
    g.n++;
}

static int answer(const answer_t *script, int len, int *calls, axiam_http_response_t *resp) {
    int i = *calls < len ? *calls : len - 1;
    (*calls)++;
    if (i < 0) {
        resp->status = 200;
        resp->body = strdup("{}");
        return 0;
    }
    if (script[i].transport_fails) {
        resp->transport_err = 52;
        resp->transport_msg = strdup("empty reply from server");
        return 1;
    }
    resp->status = script[i].status;
    if (script[i].body) resp->body = strdup(script[i].body);
    return 0;
}

static int fake_transport(void *ctx, const axiam_http_request_t *req, axiam_http_response_t *resp) {
    (void) ctx;
    memset(resp, 0, sizeof *resp);
    const char *url = req->url ? req->url : "";
    if (strstr(url, "/.well-known/openid-configuration")) {
        g.discovery_calls++;
        resp->status = 200;
        resp->body = strdup(g.discovery ? g.discovery : DISCOVERY);
        return 0;
    }
    if (strstr(url, "/oauth2/jwks")) {
        g.jwks_calls++;
        resp->status = 200;
        resp->body = strdup(g.jwks ? g.jwks : "{\"keys\":[]}");
        return 0;
    }
    if (strstr(url, "/oauth2/bc-authorize")) {
        record(req);
        return answer(g.bc, g.bc_len, &g.bc_calls, resp);
    }
    if (strstr(url, "/oauth2/token")) {
        record(req);
        return answer(g.token, g.token_len, &g.token_calls, resp);
    }
    g.other_calls++;
    resp->status = 404;
    return 0;
}

static time_t clock_now(void *ctx) {
    (void) ctx;
    return (time_t) g.clock_s;
}

static void clock_sleep(void *ctx, long seconds) {
    (void) ctx;
    if (g.n_sleeps < MAX) g.sleeps[g.n_sleeps++] = seconds;
    g.clock_s += seconds;
}

static const axiam_ciba_clock_t TEST_CLOCK = {clock_now, clock_sleep, NULL};

/* §16's waits inside a poll are faked separately: retry stays ENABLED. */
static void retry_sleep(void *ctx, long ms) {
    (void) ctx;
    (void) ms;
}

static double no_jitter(void *ctx) {
    (void) ctx;
    return 0.0;
}

static time_t client_clock(void *ctx) {
    (void) ctx;
    return (time_t) g.clock_s;
}

static char g_secret[65];

static axiam_client_t *client_with(const char *secret, int with_cert) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, BASE);
    axiam_client_config_set_tenant_id(cfg, TENANT);
    axiam_client_config_set_oidc_client_id(cfg, CLIENT_ID);
    if (secret) axiam_client_config_set_oidc_client_secret(cfg, secret);
    if (with_cert) {
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_client_cert(
            cfg, "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
            "-----BEGIN AXIAM TEST PLACEHOLDER-----\nZmFrZQ==\n-----END AXIAM TEST PLACEHOLDER-----\n"));
    }
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    c->sleep_fn = retry_sleep;
    c->jitter_fn = no_jitter;
    c->clock_fn = client_clock;
    return c;
}

static axiam_client_t *make_client(void) { return client_with(g_secret, 0); }

/* The client's own sleep seam, advancing the fake clock: the default CIBA clock is the
 * client's clock_fn/sleep_fn pair. */
static void advancing_sleep(void *ctx, long ms) {
    (void) ctx;
    g.clock_s += ms / 1000;
}

/* A TokenResponse carrying a signed ID token for this client, and the JWKS for it. */
static char g_tokens[8192];
static void mint_tokens(void) {
    char claims[512];
    long long now = (long long) time(NULL);
    snprintf(claims, sizeof claims,
             "{\"iss\":\"" ISSUER "\",\"aud\":\"" CLIENT_ID "\",\"sub\":\"user-1\","
             "\"exp\":%lld,\"iat\":%lld,\"acr\":\"urn:axiam:acr:mfa\"}", now + 600, now - 5);
    char *id_token = NULL;
    free(g.jwks);
    g.jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(KID, claims, &id_token, &g.jwks));
    char access[33];
    random_hex(access, 16);
    snprintf(g_tokens, sizeof g_tokens,
             "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":900,"
             "\"scope\":\"openid\",\"id_token\":\"%s\"}", access, id_token);
    free(id_token);
}

static axiam_ciba_initiate_params_t poll_params(void) {
    axiam_ciba_initiate_params_t p;
    memset(&p, 0, sizeof p);
    p.scope = "openid";
    p.hint_kind = AXIAM_CIBA_LOGIN_HINT;
    p.hint = "alice@example.com";
    return p;
}

static axiam_ciba_initiate_response_t initiated(const char *id, long expires_in, long interval) {
    axiam_ciba_initiate_response_t r;
    memset(&r, 0, sizeof r);
    r.auth_req_id = axiam_sensitive_new(id);
    r.expires_in = expires_in;
    r.interval = interval;
    r.received_at = (time_t) g.clock_s;
    return r;
}

/* The value of `key` in a recorded form body, percent-decoded, or "" when absent. */
static int form_get(const char *body, const char *key, char *out, size_t cap) {
    size_t klen = strlen(key);
    for (const char *p = body; *p;) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t) (amp - p) : strlen(p);
        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            size_t o = 0;
            for (size_t i = klen + 1; i < len && o + 1 < cap; i++) {
                if (p[i] == '%' && i + 2 < len) {
                    char hex[3] = {p[i + 1], p[i + 2], 0};
                    out[o++] = (char) strtol(hex, NULL, 16);
                    i += 2;
                } else {
                    out[o++] = p[i] == '+' ? ' ' : p[i];
                }
            }
            out[o] = '\0';
            return 1;
        }
        p = amp ? amp + 1 : p + len;
    }
    out[0] = '\0';
    return 0;
}

/* The keys of a form body, in order, comma-joined. */
static void form_keys(const char *body, char *out, size_t cap) {
    out[0] = '\0';
    for (const char *p = body; *p;) {
        const char *amp = strchr(p, '&');
        const char *eq = strchr(p, '=');
        size_t len = amp ? (size_t) (amp - p) : strlen(p);
        size_t klen = (eq && (size_t) (eq - p) < len) ? (size_t) (eq - p) : len;
        if (out[0]) strncat(out, ",", cap - strlen(out) - 1);
        strncat(out, p, klen < cap - strlen(out) - 1 ? klen : cap - strlen(out) - 1);
        p = amp ? amp + 1 : p + len;
    }
}

static char g_bc_ok[256];

void setUp(void) {
    free(g.jwks);
    memset(&g, 0, sizeof g);
    g.clock_s = 1760000000;
    random_hex(g_secret, 24);
    char id[65];
    random_hex(id, 32);
    snprintf(g_bc_ok, sizeof g_bc_ok, "{\"auth_req_id\":\"%s\",\"expires_in\":300,\"interval\":5}", id);
}

void tearDown(void) {}

/* ---- 1. Redaction ----------------------------------------------------------------- */

static void test_t01_the_three_values_are_on_the_wire_and_in_no_rendering(void) {
    axiam_client_t *c = make_client();
    char notify[65], id[65];
    random_hex(notify, 32);
    random_hex(id, 32);
    char body[256];
    snprintf(body, sizeof body, "{\"auth_req_id\":\"%s\",\"expires_in\":300}", id);
    g.bc[0] = (answer_t){200, body, 0};
    g.bc[1] = (answer_t){400, "{\"error\":\"invalid_request\",\"error_description\":\"refused\"}", 0};
    g.bc_len = 2;
    axiam_sensitive_t *token = axiam_sensitive_new(notify);
    axiam_ciba_initiate_params_t p = poll_params();
    p.delivery = AXIAM_CIBA_DELIVERY_PING;
    p.client_notification_token = token;
    axiam_ciba_initiate_response_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
    char sent[128];
    TEST_ASSERT_TRUE(form_get(g.bodies[0], "client_notification_token", sent, sizeof sent));
    TEST_ASSERT_TRUE_MESSAGE(strcmp(sent, notify) == 0, "the notification token is on the wire");
    TEST_ASSERT_TRUE_MESSAGE(strcmp(axiam_sensitive_reveal(r.auth_req_id), id) == 0,
                             "the auth_req_id is returned");
    assert_no_fragment(axiam_sensitive_to_string(r.auth_req_id), id);
    assert_no_fragment(axiam_sensitive_to_string(token), notify);
    /* An error from an initiate given the token names neither value. */
    axiam_ciba_initiate_response_t r2;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r2, &err));
    assert_no_fragment(err.message, notify);
    assert_no_fragment(err.message, g_secret);
    /* ... nor does an error from a poll given the id. */
    g.token[0] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token_len = 1;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, r.auth_req_id, NULL, NULL, &set, &err));
    assert_no_fragment(err.message, id);
    TEST_ASSERT_TRUE(form_get(g.bodies[2], "auth_req_id", sent, sizeof sent));
    TEST_ASSERT_TRUE_MESSAGE(strcmp(sent, id) == 0, "the id is on the wire");
    axiam_ciba_initiate_response_dispose(&r);
    axiam_ciba_initiate_response_dispose(NULL);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ---- 2. Client authentication is mandatory ---------------------------------------- */

static void test_t02_no_credential_is_refused_locally_and_one_is_sent_with_tenant_in_the_query(void) {
    /* No secret, no certificate: refused, zero requests, on all three wire operations. */
    axiam_client_t *c = client_with(NULL, 0);
    axiam_ciba_initiate_params_t p = poll_params();
    axiam_ciba_initiate_response_t r;
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "never public"));
    axiam_sensitive_t *id = axiam_sensitive_new("x");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    axiam_ciba_initiate_response_t in = initiated("x", 60, 5);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    axiam_ciba_initiate_response_dispose(&in);
    TEST_ASSERT_EQUAL_INT(0, g.n);
    TEST_ASSERT_EQUAL_INT(0, g.discovery_calls);
    axiam_client_free(c);

    /* With a secret: client_secret_post on initiate AND poll, tenant_id in the query. */
    c = make_client();
    g.bc[0] = (answer_t){200, g_bc_ok, 0};
    g.bc_len = 1;
    g.token[0] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token_len = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, r.auth_req_id, NULL, NULL, &set, &err));
    for (int i = 0; i < 2; i++) {
        char v[128];
        TEST_ASSERT_TRUE(form_get(g.bodies[i], "client_id", v, sizeof v));
        TEST_ASSERT_EQUAL_STRING(CLIENT_ID, v);
        TEST_ASSERT_TRUE(form_get(g.bodies[i], "client_secret", v, sizeof v));
        TEST_ASSERT_TRUE_MESSAGE(strcmp(v, g_secret) == 0, "the secret is sent");
        TEST_ASSERT_NOT_NULL(strstr(g.urls[i], "?tenant_id=" TENANT));
        TEST_ASSERT_FALSE(form_get(g.bodies[i], "tenant_id", v, sizeof v));
        TEST_ASSERT_EQUAL_STRING(TENANT, g.tenant_headers[i]);
    }
    TEST_ASSERT_NOT_NULL(strstr(g.urls[0], BASE "/oauth2/bc-authorize?"));
    TEST_ASSERT_NOT_NULL(strstr(g.urls[1], BASE "/oauth2/token?"));
    char v[128];
    TEST_ASSERT_TRUE(form_get(g.bodies[1], "grant_type", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING(AXIAM_CIBA_GRANT_TYPE, v);
    axiam_ciba_initiate_response_dispose(&r);
    axiam_client_free(c);

    /* An mTLS-only client (tls_client_auth): client_id only. */
    memset(&g, 0, sizeof g);
    g.clock_s = 1760000000;
    c = client_with(NULL, 1);
    g.bc[0] = (answer_t){200, g_bc_ok, 0};
    g.bc_len = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_TRUE(form_get(g.bodies[0], "client_id", v, sizeof v));
    TEST_ASSERT_FALSE(form_get(g.bodies[0], "client_secret", v, sizeof v));
    axiam_ciba_initiate_response_dispose(&r);
    axiam_sensitive_free(id);
    axiam_client_free(c);
}

/* ---- 3. The initiate request ------------------------------------------------------ */

static void test_t03_exactly_the_members_set_are_sent(void) {
    axiam_client_t *c = make_client();
    g.bc[0] = (answer_t){200, g_bc_ok, 0};
    g.bc_len = 1;
    char notify[65];
    random_hex(notify, 32);
    axiam_sensitive_t *token = axiam_sensitive_new(notify);
    axiam_ciba_initiate_params_t p = poll_params();
    p.binding_message = "W4SCT";
    p.requested_expiry = 120;
    p.has_requested_expiry = 1;
    p.acr_values = "urn:axiam:acr:mfa";
    p.resource = "https://api.example/payments";
    p.delivery = AXIAM_CIBA_DELIVERY_PING;
    p.client_notification_token = token;
    axiam_ciba_initiate_response_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT(1, g.n);
    char keys[512], v[256];
    form_keys(g.bodies[0], keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("client_id,client_secret,scope,login_hint,binding_message,"
                             "requested_expiry,acr_values,resource,client_notification_token",
                             keys);
    form_get(g.bodies[0], "requested_expiry", v, sizeof v);
    TEST_ASSERT_EQUAL_STRING("120", v);
    form_get(g.bodies[0], "login_hint", v, sizeof v);
    TEST_ASSERT_EQUAL_STRING("alice@example.com", v);
    axiam_ciba_initiate_response_dispose(&r);

    /* The minimal request, with the other hint. */
    axiam_ciba_initiate_params_t q = poll_params();
    q.hint_kind = AXIAM_CIBA_ID_TOKEN_HINT;
    q.hint = "eyJhbGciOiJFZERTQSJ9.e30.sig";
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &q, &r, &err));
    form_keys(g.bodies[1], keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("client_id,client_secret,scope,id_token_hint", keys);
    TEST_ASSERT_EQUAL_INT(300, (int) r.expires_in);
    TEST_ASSERT_EQUAL_INT(5, (int) r.interval);
    axiam_ciba_initiate_response_dispose(&r);

    /* Refused client-side, before any request: no hint (the type cannot carry two, and
     * has no member for login_hint_token, user_code or request_uri), no scope, a ping
     * request with no or an empty notification token, a poll request carrying one. */
    int before = g.n;
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_ciba_initiate_params_t bad[5];
    for (int i = 0; i < 5; i++) bad[i] = poll_params();
    bad[0].hint = NULL;
    bad[1].scope = "";
    bad[2].delivery = AXIAM_CIBA_DELIVERY_PING;
    bad[3].delivery = AXIAM_CIBA_DELIVERY_PING;
    bad[3].client_notification_token = empty;
    bad[4].client_notification_token = token;
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &bad[i], &r, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));
    }
    TEST_ASSERT_EQUAL_INT(before, g.n);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, NULL, &r, &err));
    axiam_sensitive_free(empty);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ---- 4. No retry on initiate ------------------------------------------------------ */

typedef struct {
    int fd;
    int accepts;
    volatile int stop;
} listener_t;

static void *accept_and_drop(void *arg) {
    listener_t *l = arg;
    while (!l->stop) {
        int s = accept(l->fd, NULL, NULL);
        if (s < 0) break;
        l->accepts++;
        close(s);
    }
    return NULL;
}

static void test_t04_initiate_is_sent_once_on_503_429_and_a_dropped_connection(void) {
    axiam_client_t *c = make_client(); /* retry ENABLED */
    axiam_ciba_initiate_params_t p = poll_params();
    axiam_ciba_initiate_response_t r;
    axiam_error_t err;
    g.bc[0] = (answer_t){503, NULL, 0};
    g.bc[1] = (answer_t){200, g_bc_ok, 0};
    g.bc_len = 2;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.bc_calls, "503: exactly one request");

    g.bc_calls = 0;
    g.bc[0] = (answer_t){429, "{\"error\":\"rate_limit_exceeded\"}", 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_STRING("rate_limit_exceeded", err.oauth_error);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.bc_calls, "429: exactly one request");

    g.bc_calls = 0;
    g.bc[0] = (answer_t){0, NULL, 1};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.bc_calls, "a transport failure: exactly one request");
    axiam_client_free(c);

    /* A real listener that accepts and hangs up, through the real libcurl transport. */
    listener_t l = {socket(AF_INET, SOCK_STREAM, 0), 0, 0};
    TEST_ASSERT_TRUE(l.fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT_EQUAL_INT(0, bind(l.fd, (struct sockaddr *) &addr, sizeof addr));
    TEST_ASSERT_EQUAL_INT(0, listen(l.fd, 8));
    socklen_t alen = sizeof addr;
    getsockname(l.fd, (struct sockaddr *) &addr, &alen);
    int port = ntohs(addr.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, accept_and_drop, &l);

    char base[64], endpoint[128], token_endpoint[128];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", port);
    snprintf(endpoint, sizeof endpoint, "%s/oauth2/bc-authorize", base);
    snprintf(token_endpoint, sizeof token_endpoint, "%s/oauth2/token", base);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_id(cfg, TENANT);
    axiam_client_config_set_oidc_client_id(cfg, CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, g_secret);
    axiam_client_config_set_timeout_ms(cfg, 5000);
    c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    axiam_oidc_config_t doc;
    memset(&doc, 0, sizeof doc);
    doc.issuer = (char *) ISSUER;
    doc.token_endpoint = token_endpoint;
    doc.backchannel_authentication_endpoint = endpoint;
    p.config = &doc;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
    axiam_client_free(c);
    usleep(100 * 1000);
    l.stop = 1;
    shutdown(l.fd, SHUT_RDWR);
    close(l.fd);
    pthread_join(th, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, l.accepts, "one connection, no retry");
}

/* ---- 5. Poll outcomes --------------------------------------------------------------- */

static void test_t05_pending_loops_slow_down_persists_and_the_terminal_answers_are_distinct(void) {
    mint_tokens();
    axiam_client_t *c = make_client();
    g.token[0] = (answer_t){400, "{\"error\":\"slow_down\"}", 0};
    g.token[1] = (answer_t){400, "{\"error\":\"slow_down\"}", 0};
    g.token[2] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token[3] = (answer_t){200, g_tokens, 0};
    g.token_len = 4;
    char id[65];
    random_hex(id, 32);
    axiam_ciba_initiate_response_t in = initiated(id, 600, 5);
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_NOT_NULL(set.id_claims);
    TEST_ASSERT_EQUAL_INT(4, g.n_sleeps);
    long expected[4] = {5, 10, 15, 15}; /* +5 s twice, and pending lowers nothing */
    for (int i = 0; i < 4; i++) TEST_ASSERT_EQUAL_INT(expected[i], g.sleeps[i]);
    for (int i = 0; i < 4; i++) {
        char v[160];
        form_get(g.bodies[i], "grant_type", v, sizeof v);
        TEST_ASSERT_EQUAL_STRING(AXIAM_CIBA_GRANT_TYPE, v);
        form_get(g.bodies[i], "auth_req_id", v, sizeof v);
        TEST_ASSERT_TRUE(strcmp(v, id) == 0);
    }
    axiam_oidc_token_set_dispose(&set);

    static const char *const codes[] = {"access_denied", "expired_token", "invalid_grant",
                                        "a_code_nobody_defined"};
    char bodies[4][96];
    for (int k = 0; k < 4; k++) {
        g.token_calls = 0;
        g.n = 0;
        snprintf(bodies[k], sizeof bodies[k], "{\"error\":\"%s\"}", codes[k]);
        g.token[0] = (answer_t){400, bodies[k], 0};
        g.token_len = 1;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
        TEST_ASSERT_EQUAL_STRING(codes[k], err.oauth_error);
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.token_calls, "terminal after one request");
        TEST_ASSERT_EQUAL_INT(k == 0, axiam_error_is_access_denied(&err));
        TEST_ASSERT_EQUAL_INT(k == 1, axiam_error_is_expired_token(&err));
    }
    TEST_ASSERT_FALSE(axiam_error_is_access_denied(NULL));
    TEST_ASSERT_FALSE(axiam_error_is_expired_token(NULL));
    axiam_ciba_initiate_response_dispose(&in);
    axiam_client_free(c);
}

/* ---- 6. The first poll waits -------------------------------------------------------- */

static void test_t06_the_first_poll_waits_the_interval_or_five_seconds(void) {
    static const char *const responses[] = {
        "{\"auth_req_id\":\"id-seven\",\"expires_in\":300,\"interval\":7}",
        "{\"auth_req_id\":\"id-absent\",\"expires_in\":300}",
        "{\"auth_req_id\":\"id-zero\",\"expires_in\":300,\"interval\":0}",
    };
    static const long expected[] = {7, 5, 5};
    for (int k = 0; k < 3; k++) {
        free(g.jwks);
        memset(&g, 0, sizeof g);
        g.clock_s = 1760000000;
        axiam_client_t *c = make_client();
        g.bc[0] = (answer_t){200, responses[k], 0};
        g.bc_len = 1;
        g.token[0] = (answer_t){400, "{\"error\":\"access_denied\"}", 0};
        g.token_len = 1;
        axiam_ciba_initiate_params_t p = poll_params();
        axiam_ciba_initiate_response_t r;
        axiam_oidc_token_set_t set;
        axiam_error_t err;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
        TEST_ASSERT_EQUAL_INT(expected[k], r.interval);
        TEST_ASSERT_EQUAL_INT(1760000000, (int) r.received_at);
        axiam_ciba_await(c, &r, NULL, NULL, &TEST_CLOCK, &set, &err);
        TEST_ASSERT_EQUAL_INT(2, g.n);
        TEST_ASSERT_EQUAL_INT_MESSAGE(1760000000 + expected[k], g.at[1],
                                      "the first poll is not sent before the interval");
        axiam_ciba_initiate_response_dispose(&r);
        axiam_client_free(c);
    }
}

/* ---- 7. Deadline ------------------------------------------------------------------- */

static void test_t07_no_request_after_expires_in_and_expired_token_is_raised_locally(void) {
    axiam_client_t *c = make_client();
    g.token[0] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token_len = 1;
    axiam_ciba_initiate_response_t in = initiated("pending-forever", 12, 5);
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_TRUE(axiam_error_is_expired_token(&err));
    TEST_ASSERT_EQUAL_INT(2, g.token_calls);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1760000005, g.at[0], "the first poll at 5 s");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1760000010, g.at[1], "the second at 10 s, nothing at 15 s");
    axiam_ciba_initiate_response_dispose(&in);

    /* The default clock (the client's) runs the same loop. */
    g.n = 0;
    g.token_calls = 0;
    c->sleep_fn = advancing_sleep;
    in = initiated("pending-forever", 6, 5);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_await(c, &in, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_TRUE(axiam_error_is_expired_token(&err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g.token_calls, "one poll at 5 s, none at 10 s past 6 s");
    axiam_ciba_initiate_response_dispose(&in);
    axiam_client_free(c);
}

/* ---- 8. Transient failure is not terminal ------------------------------------------ */

static void test_t08_a_500_and_a_429_mid_loop_are_survived(void) {
    mint_tokens();
    axiam_client_t *c = make_client();
    g.token[0] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token[1] = (answer_t){500, NULL, 0};
    g.token[2] = (answer_t){429, "{\"error\":\"rate_limit_exceeded\"}", 0};
    g.token[3] = (answer_t){200, g_tokens, 0};
    g.token_len = 4;
    axiam_ciba_initiate_response_t in = initiated("transient", 600, 5);
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_NOT_NULL(set.access_token);
    TEST_ASSERT_NOT_NULL(set.id_token);
    TEST_ASSERT_NOT_NULL(set.id_claims);
    TEST_ASSERT_EQUAL_INT(4, g.token_calls);
    axiam_oidc_token_set_dispose(&set);

    /* Transport failures that outlive §16 are survived too; a bodiless 429 is retried
     * inside the call. */
    g.token_calls = 0;
    g.token[0] = (answer_t){0, NULL, 1};
    g.token[1] = (answer_t){0, NULL, 1};
    g.token[2] = (answer_t){0, NULL, 1};
    g.token[3] = (answer_t){429, NULL, 0};
    g.token[4] = (answer_t){200, g_tokens, 0};
    g.token_len = 5;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_EQUAL_INT(5, g.token_calls);
    axiam_oidc_token_set_dispose(&set);

    /* A bodiless 400 is decisive: terminal, one request. */
    g.token_calls = 0;
    g.token[0] = (answer_t){400, NULL, 0};
    g.token_len = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    axiam_ciba_initiate_response_dispose(&in);
    axiam_client_free(c);
}

/* ---- 9. Single use ------------------------------------------------------------------ */

static void test_t09_a_second_redemption_is_invalid_grant_and_not_retried(void) {
    mint_tokens();
    axiam_client_t *c = make_client();
    g.token[0] = (answer_t){200, g_tokens, 0};
    g.token[1] = (answer_t){400, "{\"error\":\"invalid_grant\"}", 0};
    g.token_len = 2;
    char raw[65];
    random_hex(raw, 32);
    axiam_sensitive_t *id = axiam_sensitive_new(raw);
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    axiam_oidc_token_set_dispose(&set);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g.token_calls, "no retry of the second");
    /* A 200 whose body is not a token set is not retried either. */
    g.token_calls = 0;
    g.token[0] = (answer_t){200, "not json", 0};
    g.token_len = 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_poll(c, NULL, NULL, NULL, &set, &err));
    axiam_sensitive_free(id);
    axiam_client_free(c);
}

/* ---- 10–13. The ping ---------------------------------------------------------------- */

static axiam_kv_t *ping_headers(const char *const *authorization, int n) {
    axiam_kv_t *h = axiam_kv_append(NULL, "content-type", "application/json");
    for (int i = 0; i < n; i++) h = axiam_kv_append(h, "Authorization", authorization[i]);
    return h;
}

static void test_t10_a_valid_ping_returns_its_auth_req_id_in_any_scheme_case(void) {
    char token[65], id[65], body[128];
    random_hex(token, 32);
    random_hex(id, 32);
    snprintf(body, sizeof body, "{\"auth_req_id\":\"%s\"}", id);
    axiam_sensitive_t *expected = axiam_sensitive_new(token);
    static const char *const schemes[] = {"Bearer", "bearer", "BEARER"};
    for (int i = 0; i < 3; i++) {
        char header[96];
        snprintf(header, sizeof header, "%s %s", schemes[i], token);
        const char *one[] = {header};
        axiam_kv_t *h = ping_headers(one, 1);
        axiam_sensitive_t *got = NULL;
        axiam_error_t err;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_handle_ping(h, body, strlen(body), expected, &got, &err));
        TEST_ASSERT_TRUE_MESSAGE(strcmp(axiam_sensitive_reveal(got), id) == 0, "the ping's id");
        TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(got));
        axiam_sensitive_free(got);
        /* A lowercase header name is the same header. */
        axiam_kv_free(h);
    }
    const char *lower[] = {NULL};
    char header[96];
    snprintf(header, sizeof header, "Bearer %s", token);
    lower[0] = header;
    axiam_kv_t *h = axiam_kv_append(NULL, "authorization", lower[0]);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_handle_ping(h, body, strlen(body), expected, NULL, &err));
    axiam_kv_free(h);
    axiam_sensitive_free(expected);
}

static void test_t11_a_wrong_absent_empty_duplicate_or_basic_authorization_is_refused(void) {
    char token[65], other[65];
    random_hex(token, 32);
    random_hex(other, 32);
    const char *body = "{\"auth_req_id\":\"id-1\"}";
    axiam_sensitive_t *expected = axiam_sensitive_new(token);
    char right[96], wrong[96], last[96], basic[96], twice[96], empty[16], bare[96];
    snprintf(right, sizeof right, "Bearer %s", token);
    snprintf(wrong, sizeof wrong, "Bearer %s", other);
    snprintf(last, sizeof last, "Bearer %s", token);
    last[strlen(last) - 1] = last[strlen(last) - 1] == 'a' ? 'b' : 'a'; /* the LAST character */
    snprintf(basic, sizeof basic, "Basic %s", token);
    snprintf(twice, sizeof twice, "Bearer  %s", token); /* two spaces */
    snprintf(empty, sizeof empty, "Bearer ");
    snprintf(bare, sizeof bare, "%s", token);
    struct {
        const char *values[2];
        int n;
    } cases[] = {
        {{wrong}, 1}, {{NULL}, 0}, {{""}, 1}, {{empty}, 1}, {{right, right}, 2},
        {{basic}, 1}, {{last}, 1}, {{twice}, 1}, {{bare}, 1},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        axiam_kv_t *h = ping_headers(cases[i].values, cases[i].n);
        axiam_sensitive_t *got = NULL;
        axiam_error_t err;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_handle_ping(h, body, strlen(body), expected, &got, &err));
        TEST_ASSERT_NULL(got);
        assert_no_fragment(err.message, token);
        axiam_kv_free(h);
    }
    /* An empty expected token can be matched by nothing. */
    axiam_sensitive_t *nothing = axiam_sensitive_new("");
    const char *one[] = {"Bearer "};
    axiam_kv_t *h = ping_headers(one, 1);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_handle_ping(h, body, strlen(body), nothing, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_handle_ping(h, body, strlen(body), NULL, NULL, &err));
    axiam_kv_free(h);
    axiam_sensitive_free(nothing);

    /* The comparison is constant-time, asserted structurally: the helper's body calls
     * OpenSSL's CRYPTO_memcmp, and no strcmp/memcmp touches the token. */
    FILE *f = fopen(AXIAM_REPO_ROOT "/src/oidc_ciba.c", "rb");
    TEST_ASSERT_NOT_NULL(f);
    static char src[65536];
    size_t n = fread(src, 1, sizeof src - 1, f);
    fclose(f);
    src[n] = '\0';
    const char *fn = strstr(src, "axiam_error_kind_t axiam_ciba_handle_ping(");
    TEST_ASSERT_NOT_NULL(fn);
    const char *ct = strstr(fn, "CRYPTO_memcmp(token, expected, expected_len)");
    TEST_ASSERT_NOT_NULL_MESSAGE(ct, "the token is compared with CRYPTO_memcmp");
    const char *end = strstr(fn, "\n}\n");
    TEST_ASSERT_TRUE(ct < end);
    char between[4096];
    size_t len = (size_t) (end - fn) < sizeof between - 1 ? (size_t) (end - fn) : sizeof between - 1;
    memcpy(between, fn, len);
    between[len] = '\0';
    /* Every memcmp in the helper is OpenSSL's constant-time one. */
    for (const char *m = strstr(between, "memcmp("); m; m = strstr(m + 1, "memcmp(")) {
        TEST_ASSERT_TRUE_MESSAGE(m - between >= 7 && strncmp(m - 7, "CRYPTO_", 7) == 0,
                                 "a plain memcmp in the ping helper");
    }
    TEST_ASSERT_NULL(strstr(between, "strcmp(token"));
    axiam_sensitive_free(expected);
}

static void test_t12_a_malformed_body_is_a_validation_error_and_extras_are_ignored(void) {
    char token[65], header[96];
    random_hex(token, 32);
    snprintf(header, sizeof header, "Bearer %s", token);
    axiam_sensitive_t *expected = axiam_sensitive_new(token);
    const char *one[] = {header};
    axiam_kv_t *h = ping_headers(one, 1);
    static const char *const bad[] = {
        "not json", "{}", "{\"auth_req_id\":7}", "{\"auth_req_id\":\"\"}", "[\"auth_req_id\"]",
        "{\"auth_req_id\":null}",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        axiam_error_t err;
        axiam_sensitive_t *got = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_ciba_handle_ping(h, bad[i], strlen(bad[i]), expected, &got, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_NULL(got);
    }
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_handle_ping(h, NULL, 0, expected, NULL, &err));
    /* Extra members are ignored, never acted on; the body need not be NUL-terminated. */
    const char extra[] = "{\"auth_req_id\":\"id-2\",\"status\":\"approved\",\"access_token\":\"x\"}XYZ";
    axiam_sensitive_t *got = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_handle_ping(h, extra, sizeof extra - 4, expected, &got, &err));
    TEST_ASSERT_EQUAL_STRING("id-2", axiam_sensitive_reveal(got));
    axiam_sensitive_free(got);
    axiam_kv_free(h);
    axiam_sensitive_free(expected);
}

static void test_t13_the_ping_helper_makes_no_network_call(void) {
    /* axiam_ciba_handle_ping() takes no client, so it has no transport to call. A client
     * built next to it records every request: none is made. */
    axiam_client_t *c = make_client();
    char token[65], header[96];
    random_hex(token, 32);
    snprintf(header, sizeof header, "Bearer %s", token);
    axiam_sensitive_t *expected = axiam_sensitive_new(token);
    const char *one[] = {header};
    axiam_kv_t *h = ping_headers(one, 1);
    const char *body = "{\"auth_req_id\":\"id-3\"}";
    axiam_sensitive_t *got = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_handle_ping(h, body, strlen(body), expected, &got, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n + g.discovery_calls + g.jwks_calls + g.other_calls);
    axiam_sensitive_free(got);
    axiam_kv_free(h);
    axiam_sensitive_free(expected);
    axiam_client_free(c);
}

/* ---- 14–16. The signed form ------------------------------------------------------- */

static axiam_sensitive_t *pem_of(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    TEST_ASSERT_EQUAL_INT(1, PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL));
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    axiam_sensitive_t *s = axiam_sensitive_new_bytes(data, (size_t) len);
    BIO_free(bio);
    return s;
}

static EVP_PKEY *keygen(axiam_ciba_signing_alg_t alg) {
    switch (alg) {
        case AXIAM_CIBA_SIGNING_EDDSA: return EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        case AXIAM_CIBA_SIGNING_ES256: return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        default: return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
    }
}

static unsigned char *b64d(const char *s, size_t len, size_t *out_len) {
    return axiam_b64url_decode(s, len, out_len);
}

/* Verify the JWS `jws` with `key` under `alg`; return its claims (caller deletes). */
static cJSON *verify_jws(const char *jws, EVP_PKEY *key, axiam_ciba_signing_alg_t alg,
                         const char *expected_alg, const char *expected_kid) {
    const char *d1 = strchr(jws, '.');
    const char *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
    TEST_ASSERT_NOT_NULL(d2);
    size_t hl = 0, cl = 0, sl = 0;
    unsigned char *h = b64d(jws, (size_t) (d1 - jws), &hl);
    unsigned char *cl_raw = b64d(d1 + 1, (size_t) (d2 - d1 - 1), &cl);
    unsigned char *sig = b64d(d2 + 1, strlen(d2 + 1), &sl);
    cJSON *header = cJSON_ParseWithLength((char *) h, hl);
    cJSON *claims = cJSON_ParseWithLength((char *) cl_raw, cl);
    TEST_ASSERT_EQUAL_STRING(expected_alg, cJSON_GetObjectItemCaseSensitive(header, "alg")->valuestring);
    TEST_ASSERT_EQUAL_STRING(expected_kid, cJSON_GetObjectItemCaseSensitive(header, "kid")->valuestring);

    unsigned char der[80];
    const unsigned char *to_verify = sig;
    size_t verify_len = sl;
    if (alg == AXIAM_CIBA_SIGNING_ES256) {
        TEST_ASSERT_EQUAL_INT(64, (int) sl);
        ECDSA_SIG *es = ECDSA_SIG_new();
        ECDSA_SIG_set0(es, BN_bin2bn(sig, 32, NULL), BN_bin2bn(sig + 32, 32, NULL));
        unsigned char *p = der;
        verify_len = (size_t) i2d_ECDSA_SIG(es, &p);
        to_verify = der;
        ECDSA_SIG_free(es);
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestVerifyInit(ctx, &pctx, alg == AXIAM_CIBA_SIGNING_EDDSA ? NULL : EVP_sha256(), NULL, key));
    if (alg == AXIAM_CIBA_SIGNING_PS256) {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, EVP_DigestVerify(ctx, to_verify, verify_len, (const unsigned char *) jws,
                                                      (size_t) (d2 - jws)),
                                  "the signature verifies with the caller's public key");
    EVP_MD_CTX_free(ctx);
    cJSON_Delete(header);
    free(h);
    free(cl_raw);
    free(sig);
    return claims;
}

static void test_t14_the_signed_request_is_one_member_with_the_registered_alg_and_fresh_jti(void) {
    static const axiam_ciba_signing_alg_t algs[] = {AXIAM_CIBA_SIGNING_EDDSA, AXIAM_CIBA_SIGNING_ES256,
                                                   AXIAM_CIBA_SIGNING_PS256};
    static const char *const names[] = {"EdDSA", "ES256", "PS256"};
    for (int k = 0; k < 3; k++) {
        free(g.jwks);
        memset(&g, 0, sizeof g);
        g.clock_s = 1760000000;
        axiam_client_t *c = make_client();
        g.bc[0] = (answer_t){200, g_bc_ok, 0};
        g.bc_len = 1;
        EVP_PKEY *key = keygen(algs[k]);
        TEST_ASSERT_NOT_NULL(key);
        axiam_sensitive_t *pem = pem_of(key);
        axiam_error_t err;
        axiam_ciba_request_signer_t *signer = axiam_ciba_request_signer_new(algs[k], pem, "sig-1", &err);
        TEST_ASSERT_NOT_NULL_MESSAGE(signer, names[k]);
        TEST_ASSERT_EQUAL_INT(algs[k], axiam_ciba_request_signer_alg(signer));
        char notify[65];
        random_hex(notify, 32);
        axiam_sensitive_t *token = axiam_sensitive_new(notify);
        axiam_ciba_initiate_params_t p = poll_params();
        p.binding_message = "W4SCT";
        p.requested_expiry = 120;
        p.has_requested_expiry = 1;
        p.acr_values = "urn:axiam:acr:mfa";
        p.resource = "https://api.example/payments";
        p.delivery = AXIAM_CIBA_DELIVERY_PING;
        p.client_notification_token = token;
        p.signer = signer;
        axiam_ciba_initiate_response_t r;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
        axiam_ciba_initiate_response_dispose(&r);
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
        axiam_ciba_initiate_response_dispose(&r);
        TEST_ASSERT_EQUAL_INT(2, g.n);

        char keys[256];
        form_keys(g.bodies[0], keys, sizeof keys);
        TEST_ASSERT_EQUAL_STRING("client_id,client_secret,request", keys);
        static char request[2][4096];
        form_get(g.bodies[0], "request", request[0], sizeof request[0]);
        form_get(g.bodies[1], "request", request[1], sizeof request[1]);
        cJSON *claims = verify_jws(request[0], key, algs[k], names[k], "sig-1");
        cJSON *second = verify_jws(request[1], key, algs[k], names[k], "sig-1");
        TEST_ASSERT_EQUAL_STRING(CLIENT_ID, cJSON_GetObjectItemCaseSensitive(claims, "iss")->valuestring);
        TEST_ASSERT_EQUAL_STRING(ISSUER, cJSON_GetObjectItemCaseSensitive(claims, "aud")->valuestring);
        double iat = cJSON_GetObjectItemCaseSensitive(claims, "iat")->valuedouble;
        double nbf = cJSON_GetObjectItemCaseSensitive(claims, "nbf")->valuedouble;
        double exp = cJSON_GetObjectItemCaseSensitive(claims, "exp")->valuedouble;
        TEST_ASSERT_TRUE(iat == nbf);
        TEST_ASSERT_TRUE(exp - nbf > 0 && exp - nbf <= 3600);
        const char *jti1 = cJSON_GetObjectItemCaseSensitive(claims, "jti")->valuestring;
        const char *jti2 = cJSON_GetObjectItemCaseSensitive(second, "jti")->valuestring;
        TEST_ASSERT_EQUAL_INT(32, (int) strlen(jti1));
        TEST_ASSERT_TRUE_MESSAGE(strcmp(jti1, jti2) != 0, "two requests, two jtis");
        /* Every member is inside, requested_expiry as a NUMBER. */
        TEST_ASSERT_TRUE(cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(claims, "requested_expiry")));
        TEST_ASSERT_EQUAL_INT(120, cJSON_GetObjectItemCaseSensitive(claims, "requested_expiry")->valueint);
        TEST_ASSERT_EQUAL_STRING("openid", cJSON_GetObjectItemCaseSensitive(claims, "scope")->valuestring);
        TEST_ASSERT_EQUAL_STRING("alice@example.com", cJSON_GetObjectItemCaseSensitive(claims, "login_hint")->valuestring);
        TEST_ASSERT_EQUAL_STRING("W4SCT", cJSON_GetObjectItemCaseSensitive(claims, "binding_message")->valuestring);
        TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(claims, "acr_values"));
        TEST_ASSERT_NOT_NULL(cJSON_GetObjectItemCaseSensitive(claims, "resource"));
        TEST_ASSERT_TRUE(strcmp(cJSON_GetObjectItemCaseSensitive(claims, "client_notification_token")->valuestring,
                                notify) == 0);
        cJSON_Delete(claims);
        cJSON_Delete(second);
        axiam_sensitive_free(token);
        axiam_ciba_request_signer_free(signer);
        axiam_sensitive_free(pem);
        EVP_PKEY_free(key);
        axiam_client_free(c);
    }
}

static void test_t15_no_key_or_a_key_for_another_alg_is_refused_before_any_request(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    EVP_PKEY *ed = keygen(AXIAM_CIBA_SIGNING_EDDSA);
    EVP_PKEY *ec384 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    EVP_PKEY *rsa_small = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 1024);
    axiam_sensitive_t *ed_pem = pem_of(ed);
    axiam_sensitive_t *ec_pem = pem_of(ec384);
    axiam_sensitive_t *rsa_pem = pem_of(rsa_small);
    axiam_sensitive_t *garbage = axiam_sensitive_new("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n");
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    /* No defaults: no algorithm, no key. */
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new((axiam_ciba_signing_alg_t) 0, ed_pem, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new((axiam_ciba_signing_alg_t) 99, ed_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, NULL, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, empty, NULL, &err));
    /* A key that does not sign under the named algorithm. */
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_ES256, ed_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_PS256, ed_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_ES256, ec_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_PS256, rsa_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, rsa_pem, NULL, &err));
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, garbage, NULL, &err));
    /* A passphrase-protected PEM is not a usable key: the SDK never prompts for one. */
    {
        BIO *bio = BIO_new(BIO_s_mem());
        TEST_ASSERT_EQUAL_INT(1, PEM_write_bio_PrivateKey(bio, ed, EVP_aes_256_cbc(),
                                                          (unsigned char *) "pw", 2, NULL, NULL));
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        axiam_sensitive_t *locked = axiam_sensitive_new_bytes(data, (size_t) len);
        BIO_free(bio);
        TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, locked, NULL, &err));
        axiam_sensitive_free(locked);
    }
    TEST_ASSERT_EQUAL_INT(0, g.n + g.discovery_calls);
    /* C has no channel for extra form parameters: with a signer, every member of the
     * params goes inside `request`, so "a form parameter beside it" cannot be written. */
    axiam_ciba_request_signer_free(NULL);
    TEST_ASSERT_EQUAL_INT(0, axiam_ciba_request_signer_alg(NULL));
    axiam_sensitive_free(ed_pem);
    axiam_sensitive_free(ec_pem);
    axiam_sensitive_free(rsa_pem);
    axiam_sensitive_free(garbage);
    axiam_sensitive_free(empty);
    EVP_PKEY_free(ed);
    EVP_PKEY_free(ec384);
    EVP_PKEY_free(rsa_small);
    axiam_client_free(c);
}

static void test_t16_the_key_and_the_request_appear_in_no_rendering(void) {
    axiam_client_t *c = make_client();
    EVP_PKEY *key = keygen(AXIAM_CIBA_SIGNING_EDDSA);
    axiam_sensitive_t *pem = pem_of(key);
    axiam_error_t err;
    axiam_ciba_request_signer_t *signer = axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, pem, "k", &err);
    TEST_ASSERT_NOT_NULL(signer);
    /* The key's base64 body, as a secret string to look for. */
    const char *raw = axiam_sensitive_reveal(pem);
    const char *nl = strchr(raw, '\n');
    char key_body[128];
    snprintf(key_body, sizeof key_body, "%.*s", (int) strcspn(nl + 1, "\n"), nl + 1);
    assert_no_fragment(axiam_sensitive_to_string(pem), key_body);

    g.bc[0] = (answer_t){400, "{\"error\":\"invalid_request\",\"error_description\":\"bad signature\"}", 0};
    g.bc_len = 1;
    axiam_ciba_initiate_params_t p = poll_params();
    p.signer = signer;
    axiam_ciba_initiate_response_t r;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    char request[4096];
    form_get(g.bodies[0], "request", request, sizeof request);
    TEST_ASSERT_TRUE(strlen(request) > 40);
    assert_no_fragment(err.message, request + strlen(request) - 40); /* the signature */
    assert_no_fragment(err.message, key_body);
    /* A failed construction names nothing of the key either. */
    TEST_ASSERT_NULL(axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_ES256, pem, NULL, &err));
    assert_no_fragment(err.message, key_body);
    axiam_ciba_request_signer_free(signer);
    axiam_sensitive_free(pem);
    EVP_PKEY_free(key);
    axiam_client_free(c);
}

/* ---- beyond the sixteen ------------------------------------------------------------ */

static void test_a_server_without_ciba_and_the_discovery_members(void) {
    axiam_client_t *c = make_client();
    axiam_oidc_config_t doc;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_oidc_discover(c, &doc, &err));
    TEST_ASSERT_EQUAL_STRING(BASE "/oauth2/bc-authorize", doc.backchannel_authentication_endpoint);
    TEST_ASSERT_EQUAL_INT(2, (int) doc.backchannel_token_delivery_modes_supported_count);
    TEST_ASSERT_EQUAL_STRING("ping", doc.backchannel_token_delivery_modes_supported[1]);
    TEST_ASSERT_EQUAL_INT(3, (int) doc.backchannel_authentication_request_signing_alg_values_supported_count);
    TEST_ASSERT_TRUE(doc.has_backchannel_user_code_parameter_supported);
    TEST_ASSERT_FALSE(doc.backchannel_user_code_parameter_supported);
    axiam_oidc_config_dispose(&doc);
    axiam_client_free(c);

    g.discovery = DISCOVERY_WITHOUT_CIBA;
    c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_oidc_discover(c, &doc, &err));
    TEST_ASSERT_NULL(doc.backchannel_authentication_endpoint);
    TEST_ASSERT_FALSE(doc.has_backchannel_user_code_parameter_supported);
    axiam_oidc_config_dispose(&doc);
    axiam_ciba_initiate_params_t p = poll_params();
    axiam_ciba_initiate_response_t r;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "does not support CIBA"));
    TEST_ASSERT_EQUAL_INT(0, g.n);
    /* A slug-only tenant cannot name the query parameter. */
    axiam_client_free(c);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, BASE);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_oidc_client_id(cfg, CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, g_secret);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    axiam_sensitive_t *id = axiam_sensitive_new("x");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    axiam_ciba_initiate_response_t in = initiated("x", 60, 5);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n);
    axiam_ciba_initiate_response_dispose(&in);
    axiam_sensitive_free(id);
    axiam_client_free(c);
}

static void test_an_mtls_client_uses_the_backchannel_alias(void) {
    g.discovery =
        "{\"issuer\":\"" ISSUER "\",\"authorization_endpoint\":\"" BASE "/oauth2/authorize\","
        "\"token_endpoint\":\"" BASE "/oauth2/token\",\"jwks_uri\":\"" BASE "/oauth2/jwks\","
        "\"backchannel_authentication_endpoint\":\"" BASE "/oauth2/bc-authorize\","
        "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://mtls.api.test/oauth2/token\","
        "\"backchannel_authentication_endpoint\":\"https://mtls.api.test/oauth2/bc-authorize\"}}";
    axiam_client_t *c = client_with(NULL, 1);
    g.bc[0] = (answer_t){200, g_bc_ok, 0};
    g.bc_len = 1;
    g.token[0] = (answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g.token_len = 1;
    axiam_ciba_initiate_params_t p = poll_params();
    axiam_ciba_initiate_response_t r;
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.urls[0], "https://mtls.api.test/oauth2/bc-authorize?tenant_id="));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_poll(c, r.auth_req_id, NULL, NULL, &set, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.urls[1], "https://mtls.api.test/oauth2/token?tenant_id="));
    axiam_ciba_initiate_response_dispose(&r);

    /* An alias that cannot carry a certificate is refused, not fallen back from. */
    g.discovery =
        "{\"issuer\":\"" ISSUER "\",\"authorization_endpoint\":\"" BASE "/oauth2/authorize\","
        "\"token_endpoint\":\"" BASE "/oauth2/token\",\"jwks_uri\":\"" BASE "/oauth2/jwks\","
        "\"backchannel_authentication_endpoint\":\"" BASE "/oauth2/bc-authorize\","
        "\"mtls_endpoint_aliases\":{\"backchannel_authentication_endpoint\":\"/relative\"}}";
    axiam_client_free(c);
    c = client_with(NULL, 1);
    int before = g.n;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n);
    axiam_client_free(c);
}

static void test_malformed_initiate_responses_and_a_closed_client(void) {
    axiam_client_t *c = make_client();
    axiam_ciba_initiate_params_t p = poll_params();
    axiam_ciba_initiate_response_t r;
    axiam_error_t err;
    static const char *const bodies[] = {"not json", "{\"expires_in\":300}",
                                         "{\"auth_req_id\":\"\",\"expires_in\":300}",
                                         "{\"auth_req_id\":\"x\"}"};
    for (int i = 0; i < 4; i++) {
        g.bc_calls = 0;
        g.bc[0] = (answer_t){200, bodies[i], 0};
        g.bc_len = 1;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
        TEST_ASSERT_NULL(r.auth_req_id);
    }
    /* A 400 without an error member is §2's NetworkError. */
    g.bc[0] = (answer_t){400, NULL, 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
    axiam_sensitive_t *id = axiam_sensitive_new("x");
    axiam_oidc_token_set_t set;
    /* No out parameter, and an initiation with no auth_req_id: refused, nothing sent. */
    int sent = g.n;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_poll(c, id, NULL, NULL, NULL, &err));
    axiam_ciba_initiate_response_t blank = initiated("", 60, 5);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_await(c, &blank, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(sent, g.n);
    axiam_ciba_initiate_response_dispose(&blank);
    axiam_client_close(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_initiate(c, &p, &r, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_poll(c, id, NULL, NULL, &set, &err));
    axiam_ciba_initiate_response_t in = initiated("x", 60, 5);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_await(c, &in, NULL, NULL, &TEST_CLOCK, &set, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ciba_await(c, NULL, NULL, NULL, &TEST_CLOCK, &set, &err));
    axiam_ciba_initiate_response_dispose(&in);
    axiam_sensitive_free(id);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_t01_the_three_values_are_on_the_wire_and_in_no_rendering);
    RUN_TEST(test_t02_no_credential_is_refused_locally_and_one_is_sent_with_tenant_in_the_query);
    RUN_TEST(test_t03_exactly_the_members_set_are_sent);
    RUN_TEST(test_t04_initiate_is_sent_once_on_503_429_and_a_dropped_connection);
    RUN_TEST(test_t05_pending_loops_slow_down_persists_and_the_terminal_answers_are_distinct);
    RUN_TEST(test_t06_the_first_poll_waits_the_interval_or_five_seconds);
    RUN_TEST(test_t07_no_request_after_expires_in_and_expired_token_is_raised_locally);
    RUN_TEST(test_t08_a_500_and_a_429_mid_loop_are_survived);
    RUN_TEST(test_t09_a_second_redemption_is_invalid_grant_and_not_retried);
    RUN_TEST(test_t10_a_valid_ping_returns_its_auth_req_id_in_any_scheme_case);
    RUN_TEST(test_t11_a_wrong_absent_empty_duplicate_or_basic_authorization_is_refused);
    RUN_TEST(test_t12_a_malformed_body_is_a_validation_error_and_extras_are_ignored);
    RUN_TEST(test_t13_the_ping_helper_makes_no_network_call);
    RUN_TEST(test_t14_the_signed_request_is_one_member_with_the_registered_alg_and_fresh_jti);
    RUN_TEST(test_t15_no_key_or_a_key_for_another_alg_is_refused_before_any_request);
    RUN_TEST(test_t16_the_key_and_the_request_appear_in_no_rendering);
    RUN_TEST(test_a_server_without_ciba_and_the_discovery_members);
    RUN_TEST(test_an_mtls_client_uses_the_backchannel_alias);
    RUN_TEST(test_malformed_initiate_responses_and_a_closed_client);
    free(g.jwks);
    g.jwks = NULL;
    return UNITY_END();
}
