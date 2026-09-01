/*
 * Shared harness for the §12 / §12.7 / §14 / §15 tests.
 *
 * One scriptable fake transport, so every test can assert the thing these
 * sections are actually about: WHAT WENT ON THE WIRE, and HOW MANY TIMES. §16.7
 * makes that discipline explicit for the retry policy — "a tested surface nobody
 * calls is worse than an absent one" — and the same reasoning applies to
 * §12.3's statelessness, §12.4's all-or-nothing, §14.2's polling and §15.2's
 * refusals: each is an assertion about requests, not about a helper in
 * isolation.
 */
#ifndef AXIAM_OIDC_TEST_UTIL_H
#define AXIAM_OIDC_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

#define OIDC_BASE          "https://api.test"
#define OIDC_ISSUER        "https://issuer.test"
#define OIDC_CLIENT_ID     "rp-client"
#define OIDC_CLIENT_SECRET "rp-secret"
#define OIDC_KID           "test-kid"
#define OIDC_REDIRECT_URI  "https://app.test/callback"

/*
 * The issuer here is deliberately NOT the base URL. §12.3 rule 6 forbids
 * rejecting a document over an issuer/base-URL mismatch — the server derives
 * `issuer` from its own configuration and behind a proxy the two legitimately
 * differ — and §12.4 rule 3 compares the ID token's `iss` against the
 * DOCUMENT's value. Making them differ in the fixture is what keeps a
 * "compare against the base URL" regression from passing.
 */
#define OIDC_DISCOVERY_BODY                                                    \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"userinfo_endpoint\":\"" OIDC_BASE "/oauth2/userinfo\","                 \
    "\"introspection_endpoint\":\"" OIDC_BASE "/oauth2/introspect\","          \
    "\"revocation_endpoint\":\"" OIDC_BASE "/oauth2/revoke\","                 \
    "\"end_session_endpoint\":\"" OIDC_BASE "/oauth2/end_session\","           \
    "\"device_authorization_endpoint\":\"" OIDC_BASE "/oauth2/device_authorization\"," \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\",\"profile\"]}"

#define OIDC_MAX_SCRIPT 8
#define OIDC_MAX_CALLS  32

typedef struct {
    long status;
    const char *body;
    int transport_fails;
} oidc_answer_t;

typedef struct {
    /*
     * The discovery document this run serves. NULL means OIDC_DISCOVERY_BODY.
     * §26 needs both a server that advertises a PAR endpoint and one that does
     * not, and the difference between those two IS the assertion — so the
     * document has to be a per-test input rather than a compile-time constant.
     */
    const char *discovery_body;

    /* Per-endpoint call counters — the assertions in these suites are counts. */
    int discovery_calls;
    int jwks_calls;
    int token_calls;
    int introspect_calls;
    int revoke_calls;
    int device_authorize_calls;
    int sso_start_calls;
    int sso_complete_calls;
    int sso_providers_calls;
    int sso_oauth2_start_calls;
    int sso_oauth2_callback_calls;
    int sso_handoff_calls;
    int par_calls;

    const char *jwks_body;
    /* One scripted answer per /oauth2/token call, consumed in order; the last
     * one repeats so a "forever pending" server needs one entry. */
    oidc_answer_t token_script[OIDC_MAX_SCRIPT];
    int token_script_len;

    oidc_answer_t device_answer;
    oidc_answer_t introspect_answer;
    oidc_answer_t revoke_answer;
    oidc_answer_t sso_start_answer;
    oidc_answer_t sso_complete_answer;
    oidc_answer_t sso_providers_answer;
    oidc_answer_t sso_oauth2_start_answer;
    oidc_answer_t sso_oauth2_callback_answer;
    oidc_answer_t sso_handoff_answer;
    oidc_answer_t par_answer;

    /* Every request that reached the transport, in order. */
    char methods[OIDC_MAX_CALLS][8];
    char urls[OIDC_MAX_CALLS][512];
    char content_types[OIDC_MAX_CALLS][64];
    char tenant_headers[OIDC_MAX_CALLS][128];
    char authorizations[OIDC_MAX_CALLS][256];
    char bodies[OIDC_MAX_CALLS][2048];
    int n_calls;

    /* Sleep seam (§16.7's injected-seam idea, reused for §14.2): the device
     * loop's waits are recorded rather than taken, so a 600-second grant runs
     * in microseconds and the INTERVALS themselves become assertable. */
    long sleeps[OIDC_MAX_CALLS];
    int n_sleeps;
    /* Virtual wall clock, advanced by the fake sleep. */
    time_t clock_base;
    long virtual_elapsed_s;
} oidc_state_t;

static oidc_state_t g_oidc;

static void oidc_record(const axiam_http_request_t *req) {
    if (g_oidc.n_calls >= OIDC_MAX_CALLS) return;
    int i = g_oidc.n_calls++;
    snprintf(g_oidc.methods[i], sizeof(g_oidc.methods[i]), "%s", req->method ? req->method : "");
    snprintf(g_oidc.urls[i], sizeof(g_oidc.urls[i]), "%s", req->url ? req->url : "");
    const char *ct = axiam_kv_get(req->headers, "Content-Type");
    snprintf(g_oidc.content_types[i], sizeof(g_oidc.content_types[i]), "%s", ct ? ct : "");
    const char *tenant = axiam_kv_get(req->headers, "X-Tenant-ID");
    snprintf(g_oidc.tenant_headers[i], sizeof(g_oidc.tenant_headers[i]), "%s", tenant ? tenant : "");
    const char *auth = axiam_kv_get(req->headers, "Authorization");
    snprintf(g_oidc.authorizations[i], sizeof(g_oidc.authorizations[i]), "%s", auth ? auth : "");
    snprintf(g_oidc.bodies[i], sizeof(g_oidc.bodies[i]), "%s", req->body ? req->body : "");
}

static int oidc_answer(const oidc_answer_t *a, long default_status, const char *default_body,
                       axiam_http_response_t *resp) {
    if (a && a->transport_fails) {
        memset(resp, 0, sizeof(*resp));
        resp->transport_err = 7;
        resp->transport_msg = strdup("connection refused");
        return -1;
    }
    resp_fill(resp, (a && a->status) ? a->status : default_status,
              (a && a->body) ? a->body : default_body, NULL);
    return 0;
}

static int oidc_fake_transport(void *ctx, const axiam_http_request_t *req,
                               axiam_http_response_t *resp) {
    (void)ctx;
    oidc_record(req);
    const char *url = req->url ? req->url : "";

    if (strstr(url, "/.well-known/openid-configuration")) {
        g_oidc.discovery_calls++;
        resp_fill(resp, 200,
                  g_oidc.discovery_body ? g_oidc.discovery_body : OIDC_DISCOVERY_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/oauth2/par")) {
        g_oidc.par_calls++;
        /* RFC 9126 §2.2 answers Created, and that is the point of the default:
         * a success predicate written `== 200` must fail here. */
        return oidc_answer(&g_oidc.par_answer, 201, "{}", resp);
    }
    if (strstr(url, "/oauth2/jwks")) {
        g_oidc.jwks_calls++;
        resp_fill(resp, 200, g_oidc.jwks_body ? g_oidc.jwks_body : "{\"keys\":[]}", NULL);
        return 0;
    }
    if (strstr(url, "/oauth2/device_authorization")) {
        g_oidc.device_authorize_calls++;
        return oidc_answer(&g_oidc.device_answer, 200, "{}", resp);
    }
    if (strstr(url, "/oauth2/introspect")) {
        g_oidc.introspect_calls++;
        return oidc_answer(&g_oidc.introspect_answer, 200, "{\"active\":false}", resp);
    }
    if (strstr(url, "/oauth2/revoke")) {
        g_oidc.revoke_calls++;
        return oidc_answer(&g_oidc.revoke_answer, 200, "", resp);
    }
    if (strstr(url, "/oauth2/token")) {
        int i = g_oidc.token_calls++;
        if (g_oidc.token_script_len == 0) return oidc_answer(NULL, 200, "{}", resp);
        if (i >= g_oidc.token_script_len) i = g_oidc.token_script_len - 1;
        return oidc_answer(&g_oidc.token_script[i], 200, "{}", resp);
    }
    if (strstr(url, "/federation/oidc/start")) {
        g_oidc.sso_start_calls++;
        return oidc_answer(&g_oidc.sso_start_answer, 200, "{}", resp);
    }
    if (strstr(url, "/federation/oidc/callback")) {
        g_oidc.sso_complete_calls++;
        return oidc_answer(&g_oidc.sso_complete_answer, 200, "{}", resp);
    }
    /* §12.1's four login-provider endpoints. None of the "/oauth2/..." matchers
     * above can claim these: the federation OAuth2 paths end in /start and
     * /callback, not /token, /par, /jwks, /introspect or /revoke. */
    if (strstr(url, "/federation/providers")) {
        g_oidc.sso_providers_calls++;
        return oidc_answer(&g_oidc.sso_providers_answer, 200, "{\"providers\":[]}", resp);
    }
    if (strstr(url, "/federation/oauth2/start")) {
        g_oidc.sso_oauth2_start_calls++;
        return oidc_answer(&g_oidc.sso_oauth2_start_answer, 200, "{}", resp);
    }
    if (strstr(url, "/federation/oauth2/callback")) {
        g_oidc.sso_oauth2_callback_calls++;
        return oidc_answer(&g_oidc.sso_oauth2_callback_answer, 200, "{}", resp);
    }
    if (strstr(url, "/federation/handoff")) {
        g_oidc.sso_handoff_calls++;
        return oidc_answer(&g_oidc.sso_handoff_answer, 200, "{}", resp);
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

/*
 * Record the wait instead of taking it, and ADVANCE A VIRTUAL CLOCK by the same
 * amount. Both halves are needed together: §14.2 rule 4 says polling stops at
 * `expires_in`, and with a frozen clock a test asserting that would hang rather
 * than fail. With the pair, a 600-second grant runs in microseconds and the
 * intervals themselves become assertable.
 */
static void oidc_fake_sleep(void *ctx, long ms) {
    (void)ctx;
    if (g_oidc.n_sleeps < OIDC_MAX_CALLS) g_oidc.sleeps[g_oidc.n_sleeps++] = ms;
    g_oidc.virtual_elapsed_s += ms / 1000;
}

static time_t oidc_fake_clock(void *ctx) {
    (void)ctx;
    return g_oidc.clock_base + g_oidc.virtual_elapsed_s;
}

/* `secret` NULL builds a PUBLIC client — the shape §14.1 requires a device to
 * work with, and the shape §12.1 rule 4 makes introspect/revoke refuse. */
static axiam_client_t *oidc_make_client_ex(const char *client_id, const char *secret,
                                           const char *tenant_id, const char *tenant_slug) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    if (tenant_id) axiam_client_config_set_tenant_id(cfg, tenant_id);
    if (tenant_slug) axiam_client_config_set_tenant_slug(cfg, tenant_slug);
    if (client_id) axiam_client_config_set_oidc_client_id(cfg, client_id);
    if (secret) axiam_client_config_set_oidc_client_secret(cfg, secret);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (c) {
        c->sleep_fn = oidc_fake_sleep;
        c->sleep_ctx = NULL;
        c->clock_fn = oidc_fake_clock;
        c->clock_ctx = NULL;
    }
    return c;
}

static axiam_client_t *oidc_make_client(void) {
    return oidc_make_client_ex(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, AXIAM_TEST_TENANT_ID, NULL);
}

/* The most recent request whose URL contains `needle`, or -1. */
static int oidc_last_call(const char *needle) {
    for (int i = g_oidc.n_calls - 1; i >= 0; i--) {
        if (strstr(g_oidc.urls[i], needle)) return i;
    }
    return -1;
}

/* 1 when the last request to `needle` carried `field=` in its form body. */
static int oidc_body_has_field(const char *needle, const char *field) {
    int i = oidc_last_call(needle);
    if (i < 0) return 0;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", field);
    const char *body = g_oidc.bodies[i];
    if (strncmp(body, pattern, strlen(pattern)) == 0) return 1;
    char amped[66];
    snprintf(amped, sizeof(amped), "&%s=", field);
    return strstr(body, amped) != NULL;
}

static void oidc_reset(void) {
    memset(&g_oidc, 0, sizeof(g_oidc));
    g_oidc.clock_base = time(NULL);
}

#endif /* AXIAM_OIDC_TEST_UTIL_H */
