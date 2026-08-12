/*
 * The §20.3 emit half, wired into the §11 guard (axiam_require_access_uma).
 *
 * Everything asserted here is about the DENY path, because that is the only
 * path that mints anything:
 *
 *   1. A denial with a challenger mints exactly one ticket and emits it.
 *   2. An allow mints nothing — a guard that minted on the happy path would put
 *      a Protection API call in front of every authorized request.
 *   3. A minting failure still denies, without a challenge. An outage must not
 *      turn a deny into a 503, and must never turn it into an allow.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"
#include "internal.h" /* axiam_sensitive_bytes: reading a ticket back is a test-only need */

#define RESOURCE_ID "44444444-4444-4444-4444-444444444444"
#define TICKET "ticket-value"

#define UMA_CONFIG_BODY \
    "{\"issuer\":\"https://api.test\"," \
    "\"token_endpoint\":\"https://api.test/oauth2/token\"," \
    "\"permission_endpoint\":\"https://api.test/uma2/perm\"," \
    "\"resource_registration_endpoint\":\"https://api.test/uma2/rreg/resource_set\"," \
    "\"permission_ticket_lifetime\":60}"

typedef struct {
    const char *jwks_body;
    long check_status;
    const char *check_body;
    long perm_status;
    const char *perm_body;
    int perm_calls;
    char last_perm_body[1024];
} fake_state_t;

static fake_state_t g;
static char *g_token;
static char *g_jwks;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    const char *url = req->url ? req->url : "";

    if (strstr(url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    if (strstr(url, "/authz/check")) {
        resp_fill(resp, st->check_status, st->check_body, NULL);
        return 0;
    }
    if (strstr(url, "/.well-known/uma2-configuration")) {
        resp_fill(resp, 200, UMA_CONFIG_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/uma2/perm")) {
        st->perm_calls++;
        snprintf(st->last_perm_body, sizeof(st->last_perm_body), "%s",
                 req->body ? req->body : "");
        resp_fill(resp, st->perm_status ? st->perm_status : 201,
                  st->perm_body ? st->perm_body : "{\"ticket\":\"" TICKET "\"}", NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static axiam_headers_t *bearer_headers(const char *token) {
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    return axiam_kv_append(NULL, "Authorization", v);
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    char payload[256];
    jwt_make("k1", test_claims(payload, sizeof(payload), "user-9", ",\"roles\":[\"viewer\"]"),
             &g_token, &g_jwks);
    g.jwks_body = g_jwks;
    g.check_status = 200;
}

void tearDown(void) {
    free(g_token); g_token = NULL;
    free(g_jwks); g_jwks = NULL;
}

static axiam_uma_challenger_t challenger(axiam_sensitive_t *pat) {
    axiam_uma_challenger_t ch;
    ch.realm = "invoices";
    ch.as_uri = "https://id.example";
    ch.pat = pat;
    return ch;
}

static void test_a_denial_mints_one_ticket_and_emits_the_challenge(void) {
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    axiam_uma_challenger_t ch = challenger(pat);

    char *header = NULL;
    axiam_guard_status_t st = axiam_require_access_uma(
        c, h, "invoices:read", RESOURCE_ID, NULL, &ch, &header);

    /* The challenge is additive, not a redirect. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_EQUAL_INT(1, g.perm_calls); /* one ticket, not two */
    TEST_ASSERT_NOT_NULL(header);

    /* The emitted header is the one this SDK's own parser consumes — the round
     * trip is the point of shipping both halves. */
    axiam_uma_challenge_t parsed;
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(header, &parsed));
    TEST_ASSERT_EQUAL_STRING("invoices", parsed.realm);
    TEST_ASSERT_EQUAL_STRING("https://id.example", parsed.as_uri);
    TEST_ASSERT_NOT_NULL(parsed.ticket);
    TEST_ASSERT_EQUAL_STRING(TICKET, (const char *)axiam_sensitive_bytes(parsed.ticket));
    axiam_uma_challenge_dispose(&parsed);

    free(header);
    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_the_ticket_asks_for_the_action_that_was_refused(void) {
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    axiam_uma_challenger_t ch = challenger(pat);

    char *header = NULL;
    axiam_require_access_uma(c, h, "invoices:approve", RESOURCE_ID, NULL, &ch, &header);

    /* §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
     * mint a ticket for authority other than the one just refused — and would
     * step outside the grants the engine evaluated, deny rules included. */
    TEST_ASSERT_NOT_NULL(strstr(g.last_perm_body, "\"resource_id\":\"" RESOURCE_ID "\""));
    TEST_ASSERT_NOT_NULL(strstr(g.last_perm_body, "\"invoices:approve\""));

    free(header);
    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_an_allow_mints_nothing(void) {
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    axiam_uma_challenger_t ch = challenger(pat);

    char *header = NULL;
    axiam_guard_status_t st = axiam_require_access_uma(
        c, h, "invoices:read", RESOURCE_ID, NULL, &ch, &header);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    /* Minting on the happy path would put a Protection API call — and a live
     * credential — in front of every authorized request. */
    TEST_ASSERT_EQUAL_INT(0, g.perm_calls);
    TEST_ASSERT_NULL(header);

    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_a_minting_failure_still_denies_without_a_challenge(void) {
    g.check_body = "{\"allowed\":false}";
    g.perm_status = 500;
    g.perm_body = "{\"error\":\"server_error\"}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    axiam_uma_challenger_t ch = challenger(pat);

    char *header = NULL;
    axiam_guard_status_t st = axiam_require_access_uma(
        c, h, "invoices:read", RESOURCE_ID, NULL, &ch, &header);

    /* Failure is not escalation: the caller was going to be refused, and a
     * Protection API outage must not turn that into a 503 — nor, far worse,
     * into an allow. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_NULL(header);
    TEST_ASSERT_TRUE(g.perm_calls >= 1);

    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_without_a_challenger_a_denial_mints_nothing(void) {
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);

    /* Both the NULL-challenger call and the original entry point: opt-in means
     * opt-in, and axiam_require_access() must be untouched by this addition. */
    char poison = 0;
    char *header = &poison; /* the call must overwrite this with NULL */
    axiam_guard_status_t st = axiam_require_access_uma(
        c, h, "invoices:read", RESOURCE_ID, NULL, NULL, &header);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_NULL(header);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access(c, h, "invoices:read", RESOURCE_ID, NULL));
    TEST_ASSERT_EQUAL_INT(0, g.perm_calls);

    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_an_incomplete_challenger_mints_nothing(void) {
    /* A half-configured challenger is a programming error, not a reason to send
     * the Protection API a request that cannot produce a usable header. */
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");

    axiam_uma_challenger_t no_realm = challenger(pat);
    no_realm.realm = NULL;
    char *header = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access_uma(c, h, "invoices:read", RESOURCE_ID, NULL, &no_realm, &header));
    TEST_ASSERT_NULL(header);

    axiam_uma_challenger_t no_pat = challenger(pat);
    no_pat.pat = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access_uma(c, h, "invoices:read", RESOURCE_ID, NULL, &no_pat, &header));
    TEST_ASSERT_NULL(header);

    TEST_ASSERT_EQUAL_INT(0, g.perm_calls);

    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_a_null_out_pointer_is_accepted(void) {
    /* A caller that only wants the status — a framework adapter that does not
     * speak UMA — must not be forced to hold a pointer it will not read. */
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    axiam_uma_challenger_t ch = challenger(pat);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access_uma(c, h, "invoices:read", RESOURCE_ID, NULL, &ch, NULL));
    TEST_ASSERT_EQUAL_INT(0, g.perm_calls);

    axiam_sensitive_free(pat);
    axiam_kv_free(h);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_denial_mints_one_ticket_and_emits_the_challenge);
    RUN_TEST(test_the_ticket_asks_for_the_action_that_was_refused);
    RUN_TEST(test_an_allow_mints_nothing);
    RUN_TEST(test_a_minting_failure_still_denies_without_a_challenge);
    RUN_TEST(test_without_a_challenger_a_denial_mints_nothing);
    RUN_TEST(test_an_incomplete_challenger_mints_nothing);
    RUN_TEST(test_a_null_out_pointer_is_accepted);
    return UNITY_END();
}
