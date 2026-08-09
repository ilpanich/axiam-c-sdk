/*
 * Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
 *
 * The rule exists because the two refusals mean opposite things to the person
 * on the other end: `no_grant` says *ask an admin for access*, `denied_by_rule`
 * says *an admin has already decided*. An application that cannot tell them
 * apart sends users to raise tickets that will be refused.
 *
 * The guard half of the file asserts the other side of the clause: reporting
 * changed, enforcement did not.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

typedef struct {
    test_recorder_t rec;
    const char *jwks_body;
    long status;
    const char *body;
} fake_state_t;

static fake_state_t g;
static char *g_token;
static char *g_jwks;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    recorder_capture(&st->rec, req);
    resp_fill(resp, st->status, st->body, NULL);
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

void setUp(void) {
    memset(&g, 0, sizeof(g));
    char payload[256];
    jwt_make("k1", test_claims(payload, sizeof(payload), "user-9", ""), &g_token, &g_jwks);
    g.jwks_body = g_jwks;
}

void tearDown(void) {
    free(g_token); g_token = NULL;
    free(g_jwks); g_jwks = NULL;
}

/* Run one check against `body` and hand the result to the caller. */
static axiam_check_result_t check_with(const char *body) {
    g.status = 200;
    g.body = body;
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "docs:read",
        "44444444-4444-4444-4444-444444444444", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    axiam_client_free(c);
    return res;
}

/* ------------------------------------------------------------------ */
/* check_access                                                       */
/* ------------------------------------------------------------------ */

static void test_allow_carries_allowed_code(void) {
    axiam_check_result_t r = check_with("{\"allowed\":true,\"reason_code\":\"allowed\"}");
    TEST_ASSERT_TRUE(r.allowed);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_ALLOWED, r.reason_code);
    axiam_check_result_dispose(&r);
}

static void test_the_two_refusals_are_not_collapsed(void) {
    axiam_check_result_t no_grant =
        check_with("{\"allowed\":false,\"reason_code\":\"no_grant\"}");
    axiam_check_result_t by_rule =
        check_with("{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}");

    /* Both are refusals… */
    TEST_ASSERT_FALSE(no_grant.allowed);
    TEST_ASSERT_FALSE(by_rule.allowed);
    /* …and the SDK must not reduce them to that shared `false`. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_NO_GRANT, no_grant.reason_code);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_DENIED_BY_RULE, by_rule.reason_code);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(no_grant.reason_code, by_rule.reason_code));

    axiam_check_result_dispose(&no_grant);
    axiam_check_result_dispose(&by_rule);
}

static void test_unknown_code_passes_through_and_changes_nothing(void) {
    /* This is what lets the server add a fourth code without breaking every
       deployed SDK: the outcome is carried by `allowed` alone. */
    axiam_check_result_t denied =
        check_with("{\"allowed\":false,\"reason_code\":\"denied_by_some_future_thing\"}");
    TEST_ASSERT_FALSE(denied.allowed);
    TEST_ASSERT_EQUAL_STRING("denied_by_some_future_thing", denied.reason_code);
    axiam_check_result_dispose(&denied);

    /* And it must not flip an allow either. */
    axiam_check_result_t allowed =
        check_with("{\"allowed\":true,\"reason_code\":\"something-unrecognised\"}");
    TEST_ASSERT_TRUE(allowed.allowed);
    TEST_ASSERT_EQUAL_STRING("something-unrecognised", allowed.reason_code);
    axiam_check_result_dispose(&allowed);
}

static void test_older_server_omitting_the_field_is_absent_not_an_error(void) {
    axiam_check_result_t denied = check_with("{\"allowed\":false}");
    TEST_ASSERT_FALSE(denied.allowed);
    TEST_ASSERT_NULL(denied.reason_code);
    axiam_check_result_dispose(&denied);

    /* A JSON null is the same thing as absent, not a decode failure. */
    axiam_check_result_t allowed =
        check_with("{\"allowed\":true,\"reason\":\"role grants it\",\"reason_code\":null}");
    TEST_ASSERT_TRUE(allowed.allowed);
    TEST_ASSERT_NULL(allowed.reason_code);
    TEST_ASSERT_EQUAL_STRING("role grants it", allowed.reason);
    axiam_check_result_dispose(&allowed);
}

static void test_reason_and_reason_code_are_independent(void) {
    /* `reason` is prose for a human, `reason_code` is for a branch in code.
       Neither is derived from the other. */
    axiam_check_result_t r = check_with(
        "{\"allowed\":false,\"reason\":\"no grant on /docs/42\",\"reason_code\":\"no_grant\"}");
    TEST_ASSERT_EQUAL_STRING("no grant on /docs/42", r.reason);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_NO_GRANT, r.reason_code);
    axiam_check_result_dispose(&r);
}

/* ------------------------------------------------------------------ */
/* batch_check                                                        */
/* ------------------------------------------------------------------ */

static void test_batch_surfaces_a_code_per_decision(void) {
    g.status = 200;
    g.body = "{\"results\":["
             "{\"allowed\":true,\"reason_code\":\"allowed\"},"
             "{\"allowed\":false,\"reason_code\":\"no_grant\"},"
             "{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}]}";
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[3] = {
        {"docs:read", "r1", NULL, NULL},
        {"docs:write", "r1", NULL, NULL},
        {"docs:delete", "r1", NULL, NULL},
    };
    axiam_check_result_t out[3];
    size_t n = 0;
    axiam_error_t err;

    axiam_error_kind_t k = axiam_batch_check(c, checks, 3, out, &n, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_UINT(3, (unsigned)n);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_ALLOWED, out[0].reason_code);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_NO_GRANT, out[1].reason_code);
    TEST_ASSERT_EQUAL_STRING(AXIAM_REASON_CODE_DENIED_BY_RULE, out[2].reason_code);

    for (size_t i = 0; i < n; i++) axiam_check_result_dispose(&out[i]);
    axiam_client_free(c);
}

static void test_batch_tolerates_a_server_that_omits_codes(void) {
    g.status = 200;
    g.body = "{\"results\":[{\"allowed\":true},{\"allowed\":false,\"reason\":\"no\"}]}";
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[2] = {
        {"a1", "r1", NULL, NULL},
        {"a2", "r2", NULL, NULL},
    };
    axiam_check_result_t out[2];
    size_t n = 0;
    axiam_error_t err;

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_batch_check(c, checks, 2, out, &n, &err));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)n);
    TEST_ASSERT_NULL(out[0].reason_code);
    TEST_ASSERT_NULL(out[1].reason_code);
    TEST_ASSERT_EQUAL_STRING("no", out[1].reason);

    for (size_t i = 0; i < n; i++) axiam_check_result_dispose(&out[i]);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Ownership                                                          */
/* ------------------------------------------------------------------ */

static void test_dispose_frees_and_clears_the_code(void) {
    /* The struct is caller-allocated, so a missed free here is a leak in every
       application that checks access in a loop — which is all of them. The
       valgrind and ASan CI jobs are what actually prove the free; this asserts
       the observable half, that dispose leaves nothing dangling to re-free. */
    axiam_check_result_t r = check_with("{\"allowed\":false,\"reason_code\":\"no_grant\"}");
    TEST_ASSERT_NOT_NULL(r.reason_code);

    axiam_check_result_dispose(&r);
    TEST_ASSERT_NULL(r.reason_code);
    TEST_ASSERT_NULL(r.reason);
    TEST_ASSERT_FALSE(r.allowed);

    /* Idempotent: a second dispose must not double-free. */
    axiam_check_result_dispose(&r);
    TEST_ASSERT_NULL(r.reason_code);
}

/* ------------------------------------------------------------------ */
/* Enforcement is unchanged (§11 rule 9)                              */
/* ------------------------------------------------------------------ */

static void test_guard_returns_403_for_both_refusals(void) {
    /* "This clause is about *reporting*, not enforcement, and an SDK MUST NOT
       vary its guard behaviour on reason_code." Both refusals stop the request
       identically; only the reporting differs. */
    axiam_headers_t *h;
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", g_token);

    g.status = 200;
    g.body = "{\"allowed\":false,\"reason_code\":\"no_grant\"}";
    axiam_client_t *c1 = make_client();
    h = axiam_kv_append(NULL, "Authorization", v);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access(c1, h, "docs:read", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c1);

    g.body = "{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}";
    axiam_client_t *c2 = make_client();
    h = axiam_kv_append(NULL, "Authorization", v);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access(c2, h, "docs:read", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c2);
}

static void test_guard_allows_on_an_unknown_code(void) {
    /* An allow with a code this build has never seen is still an allow. */
    g.status = 200;
    g.body = "{\"allowed\":true,\"reason_code\":\"allowed_by_some_future_thing\"}";
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", g_token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        axiam_require_access(c, h, "docs:read", "44444444-4444-4444-4444-444444444444", NULL));

    axiam_kv_free(h);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_allow_carries_allowed_code);
    RUN_TEST(test_the_two_refusals_are_not_collapsed);
    RUN_TEST(test_unknown_code_passes_through_and_changes_nothing);
    RUN_TEST(test_older_server_omitting_the_field_is_absent_not_an_error);
    RUN_TEST(test_reason_and_reason_code_are_independent);
    RUN_TEST(test_batch_surfaces_a_code_per_decision);
    RUN_TEST(test_batch_tolerates_a_server_that_omits_codes);
    RUN_TEST(test_dispose_frees_and_clears_the_code);
    RUN_TEST(test_guard_returns_403_for_both_refusals);
    RUN_TEST(test_guard_allows_on_an_unknown_code);
    return UNITY_END();
}
