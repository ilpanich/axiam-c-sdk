/* C2: src/client.c thin-branch depth.
 *
 * Targets (per claude_dev/test-coverage-round2-plan.md, task C2):
 *  - axiam_client_new() config-validation failure branch (src/client.c:12),
 *    including a NULL cfg (also exercises src/config.c:82-84).
 *  - parse_login_like: a 2xx body that is present but not parseable JSON
 *    (cJSON_Parse returns NULL) on the login/mfa-verify 2xx arm.
 *  - axiam_check_access / axiam_batch_check: a 2xx response whose body is
 *    not valid JSON (the `if (root)` guard around parse_check_result).
 *  - axiam_batch_check: `results` shorter than n, and longer than n (the
 *    `i >= n` break).
 *  - resolve_ids_from_login cookie edge cases: a bare token (no trailing
 *    attributes), a cookie value WITH attributes, a Set-Cookie header that
 *    never carries "axiam_access=", and a malformed-base64url payload that
 *    must leave the previously-resolved tenant/org ids untouched.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

typedef struct {
    long login_status;
    const char *login_body;
    const char *login_cookie; /* full Set-Cookie header value, or NULL to omit */
    long check_status;
    const char *check_body;
    long batch_status;
    const char *batch_body;
    char refresh_body[2048];
} branch_state_t;

static branch_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    branch_state_t *st = ctx;
    if (strstr(req->url, "/auth/login") || strstr(req->url, "/auth/mfa/verify")) {
        resp_fill(resp, st->login_status, st->login_body, NULL);
        if (st->login_cookie)
            resp->headers = axiam_kv_append(resp->headers, "Set-Cookie", st->login_cookie);
        return 0;
    }
    if (strstr(req->url, "/auth/refresh")) {
        snprintf(st->refresh_body, sizeof(st->refresh_body), "%s", req->body ? req->body : "");
        resp_fill(resp, 200, "{\"expires_in\":900}", NULL);
        return 0;
    }
    if (strstr(req->url, "/authz/check/batch")) {
        resp_fill(resp, st->batch_status, st->batch_body, NULL);
        return 0;
    }
    if (strstr(req->url, "/authz/check")) {
        resp_fill(resp, st->check_status, st->check_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* A client configured with SLUGS ONLY, so that resolve_ids_from_login's
 * cookie decode is the ONLY source of tenant/org UUIDs for refresh(). */
static axiam_client_t *make_slug_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "globex");
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g, 0, sizeof(g)); }
void tearDown(void) {}

/* --- axiam_client_new() config-validation failure (src/client.c:12) --- */

static void test_client_new_null_cfg_fails(void) {
    /* Also exercises src/config.c:82-84 (validate(NULL,...)). */
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(NULL, &err);
    TEST_ASSERT_NULL(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "NULL"));
}

static void test_client_new_invalid_cfg_fails(void) {
    /* Missing tenant_slug/tenant_id -> validate() fails -> client_new returns
     * NULL without ever constructing a client (src/client.c:12). */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_NULL(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    axiam_client_config_free(cfg);
}

/* --- parse_login_like: 2xx body present but unparseable --- */

static void test_login_2xx_unparseable_body(void) {
    g.login_status = 200;
    g.login_body = "this is not json {{{";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "pw", &res, &err);
    /* Still AXIAM_OK: status drives success, JSON is best-effort. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_FALSE(res.authenticated); /* root==NULL -> out fields left zeroed */
    TEST_ASSERT_NULL(res.session_id);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_mfa_verify_2xx_unparseable_body(void) {
    g.login_status = 200;
    g.login_body = "[[[not an object";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_verify_mfa(c, "chal", "123456", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_FALSE(res.authenticated);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_login_202_unparseable_body(void) {
    /* MFA-required arm (status==202) with a body that fails cJSON_Parse:
     * challenge_token stays NULL via the `root ? ... : NULL` ternary. */
    g.login_status = 202;
    g.login_body = "not json";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "pw", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.mfa_required);
    TEST_ASSERT_NULL(res.challenge_token);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

/* --- axiam_check_access / axiam_batch_check: 2xx-but-invalid-JSON --- */

static void test_check_access_2xx_unparseable_body(void) {
    g.check_status = 200;
    g.check_body = "not json at all";
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "a", "r", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_FALSE(res.allowed);
    TEST_ASSERT_NULL(res.reason);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

static void test_batch_check_2xx_unparseable_body(void) {
    g.batch_status = 200;
    g.batch_body = "{not: valid json";
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[1] = { {"a", "r", NULL, NULL} };
    axiam_check_result_t out[1];
    memset(out, 0, sizeof(out));
    size_t n = 999;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_batch_check(c, checks, 1, out, &n, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    /* out_count stays at its axiam_batch_check-entry reset (0): the `results`
     * array was never found because the body never parsed. */
    TEST_ASSERT_EQUAL_UINT(0, n);
    axiam_client_free(c);
}

static void test_batch_check_results_missing_field(void) {
    /* Body parses but has no "results" array at all -> cJSON_IsArray(NULL)
     * is false -> the whole fan-out is skipped, out_count stays 0. */
    g.batch_status = 200;
    g.batch_body = "{\"other\":1}";
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[1] = { {"a", "r", NULL, NULL} };
    axiam_check_result_t out[1];
    memset(out, 0, sizeof(out));
    size_t n = 999;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_batch_check(c, checks, 1, out, &n, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_UINT(0, n);
    axiam_client_free(c);
}

/* --- axiam_batch_check: results array LONGER than n (the i>=n break) --- */

static void test_batch_check_results_longer_than_n(void) {
    g.batch_status = 200;
    g.batch_body = "{\"results\":["
                   "{\"allowed\":true},"
                   "{\"allowed\":false,\"reason\":\"no\"},"
                   "{\"allowed\":true}]}"; /* 3 results, only 2 requested */
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[2] = {
        {"a1", "r1", NULL, NULL},
        {"a2", "r2", NULL, NULL},
    };
    axiam_check_result_t out[2];
    memset(out, 0, sizeof(out));
    size_t n = 0;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_batch_check(c, checks, 2, out, &n, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    /* The loop must stop at i==n==2, never touching a 3rd result. */
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_TRUE(out[0].allowed);
    TEST_ASSERT_FALSE(out[1].allowed);
    axiam_check_result_dispose(&out[0]);
    axiam_check_result_dispose(&out[1]);
    axiam_client_free(c);
}

/* --- axiam_batch_check: results array SHORTER than n --- */

static void test_batch_check_results_shorter_than_n(void) {
    g.batch_status = 200;
    g.batch_body = "{\"results\":[{\"allowed\":true}]}"; /* 1 result, 2 requested */
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[2] = {
        {"a1", "r1", NULL, NULL},
        {"a2", "r2", NULL, NULL},
    };
    axiam_check_result_t out[2];
    memset(out, 0, sizeof(out));
    size_t n = 0;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_batch_check(c, checks, 2, out, &n, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_TRUE(out[0].allowed);
    axiam_check_result_dispose(&out[0]);
    axiam_client_free(c);
}

/* --- resolve_ids_from_login cookie edge cases --- */

/* Payload {"tenant_id":"tenant-bare","org_id":"org-bare"}. */
#define JWT_BARE \
    "eyJhbGciOiAiRWREU0EiLCAidHlwIjogIkpXVCJ9." \
    "eyJ0ZW5hbnRfaWQiOiAidGVuYW50LWJhcmUiLCAib3JnX2lkIjogIm9yZy1iYXJlIn0." \
    "sig"

/* Payload {"tenant_id":"tenant-attrs","org_id":"org-attrs"}. */
#define JWT_ATTRS \
    "eyJhbGciOiAiRWREU0EiLCAidHlwIjogIkpXVCJ9." \
    "eyJ0ZW5hbnRfaWQiOiAidGVuYW50LWF0dHJzIiwgIm9yZ19pZCI6ICJvcmctYXR0cnMifQ." \
    "sig"

static void test_resolve_ids_bare_token_no_attributes(void) {
    /* Set-Cookie value with NO trailing ";attrs" — strcspn(access, ";")
     * copies the whole remaining string (src/client.c:303). */
    g.login_status = 200;
    g.login_body = "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                   "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"tenant-bare\"}}";
    g.login_cookie = "axiam_access=" JWT_BARE;
    axiam_client_t *c = make_slug_client();

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_refresh(c, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"tenant_id\":\"tenant-bare\""));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"org_id\":\"org-bare\""));
    axiam_client_free(c);
}

static void test_resolve_ids_cookie_with_attributes(void) {
    g.login_status = 200;
    g.login_body = "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                   "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"tenant-attrs\"}}";
    g.login_cookie = "axiam_access=" JWT_ATTRS "; Path=/; HttpOnly; SameSite=Lax";
    axiam_client_t *c = make_slug_client();

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_refresh(c, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"tenant_id\":\"tenant-attrs\""));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"org_id\":\"org-attrs\""));
    axiam_client_free(c);
}

static void test_resolve_ids_missing_axiam_access_cookie(void) {
    /* Set-Cookie present but never carries "axiam_access=" — resolve stays a
     * no-op (src/client.c:299-300); refresh has no UUIDs to work with and
     * fails AUTH (never AXIAM_OK) on a slug-only client. */
    g.login_status = 200;
    g.login_body = "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                   "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}";
    g.login_cookie = "other_cookie=xyz; Path=/";
    axiam_client_t *c = make_slug_client();

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_refresh(c, &err));
    axiam_client_free(c);
}

static void test_resolve_ids_decode_failure_preserves_prior_values(void) {
    /* First login resolves real UUIDs from a valid cookie. */
    g.login_status = 200;
    g.login_body = "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                   "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"tenant-bare\"}}";
    g.login_cookie = "axiam_access=" JWT_BARE;
    axiam_client_t *c = make_slug_client();

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    /* Second login's cookie has a payload segment with characters outside the
     * base64url alphabet ('#'), so axiam_b64url_decode fails, jwt_claim_dup
     * returns NULL for both claims, and resolve_ids_from_login must leave the
     * previously-resolved tenant/org ids untouched (src/client.c:314-315). */
    g.login_cookie = "axiam_access=eyJhbGciOiJFZERTQSJ9.###not-base64url###.sig";
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_refresh(c, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"tenant_id\":\"tenant-bare\""));
    TEST_ASSERT_NOT_NULL(strstr(g.refresh_body, "\"org_id\":\"org-bare\""));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_client_new_null_cfg_fails);
    RUN_TEST(test_client_new_invalid_cfg_fails);
    RUN_TEST(test_login_2xx_unparseable_body);
    RUN_TEST(test_mfa_verify_2xx_unparseable_body);
    RUN_TEST(test_login_202_unparseable_body);
    RUN_TEST(test_check_access_2xx_unparseable_body);
    RUN_TEST(test_batch_check_2xx_unparseable_body);
    RUN_TEST(test_batch_check_results_missing_field);
    RUN_TEST(test_batch_check_results_longer_than_n);
    RUN_TEST(test_batch_check_results_shorter_than_n);
    RUN_TEST(test_resolve_ids_bare_token_no_attributes);
    RUN_TEST(test_resolve_ids_cookie_with_attributes);
    RUN_TEST(test_resolve_ids_missing_axiam_access_cookie);
    RUN_TEST(test_resolve_ids_decode_failure_preserves_prior_values);
    return UNITY_END();
}
