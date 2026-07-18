#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

typedef struct {
    test_recorder_t rec;
    long status;
    const char *body;
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    recorder_capture(&st->rec, req);
    resp_fill(resp, st->status, st->body, NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com/");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g, 0, sizeof(g)); }
void tearDown(void) {}

static void test_check_access_allowed(void) {
    g.status = 200;
    g.body = "{\"allowed\":true,\"reason\":null}";
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "users:get",
        "44444444-4444-4444-4444-444444444444", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.allowed);
    /* base_url trailing slash is normalized. */
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/authz/check", g.rec.url);
    TEST_ASSERT_EQUAL_STRING("acme", g.rec.tenant);
    /* Argument order (action, resource[, scope]) reflected in the body. */
    TEST_ASSERT_NOT_NULL(strstr(g.rec.body, "\"action\":\"users:get\""));
    TEST_ASSERT_NOT_NULL(strstr(g.rec.body, "\"resource_id\":\"44444444"));
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

static void test_check_access_denied_403(void) {
    g.status = 403;
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "a", "r", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, k);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

static void test_check_access_with_scope_and_subject(void) {
    g.status = 200;
    g.body = "{\"allowed\":false,\"reason\":\"denied by policy\"}";
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "docs:edit",
        "55555555-5555-5555-5555-555555555555", "field:title",
        "66666666-6666-6666-6666-666666666666", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_FALSE(res.allowed);
    TEST_ASSERT_EQUAL_STRING("denied by policy", res.reason);
    TEST_ASSERT_NOT_NULL(strstr(g.rec.body, "\"scope\":\"field:title\""));
    TEST_ASSERT_NOT_NULL(strstr(g.rec.body, "\"subject_id\":\"66666666"));
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

static void test_can_alias(void) {
    g.status = 200;
    g.body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_can(c, "page:view", "77777777-7777-7777-7777-777777777777",
                                     NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.allowed);
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/authz/check", g.rec.url);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

static void test_batch_check_ordered(void) {
    g.status = 200;
    g.body = "{\"results\":[{\"allowed\":true},{\"allowed\":false,\"reason\":\"no\"}]}";
    axiam_client_t *c = make_client();
    axiam_check_input_t checks[2] = {
        {"a1", "r1", NULL, NULL},
        {"a2", "r2", "s2", NULL},
    };
    axiam_check_result_t out[2];
    size_t n = 0;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_batch_check(c, checks, 2, out, &n, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)n);
    TEST_ASSERT_TRUE(out[0].allowed);
    TEST_ASSERT_FALSE(out[1].allowed);
    TEST_ASSERT_EQUAL_STRING("no", out[1].reason);
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/authz/check/batch", g.rec.url);
    axiam_check_result_dispose(&out[0]);
    axiam_check_result_dispose(&out[1]);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_check_access_allowed);
    RUN_TEST(test_check_access_denied_403);
    RUN_TEST(test_check_access_with_scope_and_subject);
    RUN_TEST(test_can_alias);
    RUN_TEST(test_batch_check_ordered);
    return UNITY_END();
}
