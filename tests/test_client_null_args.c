/* C2: src/client.c thin-branch depth — NULL-arg / NULL-out-param branches
 * not reachable through the higher-level scenarios already covered in
 * tests/test_client_auth.c, tests/test_client_failing_transport.c and
 * tests/test_client_branches.c.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

typedef struct {
    long status;
    const char *body;
} status_state_t;

static int status_transport(void *ctx, const axiam_http_request_t *req,
                            axiam_http_response_t *resp) {
    (void)req;
    status_state_t *st = ctx;
    resp_fill(resp, st->status, st->body, NULL);
    return 0;
}

/* A transport that reports a network failure WITHOUT a transport_msg, so the
 * caller falls back to the default message string (the ternary's false arm
 * on src/client.c:157, 195, 399, 425, 455, 495, 513). */
static int silent_failure_transport(void *ctx, const axiam_http_request_t *req,
                                    axiam_http_response_t *resp) {
    (void)ctx; (void)req;
    memset(resp, 0, sizeof(*resp));
    resp->status = 0;
    resp->transport_err = 7;
    resp->transport_msg = NULL;
    return 1;
}

static axiam_client_t *make_client(axiam_transport_fn fn, void *ctx) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fn, ctx);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {}
void tearDown(void) {}

/* axiam_client_free(NULL) / axiam_client_refresh_count(NULL): the module's
 * own top-level NULL guards (src/client.c:57, 72). */
static void test_client_free_and_refresh_count_null(void) {
    axiam_client_free(NULL); /* must not crash */
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)axiam_client_refresh_count(NULL));
}

/* axiam_login_result_dispose(NULL) / axiam_check_result_dispose(NULL). */
static void test_result_dispose_null(void) {
    axiam_login_result_dispose(NULL);
    axiam_check_result_dispose(NULL);
}

/* axiam_client_raw_get with out_body == NULL on a successful 2xx response:
 * the `if (out_body) *out_body = ...` guard's false arm (src/client.c:160). */
static void test_raw_get_null_out_body_on_success(void) {
    status_state_t st = { .status = 200, .body = "{\"keys\":[]}" };
    axiam_client_t *c = make_client(status_transport, &st);
    axiam_error_t err;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    axiam_client_free(c);
}

/* raw_get: a network failure with NULL transport_msg falls back to the
 * default message (src/client.c:156-157). */
static void test_raw_get_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    char *body = (char *)0x1;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/x", &body, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(body);
    TEST_ASSERT_EQUAL_STRING("network failure", err.message);
    axiam_client_free(c);
}

/* perform_refresh (via axiam_refresh): a network failure with NULL
 * transport_msg falls back to "refresh transport failure"
 * (src/client.c:194-195). */
static void test_refresh_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_refresh(c, &err));
    TEST_ASSERT_EQUAL_STRING("refresh transport failure", err.message);
    axiam_client_free(c);
}

/* login/verify_mfa/logout/check_access: a network failure with NULL
 * transport_msg falls back to "network failure"
 * (src/client.c:398-399, 424-425, 454-455, 494-495). */
static void test_login_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login(c, "a", "b", &res, &err));
    TEST_ASSERT_EQUAL_STRING("network failure", err.message);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_verify_mfa_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_verify_mfa(c, "chal", "123456", &res, &err));
    TEST_ASSERT_EQUAL_STRING("network failure", err.message);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_logout_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_logout(c, &err));
    TEST_ASSERT_EQUAL_STRING("network failure", err.message);
    axiam_client_free(c);
}

static void test_check_access_network_failure_default_message(void) {
    axiam_client_t *c = make_client(silent_failure_transport, NULL);
    axiam_check_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_check_access(c, "a", "r", NULL, NULL, &res, &err));
    TEST_ASSERT_EQUAL_STRING("network failure", err.message);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

/* axiam_check_access / axiam_verify_mfa with out == NULL: the `if (out)`
 * memset/fill guards' false arms (src/client.c:343, 369, 412, 537). */
static void test_check_access_null_out(void) {
    status_state_t st = { .status = 200, .body = "{\"allowed\":true}" };
    axiam_client_t *c = make_client(status_transport, &st);
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(c, "a", "r", NULL, NULL, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    axiam_client_free(c);
}

static void test_login_null_out(void) {
    status_state_t st = { .status = 200,
        .body = "{\"session_id\":\"s\",\"expires_in\":900,"
                "\"user\":{\"id\":\"u\",\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}" };
    axiam_client_t *c = make_client(status_transport, &st);
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "a", "b", NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_client_free_and_refresh_count_null);
    RUN_TEST(test_result_dispose_null);
    RUN_TEST(test_raw_get_null_out_body_on_success);
    RUN_TEST(test_raw_get_network_failure_default_message);
    RUN_TEST(test_refresh_network_failure_default_message);
    RUN_TEST(test_login_network_failure_default_message);
    RUN_TEST(test_verify_mfa_network_failure_default_message);
    RUN_TEST(test_logout_network_failure_default_message);
    RUN_TEST(test_check_access_network_failure_default_message);
    RUN_TEST(test_check_access_null_out);
    RUN_TEST(test_login_null_out);
    return UNITY_END();
}
