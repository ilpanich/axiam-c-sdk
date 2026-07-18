#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

/* --- Programmable fake transport --- */
typedef struct {
    test_recorder_t rec;
    long next_status;
    const char *next_body;
    const char *next_csrf;
    int fail_transport;
} fake_state_t;

static fake_state_t g_fake;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    recorder_capture(&st->rec, req);
    if (st->fail_transport) {
        memset(resp, 0, sizeof(*resp));
        resp->status = 0;
        resp->transport_err = 7;
        resp->transport_msg = strdup("Couldn't connect");
        return 1;
    }
    resp_fill(resp, st->next_status, st->next_body, st->next_csrf);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g_fake, 0, sizeof(g_fake)); }
void tearDown(void) {}

static void test_login_success_sets_tenant_and_csrf(void) {
    g_fake.next_status = 200;
    g_fake.next_body =
        "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
        "\"expires_in\":900,"
        "\"user\":{\"id\":\"u-1\",\"username\":\"alice\",\"email\":\"a@x.io\","
        "\"tenant_id\":\"11111111-1111-1111-1111-111111111111\"}}";
    g_fake.next_csrf = "csrf-abc";

    axiam_client_t *c = make_client();
    TEST_ASSERT_NOT_NULL(c);

    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "pw", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.authenticated);
    TEST_ASSERT_EQUAL_STRING("alice", res.username);
    TEST_ASSERT_EQUAL_INT(900, (int)res.expires_in);
    /* §5: tenant header present. */
    TEST_ASSERT_EQUAL_STRING("11111111-1111-1111-1111-111111111111", g_fake.rec.tenant);
    /* Request went to the right URL and method. */
    TEST_ASSERT_EQUAL_STRING("POST", g_fake.rec.method);
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/auth/login", g_fake.rec.url);
    TEST_ASSERT_EQUAL_STRING("application/json", g_fake.rec.content_type);
    /* Body carries tenant + org for login. */
    TEST_ASSERT_NOT_NULL(strstr(g_fake.rec.body, "\"username_or_email\":\"alice\""));
    TEST_ASSERT_NOT_NULL(strstr(g_fake.rec.body, "\"tenant_id\""));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_csrf_echoed_on_next_state_change(void) {
    /* First login captures CSRF; a subsequent POST echoes it (§3). */
    g_fake.next_status = 200;
    g_fake.next_body = "{\"session_id\":\"s\",\"expires_in\":900,"
                       "\"user\":{\"id\":\"u\",\"username\":\"a\",\"email\":\"e\","
                       "\"tenant_id\":\"t\"}}";
    g_fake.next_csrf = "tok-42";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_login(c, "a", "b", &res, &err);
    axiam_login_result_dispose(&res);

    /* Next request should echo tok-42. */
    g_fake.next_csrf = NULL;
    g_fake.next_status = 204;
    g_fake.next_body = NULL;
    axiam_logout(c, &err);
    TEST_ASSERT_EQUAL_STRING("tok-42", g_fake.rec.csrf_sent);

    axiam_client_free(c);
}

static void test_login_401_is_auth_error(void) {
    g_fake.next_status = 401;
    g_fake.next_body = NULL;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "bad", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_EQUAL_INT(401, (int)err.transport_cause);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_login_mfa_required(void) {
    g_fake.next_status = 202;
    g_fake.next_body = "{\"mfa_required\":true,\"challenge_token\":\"chal-1\","
                       "\"available_methods\":[\"totp\"]}";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "pw", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.mfa_required);
    TEST_ASSERT_EQUAL_STRING("chal-1", res.challenge_token);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_login_mfa_setup_required(void) {
    g_fake.next_status = 403;
    g_fake.next_body = "{\"mfa_setup_required\":true,\"setup_token\":\"setup-9\"}";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "alice", "pw", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.mfa_setup_required);
    TEST_ASSERT_EQUAL_STRING("setup-9", res.setup_token);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_verify_mfa_success(void) {
    g_fake.next_status = 200;
    g_fake.next_body = "{\"session_id\":\"s\",\"expires_in\":900,"
                       "\"user\":{\"id\":\"u\",\"username\":\"a\",\"email\":\"e\","
                       "\"tenant_id\":\"t\"}}";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_verify_mfa(c, "chal-1", "123456", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.authenticated);
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/auth/mfa/verify", g_fake.rec.url);
    TEST_ASSERT_NOT_NULL(strstr(g_fake.rec.body, "\"totp_code\":\"123456\""));
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_logout_success(void) {
    g_fake.next_status = 204;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_logout(c, &err));
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/auth/logout", g_fake.rec.url);
    axiam_client_free(c);
}

static void test_transport_failure_is_network(void) {
    g_fake.fail_transport = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(c, "a", "b", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    /* Message must not leak anything token-like; here it's the transport msg. */
    TEST_ASSERT_NOT_NULL(strstr(err.message, "connect"));
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_refresh_success(void) {
    g_fake.next_status = 200;
    g_fake.next_body = "{\"expires_in\":900}";
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_refresh(c, &err));
    TEST_ASSERT_EQUAL_STRING("https://iam.example.com/api/v1/auth/refresh", g_fake.rec.url);
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)axiam_client_refresh_count(c));
    axiam_client_free(c);
}

static void test_refresh_401_no_retry(void) {
    g_fake.next_status = 401;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    /* §9.3: refresh 401 is AuthError, no retry loop. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_refresh(c, &err));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_login_success_sets_tenant_and_csrf);
    RUN_TEST(test_csrf_echoed_on_next_state_change);
    RUN_TEST(test_login_401_is_auth_error);
    RUN_TEST(test_login_mfa_required);
    RUN_TEST(test_login_mfa_setup_required);
    RUN_TEST(test_verify_mfa_success);
    RUN_TEST(test_logout_success);
    RUN_TEST(test_transport_failure_is_network);
    RUN_TEST(test_refresh_success);
    RUN_TEST(test_refresh_401_no_retry);
    return UNITY_END();
}
