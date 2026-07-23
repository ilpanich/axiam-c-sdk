#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

typedef struct {
    const char *jwks_body;
    long check_status;
    const char *check_body;
    int fail_check_transport;
    int fail_jwks_transport;
    char last_check_body[1024];
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        if (st->fail_jwks_transport) {
            memset(resp, 0, sizeof(*resp));
            resp->status = 0;
            resp->transport_err = 7;
            resp->transport_msg = strdup("connect failed");
            return 1;
        }
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    if (strstr(req->url, "/authz/check")) {
        snprintf(st->last_check_body, sizeof(st->last_check_body), "%s",
                 req->body ? req->body : "");
        if (st->fail_check_transport) {
            memset(resp, 0, sizeof(*resp));
            resp->status = 0;
            resp->transport_err = 7;
            resp->transport_msg = strdup("connect failed");
            return 1;
        }
        resp_fill(resp, st->check_status, st->check_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

static char *g_token;
static char *g_jwks;

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
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
    jwt_make("k1", "{\"sub\":\"user-9\",\"roles\":[\"admin\",\"viewer\"]}",
             &g_token, &g_jwks);
    g.jwks_body = g_jwks;
}
void tearDown(void) {
    free(g_token); g_token = NULL;
    free(g_jwks); g_jwks = NULL;
}

static void test_require_auth_allow_and_deny(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);

    /* No credential -> 401. */
    axiam_headers_t *empty = axiam_kv_append(NULL, "X-Other", "1");
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, empty));
    axiam_kv_free(empty);
    axiam_client_free(c);
}

static void test_require_access_allow(void) {
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_guard_status_t st = axiam_require_access(c, h, "users:get",
        "44444444-4444-4444-4444-444444444444", NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    /* §11.2(2): subject propagation — the authenticated user id is the subject. */
    TEST_ASSERT_NOT_NULL(strstr(g.last_check_body, "\"subject_id\":\"user-9\""));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_require_access_denied(void) {
    g.check_status = 200;
    g.check_body = "{\"allowed\":false}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_require_access_bad_resource(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    /* §11.2(3): empty resource id -> 400. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_BAD_REQUEST,
                          axiam_require_access(c, h, "a", "", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_require_access_unauthenticated(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *empty = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
        axiam_require_access(c, empty, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_client_free(c);
}

static void test_require_access_fail_closed_on_network(void) {
    g.fail_check_transport = 1;
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    /* §11.2(5): transport failure fails CLOSED -> 503. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAVAILABLE,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_require_role_local(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    const char *want_ok[] = {"editor", "admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_role(c, h, want_ok, 2));
    const char *want_no[] = {"superuser"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, want_no, 1));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_sourced_token(void) {
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    char cookie[2048];
    snprintf(cookie, sizeof(cookie), "axiam_access=%s; other=1", g_token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", cookie);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* CONTRACT §11.2 fail-closed: a JWKS network failure while verifying a
 * present token maps to AXIAM_GUARD_UNAVAILABLE (src/guard.c:51-53), not a
 * silent allow or a plain 401. */
static void test_require_auth_jwks_network_failure_is_unavailable(void) {
    g.fail_jwks_transport = 1;
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAVAILABLE, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* A present-but-invalid token (JWKS fetch succeeds, signature verification
 * fails) maps to AXIAM_GUARD_UNAUTHENTICATED via the same lines. */
static void test_require_auth_invalid_token_is_unauthenticated(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers("not-a-jwt-at-all");
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* CONTRACT §11.2: an authorization-server DENY (403/409 -> AXIAM_ERR_AUTHZ)
 * maps to AXIAM_GUARD_DENIED (src/guard.c:97). */
static void test_require_access_authz_error_is_denied(void) {
    g.check_status = 403;
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* CONTRACT §11.2: a check_access AUTH error (401 with no active session, so
 * no retry loop) maps to AXIAM_GUARD_UNAUTHENTICATED (src/guard.c:99). */
static void test_require_access_auth_error_is_unauthenticated(void) {
    g.check_status = 401;
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_macro_forms(void) {
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, AXIAM_REQUIRE_AUTH(c, h));
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        AXIAM_REQUIRE_ACCESS(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, AXIAM_REQUIRE_ROLE(c, h, roles, 1));
    axiam_kv_free(h);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_require_auth_allow_and_deny);
    RUN_TEST(test_require_access_allow);
    RUN_TEST(test_require_access_denied);
    RUN_TEST(test_require_access_bad_resource);
    RUN_TEST(test_require_access_unauthenticated);
    RUN_TEST(test_require_access_fail_closed_on_network);
    RUN_TEST(test_require_role_local);
    RUN_TEST(test_cookie_sourced_token);
    RUN_TEST(test_require_auth_jwks_network_failure_is_unavailable);
    RUN_TEST(test_require_auth_invalid_token_is_unauthenticated);
    RUN_TEST(test_require_access_authz_error_is_denied);
    RUN_TEST(test_require_access_auth_error_is_unauthenticated);
    RUN_TEST(test_macro_forms);
    return UNITY_END();
}
