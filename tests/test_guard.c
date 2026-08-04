#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

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
    jwt_make("k1", test_claims(payload, sizeof(payload), "user-9",
                               ",\"roles\":[\"admin\",\"viewer\"]"),
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


/* ---------------------------------------------------------------------------
 * CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
 *
 * Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the token
 * the decision is even ABOUT. SEC-085 satisfied all seven and was still an
 * authentication bypass: the PHP guard routed a failed verification into a
 * second, successful one against the *application's own* session, so the caller
 * was admitted as the app's service account — in an IAM integration typically
 * far more privileged than the user whose request it replaced.
 *
 * This SDK matters here more than the ones handed a bare verifier: the C guard
 * takes an `axiam_client_t *`, which carries its own session state
 * (`authenticated`, the CSRF token, the resolved tenant/org). That is the same
 * structural shape SEC-085 exploited — a stateful client reachable from the
 * guard. The guard is correct today (it verifies the token it pulled from the
 * request headers and nothing else), but nothing pinned that.
 *
 * These tests make the substitution genuinely available before asserting it is
 * not taken. The precondition that matters is asserted directly: a SECOND,
 * fully valid token for a more privileged principal is shown to pass this very
 * guard, so a fallback would have succeeded had one existed. Without that
 * check the tests could pass merely because nothing was available to
 * substitute, which proves nothing.
 * ------------------------------------------------------------------------- */

static void test_rule8_failed_caller_token_rejected_with_live_client_session(void) {
    axiam_client_t *c = make_client();

    /* The application's own credential: a valid, admin-roled token for a
     * DIFFERENT principal than the caller. Publishing its key makes it the
     * credential a fallback would have substituted — and one that genuinely
     * verifies, which is what makes the assertions below meaningful rather
     * than passing because nothing could have been substituted. */
    char app_payload[256];
    char *app_token = NULL, *app_jwks = NULL;
    jwt_make("k1", test_claims(app_payload, sizeof(app_payload),
                               "app-service-account", ",\"roles\":[\"admin\"]"),
             &app_token, &app_jwks);
    g.jwks_body = app_jwks;

    /* Precondition, asserted rather than assumed. */
    axiam_headers_t *app_h = bearer_headers(app_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, app_h));
    axiam_kv_free(app_h);

    /* The caller presents a credential that cannot verify. With the app's key
     * published and its token valid, the ONLY way to admit this caller is to
     * decide on a credential it never presented. */
    axiam_headers_t *bad = bearer_headers("not.a.valid-jwt");
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, bad));
    axiam_kv_free(bad);

    free(app_token); free(app_jwks);
    g.jwks_body = g_jwks;
    axiam_client_free(c);
}

static void test_rule8_an_expired_caller_token_is_not_swapped_for_a_valid_one(void) {
    /* Sharper than the malformed case: this token's own key IS the published
     * one, so its signature is genuinely valid and it fails on `exp` alone.
     * Nothing but the caller's own expiry can be the reason for the refusal. */
    axiam_client_t *c = make_client();

    char exp_payload[256];
    snprintf(exp_payload, sizeof(exp_payload),
             "{\"sub\":\"caller-1\",\"tenant_id\":\"%s\",\"exp\":%lld}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) - 900);
    char *expired = NULL, *expired_jwks = NULL;
    jwt_make("k1", exp_payload, &expired, &expired_jwks);
    g.jwks_body = expired_jwks;

    axiam_headers_t *eh = bearer_headers(expired);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, eh));
    axiam_kv_free(eh);

    free(expired); free(expired_jwks);
    g.jwks_body = g_jwks;
    axiam_client_free(c);
}

static void test_rule8_authz_check_carries_the_callers_subject_not_the_apps(void) {
    /* The consequence that made SEC-085 a bypass: the authorization check ran
     * for the WRONG subject. The subject propagated to /authz/check must be the
     * caller's own, never an identity belonging to the client. */
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();

    axiam_headers_t *h = bearer_headers(g_token); /* sub = user-9 */
    axiam_guard_status_t st = axiam_require_access(
        c, h, "users:get", "44444444-4444-4444-4444-444444444444", NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    TEST_ASSERT_NOT_NULL(strstr(g.last_check_body, "\"subject_id\":\"user-9\""));
    TEST_ASSERT_NULL(strstr(g.last_check_body, "app-service-account"));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_rule8_rejection_performs_no_authz_check_at_all(void) {
    /* A rejected caller must not reach the authorization stage under ANY
     * identity. Had a fallback substituted another credential, a check would
     * have been issued — so an empty recorded body is the evidence that no
     * second credential was consulted. */
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    g.last_check_body[0] = '\0';

    axiam_headers_t *bad = bearer_headers("not.a.valid-jwt");
    axiam_guard_status_t st = axiam_require_access(
        c, bad, "users:get", "44444444-4444-4444-4444-444444444444", NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st);
    TEST_ASSERT_EQUAL_STRING("", g.last_check_body);
    axiam_kv_free(bad);
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
    RUN_TEST(test_rule8_failed_caller_token_rejected_with_live_client_session);
    RUN_TEST(test_rule8_an_expired_caller_token_is_not_swapped_for_a_valid_one);
    RUN_TEST(test_rule8_authz_check_carries_the_callers_subject_not_the_apps);
    RUN_TEST(test_rule8_rejection_performs_no_authz_check_at_all);
    return UNITY_END();
}
