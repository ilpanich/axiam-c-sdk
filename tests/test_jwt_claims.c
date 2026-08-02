/* SEC-071: strict local token verification.
 *
 * The JWKS trust anchor is organization-wide and the SDK's route guards are a
 * relying party, so a valid Ed25519 signature is NOT by itself an
 * authenticated caller. These tests pin the two controls the guards depend on:
 *
 *   - lifetime: `exp` is mandatory and enforced (with a bounded clock skew),
 *     `nbf` is honoured when present;
 *   - tenant binding: the `tenant_id` claim must equal the client's
 *     configured tenant.
 *
 * Every negative case must fail CLOSED — 401 from the guards, AXIAM_ERR_AUTH
 * from the verifier — and the positive case must still be admitted.
 */
#include <string.h>
#include <time.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define FOREIGN_TENANT_ID "99999999-9999-9999-9999-999999999999"

typedef struct {
    const char *jwks_body;
    long check_status;
    const char *check_body;
    const char *login_access_token; /* served as the axiam_access cookie */
    char last_check_body[1024];
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    if (strstr(req->url, "/auth/login")) {
        resp_fill(resp, 200, "{\"session_id\":\"s\",\"expires_in\":900}", NULL);
        char cookie[4096];
        snprintf(cookie, sizeof(cookie), "axiam_access=%s; Path=/; HttpOnly",
                 st->login_access_token ? st->login_access_token : "");
        resp->headers = axiam_kv_append(resp->headers, "Set-Cookie", cookie);
        return 0;
    }
    if (strstr(req->url, "/authz/check")) {
        snprintf(st->last_check_body, sizeof(st->last_check_body), "%s",
                 req->body ? req->body : "");
        resp_fill(resp, st->check_status, st->check_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

static axiam_client_t *make_client_with_tenant(const char *tenant_id,
                                               const char *tenant_slug) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    if (tenant_id) axiam_client_config_set_tenant_id(cfg, tenant_id);
    if (tenant_slug) axiam_client_config_set_tenant_slug(cfg, tenant_slug);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static axiam_client_t *make_client(void) {
    return make_client_with_tenant(AXIAM_TEST_TENANT_ID, NULL);
}

static axiam_headers_t *bearer_headers(const char *token) {
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    return axiam_kv_append(NULL, "Authorization", v);
}

/* Mint a token with an arbitrary claims payload and serve its key via JWKS. */
static char *mint(const char *payload) {
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    free((char *)g.jwks_body); /* previous doc, if any */
    g.jwks_body = jwks;
    return token;
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
}
void tearDown(void) {
    free((char *)g.jwks_body);
    g.jwks_body = NULL;
}

/* --- 1. the happy path is unchanged: a live, same-tenant token is admitted --- */

static void test_valid_token_is_accepted(void) {
    char payload[256];
    char *token = mint(test_claims(payload, sizeof(payload), "user-1",
                                   ",\"roles\":[\"admin\"]"));
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(token);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_role(c, h, roles, 1));

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));

    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

/* --- 2. expired token --- */

static void test_expired_token_is_rejected(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"user-1\",\"tenant_id\":\"%s\",\"exp\":%lld,\"roles\":[\"admin\"]}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) - 3600);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(token);

    /* All three guards fail closed... */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_role(c, h, roles, 1));
    /* ...and the authorization server was never consulted. */
    TEST_ASSERT_EQUAL_STRING("", g.last_check_body);

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "expired"));

    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

/* A token that expired within the clock-skew allowance is still accepted. */
static void test_token_expired_inside_clock_skew_is_accepted(void) {
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld}",
             AXIAM_TEST_TENANT_ID,
             (long long)time(NULL) - (AXIAM_JWT_CLOCK_SKEW_SECS / 2));
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));
    free(token);
    axiam_client_free(c);
}

/* --- 3. missing / malformed exp: an unbounded token is refused --- */

static void test_token_without_exp_is_rejected(void) {
    char *token = mint("{\"sub\":\"u\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}");
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "exp"));
    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

static void test_token_with_non_numeric_exp_is_rejected(void) {
    char *token = mint("{\"sub\":\"u\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID
                       "\",\"exp\":\"soon\"}");
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    free(token);
    axiam_client_free(c);
}

/* --- 4. nbf (honoured when present) --- */

static void test_not_yet_valid_token_is_rejected(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld,\"nbf\":%lld}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 7200,
             (long long)time(NULL) + 3600);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "not yet valid"));
    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

static void test_already_valid_nbf_is_accepted(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld,\"nbf\":%lld}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 900,
             (long long)time(NULL) - 60);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));
    free(token);
    axiam_client_free(c);
}

static void test_malformed_nbf_is_rejected(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld,\"nbf\":\"later\"}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 900);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "nbf"));
    free(token);
    axiam_client_free(c);
}

/* --- 5. cross-tenant token (same organization, so the signature verifies) --- */

static void test_foreign_tenant_token_is_rejected(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"user-1\",\"tenant_id\":\"%s\",\"exp\":%lld,\"roles\":[\"admin\"]}",
             FOREIGN_TENANT_ID, (long long)time(NULL) + 900);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(token);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_role(c, h, roles, 1));
    TEST_ASSERT_EQUAL_STRING("", g.last_check_body);

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "tenant"));

    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

static void test_token_without_tenant_claim_is_rejected(void) {
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"sub\":\"u\",\"exp\":%lld}",
             (long long)time(NULL) + 900);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "tenant"));
    free(token);
    axiam_client_free(c);
}

/* A slug-only client cannot compare against the token's tenant UUID, so it has
 * no binding available and must fail CLOSED rather than skip the check. */
static void test_slug_only_client_cannot_bind_and_fails_closed(void) {
    char payload[256];
    char *token = mint(test_claims(payload, sizeof(payload), "u", NULL));
    axiam_client_t *c = make_client_with_tenant(NULL, "acme");
    axiam_headers_t *h = bearer_headers(token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "tenant_id"));
    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

/* A slug-configured client that HAS logged in binds to the tenant UUID
 * recovered from its own session claims (D-14), so the guard works — and
 * still refuses a sibling tenant's token. */
static void test_slug_client_binds_to_tenant_resolved_at_login(void) {
    char payload[256];
    char *token = mint(test_claims(payload, sizeof(payload), "u", NULL));

    axiam_client_t *c = make_client_with_tenant(NULL, "acme");
    axiam_headers_t *h = bearer_headers(token);
    /* Before login there is no UUID to bind to: fail closed. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));

    /* The login response's access-token cookie carries the tenant UUID. */
    char session_payload[256];
    snprintf(session_payload, sizeof(session_payload),
             "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"org_id\":"
             "\"22222222-2222-2222-2222-222222222222\",\"exp\":%lld}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 900);
    char *session_token = NULL, *session_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k9", session_payload, &session_token,
                                      &session_jwks));
    free(session_jwks);
    g.login_access_token = session_token;

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "alice", "pw", &lr, &err));
    axiam_login_result_dispose(&lr);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);

    free(session_token);
    free(token);
    axiam_client_free(c);
}

/* --- 6. the explicit opt-out still exists, and is the ONLY way to get the
 * old signature-only behaviour --- */

static void test_signature_only_flag_skips_claim_checks(void) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld}",
             FOREIGN_TENANT_ID, (long long)time(NULL) - 3600);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    axiam_error_t err;

    /* Expired AND foreign-tenant: refused by the default policy... */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    /* ...accepted only when a caller explicitly asks for signature-only. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_jwt_verify_ex(c, token, AXIAM_JWT_VERIFY_SIGNATURE_ONLY, NULL, &err));

    /* Each half of the policy can also be selected on its own. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
        axiam_jwt_verify_ex(c, token, AXIAM_JWT_VERIFY_EXPIRY, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "expired"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
        axiam_jwt_verify_ex(c, token, AXIAM_JWT_VERIFY_TENANT, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "tenant"));

    free(token);
    axiam_client_free(c);
}

/* The claims are still returned to the caller on the strict path. */
static void test_strict_verify_returns_claims(void) {
    char payload[256];
    char *token = mint(test_claims(payload, sizeof(payload), "user-7", NULL));
    axiam_client_t *c = make_client();
    char *claims = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, &claims, &err));
    TEST_ASSERT_NOT_NULL(claims);
    TEST_ASSERT_NOT_NULL(strstr(claims, "user-7"));
    free(claims);
    free(token);
    axiam_client_free(c);
}

/* A rejected token must not hand back claims. */
static void test_rejected_token_yields_no_claims(void) {
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"sub\":\"u\",\"tenant_id\":\"%s\",\"exp\":%lld}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) - 3600);
    char *token = mint(payload);
    axiam_client_t *c = make_client();
    char *claims = (char *)0x1; /* must be overwritten with NULL */
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, &claims, &err));
    TEST_ASSERT_NULL(claims);
    free(token);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_valid_token_is_accepted);
    RUN_TEST(test_expired_token_is_rejected);
    RUN_TEST(test_token_expired_inside_clock_skew_is_accepted);
    RUN_TEST(test_token_without_exp_is_rejected);
    RUN_TEST(test_token_with_non_numeric_exp_is_rejected);
    RUN_TEST(test_not_yet_valid_token_is_rejected);
    RUN_TEST(test_already_valid_nbf_is_accepted);
    RUN_TEST(test_malformed_nbf_is_rejected);
    RUN_TEST(test_foreign_tenant_token_is_rejected);
    RUN_TEST(test_token_without_tenant_claim_is_rejected);
    RUN_TEST(test_slug_only_client_cannot_bind_and_fails_closed);
    RUN_TEST(test_slug_client_binds_to_tenant_resolved_at_login);
    RUN_TEST(test_signature_only_flag_skips_claim_checks);
    RUN_TEST(test_strict_verify_returns_claims);
    RUN_TEST(test_rejected_token_yields_no_claims);
    return UNITY_END();
}
