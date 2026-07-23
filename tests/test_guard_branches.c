/* C2: src/guard.c thin-branch depth.
 *
 * Targets (per claude_dev/test-coverage-round2-plan.md, task C2):
 *  - extract_token: leading whitespace before "Bearer", a non-Bearer scheme
 *    (falls through to the cookie lookup), a "Bearer" value that is empty
 *    after whitespace-skipping, a cookie header with no "axiam_access="
 *    substring at all, and a cookie whose value is empty (end == pos).
 *  - require_role with an absent "roles" claim and with a non-array "roles"
 *    claim.
 *  - the `!client` guard on all three entry points.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

typedef struct {
    const char *jwks_body;
    long check_status;
    const char *check_body;
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
    if (strstr(req->url, "/authz/check")) {
        snprintf(st->last_check_body, sizeof(st->last_check_body), "%s",
                 req->body ? req->body : "");
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
    jwt_make("k1", "{\"sub\":\"user-9\",\"roles\":[\"admin\",\"viewer\"]}", &g_token, &g_jwks);
    g.jwks_body = g_jwks;
}
void tearDown(void) {
    free(g_token); g_token = NULL;
    free(g_jwks); g_jwks = NULL;
}

/* --- extract_token edge cases (via axiam_require_auth) --- */

static void test_authorization_leading_whitespace(void) {
    char v[2048];
    snprintf(v, sizeof(v), "   Bearer %s", g_token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_authorization_internal_extra_whitespace(void) {
    char v[2048];
    snprintf(v, sizeof(v), "Bearer     %s", g_token); /* multiple spaces after scheme */
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_authorization_non_bearer_scheme_falls_through(void) {
    /* "Basic ..." doesn't match strncasecmp(p, "Bearer ", 7): extract_token
     * falls through to the (absent) cookie lookup and returns NULL. */
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", "Basic dXNlcjpwYXNz");
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_authorization_bearer_empty_after_whitespace(void) {
    /* "Bearer" followed only by spaces: *p is '\0' after the second skip
     * loop, so the `if (*p) return ...` arm is never taken -> falls through
     * to the cookie lookup (absent here) -> UNAUTHENTICATED. */
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", "Bearer    ");
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_header_without_axiam_access_substring(void) {
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", "session=abc; other=1");
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_axiam_access_empty_value(void) {
    /* "axiam_access=" immediately followed by ';' -> end == pos -> the
     * `if (end > pos)` guard is false -> falls through to the function's
     * final `return NULL` (src/guard.c:29,36). */
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", "axiam_access=;other=1");
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_axiam_access_empty_value_end_of_string(void) {
    /* "axiam_access=" as the entire (trimmed) header value: end stops at the
     * NUL, still == pos. */
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", "axiam_access=");
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_axiam_access_value_ends_at_space(void) {
    /* The end-scan loop's *end != ' ' arm: a space (not a ';') terminates
     * the token (src/guard.c:28). */
    char v[2048];
    snprintf(v, sizeof(v), "axiam_access=%s other=1", g_token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", v);
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_cookie_axiam_access_value_ends_at_string_end(void) {
    /* The end-scan loop's *end (NUL) arm: the token runs to end-of-string,
     * no trailing ';' or ' ' at all (src/guard.c:28). */
    char v[2048];
    snprintf(v, sizeof(v), "axiam_access=%s", g_token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Cookie", v);
    axiam_client_t *c = make_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* --- require_access: NULL vs empty resource_id (two distinct branches) --- */

static void test_require_access_null_resource_id(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *h = bearer_headers(g_token);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_BAD_REQUEST,
                          axiam_require_access(c, h, "a", NULL, NULL));
    axiam_kv_free(h);
    axiam_client_free(c);
}

/* --- claims JSON that fails to parse (a JWT whose signed payload is NOT
 * valid JSON — axiam_jwt_verify only checks the signature, not the payload
 * shape) — the `if (root)` guard's false arm in both require_access
 * (src/guard.c:80) and require_role (src/guard.c:117). --- */

static void test_require_access_non_json_claims(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("kx", "not-a-json-payload-at-all", &token, &jwks);
    g.jwks_body = jwks;
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    /* subject stays NULL (no "sub" recovered) but the check still proceeds. */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    TEST_ASSERT_NULL(strstr(g.last_check_body, "\"subject_id\""));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

static void test_require_role_non_json_claims(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("ky", "[1,2,3]", &token, &jwks); /* valid JSON, but not an object */
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, roles, 1));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* --- require_access: claims parse but carry no "sub" claim at all --- */

static void test_require_access_missing_sub_claim(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("kz", "{\"other\":1}", &token, &jwks);
    g.jwks_body = jwks;
    g.check_status = 200;
    g.check_body = "{\"allowed\":true}";
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW,
        axiam_require_access(c, h, "a", "44444444-4444-4444-4444-444444444444", NULL));
    TEST_ASSERT_NULL(strstr(g.last_check_body, "\"subject_id\""));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* --- require_role: no credential at all (claims NULL, src/guard.c:113) --- */

static void test_require_role_no_credential(void) {
    axiam_client_t *c = make_client();
    axiam_headers_t *empty = NULL;
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
                          axiam_require_role(c, empty, roles, 1));
    axiam_client_free(c);
}

/* --- require_role: "roles" present but an EMPTY array (0 loop iterations,
 * src/guard.c:121) --- */

static void test_require_role_empty_array(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("kw", "{\"sub\":\"user-1\",\"roles\":[]}", &token, &jwks);
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, roles, 1));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* --- require_role: absent / non-array "roles" claim --- */

static void test_require_role_claim_absent(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k2", "{\"sub\":\"user-1\"}", &token, &jwks); /* no "roles" at all */
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, roles, 1));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

static void test_require_role_claim_non_array(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k3", "{\"sub\":\"user-1\",\"roles\":\"admin\"}", &token, &jwks); /* string, not array */
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, roles, 1));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

static void test_require_role_array_with_non_string_and_non_matching_items(void) {
    /* An array containing a non-string item (skipped via `continue`) plus a
     * string that doesn't match any wanted role -> exhausts the loop without
     * ever setting matched. */
    char *token = NULL, *jwks = NULL;
    jwt_make("k4", "{\"sub\":\"user-1\",\"roles\":[42,\"guest\"]}", &token, &jwks);
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    char v[2048];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, axiam_require_role(c, h, roles, 1));
    axiam_kv_free(h);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* --- !client guards --- */

static void test_null_client_guards(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAVAILABLE, axiam_require_auth(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAVAILABLE,
        axiam_require_access(NULL, NULL, "a", "r", NULL));
    const char *roles[] = {"admin"};
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAVAILABLE, axiam_require_role(NULL, NULL, roles, 1));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_authorization_leading_whitespace);
    RUN_TEST(test_authorization_internal_extra_whitespace);
    RUN_TEST(test_authorization_non_bearer_scheme_falls_through);
    RUN_TEST(test_authorization_bearer_empty_after_whitespace);
    RUN_TEST(test_cookie_header_without_axiam_access_substring);
    RUN_TEST(test_cookie_axiam_access_empty_value);
    RUN_TEST(test_cookie_axiam_access_empty_value_end_of_string);
    RUN_TEST(test_cookie_axiam_access_value_ends_at_space);
    RUN_TEST(test_cookie_axiam_access_value_ends_at_string_end);
    RUN_TEST(test_require_access_null_resource_id);
    RUN_TEST(test_require_access_non_json_claims);
    RUN_TEST(test_require_role_non_json_claims);
    RUN_TEST(test_require_access_missing_sub_claim);
    RUN_TEST(test_require_role_no_credential);
    RUN_TEST(test_require_role_empty_array);
    RUN_TEST(test_require_role_claim_absent);
    RUN_TEST(test_require_role_claim_non_array);
    RUN_TEST(test_require_role_array_with_non_string_and_non_matching_items);
    RUN_TEST(test_null_client_guards);
    return UNITY_END();
}
