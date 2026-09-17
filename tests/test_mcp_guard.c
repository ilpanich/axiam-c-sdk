/*
 * CONTRACT.md §28.9 required tests 3, 4, 5 — the ones that need a guard
 * behind a real decision, and the regression that matters more than the
 * five: with resource_metadata_url unset, nothing changes.
 *
 * §28.3's part of test 3 — "a GET of metadata_path with no credential
 * returns 200" — needs a request pipeline this SDK's guard does not have
 * (axiam_require_auth/axiam_require_access take headers and return a status;
 * there is no router, and no response object to exempt a path on). That half
 * is exercised at the level that actually produces the value instead:
 * axiam_protected_resource_metadata_json()/`_path`() are pure functions with
 * no guard and no authentication concept at all (test_mcp.c), and
 * README.md's CivetWeb walkthrough shows the unauthenticated handler wired
 * to them. What THIS file tests is the guard's own contribution — the
 * `WWW-Authenticate` value axiam_require_auth_mcp()/axiam_require_access_mcp()
 * attach to the 401/403 they already produce — against a real signed token
 * and a real (faked-transport) authorization decision, exactly as
 * test_uma_challenge.c does for §20.3's emit half.
 *
 * The fixture matches CONTRACT.md §28.9's table and test_mcp.c's constants.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define RESOURCE            "https://mcp.example.com/mcp"
#define METADATA_URL         "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
#define EXPECTED_AUDIENCE   RESOURCE
#define VECTOR_NO_CREDENTIAL "Bearer resource_metadata=\"" METADATA_URL "\""
#define VECTOR_INVALID_TOKEN "Bearer error=\"invalid_token\", resource_metadata=\"" METADATA_URL "\""
#define VECTOR_INSUFFICIENT_SCOPE \
    "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"" \
    METADATA_URL "\""
#define ACTION "mcp:invoke"
#define RESOURCE_ID "tool-1"

typedef struct {
    const char *jwks_body;
    long check_status;
    const char *check_body;
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
        resp_fill(resp, st->check_status, st->check_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static char *g_token;
static char *g_jwks;

/* client configured with §28 ON: resource_metadata_url + expected_audience,
 * both from the fixture. */
static axiam_client_t *make_mcp_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_client_config_set_expected_audience(cfg, EXPECTED_AUDIENCE);
    axiam_client_config_set_resource_metadata_url(cfg, METADATA_URL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* The same client with §28 OFF — the regression's baseline. */
static axiam_client_t *make_plain_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_client_config_set_expected_audience(cfg, EXPECTED_AUDIENCE);
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

/* Mint a token with an explicit `aud`, live for `ttl_seconds` (negative =
 * already expired). */
static void mint(const char *aud, long long ttl_seconds, char **out_token, char **out_jwks) {
    char payload[384];
    snprintf(payload, sizeof(payload),
            "{\"sub\":\"user-9\",\"tenant_id\":\"%s\",\"aud\":\"%s\",\"exp\":%lld,\"scope\":\"mcp:read\"}",
            AXIAM_TEST_TENANT_ID, aud, (long long)time(NULL) + ttl_seconds);
    jwt_make("k1", payload, out_token, out_jwks);
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    mint(EXPECTED_AUDIENCE, 900, &g_token, &g_jwks);
    g.jwks_body = g_jwks;
    g.check_status = 200;
    g.check_body = "{\"allowed\":true,\"reason_code\":\"allowed\"}";
}

void tearDown(void) {
    free(g_token); g_token = NULL;
    free(g_jwks); g_jwks = NULL;
}

/* ------------------------------------------------------------------ */
/* §28.9 test 3 — 401 with the challenge                                */
/* ------------------------------------------------------------------ */

static void test_no_credential_answers_vector1(void) {
    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *empty = NULL;

    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, empty, &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st);
    TEST_ASSERT_NOT_NULL(challenge);
    TEST_ASSERT_EQUAL_STRING(VECTOR_NO_CREDENTIAL, challenge);
    /* No `error` parameter: no credential is not a bad credential. */
    TEST_ASSERT_NULL(strstr(challenge, "error="));

    free(challenge);
    axiam_client_free(c);
}

static void test_expired_token_answers_vector2_and_says_nothing_else(void) {
    char *expired, *expired_jwks;
    mint(EXPECTED_AUDIENCE, -900, &expired, &expired_jwks);
    g.jwks_body = expired_jwks;

    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(expired);

    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, h, &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st);
    TEST_ASSERT_EQUAL_STRING(VECTOR_INVALID_TOKEN, challenge);
    /* §28.4/§28.8: no error_description, and nothing derived from the token. */
    TEST_ASSERT_NULL(strstr(challenge, "error_description"));
    TEST_ASSERT_NULL(strstr(challenge, "expired"));

    free(challenge);
    free(expired);
    free(expired_jwks);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_allow_carries_no_challenge(void) {
    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(g_token);

    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, h, &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    TEST_ASSERT_NULL(challenge);

    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_a_null_out_pointer_is_accepted(void) {
    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *empty = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED,
                          axiam_require_auth_mcp(c, empty, NULL));
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §28.9 test 4 — 403 insufficient_scope                                */
/* ------------------------------------------------------------------ */

static axiam_guard_status_t denial(const char *body, const char *scope, char **out_challenge) {
    g.check_body = body;
    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(g_token);
    axiam_guard_status_t st =
        axiam_require_access_mcp(c, h, ACTION, RESOURCE_ID, scope, out_challenge);
    axiam_kv_free(h);
    axiam_client_free(c);
    return st;
}

static void test_no_grant_with_scope_answers_vector3(void) {
    char *challenge = NULL;
    axiam_guard_status_t st =
        denial("{\"allowed\":false,\"reason_code\":\"no_grant\"}", "mcp:tools", &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_EQUAL_STRING(VECTOR_INSUFFICIENT_SCOPE, challenge);
    free(challenge);
}

static void test_names_the_scope_the_route_asked_for_verbatim(void) {
    char *challenge = NULL;
    axiam_guard_status_t st = denial("{\"allowed\":false,\"reason_code\":\"no_grant\"}",
                                     "urn:example:tools.invoke", &challenge);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_EQUAL_STRING(
        "Bearer error=\"insufficient_scope\", scope=\"urn:example:tools.invoke\", "
        "resource_metadata=\"" METADATA_URL "\"",
        challenge);
    free(challenge);
}

static void test_carries_no_challenge_on_denied_by_rule_absent_or_unknown_code_or_no_scope(void) {
    char *challenge = NULL;

    challenge = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        denial("{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}", "mcp:tools", &challenge));
    TEST_ASSERT_NULL(challenge);

    challenge = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        denial("{\"allowed\":false}", "mcp:tools", &challenge));
    TEST_ASSERT_NULL(challenge);

    challenge = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        denial("{\"allowed\":false,\"reason_code\":\"quota_exhausted\"}", "mcp:tools", &challenge));
    TEST_ASSERT_NULL(challenge);

    /* No scope argument: nothing to name, and §28 forbids guessing. */
    challenge = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
        denial("{\"allowed\":false,\"reason_code\":\"no_grant\"}", NULL, &challenge));
    TEST_ASSERT_NULL(challenge);
}

static void test_touches_no_other_response(void) {
    char *challenge = NULL;
    axiam_guard_status_t st =
        denial("{\"allowed\":true,\"reason_code\":\"allowed\"}", "mcp:tools", &challenge);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    TEST_ASSERT_NULL(challenge);
}

/* ------------------------------------------------------------------ */
/* §28.9 test 5 — a token whose aud is not the resource is refused      */
/* ------------------------------------------------------------------ */

static void test_refuses_a_token_minted_for_another_resource_server(void) {
    char *other, *other_jwks;
    mint("https://other.example.com/mcp", 900, &other, &other_jwks);
    g.jwks_body = other_jwks;

    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(other);
    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, h, &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st);
    TEST_ASSERT_EQUAL_STRING(VECTOR_INVALID_TOKEN, challenge);

    free(challenge);
    free(other);
    free(other_jwks);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_refuses_a_general_purpose_axiam_user_token_identically(void) {
    /* A perfectly valid AXIAM token that simply was not minted for this
     * resource — refused indistinguishably from the wrong-resource case,
     * which is the point. */
    char *user_tok, *user_jwks;
    mint("axiam:user", 900, &user_tok, &user_jwks);
    g.jwks_body = user_jwks;

    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(user_tok);
    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, h, &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st);
    TEST_ASSERT_EQUAL_STRING(VECTOR_INVALID_TOKEN, challenge);

    free(challenge);
    free(user_tok);
    free(user_jwks);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_admits_a_token_whose_aud_is_this_resource(void) {
    axiam_client_t *c = make_mcp_client();
    axiam_headers_t *h = bearer_headers(g_token); /* aud = EXPECTED_AUDIENCE */
    char *challenge = NULL;
    axiam_guard_status_t st = axiam_require_auth_mcp(c, h, &challenge);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st);
    TEST_ASSERT_NULL(challenge);
    axiam_kv_free(h);
    axiam_client_free(c);
}

static void test_refuses_at_construction_with_no_expected_audience(void) {
    /* The configuration negative from §28.9 test 5: constructing the client
     * with resource_metadata_url set and no expected audience fails at
     * construction, naming both options — CONTRACT.md §28.5 rule 2. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_resource_metadata_url(cfg, METADATA_URL);

    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_NULL(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "resource_metadata_url"));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "expected_audience"));

    axiam_client_config_free(cfg);
}

/* ------------------------------------------------------------------ */
/* The regression that matters more than all five                      */
/* ------------------------------------------------------------------ */

static void test_off_by_default_auth_emits_no_challenge_ever(void) {
    axiam_client_t *plain = make_plain_client();

    axiam_headers_t *empty = NULL;
    char *c1 = (char *)0xdeadbeef; /* poisoned: the call must overwrite it */
    axiam_guard_status_t st1 = axiam_require_auth_mcp(plain, empty, &c1);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, st1);
    TEST_ASSERT_NULL(c1);
    /* Byte-for-byte axiam_require_auth(). */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(plain, empty));

    axiam_headers_t *h = bearer_headers(g_token);
    char *c2 = NULL;
    axiam_guard_status_t st2 = axiam_require_auth_mcp(plain, h, &c2);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, st2);
    TEST_ASSERT_NULL(c2);

    axiam_kv_free(h);
    axiam_client_free(plain);
}

static void test_off_by_default_access_emits_no_challenge_on_a_no_grant_denial(void) {
    g.check_body = "{\"allowed\":false,\"reason_code\":\"no_grant\"}";
    axiam_client_t *plain = make_plain_client();
    axiam_headers_t *h = bearer_headers(g_token);

    char *challenge = (char *)0xdeadbeef;
    axiam_guard_status_t st =
        axiam_require_access_mcp(plain, h, ACTION, RESOURCE_ID, "mcp:tools", &challenge);

    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED, st);
    TEST_ASSERT_NULL(challenge);
    /* Byte-for-byte axiam_require_access(). */
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_DENIED,
                          axiam_require_access(plain, h, ACTION, RESOURCE_ID, "mcp:tools"));

    axiam_kv_free(h);
    axiam_client_free(plain);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_no_credential_answers_vector1);
    RUN_TEST(test_expired_token_answers_vector2_and_says_nothing_else);
    RUN_TEST(test_allow_carries_no_challenge);
    RUN_TEST(test_a_null_out_pointer_is_accepted);
    RUN_TEST(test_no_grant_with_scope_answers_vector3);
    RUN_TEST(test_names_the_scope_the_route_asked_for_verbatim);
    RUN_TEST(test_carries_no_challenge_on_denied_by_rule_absent_or_unknown_code_or_no_scope);
    RUN_TEST(test_touches_no_other_response);
    RUN_TEST(test_refuses_a_token_minted_for_another_resource_server);
    RUN_TEST(test_refuses_a_general_purpose_axiam_user_token_identically);
    RUN_TEST(test_admits_a_token_whose_aud_is_this_resource);
    RUN_TEST(test_refuses_at_construction_with_no_expected_audience);
    RUN_TEST(test_off_by_default_auth_emits_no_challenge_ever);
    RUN_TEST(test_off_by_default_access_emits_no_challenge_on_a_no_grant_denial);
    return UNITY_END();
}
