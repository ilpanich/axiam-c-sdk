/* CONTRACT §10.1 rules 10-12 (contract 1.68, security audit 2026-11-14 N14).
 *
 * AXIAM signs its purpose tokens -- the MFA challenge and the WebAuthn state, the latter
 * handed to ANONYMOUS callers with the nil UUID as `sub` -- with the access-token key. They
 * carry `sub`, `tenant_id`, `iss` and `exp` and no `aud`, so a guard configured with no
 * expected audience (the default) and a single-key fallback for a header with no `kid`
 * admitted them as access tokens.
 *
 * Every negative case below is an otherwise-valid token for the configured tenant, signed by
 * the one JWKS key, with no `aud`, verified by a client with NO expected audience -- the
 * default configuration the audit's finding is about. Each is asserted refused at the guard
 * (401) and at axiam_jwt_verify().
 */
#include <string.h>
#include <time.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define NIL_UUID "00000000-0000-0000-0000-000000000000"
#define USER_UUID "22222222-2222-2222-2222-222222222222"

static char *g_jwks;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void)ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, g_jwks, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

/* Deliberately NO expected audience and NO expected issuer: the default. */
static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { g_jwks = NULL; }
void tearDown(void) { free(g_jwks); g_jwks = NULL; }

/* Mint a token with the given header members (NULL omits), serve its key as the ONE-key JWKS,
 * and return it. */
static char *mint(const char *kid, const char *typ, const char *sub, const char *extra) {
    char payload[512];
    test_claims(payload, sizeof(payload), sub, extra);
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make_hdr(kid, typ, payload, &token, &jwks));
    free(g_jwks);
    g_jwks = jwks;
    return token;
}

static void assert_refused(char *token) {
    axiam_client_t *c = make_client();
    char v[4096];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_UNAUTHENTICATED, axiam_require_auth(c, h));

    char *claims = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, &claims, &err));
    TEST_ASSERT_NULL(claims);
    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

static void assert_admitted(char *token) {
    axiam_client_t *c = make_client();
    char v[4096];
    snprintf(v, sizeof(v), "Bearer %s", token);
    axiam_headers_t *h = axiam_kv_append(NULL, "Authorization", v);
    TEST_ASSERT_EQUAL_INT(AXIAM_GUARD_ALLOW, axiam_require_auth(c, h));

    char *claims = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, &claims, &err));
    TEST_ASSERT_NOT_NULL(claims);
    free(claims);
    axiam_kv_free(h);
    free(token);
    axiam_client_free(c);
}

/* ---- rule 10: typ ---- */
static void test_typ_jwt_is_refused(void) {
    assert_refused(mint("k1", "JWT", USER_UUID, NULL));
}
static void test_typ_mfa_challenge_is_refused(void) {
    assert_refused(mint("k1", "axiam-mfa-challenge+jwt", USER_UUID, NULL));
}
static void test_typ_webauthn_state_is_refused(void) {
    /* The task's required vector: header typ axiam-webauthn-state+jwt. */
    assert_refused(mint("k1", "axiam-webauthn-state+jwt", NIL_UUID, NULL));
}
static void test_typ_logout_is_refused(void) {
    assert_refused(mint("k1", "logout+jwt", USER_UUID, NULL));
}
static void test_typ_secevent_is_refused(void) {
    assert_refused(mint("k1", "secevent+jwt", USER_UUID, NULL));
}

/* ---- rule 11: purpose ---- */
static void test_purpose_claim_is_refused_with_valid_typ_and_kid(void) {
    assert_refused(mint("k1", "at+jwt", USER_UUID, ",\"purpose\":\"mfa_challenge\""));
}
static void test_purpose_claim_is_refused_on_pre_1_67_generic_typ(void) {
    assert_refused(mint("k1", "JWT", USER_UUID, ",\"purpose\":\"mfa_challenge\""));
}
static void test_purpose_claim_is_refused_with_no_typ(void) {
    assert_refused(mint("k1", NULL, USER_UUID, ",\"purpose\":\"mfa_challenge\""));
}
static void test_webauthn_discoverable_shape_is_refused(void) {
    assert_refused(mint("k1", "at+jwt", NIL_UUID,
                        ",\"purpose\":\"webauthn_authenticate_discoverable\""));
}
static void test_purpose_null_is_refused(void) {
    assert_refused(mint("k1", "at+jwt", USER_UUID, ",\"purpose\":null"));
}
static void test_purpose_empty_string_is_refused(void) {
    assert_refused(mint("k1", "at+jwt", USER_UUID, ",\"purpose\":\"\""));
}

/* ---- rule 12: kid ---- */
static void test_kidless_token_against_one_key_jwks_is_refused(void) {
    assert_refused(mint(NULL, "at+jwt", USER_UUID, NULL));
}
static void test_kidless_token_with_no_typ_is_refused(void) {
    assert_refused(mint(NULL, NULL, USER_UUID, NULL));
}
static void test_kidless_purpose_token_is_refused(void) {
    /* The exact shape the server's MFA challenge has: no kid, generic typ-less header. */
    assert_refused(mint(NULL, NULL, USER_UUID, ",\"purpose\":\"mfa_challenge\""));
}

/* ---- positives ---- */
static void test_typ_at_jwt_is_admitted(void) {
    assert_admitted(mint("k1", "at+jwt", USER_UUID, NULL));
}
static void test_typ_upper_case_is_admitted(void) {
    assert_admitted(mint("k1", "AT+JWT", USER_UUID, NULL));
}
static void test_typ_application_prefix_is_admitted(void) {
    assert_admitted(mint("k1", "application/at+jwt", USER_UUID, NULL));
}
static void test_typ_application_prefix_upper_case_is_admitted(void) {
    assert_admitted(mint("k1", "Application/AT+JWT", USER_UUID, NULL));
}
static void test_absent_typ_is_admitted(void) {
    assert_admitted(mint("k1", NULL, USER_UUID, NULL));
}
static void test_normal_token_with_roles_and_scope_is_admitted(void) {
    assert_admitted(mint("k1", "at+jwt", USER_UUID,
                         ",\"roles\":[\"admin\"],\"scope\":\"openid roles\""));
}

/* ---- scope of the rules: only the access-token path ---- */
static void test_signature_only_path_keeps_kidless_fallback(void) {
    /* The back-channel logout token and the ID token do not go through the access-token
     * policy (§10.1 'Scope'): a SIGNATURE_ONLY verification is unchanged. */
    char *token = mint(NULL, "logout+jwt", USER_UUID, ",\"purpose\":\"x\"");
    axiam_client_t *c = make_client();
    char *claims = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify_ex(c, token, AXIAM_JWT_VERIFY_SIGNATURE_ONLY,
                                                        &claims, &err));
    free(claims);
    free(token);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_typ_jwt_is_refused);
    RUN_TEST(test_typ_mfa_challenge_is_refused);
    RUN_TEST(test_typ_webauthn_state_is_refused);
    RUN_TEST(test_typ_logout_is_refused);
    RUN_TEST(test_typ_secevent_is_refused);
    RUN_TEST(test_purpose_claim_is_refused_with_valid_typ_and_kid);
    RUN_TEST(test_purpose_claim_is_refused_on_pre_1_67_generic_typ);
    RUN_TEST(test_purpose_claim_is_refused_with_no_typ);
    RUN_TEST(test_webauthn_discoverable_shape_is_refused);
    RUN_TEST(test_purpose_null_is_refused);
    RUN_TEST(test_purpose_empty_string_is_refused);
    RUN_TEST(test_kidless_token_against_one_key_jwks_is_refused);
    RUN_TEST(test_kidless_token_with_no_typ_is_refused);
    RUN_TEST(test_kidless_purpose_token_is_refused);
    RUN_TEST(test_typ_at_jwt_is_admitted);
    RUN_TEST(test_typ_upper_case_is_admitted);
    RUN_TEST(test_typ_application_prefix_is_admitted);
    RUN_TEST(test_typ_application_prefix_upper_case_is_admitted);
    RUN_TEST(test_absent_typ_is_admitted);
    RUN_TEST(test_normal_token_with_roles_and_scope_is_admitted);
    RUN_TEST(test_signature_only_path_keeps_kidless_fallback);
    return UNITY_END();
}
