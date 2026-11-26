/*
 * CONTRACT 1.69 (#880): §12.7.3 rule 1, §12.7.6 and §12.4 rule 2.
 *
 * The server signs a back-channel logout token with the header
 * {"alg":"EdDSA","typ":"logout+jwt","kid":"<kid>"}, `kid` being the value /oauth2/jwks publishes
 * for the signing key. The verifier selects the key BY that `kid`. A token with no `kid` is
 * `unknown_kid` -- even against a one-key JWKS whose key did sign it, because a kid-less token
 * is ambiguous as soon as a rotation publishes two keys. The same holds for the ID-token path.
 *
 * The fixture below adds nothing the server does not send: the header is exactly alg, typ and
 * kid, and the JWKS holds two keys with the signing key SECOND.
 */
#include "unity.h"
#include "jwt_fixture.h"
#include "oidc_test_util.h"

#define LOGOUT_EVENTS "\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}"
#define SIGNING_KID "server-signing-key"

static char *g_token;
static char *g_jwks;

void setUp(void) { oidc_reset(); g_token = NULL; g_jwks = NULL; }
void tearDown(void) { free(g_token); free(g_jwks); }

static const char *logout_claims(char *buf, size_t n) {
    long long now = (long long)time(NULL);
    snprintf(buf, n,
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sid\":\"session-1\",\"sub\":\"user-1\",\"jti\":\"jti-1\","
             "\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}",
             now - 5, now + 120);
    return buf;
}

static const char *id_token_claims(char *buf, size_t n) {
    long long now = (long long)time(NULL);
    snprintf(buf, n,
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sub\":\"user-1\",\"iat\":%lld,\"exp\":%lld}",
             now - 5, now + 120);
    return buf;
}

/* Replace the token and JWKS: header kid / typ as given, JWKS = [rotated-out, SIGNING_KID]. */
static void mint_rotation(const char *kid_header, const char *typ, const char *payload) {
    free(g_token); free(g_jwks); g_token = NULL; g_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make_rotation(kid_header, SIGNING_KID, typ, payload,
                                               &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;
}

/* Replace the token and JWKS: header kid / typ as given, JWKS holds ONLY the signing key. */
static void mint_one_key(const char *kid_header, const char *typ, const char *payload) {
    free(g_token); free(g_jwks); g_token = NULL; g_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make_hdr(kid_header, typ, payload, &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;
}

static axiam_error_kind_t verify_logout(axiam_client_t *c, axiam_verified_logout_token_t *t,
                                        axiam_error_t *e) {
    return axiam_verify_logout_token(c, g_token, t, e);
}

void test_a_server_shaped_logout_token_verifies_against_a_two_key_jwks(void) {
    char payload[1024];
    mint_rotation(SIGNING_KID, "logout+jwt", logout_claims(payload, sizeof(payload)));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, verify_logout(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING("session-1", t.sid);
    TEST_ASSERT_EQUAL_STRING("user-1", t.subject);
    TEST_ASSERT_EQUAL_STRING("jti-1", t.jwt_id);
    axiam_verified_logout_token_dispose(&t);
    axiam_client_free(c);
}

void test_a_kidless_logout_token_is_unknown_kid_against_a_one_key_jwks(void) {
    char payload[1024];
    /* The one key in the JWKS DID sign it: the single-key fallback would verify it. */
    mint_one_key(NULL, "logout+jwt", logout_claims(payload, sizeof(payload)));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify_logout(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, err.id_token_reason);
    axiam_client_free(c);
}

void test_a_kidless_logout_token_is_unknown_kid_against_a_two_key_jwks(void) {
    char payload[1024];
    mint_rotation(NULL, "logout+jwt", logout_claims(payload, sizeof(payload)));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify_logout(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, err.id_token_reason);
    axiam_client_free(c);
}

void test_an_unknown_kid_is_unknown_kid_after_one_refetch(void) {
    char payload[1024];
    mint_rotation("not-in-the-set", "logout+jwt", logout_claims(payload, sizeof(payload)));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify_logout(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, err.id_token_reason);
    /* §12.4 rule 2: the initial fetch plus exactly one re-fetch, then fail. */
    TEST_ASSERT_EQUAL_INT(2, g_oidc.jwks_calls);
    axiam_client_free(c);
}

void test_a_kidless_id_token_is_unknown_kid_against_a_one_key_jwks(void) {
    char payload[1024];
    mint_one_key(NULL, "JWT", id_token_claims(payload, sizeof(payload)));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    char reason[32] = "";
    char *claims = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_reasoned(c, g_token, &claims, reason, sizeof(reason), &err));
    TEST_ASSERT_NULL(claims);
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, reason);
    axiam_client_free(c);
}

/* Rules 10 and 11 stay off the logout-token and ID-token paths: both verify through the
 * verifier the access-token guard shares, while that guard refuses both. */
void test_rules_10_and_11_stay_off_the_logout_and_id_token_paths(void) {
    char payload[1024];
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;

    mint_rotation(SIGNING_KID, "logout+jwt", logout_claims(payload, sizeof(payload)));
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, verify_logout(c, &t, &err));
    axiam_verified_logout_token_dispose(&t);
    char *claims = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_jwt_verify(c, g_token, &claims, &err));
    TEST_ASSERT_NULL(claims);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "not an access token"));

    /* A fresh client: the first one cached the first fixture's JWKS. */
    axiam_client_free(c);
    mint_rotation(SIGNING_KID, "JWT", id_token_claims(payload, sizeof(payload)));
    c = oidc_make_client();
    char reason[32] = "";
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_jwt_verify_reasoned(c, g_token, &claims, reason, sizeof(reason), &err));
    free(claims);
    claims = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_jwt_verify(c, g_token, &claims, &err));
    TEST_ASSERT_NULL(claims);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "not an access token"));

    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_server_shaped_logout_token_verifies_against_a_two_key_jwks);
    RUN_TEST(test_a_kidless_logout_token_is_unknown_kid_against_a_one_key_jwks);
    RUN_TEST(test_a_kidless_logout_token_is_unknown_kid_against_a_two_key_jwks);
    RUN_TEST(test_an_unknown_kid_is_unknown_kid_after_one_refetch);
    RUN_TEST(test_a_kidless_id_token_is_unknown_kid_against_a_one_key_jwks);
    RUN_TEST(test_rules_10_and_11_stay_off_the_logout_and_id_token_paths);
    return UNITY_END();
}
