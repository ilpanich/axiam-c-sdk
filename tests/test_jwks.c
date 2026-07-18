#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "jwt_fixture.h"
#include "test_util.h"

typedef struct {
    const char *jwks_body;
    int jwks_calls;
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        st->jwks_calls++;
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

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

void setUp(void) { memset(&g, 0, sizeof(g)); }
void tearDown(void) {}

static void test_verify_valid_eddsa_jwt(void) {
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", "{\"sub\":\"user-1\",\"roles\":[\"admin\"]}",
                                      &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    char *claims = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, &claims, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_NOT_NULL(claims);
    TEST_ASSERT_NOT_NULL(strstr(claims, "user-1"));

    /* Cache: a second verify does not refetch JWKS (300s TTL). */
    char *claims2 = NULL;
    axiam_jwt_verify(c, token, &claims2, &err);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);

    free(claims);
    free(claims2);
    free(token);
    free(jwks);
    axiam_client_free(c);
}

static void test_reject_tampered_signature(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"user-1\"}", &token, &jwks);
    /* Flip a significant character well inside the signature segment (avoid the
     * final base64 char, whose low bits are ignored padding). */
    size_t n = strlen(token);
    size_t at = n - 20;
    token[at] = (token[at] == 'C') ? 'D' : 'C';
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    free(token);
    free(jwks);
    axiam_client_free(c);
}

static void test_reject_non_eddsa_alg(void) {
    /* header {"alg":"RS256"} . payload . sig — must be rejected before lookup. */
    const char *hdr = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; /* {"alg":"RS256","typ":"JWT"} */
    char token[256];
    snprintf(token, sizeof(token), "%s.%s.%s", hdr, "eyJzdWIiOiJ4In0", "AAAA");
    char *token2 = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"x\"}", &token2, &jwks);
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    /* Rejected before any JWKS fetch. */
    TEST_ASSERT_EQUAL_INT(0, g.jwks_calls);
    free(token2);
    free(jwks);
    axiam_client_free(c);
}

static void test_reject_unknown_kid(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    /* Serve a JWKS whose kid does not match. */
    char *token_other = NULL, *jwks_other = NULL;
    jwt_make("different-kid", "{\"sub\":\"u\"}", &token_other, &jwks_other);
    g.jwks_body = jwks_other;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    free(token); free(jwks);
    free(token_other); free(jwks_other);
    axiam_client_free(c);
}

static void test_malformed_token(void) {
    g.jwks_body = "{\"keys\":[]}";
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, "not-a-jwt", NULL, &err));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_verify_valid_eddsa_jwt);
    RUN_TEST(test_reject_tampered_signature);
    RUN_TEST(test_reject_non_eddsa_alg);
    RUN_TEST(test_reject_unknown_kid);
    RUN_TEST(test_malformed_token);
    return UNITY_END();
}
