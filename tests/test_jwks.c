#include <string.h>

#include "cJSON.h"
#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
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

/* D2: pull the single JWK object out of a jwt_make()-produced JWKS document
 * (as raw JSON text) so it can be spliced into a hand-built multi-key doc. */
static char *extract_first_key_json(const char *jwks_doc) {
    cJSON *root = cJSON_Parse(jwks_doc);
    cJSON *keys = root ? cJSON_GetObjectItemCaseSensitive(root, "keys") : NULL;
    cJSON *first = keys ? cJSON_GetArrayItem(keys, 0) : NULL;
    char *s = first ? cJSON_PrintUnformatted(first) : NULL;
    if (root) cJSON_Delete(root);
    return s;
}

/* D2 (src/jwks.c): a document with a key missing "x" (non-string field ->
 * continue at line 26), a key whose alg is present but not EdDSA (continue at
 * line 32), and TWO valid Ed25519 keys (tail-append at line 46) — all four
 * entries parsed from one JWKS document. */
static void test_jwks_skips_bad_entries_and_appends_two_valid_keys(void) {
    char *tokA = NULL, *jwksA = NULL, *tokB = NULL, *jwksB = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("keyA", "{\"sub\":\"userA\"}", &tokA, &jwksA));
    TEST_ASSERT_EQUAL_INT(0, jwt_make("keyB", "{\"sub\":\"userB\"}", &tokB, &jwksB));
    char *keyA_json = extract_first_key_json(jwksA);
    char *keyB_json = extract_first_key_json(jwksB);
    TEST_ASSERT_NOT_NULL(keyA_json);
    TEST_ASSERT_NOT_NULL(keyB_json);

    char doc[4096];
    snprintf(doc, sizeof(doc),
             "{\"keys\":["
             "{\"kty\":\"RSA\",\"crv\":\"P-256\"},"
             "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"RS256\",\"x\":\"AAAA\"},"
             "%s,%s]}",
             keyA_json, keyB_json);
    cJSON_free(keyA_json);
    cJSON_free(keyB_json);

    g.jwks_body = doc;
    axiam_client_t *c = make_client();

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, tokA, NULL, &err));
    /* Second valid key (appended via the non-empty-list tail branch) verifies
     * too, from the SAME cached fetch (no second JWKS call). */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, tokB, NULL, &err));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);

    free(tokA); free(jwksA);
    free(tokB); free(jwksB);
    axiam_client_free(c);
}

/* D2 (src/jwks.c:81-82): a non-JSON JWKS document fails parse_jwks() ->
 * AXIAM_ERR_NETWORK "invalid JWKS document". */
static void test_jwks_invalid_document_is_network_error(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    g.jwks_body = "not a json document at all";
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "invalid JWKS"));
    free(token); free(jwks);
    axiam_client_free(c);
}

/* D2 (src/jwks.c:105-106): NULL client/token guards. */
static void test_jwt_verify_null_guards(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(c, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_jwt_verify(NULL, "x.y.z", NULL, &err));
    axiam_client_free(c);
}

/* D2 (src/jwks.c:56-59): a genuine refetch (cache forced stale) replaces the
 * cached key list, freeing the previously-cached nodes. */
static void test_jwks_refetch_frees_previously_cached_keys(void) {
    char *token1 = NULL, *jwks1 = NULL;
    jwt_make("k1", "{\"sub\":\"u1\"}", &token1, &jwks1);
    g.jwks_body = jwks1;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token1, NULL, &err));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);

    /* Force the 300s TTL cache to be considered stale (internal.h test hook). */
    c->jwks_fetched_at = 0;

    char *token2 = NULL, *jwks2 = NULL;
    jwt_make("k2", "{\"sub\":\"u2\"}", &token2, &jwks2);
    g.jwks_body = jwks2;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token2, NULL, &err));
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);

    free(token1); free(jwks1);
    free(token2); free(jwks2);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_verify_valid_eddsa_jwt);
    RUN_TEST(test_reject_tampered_signature);
    RUN_TEST(test_reject_non_eddsa_alg);
    RUN_TEST(test_reject_unknown_kid);
    RUN_TEST(test_malformed_token);
    RUN_TEST(test_jwks_skips_bad_entries_and_appends_two_valid_keys);
    RUN_TEST(test_jwks_invalid_document_is_network_error);
    RUN_TEST(test_jwt_verify_null_guards);
    RUN_TEST(test_jwks_refetch_frees_previously_cached_keys);
    return UNITY_END();
}
