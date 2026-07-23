/* C2: src/jwks.c thin-branch depth — parse_jwks() key-material edge cases.
 *
 * Targets (per claude_dev/test-coverage-round2-plan.md, task C2):
 *  - a JWK "x" value that fails base64url decode (src/jwks.c:36) — also
 *    exercises util.c's b64url_val() invalid-character return (util.c:77).
 *  - a JWK "x" value that decodes to something OTHER than 32 bytes: shorter
 *    and longer (src/jwks.c:37).
 *  - a JWKS document whose "keys" field is missing / not an array
 *    (src/jwks.c:15).
 */
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

/* JWK "x" containing characters outside the base64url alphabet ('@' / '#')
 * -> axiam_b64url_decode() returns NULL -> the entry is silently skipped
 * (parse_jwks still returns "ok", just with no key for this kid). */
static void test_x_value_invalid_base64url_is_skipped(void) {
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks));

    const char *doc =
        "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\","
        "\"kid\":\"k1\",\"x\":\"###not-base64url###\"}]}";
    g.jwks_body = doc;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    /* The JWKS document itself parsed fine; the bad entry just yields no
     * usable key, so verification fails on key lookup, not on the fetch. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no matching signing key"));
    free(token); free(jwks);
    axiam_client_free(c);
}

/* JWK "x" that decodes to fewer than 32 bytes. */
static void test_x_value_short_key_material_is_skipped(void) {
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks));

    unsigned char short_key[16];
    memset(short_key, 0x11, sizeof(short_key));
    char *short_b64 = jwt_b64url_encode(short_key, sizeof(short_key));

    char doc[1024];
    snprintf(doc, sizeof(doc),
             "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\","
             "\"kid\":\"k1\",\"x\":\"%s\"}]}", short_b64);
    free(short_b64);

    g.jwks_body = doc;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no matching signing key"));
    free(token); free(jwks);
    axiam_client_free(c);
}

/* JWK "x" that decodes to MORE than 32 bytes. */
static void test_x_value_oversized_key_material_is_skipped(void) {
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks));

    unsigned char long_key[64];
    memset(long_key, 0x22, sizeof(long_key));
    char *long_b64 = jwt_b64url_encode(long_key, sizeof(long_key));

    char doc[1024];
    snprintf(doc, sizeof(doc),
             "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\","
             "\"kid\":\"k1\",\"x\":\"%s\"}]}", long_b64);
    free(long_b64);

    g.jwks_body = doc;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no matching signing key"));
    free(token); free(jwks);
    axiam_client_free(c);
}

/* "keys" missing entirely -> cJSON_IsArray(NULL) is false -> parse_jwks()
 * returns 0 -> ensure_jwks() maps it to AXIAM_ERR_NETWORK. */
static void test_keys_field_missing(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    g.jwks_body = "{\"other\":1}";
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "invalid JWKS"));
    free(token); free(jwks);
    axiam_client_free(c);
}

/* A key entry missing "kty" entirely (not a string at all) -> the first
 * disjunct of the `!cJSON_IsString(kty) || ...` guard fires (src/jwks.c:25),
 * distinct from the existing "missing x" case in test_jwks.c which trips the
 * third disjunct. */
static void test_key_entry_missing_kty(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    const char *doc = "{\"keys\":[{\"crv\":\"Ed25519\",\"x\":\"AAAA\"}]}";
    g.jwks_body = doc;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* A key entry with kty=="OKP" (valid) but crv != "Ed25519" (src/jwks.c:29). */
static void test_key_entry_okp_wrong_curve(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    const char *doc =
        "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"P-256\",\"x\":\"AAAA\"}]}";
    g.jwks_body = doc;
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    free(token); free(jwks);
    axiam_client_free(c);
}

/* "keys" present but not an array (an object instead). */
static void test_keys_field_not_an_array(void) {
    char *token = NULL, *jwks = NULL;
    jwt_make("k1", "{\"sub\":\"u\"}", &token, &jwks);
    g.jwks_body = "{\"keys\":{\"not\":\"an-array\"}}";
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    free(token); free(jwks);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_x_value_invalid_base64url_is_skipped);
    RUN_TEST(test_x_value_short_key_material_is_skipped);
    RUN_TEST(test_x_value_oversized_key_material_is_skipped);
    RUN_TEST(test_key_entry_missing_kty);
    RUN_TEST(test_key_entry_okp_wrong_curve);
    RUN_TEST(test_keys_field_missing);
    RUN_TEST(test_keys_field_not_an_array);
    return UNITY_END();
}
