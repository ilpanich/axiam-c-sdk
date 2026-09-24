/*
 * CONTRACT.md §10.1 rule 9 (contract 1.51) — the DEFAULT verify entry point
 * (axiam_jwt_verify() / axiam_jwt_verify_ex(), which axiam_require_auth() and
 * every §10/§11 guard call) now refuses a cnf-bound token instead of silently
 * admitting it as a bearer token, closing a defect this SDK shared with the
 * Rust, TypeScript, Go, Python, C# and Java ports.
 *
 * test_rule9_binding.c already pins axiam_jwt_verify_certificate_binding()'s
 * standalone table exhaustively; this file is about the two call sites that
 * changed: the DEFAULT path (now refuses) and the NEW accept-with-evidence
 * path (accepts, with the right evidence).
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
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

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

void setUp(void) { memset(&g, 0, sizeof(g)); }
void tearDown(void) {}

#define TP "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
#define OTHER_TP "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18"

static void test_default_entry_point_refuses_cnf_bound_token(void) {
    char *token = NULL, *jwks = NULL;
    char payload[512];
    test_claims(payload, sizeof(payload), "device-1",
               ",\"cnf\":{\"x5t#S256\":\"" TP "\"}");
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        AXIAM_ERR_AUTH, k,
        "the default entry point has no evidence and MUST refuse a cnf-bound "
        "token, not silently admit it as a bearer token");

    k = axiam_jwt_verify_ex(c, token, AXIAM_JWT_VERIFY_STRICT, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);

    free(token);
    free(jwks);
    axiam_client_free(c);
}

/* The I4 twin: an UNBOUND token is unaffected by the fix -- still accepted by
 * the default entry point, with no evidence needed. */
static void test_default_entry_point_still_accepts_unbound_token(void) {
    char *token = NULL, *jwks = NULL;
    char payload[256];
    test_claims(payload, sizeof(payload), "user-1", NULL);
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(c, token, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);

    free(token);
    free(jwks);
    axiam_client_free(c);
}

static void test_with_evidence_accepts_the_matching_certificate(void) {
    char *token = NULL, *jwks = NULL;
    char payload[512];
    test_claims(payload, sizeof(payload), "device-1",
               ",\"cnf\":{\"x5t#S256\":\"" TP "\"}");
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    char *claims = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify_with_evidence(c, token, TP, &claims, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_NOT_NULL(claims);
    free(claims);

    free(token);
    free(jwks);
    axiam_client_free(c);
}

static void test_with_evidence_refuses_a_different_certificate(void) {
    char *token = NULL, *jwks = NULL;
    char payload[512];
    test_claims(payload, sizeof(payload), "device-1",
               ",\"cnf\":{\"x5t#S256\":\"" TP "\"}");
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify_with_evidence(c, token, OTHER_TP, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    k = axiam_jwt_verify_with_evidence(c, token, NULL, NULL, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);

    free(token);
    free(jwks);
    axiam_client_free(c);
}

/* axiam_require_auth() (the §10/§11 guard) reaches axiam_jwt_verify_ex() with
 * no evidence -- so a cnf-bound token in an Authorization header is refused
 * through the SAME guard every route macro uses, with no special wiring. */
static void test_require_auth_guard_refuses_cnf_bound_token(void) {
    char *token = NULL, *jwks = NULL;
    char payload[512];
    test_claims(payload, sizeof(payload), "device-1",
               ",\"cnf\":{\"x5t#S256\":\"" TP "\"}");
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    axiam_client_t *c = make_client();

    char bearer[1024];
    snprintf(bearer, sizeof(bearer), "Bearer %s", token);
    axiam_kv_t *headers = NULL;
    headers = axiam_kv_append(headers, "Authorization", bearer);

    axiam_guard_status_t st = axiam_require_auth(c, headers);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        AXIAM_GUARD_UNAUTHENTICATED, st,
        "a device token lifted off a device must not open a guarded route "
        "through the default guard");

    axiam_kv_free(headers);
    free(token);
    free(jwks);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_default_entry_point_refuses_cnf_bound_token);
    RUN_TEST(test_default_entry_point_still_accepts_unbound_token);
    RUN_TEST(test_with_evidence_accepts_the_matching_certificate);
    RUN_TEST(test_with_evidence_refuses_a_different_certificate);
    RUN_TEST(test_require_auth_guard_refuses_cnf_bound_token);
    return UNITY_END();
}
