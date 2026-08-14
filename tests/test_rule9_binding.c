/*
 * CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access
 * tokens (contract 1.15, RFC 8705 §3 / RFC 7800).
 *
 * A token carrying `cnf` is not a bearer token and must not be accepted as
 * one. Three negatives and one positive — and the POSITIVE is the one that
 * matters most: rule 9 must not become "every caller must present a
 * certificate", which would break every deployment that does not use mTLS.
 */
#include <stdlib.h>  /* free() for the heap thumbprint */
#include <string.h>

#include "axiam/axiam.h"
#include "axiam/jwks.h"
#include "unity.h"

/* A real 43-character base64url x5t#S256, and a different one. */
static const char *TP = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
static const char *OTHER_TP = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18";

static const char *UNBOUND = "{\"sub\":\"u\",\"tenant_id\":\"t\",\"exp\":9999999999}";
static const char *BOUND =
    "{\"sub\":\"u\",\"tenant_id\":\"t\",\"exp\":9999999999,"
    "\"cnf\":{\"x5t#S256\":\"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\"}}";
/* A cnf naming a method this SDK cannot check — a DPoP jkt. */
static const char *DPOPISH =
    "{\"sub\":\"u\",\"tenant_id\":\"t\",\"exp\":9999999999,"
    "\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}}";

void setUp(void) {}
void tearDown(void) {}

/* The regression test that keeps rule 9 from becoming a certificate mandate. */
static void test_unbound_token_accepted_with_or_without_a_certificate(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_jwt_verify_certificate_binding(UNBOUND, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_jwt_verify_certificate_binding(UNBOUND, TP, &err));
}

static void test_bound_token_accepted_with_its_own_certificate(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_jwt_verify_certificate_binding(BOUND, TP, &err));
}

static void test_bound_token_rejected_with_no_certificate(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(BOUND, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(BOUND, "", &err));
}

static void test_bound_token_rejected_with_a_different_certificate(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(BOUND, OTHER_TP, &err));
}

/*
 * The subtle one. A cnf naming a confirmation method this SDK cannot check is
 * an UNVERIFIABLE constraint, never NO constraint — read the other way, a
 * sender-constrained token silently degrades to a bearer token the day a newer
 * AXIAM issues a confirmation this SDK predates.
 */
static void test_unverifiable_confirmation_rejected_not_ignored(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(DPOPISH, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(DPOPISH, TP, &err));
}

static void test_malformed_inputs_fail_closed(void) {
    axiam_error_t err = {0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding(NULL, TP, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_jwt_verify_certificate_binding("not json", TP, &err));
    TEST_ASSERT_EQUAL(
        AXIAM_ERR_AUTH,
        axiam_jwt_verify_certificate_binding(
            "{\"cnf\":\"a string, not an object\"}", TP, &err));
}

/*
 * RFC 7515 §2 base64url: unpadded, '-'/'_' rather than '+'/'/'. A padded or
 * standard-base64 value will not compare equal to what AXIAM put in the token.
 */
static void test_thumbprint_is_unpadded_base64url(void) {
    unsigned char der[512];
    memset(der, 0x42, sizeof(der));

    char *tp = axiam_certificate_thumbprint_s256(der, sizeof(der));
    TEST_ASSERT_NOT_NULL(tp);
    TEST_ASSERT_EQUAL_size_t(43, strlen(tp));
    TEST_ASSERT_NULL(strchr(tp, '='));
    TEST_ASSERT_NULL(strchr(tp, '+'));
    TEST_ASSERT_NULL(strchr(tp, '/'));

    char *again = axiam_certificate_thumbprint_s256(der, sizeof(der));
    TEST_ASSERT_NOT_NULL(again);
    TEST_ASSERT_EQUAL_STRING(tp, again);

    /* A different certificate must produce a different thumbprint. */
    der[0] = 0x43;
    char *other = axiam_certificate_thumbprint_s256(der, sizeof(der));
    TEST_ASSERT_NOT_NULL(other);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(tp, other));

    free(tp);
    free(again);
    free(other);
}

static void test_thumbprint_null_der_is_null(void) {
    TEST_ASSERT_NULL(axiam_certificate_thumbprint_s256(NULL, 0));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_unbound_token_accepted_with_or_without_a_certificate);
    RUN_TEST(test_bound_token_accepted_with_its_own_certificate);
    RUN_TEST(test_bound_token_rejected_with_no_certificate);
    RUN_TEST(test_bound_token_rejected_with_a_different_certificate);
    RUN_TEST(test_unverifiable_confirmation_rejected_not_ignored);
    RUN_TEST(test_malformed_inputs_fail_closed);
    RUN_TEST(test_thumbprint_is_unpadded_base64url);
    RUN_TEST(test_thumbprint_null_der_is_null);
    return UNITY_END();
}
