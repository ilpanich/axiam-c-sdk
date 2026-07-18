#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"

static const char *PEM_CERT =
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
/* A syntactically-PEM placeholder that is deliberately NOT a real key and does
 * not match the CI private-key secret-scan pattern. axiam_is_pem() only checks
 * for the "-----BEGIN" marker. */
static const char *PEM_KEY =
    "-----BEGIN TEST KEY PLACEHOLDER-----\nMC4C\n-----END TEST KEY PLACEHOLDER-----\n";

void setUp(void) {}
void tearDown(void) {}

static void test_missing_base_url_fails(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

static void test_missing_tenant_fails(void) {
    /* §5: no default tenant. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    TEST_ASSERT_TRUE(strlen(err.message) > 0);
    axiam_client_config_free(cfg);
}

static void test_tenant_slug_valid(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

static void test_tenant_id_valid(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

static void test_custom_ca_rejects_non_pem(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_custom_ca(cfg, "not-a-pem"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_config_set_custom_ca(cfg,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"));
    axiam_client_config_free(cfg);
}

static void test_client_cert_requires_pem(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_client_cert(cfg, "x", "y"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_client_cert(cfg, PEM_CERT, "y"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_config_set_client_cert(cfg, PEM_CERT, PEM_KEY));
    axiam_client_config_free(cfg);
}

static void test_setters_dont_crash(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "org");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_client_config_set_connect_timeout_ms(cfg, 2000);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_missing_base_url_fails);
    RUN_TEST(test_missing_tenant_fails);
    RUN_TEST(test_tenant_slug_valid);
    RUN_TEST(test_tenant_id_valid);
    RUN_TEST(test_custom_ca_rejects_non_pem);
    RUN_TEST(test_client_cert_requires_pem);
    RUN_TEST(test_setters_dont_crash);
    return UNITY_END();
}
