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

/* CONTRACT.md §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug.
 *
 * A non-NULL pointer to "" (or to spaces) satisfied the old `[0] != '\0'`
 * check on `tenant_id` while failing it on `tenant_slug`, so a config carrying
 * a blank slug alongside a real id validated and put `tenant_slug: ""` on the
 * wire. Nothing can carry a blank slug: the server resolves nothing, and on
 * /auth/opaque/login/start it fails on the workspace *before* the tenant's
 * OPAQUE mode is read — so the 404 of §23.4 rule 10 never arrives, this SDK has
 * no fallback to take, and sign-in fails even against a tenant with OPAQUE
 * disabled. */
static void test_blank_tenant_slug_is_rejected(void) {
    const char *blanks[] = {"", "   "};
    for (size_t i = 0; i < sizeof(blanks) / sizeof(blanks[0]); i++) {
        axiam_client_config_t *cfg = axiam_client_config_new();
        axiam_client_config_set_base_url(cfg, "https://iam.example.com");
        axiam_client_config_set_tenant_slug(cfg, blanks[i]);
        axiam_error_t err;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
        axiam_client_config_free(cfg);
    }
}

/* The case the old check missed entirely: a real tenant_id satisfies §5, and
 * the blank slug rides along into the body. */
static void test_blank_tenant_slug_is_rejected_even_beside_a_valid_id(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_tenant_slug(cfg, "");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

static void test_blank_org_slug_is_rejected(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

/* NULL is not blank: an unset org_slug is legitimate (§5.1 — the organization
 * identifier is optional for a client that never calls login or refresh). */
static void test_unset_org_slug_is_accepted(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

/* §5.2.1: an organization-level principal signs in by naming the
 * organization's reserved tenant, whose slug is fixed in every deployment. */
static void test_reserved_organization_tenant_is_named_like_any_other(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "organization");
    axiam_client_config_set_org_slug(cfg, "globex");
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

/* C2: axiam_client_config_validate(NULL, ...) -> src/config.c:82-84 directly
 * (also reached indirectly through axiam_client_new(NULL, ...), covered in
 * tests/test_client_branches.c). */
static void test_validate_null_cfg(void) {
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "NULL"));
}

/* C2: every setter's `if (cfg) ...` guard, false arm — a NULL cfg must be a
 * silent no-op, never a crash. */
static void test_setters_tolerate_null_cfg(void) {
    axiam_client_config_set_base_url(NULL, "x");
    axiam_client_config_set_tenant_slug(NULL, "x");
    axiam_client_config_set_tenant_id(NULL, "x");
    axiam_client_config_set_org_slug(NULL, "x");
    axiam_client_config_set_org_id(NULL, "x");
    axiam_client_config_set_timeout_ms(NULL, 1000);
    axiam_client_config_set_connect_timeout_ms(NULL, 1000);
    axiam_client_config_set_transport(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_set_custom_ca(NULL, "x"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_client_cert(NULL, PEM_CERT, PEM_KEY));
}

/* C2 (src/config.c): axiam_client_config_clone() of a fully-populated config,
 * including the client_key Sensitive branch (src/config.c:112-115). */
static void test_clone_copies_all_fields_including_client_key(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "globex");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_custom_ca(cfg,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    axiam_client_config_set_client_cert(cfg, PEM_CERT, PEM_KEY);
    axiam_client_config_set_timeout_ms(cfg, 1234);
    axiam_client_config_set_connect_timeout_ms(cfg, 567);

    /* axiam_client_config_clone is exercised end-to-end via axiam_client_new,
     * which clones cfg into the client (src/client.c:19). */
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_NOT_NULL(c);
    axiam_client_config_free(cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* SEC-073 (CONTRACT §6): a plaintext base URL is refused at construction */
/* ------------------------------------------------------------------ */

/* Validate a base URL through BOTH entry points: the explicit validate() call
 * and axiam_client_new(), which must refuse to build a client at all. */
static axiam_error_kind_t validate_base_url(const char *base_url) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    axiam_error_kind_t k = axiam_client_config_validate(cfg, &err);

    axiam_error_t nerr;
    axiam_client_t *c = axiam_client_new(cfg, &nerr);
    if (k == AXIAM_OK) {
        TEST_ASSERT_NOT_NULL(c);
    } else {
        TEST_ASSERT_NULL(c);
    }
    axiam_client_free(c);
    axiam_client_config_free(cfg);
    return k;
}

static void test_plaintext_base_url_is_rejected(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("http://iam.example.com"));

    /* The message must name the requirement without leaking anything else. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "http://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "https"));
    axiam_client_config_free(cfg);
}

static void test_https_base_url_is_accepted(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("https://iam.example.com"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("HTTPS://iam.example.com"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("https://iam.example.com:8443/base"));
}

/* The one deliberate exception: loopback, for local development. */
static void test_plaintext_loopback_is_allowed_for_dev(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://localhost"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://localhost:8080"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://LOCALHOST:8080/api"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://127.0.0.1:8080"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://[::1]:8080"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, validate_base_url("http://[::1]"));
}

/* Near-miss hosts must NOT inherit the loopback exception. */
static void test_plaintext_non_loopback_lookalikes_are_rejected(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("http://localhost.evil.com"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("http://127.0.0.2"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("http://not-localhost"));
    /* Userinfo trick: the authority's host is `evil.example`, not `localhost`. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          validate_base_url("http://localhost@evil.example/api"));
    /* Other plaintext schemes get no special treatment either. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("ws://iam.example.com"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("httpss://iam.example.com"));
    /* A scheme-less value is not a usable base URL. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("iam.example.com"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, validate_base_url("://iam.example.com"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_missing_base_url_fails);
    RUN_TEST(test_plaintext_base_url_is_rejected);
    RUN_TEST(test_https_base_url_is_accepted);
    RUN_TEST(test_plaintext_loopback_is_allowed_for_dev);
    RUN_TEST(test_plaintext_non_loopback_lookalikes_are_rejected);
    RUN_TEST(test_missing_tenant_fails);
    RUN_TEST(test_tenant_slug_valid);
    RUN_TEST(test_tenant_id_valid);
    RUN_TEST(test_blank_tenant_slug_is_rejected);
    RUN_TEST(test_blank_tenant_slug_is_rejected_even_beside_a_valid_id);
    RUN_TEST(test_blank_org_slug_is_rejected);
    RUN_TEST(test_unset_org_slug_is_accepted);
    RUN_TEST(test_reserved_organization_tenant_is_named_like_any_other);
    RUN_TEST(test_custom_ca_rejects_non_pem);
    RUN_TEST(test_client_cert_requires_pem);
    RUN_TEST(test_setters_dont_crash);
    RUN_TEST(test_validate_null_cfg);
    RUN_TEST(test_setters_tolerate_null_cfg);
    RUN_TEST(test_clone_copies_all_fields_including_client_key);
    return UNITY_END();
}
