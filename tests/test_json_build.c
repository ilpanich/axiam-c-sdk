/* C2: src/json_build.c thin-branch depth — direct unit tests on the request
 * body builders (via src/internal.h), independent of any transport.
 *
 * Targets (per claude_dev/test-coverage-round2-plan.md, task C2): the
 * ternary/`if` arms around NULL-vs-present fields in axiam_build_login_body,
 * axiam_build_mfa_body, axiam_build_refresh_body and add_check_fields (via
 * axiam_build_check_body) that aren't reachable through the higher-level
 * client.c call sites already under test.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "internal.h"

void setUp(void) {}
void tearDown(void) {}

/* --- axiam_build_login_body --- */

static void test_login_body_null_user_and_password(void) {
    char *body = axiam_build_login_body(NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"username_or_email\":\"\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"password\":\"\""));
    free(body);
}

static void test_login_body_null_cfg(void) {
    char *body = axiam_build_login_body("alice", "pw", NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NULL(strstr(body, "tenant"));
    TEST_ASSERT_NULL(strstr(body, "org"));
    free(body);
}

static void test_login_body_tenant_slug_no_id(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "globex");
    char *body = axiam_build_login_body("alice", "pw", cfg);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"tenant_slug\":\"acme\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"org_slug\":\"globex\""));
    TEST_ASSERT_NULL(strstr(body, "tenant_id"));
    TEST_ASSERT_NULL(strstr(body, "org_id"));
    free(body);
    axiam_client_config_free(cfg);
}

static void test_login_body_no_tenant_no_org_at_all(void) {
    /* cfg present but every field empty: neither branch of either `if/else
     * if` pair fires. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    char *body = axiam_build_login_body("alice", "pw", cfg);
    TEST_ASSERT_NULL(strstr(body, "tenant"));
    TEST_ASSERT_NULL(strstr(body, "org"));
    free(body);
    axiam_client_config_free(cfg);
}

static void test_login_body_empty_string_tenant_and_org_treated_as_absent(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_tenant_id(cfg, "");
    axiam_client_config_set_tenant_slug(cfg, "");
    axiam_client_config_set_org_id(cfg, "");
    axiam_client_config_set_org_slug(cfg, "");
    char *body = axiam_build_login_body("alice", "pw", cfg);
    TEST_ASSERT_NULL(strstr(body, "tenant"));
    TEST_ASSERT_NULL(strstr(body, "org"));
    free(body);
    axiam_client_config_free(cfg);
}

/* --- axiam_build_mfa_body --- */

static void test_mfa_body_null_args(void) {
    char *body = axiam_build_mfa_body(NULL, NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"challenge_token\":\"\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"totp_code\":\"\""));
    free(body);
}

/* --- axiam_build_refresh_body --- */

static void test_refresh_body_each_missing_field_arm(void) {
    TEST_ASSERT_NULL(axiam_build_refresh_body(NULL, "org-1"));
    TEST_ASSERT_NULL(axiam_build_refresh_body("", "org-1"));
    TEST_ASSERT_NULL(axiam_build_refresh_body("tenant-1", NULL));
    TEST_ASSERT_NULL(axiam_build_refresh_body("tenant-1", ""));
}

static void test_refresh_body_valid(void) {
    char *body = axiam_build_refresh_body("tenant-1", "org-1");
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"tenant_id\":\"tenant-1\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"org_id\":\"org-1\""));
    free(body);
}

/* --- axiam_build_check_body (add_check_fields) --- */

static void test_check_body_null_action_and_resource(void) {
    char *body = axiam_build_check_body(NULL, NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"action\":\"\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"resource_id\":\"\""));
    TEST_ASSERT_NULL(strstr(body, "scope"));
    TEST_ASSERT_NULL(strstr(body, "subject_id"));
    free(body);
}

/* --- axiam_build_batch_body --- */

static void test_batch_body_empty(void) {
    char *body = axiam_build_batch_body(NULL, 0);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"checks\":[]"));
    free(body);
}

static void test_batch_body_null_optional_fields(void) {
    axiam_check_input_t checks[1] = { {NULL, NULL, NULL, NULL} };
    char *body = axiam_build_batch_body(checks, 1);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"action\":\"\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"resource_id\":\"\""));
    free(body);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_login_body_null_user_and_password);
    RUN_TEST(test_login_body_null_cfg);
    RUN_TEST(test_login_body_tenant_slug_no_id);
    RUN_TEST(test_login_body_no_tenant_no_org_at_all);
    RUN_TEST(test_login_body_empty_string_tenant_and_org_treated_as_absent);
    RUN_TEST(test_mfa_body_null_args);
    RUN_TEST(test_refresh_body_each_missing_field_arm);
    RUN_TEST(test_refresh_body_valid);
    RUN_TEST(test_check_body_null_action_and_resource);
    RUN_TEST(test_batch_body_empty);
    RUN_TEST(test_batch_body_null_optional_fields);
    return UNITY_END();
}
