/*
 * The §27.6/§27.7 declarative layer.
 *
 * Everything here is about the properties that make a manifest safe to run more than
 * once against a live tenant: plan writes nothing, ordering is derived and stable,
 * incoherence is refused before the first request, apply stops at the first failure
 * without rolling back, and omission is never deletion.
 */

#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_manifest.h"
#include "test_util.h"
#include "management_test_util.h"

#define UUID "11111111-1111-4111-8111-111111111111"

static const char *EMPTY_PAGE = "{\"items\":[],\"total\":0}";

static const char *PERM_PAGE =
    "{\"items\":[{\"action\":\"documents:read\",\"created_at\":\"2026-08-26T00:00:00Z\","
    "\"description\":\"Read documents\",\"id\":\"" UUID "\",\"tenant_id\":\"" UUID "\","
    "\"updated_at\":\"2026-08-26T00:00:00Z\"}],\"total\":1}";

static const char *PERM_PAGE_STALE =
    "{\"items\":[{\"action\":\"documents:read\",\"created_at\":\"2026-08-26T00:00:00Z\","
    "\"description\":\"stale\",\"id\":\"" UUID "\",\"tenant_id\":\"" UUID "\","
    "\"updated_at\":\"2026-08-26T00:00:00Z\"}],\"total\":1}";

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

static axiam_mgmt_manifest_entity_t one_permission(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_PERMISSION;
    e.key = "read";
    e.name = "documents:read";
    e.action = "documents:read";
    e.description = "Read documents";
    return e;
}

/* ---- plan writes nothing -------------------------------------------- */

static void test_plan_issues_only_reads(void) {
    mgmt_mount(200, EMPTY_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_INT(1, (int) plan->pending);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_CREATE, plan->changes[0].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

static void test_a_converged_tenant_plans_nothing(void) {
    mgmt_mount(200, PERM_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_EQUAL_INT(0, (int) plan->pending);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->changes[0].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

static void test_a_converged_tenant_applies_nothing(void) {
    mgmt_mount(200, PERM_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_apply_report_t report;

    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(0, (int) report.applied);
    /* login + the one read plan() needed, and nothing else. */
    TEST_ASSERT_EQUAL_INT(2, mgmt_request_count());
    axiam_client_free(c);
}

static void test_drift_is_updated_in_place(void) {
    mgmt_mount(200, PERM_PAGE_STALE);
    mgmt_mount_next(200, "{\"action\":\"documents:read\",\"created_at\":\"x\","
                         "\"description\":\"Read documents\",\"id\":\"" UUID "\","
                         "\"tenant_id\":\"" UUID "\",\"updated_at\":\"x\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_apply_report_t report;

    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, (int) report.applied);
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    /* Only the drifted field -- the sparse body of §27.4 rule 5. */
    TEST_ASSERT_EQUAL_STRING("{\"description\":\"Read documents\"}", mgmt_last_body());
    axiam_client_free(c);
}

/* ---- ordering is derived and stable ---------------------------------- */

static void test_ordering_is_derived_not_declared(void) {
    /* Declared backwards on purpose: group, role, permission, resource. */
    axiam_mgmt_manifest_entity_t e[4];
    memset(e, 0, sizeof e);
    e[0].kind = AXIAM_MGMT_MANIFEST_GROUP;      e[0].key = "g";   e[0].name = "engineers";
    e[1].kind = AXIAM_MGMT_MANIFEST_ROLE;       e[1].key = "r";   e[1].name = "auditor";
    e[2].kind = AXIAM_MGMT_MANIFEST_PERMISSION; e[2].key = "p";   e[2].name = "docs:read";
    e[2].action = "docs:read";
    e[3].kind = AXIAM_MGMT_MANIFEST_RESOURCE;   e[3].key = "res"; e[3].name = "root";

    mgmt_mount(200, EMPTY_PAGE);
    mgmt_mount_next(200, EMPTY_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { e, 4 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_NOT_NULL(plan);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_MANIFEST_RESOURCE, plan->changes[0].entity->kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_MANIFEST_PERMISSION, plan->changes[1].entity->kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_MANIFEST_ROLE, plan->changes[2].entity->kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_MANIFEST_GROUP, plan->changes[3].entity->kind);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

static void test_a_parent_resource_is_ordered_before_its_child(void) {
    axiam_mgmt_manifest_entity_t e[2];
    memset(e, 0, sizeof e);
    e[0].kind = AXIAM_MGMT_MANIFEST_RESOURCE; e[0].key = "child";  e[0].name = "child";
    e[0].depends_on = "parent";
    e[1].kind = AXIAM_MGMT_MANIFEST_RESOURCE; e[1].key = "parent"; e[1].name = "parent";

    mgmt_mount(200, EMPTY_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { e, 2 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_EQUAL_STRING("parent", plan->changes[0].entity->key);
    TEST_ASSERT_EQUAL_STRING("child", plan->changes[1].entity->key);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* Ties break on KEY, deterministically -- without which a plan diff is unreadable. */
static void test_ordering_is_stable_across_runs(void) {
    axiam_mgmt_manifest_entity_t e[3];
    memset(e, 0, sizeof e);
    const char *keys[3] = { "zeta", "alpha", "mid" };
    for (int i = 0; i < 3; i++) {
        e[i].kind = AXIAM_MGMT_MANIFEST_PERMISSION;
        e[i].key = keys[i];
        e[i].name = keys[i];
        e[i].action = keys[i];
    }

    for (int run = 0; run < 2; run++) {
        mgmt_reset();
        mgmt_mount(200, EMPTY_PAGE);
        axiam_client_t *c = mgmt_signed_in_client();
        axiam_error_t err;
        axiam_mgmt_manifest_t m = { e, 3 };
        axiam_mgmt_plan_t *plan = NULL;

        axiam_mgmt_plan(c, &m, &plan, &err);

        TEST_ASSERT_EQUAL_STRING("alpha", plan->changes[0].entity->key);
        TEST_ASSERT_EQUAL_STRING("mid", plan->changes[1].entity->key);
        TEST_ASSERT_EQUAL_STRING("zeta", plan->changes[2].entity->key);
        axiam_mgmt_plan_free(plan);
        axiam_client_free(c);
    }
}

/* ---- incoherence is refused BEFORE any request ----------------------- */

static void test_a_dangling_reference_is_refused_before_any_request(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_ROLE;
    e.key = "auditor";
    e.name = "auditor";
    e.depends_on = "a-permission-nobody-declared";

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_NULL(plan);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "does not declare"));
    TEST_ASSERT_EQUAL_INT(1, mgmt_request_count()); /* only the login */
    axiam_client_free(c);
}

static void test_a_cycle_is_refused_before_any_request(void) {
    axiam_mgmt_manifest_entity_t e[2];
    memset(e, 0, sizeof e);
    e[0].kind = AXIAM_MGMT_MANIFEST_RESOURCE; e[0].key = "a"; e[0].name = "a"; e[0].depends_on = "b";
    e[1].kind = AXIAM_MGMT_MANIFEST_RESOURCE; e[1].key = "b"; e[1].name = "b"; e[1].depends_on = "a";

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { e, 2 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "cycle"));
    TEST_ASSERT_EQUAL_INT(1, mgmt_request_count());
    axiam_client_free(c);
}

static void test_a_duplicate_key_is_refused(void) {
    axiam_mgmt_manifest_entity_t e[2];
    memset(e, 0, sizeof e);
    e[0].kind = AXIAM_MGMT_MANIFEST_PERMISSION; e[0].key = "read"; e[0].name = "a"; e[0].action = "a";
    e[1].kind = AXIAM_MGMT_MANIFEST_PERMISSION; e[1].key = "read"; e[1].name = "b"; e[1].action = "b";

    axiam_error_t err;
    axiam_mgmt_manifest_t m = { e, 2 };

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mgmt_manifest_validate(&m, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "twice"));
}

static void test_an_entity_without_a_key_is_refused(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_ROLE;
    e.name = "nameless";

    axiam_error_t err;
    axiam_mgmt_manifest_t m = { &e, 1 };

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mgmt_manifest_validate(&m, &err));
}

/* ---- apply stops at the first failure, without rolling back ---------- */

static void test_apply_stops_at_the_first_failure_and_does_not_roll_back(void) {
    axiam_mgmt_manifest_entity_t e[3];
    memset(e, 0, sizeof e);
    const char *keys[3] = { "a", "b", "c" };
    for (int i = 0; i < 3; i++) {
        e[i].kind = AXIAM_MGMT_MANIFEST_PERMISSION;
        e[i].key = keys[i];
        e[i].name = keys[i];
        e[i].action = keys[i];
        e[i].description = "d";
    }

    mgmt_mount(200, EMPTY_PAGE);                 /* plan */
    mgmt_mount_next(200, "{\"action\":\"a\",\"created_at\":\"x\",\"description\":\"d\","
                         "\"id\":\"" UUID "\",\"tenant_id\":\"" UUID "\",\"updated_at\":\"x\"}");
    mgmt_mount_next(500, NULL);                  /* create #2 -> boom */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { e, 3 };
    axiam_mgmt_apply_report_t report;

    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, (int) report.applied);   /* the first landed and STAYS landed */
    TEST_ASSERT_EQUAL_INT(1, (int) report.failed);
    TEST_ASSERT_EQUAL_INT(1, (int) report.remaining); /* the third was never attempted */
    /* login + 1 read + 2 creates. No rollback traffic. */
    TEST_ASSERT_EQUAL_INT(4, mgmt_request_count());
    axiam_client_free(c);
}

/* ---- omission is never deletion -------------------------------------- */

/*
 * An object the manifest does not mention is left strictly alone. There is no
 * AXIAM_MGMT_CHANGE_DELETE in the enum at all, which is the structural version of the
 * guarantee: a manifest cannot express deletion, so an incomplete one cannot become
 * destructive.
 */
static void test_omission_is_never_deletion(void) {
    mgmt_mount(200,
        "{\"items\":[{\"action\":\"documents:read\",\"created_at\":\"x\","
        "\"description\":\"Read documents\",\"id\":\"" UUID "\",\"tenant_id\":\"" UUID "\","
        "\"updated_at\":\"x\"},{\"action\":\"secrets:read\",\"created_at\":\"x\","
        "\"description\":\"nobody declared this\",\"id\":\"" UUID "\","
        "\"tenant_id\":\"" UUID "\",\"updated_at\":\"x\"}],\"total\":2}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_EQUAL_INT(1, (int) plan->count);
    TEST_ASSERT_EQUAL_INT(0, (int) plan->pending);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

static void test_plan_free_tolerates_null(void) {
    axiam_mgmt_plan_free(NULL);
    TEST_PASS();
}

static void test_validate_rejects_null(void) {
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mgmt_manifest_validate(NULL, &err));
}


/* ---- every kind's create and update arm ------------------------------ */

/*
 * perform() has a create and an update arm for each of the four kinds, and the
 * permission cases above only reach two of the eight. These drive the other six: a kind
 * whose update arm is never exercised is one where a wrong field name ships silently.
 */
static void drive_kind(axiam_mgmt_manifest_kind_t kind, const char *list_page,
                       const char *created, const char *expect_method) {
    mgmt_reset();
    mgmt_mount(200, list_page);
    mgmt_mount_next(200, created);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = kind;
    e.key = "k";
    e.name = "thing";
    e.action = "thing";
    e.resource_type = "folder";
    e.description = "wanted";
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_apply_report_t report;

    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, (int) report.applied);
    TEST_ASSERT_EQUAL_STRING(expect_method, mgmt_last_method());
    axiam_client_free(c);
}

#define OBJ(extra_fields) \
    "{\"created_at\":\"x\",\"updated_at\":\"x\",\"id\":\"" UUID "\"," \
    "\"tenant_id\":\"" UUID "\"" extra_fields "}"

static void test_a_resource_is_created(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_RESOURCE, EMPTY_PAGE,
               OBJ(",\"name\":\"thing\",\"resource_type\":\"folder\",\"metadata\":{}"), "POST");
}

static void test_a_drifted_resource_is_updated(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_RESOURCE,
               "{\"items\":[" OBJ(",\"name\":\"thing\",\"resource_type\":\"folder\",\"metadata\":{}")
               "],\"total\":1}",
               OBJ(",\"name\":\"thing\",\"resource_type\":\"folder\",\"metadata\":{}"), "PUT");
}

static void test_a_role_is_created(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_ROLE, EMPTY_PAGE,
               OBJ(",\"name\":\"thing\",\"description\":\"wanted\",\"is_global\":false"), "POST");
}

static void test_a_drifted_role_is_updated(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_ROLE,
               "{\"items\":[" OBJ(",\"name\":\"thing\",\"description\":\"stale\",\"is_global\":false")
               "],\"total\":1}",
               OBJ(",\"name\":\"thing\",\"description\":\"wanted\",\"is_global\":false"), "PUT");
}

static void test_a_group_is_created(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_GROUP, EMPTY_PAGE,
               OBJ(",\"name\":\"thing\",\"description\":\"wanted\",\"metadata\":{}"), "POST");
}

static void test_a_drifted_group_is_updated(void) {
    drive_kind(AXIAM_MGMT_MANIFEST_GROUP,
               "{\"items\":[" OBJ(",\"name\":\"thing\",\"description\":\"stale\",\"metadata\":{}")
               "],\"total\":1}",
               OBJ(",\"name\":\"thing\",\"description\":\"wanted\",\"metadata\":{}"), "PUT");
}

/*
 * A read that fails aborts the plan rather than reporting a tenant full of creates.
 *
 * 403 rather than 500 on purpose: rule 8 RETRIES a failed GET, so a single mounted 500
 * is consumed by the first attempt and the retry succeeds against the rig's default
 * response -- which is a realistic scenario (an operator who may not list permissions)
 * and also the one that actually reaches the abort path.
 */
static void test_a_failing_read_aborts_the_plan(void) {
    mgmt_mount(403, NULL);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_mgmt_plan_t *plan = NULL;

    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_NULL(plan);
    axiam_client_free(c);
}

/* An empty manifest is coherent, plans nothing, and reads nothing. */
static void test_an_empty_manifest_is_a_no_op(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_t m = { NULL, 0 };
    axiam_mgmt_apply_report_t report;

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_INT(0, (int) report.applied);
    TEST_ASSERT_EQUAL_INT(1, mgmt_request_count()); /* the login, nothing more */
    axiam_client_free(c);
}

/* plan() with out == NULL still validates and reads, and frees what it built. */
static void test_plan_discards_when_out_is_null(void) {
    mgmt_mount(200, EMPTY_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, NULL, &err));
    axiam_client_free(c);
}

/* apply() tolerates a NULL report -- a caller that only wants the return code. */
static void test_apply_tolerates_a_null_report(void) {
    mgmt_mount(200, PERM_PAGE);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_manifest_entity_t e = one_permission();
    axiam_mgmt_manifest_t m = { &e, 1 };

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, NULL, &err));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_plan_issues_only_reads);
    RUN_TEST(test_a_converged_tenant_plans_nothing);
    RUN_TEST(test_a_converged_tenant_applies_nothing);
    RUN_TEST(test_drift_is_updated_in_place);
    RUN_TEST(test_ordering_is_derived_not_declared);
    RUN_TEST(test_a_parent_resource_is_ordered_before_its_child);
    RUN_TEST(test_ordering_is_stable_across_runs);
    RUN_TEST(test_a_dangling_reference_is_refused_before_any_request);
    RUN_TEST(test_a_cycle_is_refused_before_any_request);
    RUN_TEST(test_a_duplicate_key_is_refused);
    RUN_TEST(test_an_entity_without_a_key_is_refused);
    RUN_TEST(test_apply_stops_at_the_first_failure_and_does_not_roll_back);
    RUN_TEST(test_omission_is_never_deletion);
    RUN_TEST(test_plan_free_tolerates_null);
    RUN_TEST(test_validate_rejects_null);
    RUN_TEST(test_a_resource_is_created);
    RUN_TEST(test_a_drifted_resource_is_updated);
    RUN_TEST(test_a_role_is_created);
    RUN_TEST(test_a_drifted_role_is_updated);
    RUN_TEST(test_a_group_is_created);
    RUN_TEST(test_a_drifted_group_is_updated);
    RUN_TEST(test_a_failing_read_aborts_the_plan);
    RUN_TEST(test_an_empty_manifest_is_a_no_op);
    RUN_TEST(test_plan_discards_when_out_is_null);
    RUN_TEST(test_apply_tolerates_a_null_report);
    return UNITY_END();
}
