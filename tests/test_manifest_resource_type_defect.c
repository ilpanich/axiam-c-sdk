/*
 * §13 row 17, defect #2 (the dogfooding remediation plan): this SDK's manifest used to
 * default a resource's `resource_type` to `"folder"` whenever the manifest left it
 * unstated -- a default CONTRACT.md never stated. Fixed by refusing, client-side and
 * before any request, a resource entity with no `resource_type` at all
 * (axiam_mgmt_manifest_validate()), and by sending exactly the stated value with no
 * fallback in perform()'s Create body.
 *
 * The idempotence test over a NESTED manifest the task asks for: apply a two-level
 * resource tree where NEITHER level is "folder" (so a silent substitution would be
 * impossible to miss), assert the wire body of each Create names exactly the type the
 * manifest declared, then plan() again and assert it is empty.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_manifest.h"
#include "test_util.h"
#include "management_test_util.h"

#define ROOT_ID "11111111-1111-4111-8111-111111111111"
#define CHILD_ID "22222222-2222-4222-8222-222222222222"

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ------------------------------------------------------------------------
 * Never a silent "folder": refused client-side, zero wire calls, before that.
 * ------------------------------------------------------------------------ */

static void test_resource_with_no_resource_type_is_refused_zero_wire_calls(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    e.key = "r1";
    e.name = "proj";
    /* e.resource_type left NULL -- this is the case this SDK used to paper over. */
    axiam_mgmt_manifest_t m = { &e, 1 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        AXIAM_ERR_NETWORK, rc,
        "a resource with no resource_type must be refused, never defaulted to \"folder\"");
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* The I4 twin: a resource that DOES state a type -- any type, including one that is
 * not "folder" -- is accepted and reaches the wire. */
static void test_resource_with_a_stated_type_is_accepted(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    e.key = "r1";
    e.name = "proj";
    e.resource_type = "workspace";
    axiam_mgmt_manifest_t m = { &e, 1 };
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_manifest_validate(&m, &err));
}

/* ------------------------------------------------------------------------
 * The idempotence test over a NESTED manifest: the wire carries the STATED type at
 * every level, never "folder" as a guess, and apply-then-plan is empty.
 * ------------------------------------------------------------------------ */

static void test_nested_manifest_sends_the_stated_type_at_every_level_and_is_idempotent(void) {
    axiam_mgmt_manifest_entity_t entities[2];
    memset(entities, 0, sizeof entities);
    entities[0].kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    entities[0].key = "root";
    entities[0].name = "root-res";
    entities[0].resource_type = "workspace"; /* deliberately NOT "folder" */
    entities[1].kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    entities[1].key = "child";
    entities[1].name = "child-res";
    entities[1].resource_type = "project"; /* deliberately NOT "folder" */
    entities[1].depends_on = "root";
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}"); /* resources.list: nothing exists yet */
    mgmt_mount_next(200,
        "{\"id\":\"" ROOT_ID "\",\"name\":\"root-res\",\"resource_type\":\"workspace\"}");
    mgmt_mount_next(200,
        "{\"id\":\"" CHILD_ID "\",\"name\":\"child-res\",\"resource_type\":\"project\","
        "\"parent_id\":\"" ROOT_ID "\"}");

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(2, (int) report.applied);
    /* The LAST request is the child's Create -- assert its stated type, never "folder". */
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"resource_type\":\"project\""),
                             mgmt_last_body());
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "folder"),
                             "no level of this manifest ever named \"folder\"");
    axiam_mgmt_apply_report_dispose(&report);

    /* apply(m) followed by plan(m): all NoChange (§27.6 rule 6). */
    mgmt_mount(200,
        "{\"items\":[{\"id\":\"" ROOT_ID "\",\"name\":\"root-res\","
        "\"resource_type\":\"workspace\"},"
        "{\"id\":\"" CHILD_ID "\",\"name\":\"child-res\",\"resource_type\":\"project\","
        "\"parent_id\":\"" ROOT_ID "\"}],\"total\":2}");
    axiam_mgmt_plan_t *plan = NULL;
    rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) plan->pending, "apply(m) then plan(m) must be empty");
    axiam_mgmt_plan_free(plan);

    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_resource_with_no_resource_type_is_refused_zero_wire_calls);
    RUN_TEST(test_resource_with_a_stated_type_is_accepted);
    RUN_TEST(test_nested_manifest_sends_the_stated_type_at_every_level_and_is_idempotent);
    return UNITY_END();
}
