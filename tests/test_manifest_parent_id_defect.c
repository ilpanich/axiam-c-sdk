/*
 * §13 row 17, defect #1 (the dogfooding remediation plan): this SDK's manifest never
 * sent a resource's `parent_id` on Create, although the request model has the field --
 * a nested manifest was silently created flat, and since the parent was not compared
 * either, the idempotence test (§27.6 rule 6) passed over the WRONG tree.
 *
 * Fixed: perform() resolves a resource entity's `depends_on` (already the manifest's
 * parent-key convention -- order_entities()'s depth_of() already walks it) through
 * resolved_id_for_key() and sends it as `parent_id` on Create.
 *
 * The idempotence test over a NESTED manifest the task asks for: the child's Create
 * body carries the CREATED PARENT's parent_id (resolved from THIS SAME apply, not a
 * pre-existing id), and apply(m) followed by plan(m) is empty.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_manifest.h"
#include "test_util.h"
#include "management_test_util.h"

#define ROOT_ID "33333333-3333-4333-8333-333333333333"
#define CHILD_ID "44444444-4444-4444-8444-444444444444"

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

static void test_a_root_resource_sends_no_parent_id(void) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    e.key = "root";
    e.name = "root-res";
    e.resource_type = "folder";
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    mgmt_mount_next(200, "{\"id\":\"" ROOT_ID "\",\"name\":\"root-res\","
                    "\"resource_type\":\"folder\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "parent_id"),
                             "a root resource (no depends_on) must send no parent_id key");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/*
 * The idempotence test over a NESTED manifest: the child's Create body carries the
 * CREATED PARENT's parent_id (resolved from THIS SAME apply -- the parent has no id
 * until its own Create just landed), and apply(m) then plan(m) is empty.
 */
static void test_nested_manifest_sends_the_created_parents_id_and_is_idempotent(void) {
    axiam_mgmt_manifest_entity_t entities[2];
    memset(entities, 0, sizeof entities);
    entities[0].kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    entities[0].key = "root";
    entities[0].name = "root-res";
    entities[0].resource_type = "folder";
    entities[1].kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    entities[1].key = "child";
    entities[1].name = "child-res";
    entities[1].resource_type = "folder";
    entities[1].depends_on = "root";
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}"); /* neither resource exists yet */
    mgmt_mount_next(200, "{\"id\":\"" ROOT_ID "\",\"name\":\"root-res\","
                    "\"resource_type\":\"folder\"}"); /* create root */
    mgmt_mount_next(200, "{\"id\":\"" CHILD_ID "\",\"name\":\"child-res\","
                    "\"resource_type\":\"folder\",\"parent_id\":\"" ROOT_ID "\"}"); /* create child */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(2, (int) report.applied);
    /* The LAST request is the child's Create -- its body must carry the CREATED
     * PARENT's id, resolved from earlier in this same apply, not a placeholder. */
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"parent_id\":\"" ROOT_ID "\""),
                             mgmt_last_body());
    axiam_mgmt_apply_report_dispose(&report);

    /* apply(m) followed by plan(m): all NoChange. Before the fix this passed over the
     * WRONG tree (a flat one, since the parent was never compared either); it is
     * meaningful now because the wire body above proves the parent WAS sent. */
    mgmt_mount(200,
        "{\"items\":[{\"id\":\"" ROOT_ID "\",\"name\":\"root-res\","
        "\"resource_type\":\"folder\"},"
        "{\"id\":\"" CHILD_ID "\",\"name\":\"child-res\",\"resource_type\":\"folder\","
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
    RUN_TEST(test_a_root_resource_sends_no_parent_id);
    RUN_TEST(test_nested_manifest_sends_the_created_parents_id_and_is_idempotent);
    return UNITY_END();
}
