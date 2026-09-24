/*
 * CONTRACT.md §27.6.1 (contract 1.51) — the manifest additions: resources[].metadata,
 * the two-shape role binding (plain vs `{role, resource, inherit}`), and
 * service_accounts. Also §13 row 17's two pre-existing manifest defects belong to a
 * LATER, separate commit each (parent_id, and the "folder" resource_type default);
 * this file is only the additions the coordinator's clarification called out: group →
 * role bindings did not exist in this SDK's manifest at all before this commit, and
 * are built here as their substrate.
 *
 * The shared rig (management_test_util.c) sits at the BOTTOM of the real client,
 * exactly like every other §27 test: a mock that intercepted plan()/apply() itself
 * would prove nothing about §27.8 (the generated surface must not open its own
 * connection) or about the request bodies this file asserts on.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_manifest.h"
#include "test_util.h"
#include "management_test_util.h"

#define ROLE_ID   "11111111-1111-4111-8111-111111111111"
#define RES_ID    "22222222-2222-4222-8222-222222222222"
#define OLD_RES_ID "33333333-3333-4333-8333-333333333333"
#define GROUP_ID  "44444444-4444-4444-8444-444444444444"
#define SA_ID_A   "55555555-5555-4555-8555-555555555555"
#define SA_ID_B   "66666666-6666-4666-8666-666666666666"
#define SA_ID_1   "77777777-7777-4777-8777-777777777777"
#define SA_ID_2   "88888888-8888-4888-8888-888888888888"

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

static axiam_mgmt_manifest_entity_t resource_entity(const char *key, const char *name,
                                                     const char *metadata_json) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_RESOURCE;
    e.key = key;
    e.name = name;
    e.resource_type = "project";
    e.metadata_json = metadata_json;
    return e;
}

static axiam_mgmt_manifest_entity_t role_entity(const char *key, const char *name, int is_global) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_ROLE;
    e.key = key;
    e.name = name;
    e.is_global = is_global;
    return e;
}

static axiam_mgmt_manifest_entity_t group_entity(const char *key, const char *name,
                                                 const axiam_mgmt_role_binding_t *roles,
                                                 size_t roles_count) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_GROUP;
    e.key = key;
    e.name = name;
    e.roles = roles;
    e.roles_count = roles_count;
    return e;
}

static axiam_mgmt_manifest_entity_t sa_entity(const char *key, const char *name) {
    axiam_mgmt_manifest_entity_t e;
    memset(&e, 0, sizeof e);
    e.kind = AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT;
    e.key = key;
    e.name = name;
    return e;
}

static axiam_mgmt_manifest_entity_t sa_entity_with_roles(const char *key, const char *name,
                                                         const axiam_mgmt_role_binding_t *roles,
                                                         size_t roles_count) {
    axiam_mgmt_manifest_entity_t e = sa_entity(key, name);
    e.roles = roles;
    e.roles_count = roles_count;
    return e;
}

/* ------------------------------------------------------------------------
 * 1. resources[].metadata
 * ---------------------------------------------------------------------- */

static void test_metadata_round_trips_apply_then_plan_is_nochange(void) {
    axiam_mgmt_manifest_entity_t e = resource_entity("r1", "proj", "{\"env\":\"prod\"}");
    axiam_mgmt_manifest_t m = { &e, 1 };

    /* apply(): not found -> Create, carrying the declared metadata. */
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    mgmt_mount_next(200,
        "{\"id\":\"" RES_ID "\",\"name\":\"proj\",\"resource_type\":\"project\","
        "\"metadata\":{\"env\":\"prod\"},\"tenant_id\":\"" RES_ID "\","
        "\"created_at\":\"2026-08-26T00:00:00Z\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"env\":\"prod\""),
                             "Create must carry the declared metadata");
    axiam_mgmt_apply_report_dispose(&report);

    /* plan() again: the server now has the SAME metadata -> all NoChange. */
    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\","
                    "\"resource_type\":\"project\",\"metadata\":{\"env\":\"prod\"}}],"
                    "\"total\":1}");
    axiam_mgmt_plan_t *plan = NULL;
    rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) plan->pending,
                                  "identical metadata (JSON value equality) is NoChange");
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->changes[0].action);
    axiam_mgmt_plan_free(plan);

    axiam_client_free(c);
}

static void test_metadata_change_is_update_carrying_the_whole_object(void) {
    axiam_mgmt_manifest_entity_t e = resource_entity("r1", "proj", "{\"env\":\"staging\",\"team\":\"x\"}");
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\","
                    "\"resource_type\":\"project\",\"metadata\":{\"env\":\"prod\"}}],"
                    "\"total\":1}");
    mgmt_mount_next(200, "{\"id\":\"" RES_ID "\",\"name\":\"proj\",\"resource_type\":\"project\","
                    "\"metadata\":{\"env\":\"staging\",\"team\":\"x\"}}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    /* The WHOLE object, not a merge -- both keys present even though only one changed. */
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), "\"env\":\"staging\""));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), "\"team\":\"x\""));
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_metadata_omitted_in_manifest_is_never_drift(void) {
    axiam_mgmt_manifest_entity_t e = resource_entity("r1", "proj", NULL);
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\","
                    "\"resource_type\":\"project\",\"metadata\":{\"anything\":true}}],"
                    "\"total\":1}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_MGMT_CHANGE_UNCHANGED, plan->changes[0].action,
                                  "a manifest silent about metadata must never assert emptiness");
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 2. The resource-scoped role binding: wire shape.
 * ---------------------------------------------------------------------- */

static void test_scoped_binding_sends_resource_id_and_inherit_false(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 1 };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}"); /* resources */
    mgmt_mount_next(200, "{\"items\":[],\"total\":0}"); /* roles */
    mgmt_mount_next(200, "{\"items\":[],\"total\":0}"); /* groups */
    mgmt_mount_next(200, "{\"id\":\"" RES_ID "\",\"name\":\"proj\"}"); /* create res1 */
    mgmt_mount_next(200, "{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}"); /* create role1 */
    mgmt_mount_next(200, "{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}"); /* create g1 */
    mgmt_mount_next(204, NULL); /* assign_to_group */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_path(), "/roles/" ROLE_ID "/groups") != NULL,
                             mgmt_last_path());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"resource_id\":\"" RES_ID "\""),
                             mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"inherit\":false"), mgmt_last_body());
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_plain_binding_sends_no_inherit_key(void) {
    axiam_mgmt_role_binding_t rb = { "role1", NULL, 0 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}"); /* roles */
    mgmt_mount_next(200, "{\"items\":[],\"total\":0}"); /* groups */
    mgmt_mount_next(200, "{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}");
    mgmt_mount_next(200, "{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}");
    mgmt_mount_next(204, NULL);

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "inherit"),
                             "an inheritable binding's body must stay byte-for-byte a "
                             "pre-1.51 body -- no inherit key at all");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 3. Rebind: unassign then assign, tenant_scope carried, restore on failure.
 * ---------------------------------------------------------------------- */

static void test_rebind_unassigns_then_assigns_carrying_tenant_scope(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 0 }; /* declared: scoped to res1, inherit true */
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\","
                    "\"resource_type\":\"project\"}],\"total\":1}"); /* resources */
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}"); /* roles */
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],"
                    "\"total\":1}"); /* groups */
    /* existing binding: scoped to a DIFFERENT resource -> resource mismatch -> Update */
    mgmt_mount_next(200, "[{\"inherit\":true,\"resource_id\":\"" OLD_RES_ID "\","
                    "\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false},"
                    "\"tenant_scope\":[\"" OLD_RES_ID "\"]}]");
    mgmt_mount_next(204, NULL); /* unassign */
    mgmt_mount_next(204, NULL); /* assign (new) */

    axiam_client_t *c = mgmt_signed_in_client();
    int before_apply = mgmt_request_count();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    /* Exactly two requests for the binding phase: unassign, then assign -- the plan/read
     * phase above already consumed 4 (resources, roles, groups, list_roles). */
    TEST_ASSERT_EQUAL_INT_MESSAGE(before_apply + 6, mgmt_request_count(),
                                  "unassign THEN assign -- two requests, not a PATCH");
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"resource_id\":\"" RES_ID "\""),
                             mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"tenant_scope\":[\"" OLD_RES_ID "\"]"),
                             mgmt_last_body());
    TEST_ASSERT_EQUAL_INT(0, report.restore_attempted);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_rebind_restores_the_previous_binding_when_assign_fails(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 0 };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\"}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],\"total\":1}");
    mgmt_mount_next(200, "[{\"inherit\":true,\"resource_id\":\"" OLD_RES_ID "\","
                    "\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}}]");
    mgmt_mount_next(204, NULL);            /* unassign: succeeds */
    mgmt_mount_next(500, "{}");            /* assign (new): FAILS */
    mgmt_mount_next(204, NULL);            /* restore (reassign the OLD binding): succeeds */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, report.restore_attempted, "a restore must be attempted");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, report.restore_succeeded, "the restore itself succeeded");
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"resource_id\":\"" OLD_RES_ID "\""),
                             "the restore call must name the OLD resource, not the new one");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 4. Client-side refusals, zero wire calls, with the I4 twin each.
 * ---------------------------------------------------------------------- */

static void test_one_role_bound_twice_refused_zero_wire_calls(void) {
    axiam_mgmt_role_binding_t rb[2] = {
        { "role1", NULL, 0 },
        { "role1", "res1", 1 },
    };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", rb, 2),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* I4 twin: the SAME role bound to TWO DIFFERENT subjects is fine. */
static void test_one_role_bound_to_two_different_subjects_is_allowed(void) {
    axiam_mgmt_role_binding_t rb1[1] = { { "role1", NULL, 0 } };
    axiam_mgmt_role_binding_t rb2[1] = { { "role1", NULL, 0 } };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", rb1, 1),
        group_entity("g2", "sales", rb2, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_manifest_validate(&m, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    (void) plan;
    axiam_client_free(c);
}

/* A binding naming a role_key this manifest does not declare as a ROLE is refused
 * before any request -- the same dangling-reference discipline as parent_id/
 * depends_on, just on the role side of a binding. */
static void test_binding_an_undeclared_role_refused_zero_wire_calls(void) {
    axiam_mgmt_role_binding_t rb = { "no_such_role", NULL, 0 };
    axiam_mgmt_manifest_entity_t entities[1] = {
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 1 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* Same, on the resource side: a binding's resource_key must name a RESOURCE this
 * manifest declares. */
static void test_binding_an_undeclared_resource_refused_zero_wire_calls(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "no_such_resource", 0 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* inherit:false with NO resource at all -- distinct from the global-role case
 * below, which always declares a resource_key; this is "there is no resource to
 * stop inheriting at in the first place". */
static void test_inherit_false_without_a_resource_refused_zero_wire_calls(void) {
    axiam_mgmt_role_binding_t rb = { "role1", NULL, 1 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

static void test_global_role_with_inherit_false_refused_zero_wire_calls(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 1 };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "everyone", 1 /* is_global */),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* I4 twin: a NON-global role with inherit:false is fine. */
static void test_non_global_role_with_inherit_false_is_allowed(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 1 };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_manifest_validate(&m, &err));
}

/* ------------------------------------------------------------------------
 * 5. A plain binding over a resource-scoped server assignment is an Update
 *    (plan-only; C-1's EXECUTED item 5).
 * ---------------------------------------------------------------------- */

static void test_plain_binding_over_scoped_server_assignment_is_update(void) {
    axiam_mgmt_role_binding_t rb = { "role1", NULL, 0 }; /* declared: plain */
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],\"total\":1}");
    /* existing: SCOPED to some resource. */
    mgmt_mount_next(200, "[{\"inherit\":true,\"resource_id\":\"" OLD_RES_ID "\","
                    "\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}}]");

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, (int) plan->binding_count);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_MGMT_BINDING_UPDATE, plan->bindings[0].action,
                                  "a plain binding over a scoped server assignment is an Update");
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* A declared scoped binding that already matches the server's -- same resource,
 * same inherit -- is a NoChange, not an Update: the other branch of the resource-
 * matches comparison from the test above (that one compares a PLAIN declared
 * binding against a SCOPED existing one; this one compares two SCOPED bindings
 * that agree). */
static void test_scoped_binding_matching_existing_is_nochange(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 0 }; /* inherit true, scoped to res1 */
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\"}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],\"total\":1}");
    /* existing: SAME resource, SAME (true) inherit. */
    mgmt_mount_next(200, "[{\"inherit\":true,\"resource_id\":\"" RES_ID "\","
                    "\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}}]");

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, (int) plan->binding_count);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_MGMT_BINDING_NOCHANGE, plan->bindings[0].action,
                                  "a scoped binding matching the server's is a NoChange");
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* Listing an existing subject's bindings can itself fail (the server, a network
 * blip); plan() must surface that error cleanly rather than crash or silently
 * treat "list failed" as "no bindings exist". */
static void test_plan_fails_cleanly_when_listing_a_subjects_bindings_fails(void) {
    axiam_mgmt_role_binding_t rb = { "role1", NULL, 0 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],\"total\":1}");
    /* 403, not 500: a GET is §16-retryable up to 3 attempts on a 5xx, and this rig's
     * fake transport answers an exhausted queue with 204 -- a single queued 500 would
     * be retried straight into an accidental "success" on attempt 2. A 4xx is decisive
     * (never retried) and so is the one status that proves this in a single request. */
    mgmt_mount_next(403, "{}"); /* listing g1's role bindings FAILS */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    int before = mgmt_request_count();
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_NULL(plan);
    /* roles-list, groups-list, then the failing bindings-list -- three requests
     * after login, not four: a decisive 4xx must not be retried. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 3, mgmt_request_count(),
                                  "a decisive 4xx must not be retried");
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 6. service_accounts: reconciled by name; ambiguous name fails plan.
 * ---------------------------------------------------------------------- */

static void test_ambiguous_service_account_name_fails_plan_before_any_write(void) {
    axiam_mgmt_manifest_entity_t e = sa_entity("svc", "shared-name");
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" SA_ID_A "\",\"name\":\"shared-name\","
                    "\"client_id\":\"c1\"},{\"id\":\"" SA_ID_B "\",\"name\":\"shared-name\","
                    "\"client_id\":\"c2\"}],\"total\":2}");

    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    (void) before;
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 7. The one-time client_secret survives a later action's failure; nothing rotates.
 * ---------------------------------------------------------------------- */

static void test_created_secret_kept_in_report_after_a_later_action_fails(void) {
    axiam_mgmt_manifest_entity_t entities[2] = {
        sa_entity("sa_a", "svc-a"),
        sa_entity("sa_b", "svc-b"),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[],\"total\":0}"); /* service_accounts.list */
    mgmt_mount_next(200, "{\"id\":\"" SA_ID_1 "\",\"name\":\"svc-a\","
                    "\"client_secret\":\"one-time-secret-a\"}"); /* create sa_a: OK */
    mgmt_mount_next(500, "{}"); /* create sa_b: FAILS */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, (int) report.created_secrets_count,
                                  "sa_a's secret must be recorded even though sa_b failed");
    TEST_ASSERT_EQUAL_STRING("sa_a", report.created_secrets[0].key);
    TEST_ASSERT_EQUAL_STRING("one-time-secret-a",
                             axiam_sensitive_reveal(report.created_secrets[0].client_secret));
    /* Never rotated: exactly login + list + 2 creates, no rotate-secret call. */
    TEST_ASSERT_EQUAL_INT(4, mgmt_request_count());
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* A drifted description on an EXISTING service account is an Update -- the
 * axiam_service_accounts_update() branch of perform(), never a create and never
 * touching client_secret at all. */
static void test_service_account_description_drift_is_updated(void) {
    axiam_mgmt_manifest_entity_t e = sa_entity("sa_a", "svc-a");
    e.description = "the new description";
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" SA_ID_1 "\",\"name\":\"svc-a\","
                    "\"description\":\"the old description\"}],\"total\":1}");
    mgmt_mount_next(200, "{\"id\":\"" SA_ID_1 "\",\"name\":\"svc-a\","
                    "\"description\":\"the new description\"}"); /* update response */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(1, report.applied);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) report.created_secrets_count,
                                  "an update must never mint or touch a client_secret");
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "the new description"), mgmt_last_body());
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_second_apply_of_created_service_account_is_nochange_no_rotate(void) {
    axiam_mgmt_manifest_entity_t e = sa_entity("sa_a", "svc-a");
    axiam_mgmt_manifest_t m = { &e, 1 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" SA_ID_1 "\",\"name\":\"svc-a\"}],\"total\":1}");
    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->changes[0].action);
    TEST_ASSERT_EQUAL_INT(before + 1, mgmt_request_count()); /* one list call only */
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 7. A role binding whose SUBJECT is a service_accounts entity, not a group --
 *    §27.6.1's binding shape covers both subject kinds, and phase 4 of
 *    axiam_mgmt_apply() (service-account bindings, after service-account
 *    entities themselves exist) is what runs it.
 * ---------------------------------------------------------------------- */

static void test_service_account_subject_binding_created_on_apply(void) {
    axiam_mgmt_role_binding_t rb = { "role1", NULL, 0 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("role1", "editor", 0),
        sa_entity_with_roles("sa1", "svc1", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}"); /* roles: role1 exists */
    mgmt_mount_next(200, "{\"items\":[],\"total\":0}");    /* service_accounts: none yet */
    mgmt_mount_next(200, "{\"id\":\"" SA_ID_1 "\",\"name\":\"svc1\"}"); /* create sa1 */
    mgmt_mount_next(204, NULL);                             /* assign role1 to sa1 */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, report.bindings_applied,
                                  "the service-account's binding must have been applied");
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"service_account_id\":\"" SA_ID_1 "\""),
                             mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_url(), ROLE_ID),
                             "role_id is a path parameter, not a body field");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* An existing service account's binding rebinds the same way a group's does:
 * unassign the old, assign the new, restore on failure -- this is the
 * is_group==false half of perform_binding(), exercised nowhere else in this
 * file (every rebind test above uses a group subject). */
static void test_service_account_subject_rebind_restores_on_failure(void) {
    axiam_mgmt_role_binding_t rb = { "role1", "res1", 0 }; /* declared: scoped to res1 */
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        resource_entity("res1", "proj", NULL),
        sa_entity_with_roles("sa1", "svc1", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" RES_ID "\",\"name\":\"proj\"}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" SA_ID_1 "\",\"name\":\"svc1\"}],\"total\":1}");
    /* existing binding: scoped to a DIFFERENT resource -> mismatch -> Update */
    mgmt_mount_next(200, "[{\"inherit\":true,\"resource_id\":\"" OLD_RES_ID "\","
                    "\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"editor\",\"is_global\":false}}]");
    mgmt_mount_next(204, NULL);            /* unassign: succeeds */
    mgmt_mount_next(500, "{}");            /* assign (new): FAILS */
    mgmt_mount_next(204, NULL);            /* restore (reassign the OLD binding): succeeds */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, report.restore_attempted, "a restore must be attempted");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, report.restore_succeeded, "the restore itself succeeded");
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), "\"resource_id\":\"" OLD_RES_ID "\""),
                             "the restore call must name the OLD resource, not the new one");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* When a binding fails partway through, the report counts how many PENDING
 * bindings are still left after it -- distinct from every restore-on-failure test
 * above, which all use a single binding (so "remaining" is always zero there). */
static void test_binding_failure_reports_the_remaining_pending_count(void) {
    axiam_mgmt_role_binding_t rb1[1] = { { "role1", NULL, 0 } };
    axiam_mgmt_role_binding_t rb2[1] = { { "role1", NULL, 0 } };
    axiam_mgmt_manifest_entity_t entities[3] = {
        role_entity("role1", "editor", 0),
        group_entity("g1", "eng", rb1, 1),
        group_entity("g2", "sales", rb2, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 3 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"editor\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"},"
                    "{\"id\":\"" SA_ID_2 "\",\"name\":\"sales\"}],\"total\":2}");
    mgmt_mount_next(200, "[]"); /* g1's existing bindings: none */
    mgmt_mount_next(200, "[]"); /* g2's existing bindings: none */
    mgmt_mount_next(500, "{}"); /* assign role1 to g1 (bound first): FAILS -- a POST, so
                                 * decisive on one attempt, never retried into a false pass */

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(0, report.bindings_applied);
    TEST_ASSERT_EQUAL_INT(0L, report.failed_binding);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, (int) report.bindings_remaining,
                                  "g2's still-pending binding must be counted as remaining");
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 8. Additive reconciliation: an existing binding the manifest does not name is
 *    left alone -- never unassigned, never even inspected as a candidate change.
 * ---------------------------------------------------------------------- */

static void test_existing_binding_not_named_by_the_manifest_is_untouched(void) {
    axiam_mgmt_role_binding_t rb = { "viewer", NULL, 0 };
    axiam_mgmt_manifest_entity_t entities[2] = {
        role_entity("viewer", "viewer", 0),
        group_entity("g1", "eng", &rb, 1),
    };
    axiam_mgmt_manifest_t m = { entities, 2 };

    mgmt_mount(200, "{\"items\":[{\"id\":\"" ROLE_ID "\",\"name\":\"viewer\","
                    "\"is_global\":false}],\"total\":1}");
    mgmt_mount_next(200, "{\"items\":[{\"id\":\"" GROUP_ID "\",\"name\":\"eng\"}],\"total\":1}");
    /* TWO existing bindings: "editor" (not in the manifest) and "viewer" (matches). */
    mgmt_mount_next(200,
        "[{\"inherit\":true,\"role\":{\"id\":\"" OLD_RES_ID "\",\"name\":\"editor\","
        "\"is_global\":false}},"
        "{\"inherit\":true,\"role\":{\"id\":\"" ROLE_ID "\",\"name\":\"viewer\","
        "\"is_global\":false}}]");

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, &m, &plan, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, (int) plan->binding_count,
                                  "only the NAMED binding is planned -- \"editor\" is not "
                                  "a candidate for anything, per §27.6 rule 4 (omission is "
                                  "never deletion)");
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_BINDING_NOCHANGE, plan->bindings[0].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_metadata_round_trips_apply_then_plan_is_nochange);
    RUN_TEST(test_metadata_change_is_update_carrying_the_whole_object);
    RUN_TEST(test_metadata_omitted_in_manifest_is_never_drift);
    RUN_TEST(test_scoped_binding_sends_resource_id_and_inherit_false);
    RUN_TEST(test_plain_binding_sends_no_inherit_key);
    RUN_TEST(test_rebind_unassigns_then_assigns_carrying_tenant_scope);
    RUN_TEST(test_rebind_restores_the_previous_binding_when_assign_fails);
    RUN_TEST(test_binding_an_undeclared_role_refused_zero_wire_calls);
    RUN_TEST(test_binding_an_undeclared_resource_refused_zero_wire_calls);
    RUN_TEST(test_inherit_false_without_a_resource_refused_zero_wire_calls);
    RUN_TEST(test_one_role_bound_twice_refused_zero_wire_calls);
    RUN_TEST(test_one_role_bound_to_two_different_subjects_is_allowed);
    RUN_TEST(test_global_role_with_inherit_false_refused_zero_wire_calls);
    RUN_TEST(test_non_global_role_with_inherit_false_is_allowed);
    RUN_TEST(test_plain_binding_over_scoped_server_assignment_is_update);
    RUN_TEST(test_scoped_binding_matching_existing_is_nochange);
    RUN_TEST(test_plan_fails_cleanly_when_listing_a_subjects_bindings_fails);
    RUN_TEST(test_ambiguous_service_account_name_fails_plan_before_any_write);
    RUN_TEST(test_created_secret_kept_in_report_after_a_later_action_fails);
    RUN_TEST(test_service_account_description_drift_is_updated);
    RUN_TEST(test_second_apply_of_created_service_account_is_nochange_no_rotate);
    RUN_TEST(test_service_account_subject_binding_created_on_apply);
    RUN_TEST(test_service_account_subject_rebind_restores_on_failure);
    RUN_TEST(test_binding_failure_reports_the_remaining_pending_count);
    RUN_TEST(test_existing_binding_not_named_by_the_manifest_is_untouched);
    return UNITY_END();
}
