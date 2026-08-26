/*
 * The CONTRACT.md §27.9 required-test list, hand-written.
 *
 * The generated suite next door asserts that all 146 operations reach the right route.
 * These assert the RULES -- the behaviours §27.4 specifies that hold across the whole
 * surface and that no per-operation test would catch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_ops.h"
#include "test_util.h"
#include "management_test_util.h"

#define UUID "11111111-1111-4111-8111-111111111111"
#define OTHER_ORG "22222222-2222-4222-8222-222222222222"

static const char *ROLE_JSON =
    "{\"created_at\":\"2026-08-26T00:00:00Z\",\"description\":\"d\",\"id\":\"" UUID "\","
    "\"is_global\":false,\"name\":\"auditor\",\"tenant_id\":\"" UUID "\","
    "\"updated_at\":\"2026-08-26T00:00:00Z\"}";

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- rule 1: no session, no wire call ---------------------------------- */

static void test_without_a_session_nothing_is_sent(void) {
    mgmt_mount(200, ROLE_JSON);
    axiam_client_t *c = mgmt_anonymous_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_error_kind_t rc = axiam_roles_get(c, UUID, &out, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, rc);
    TEST_ASSERT_NULL(out);
    TEST_ASSERT_EQUAL_INT(0, mgmt_request_count());
    TEST_ASSERT_NOT_NULL(strstr(err.message, "roles.get"));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "rule 1"));
    axiam_client_free(c);
}

/* ---- rule 3: implicit ids, with a per-call override --------------------- */

static void test_org_id_is_implicit_from_the_client(void) {
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ca_certificate_page_t *page = NULL;

    axiam_ca_certificates_list(c, NULL, NULL, &page, &err);

    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_path(), UUID));
    axiam_mgmt_ca_certificate_page_free(page);
    axiam_client_free(c);
}

static void test_a_scope_overrides_the_implicit_org_id(void) {
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_call_scope_t scope = { OTHER_ORG, NULL };
    axiam_mgmt_ca_certificate_page_t *page = NULL;

    axiam_ca_certificates_list(c, &scope, NULL, &page, &err);

    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_path(), OTHER_ORG));
    axiam_mgmt_ca_certificate_page_free(page);
    axiam_client_free(c);
}

/*
 * The flat-symbol form gets rule 3's "no shared object to re-scope" for free.
 * A handle-based SDK has to promise that ->in_org() COPIES; here the override is an
 * argument, so one call's scope cannot reach the next by construction.
 */
static void test_a_scope_does_not_leak_into_the_next_call(void) {
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    mgmt_mount_next(200, "{\"items\":[],\"total\":0}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_call_scope_t scope = { OTHER_ORG, NULL };
    axiam_mgmt_ca_certificate_page_t *page = NULL;

    axiam_ca_certificates_list(c, &scope, NULL, &page, &err);
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_path(), OTHER_ORG));
    axiam_mgmt_ca_certificate_page_free(page);

    page = NULL;
    axiam_ca_certificates_list(c, NULL, NULL, &page, &err);
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_path(), UUID));
    axiam_mgmt_ca_certificate_page_free(page);
    axiam_client_free(c);
}

/* ---- rule 4: paging ------------------------------------------------------ */

static void test_page_total_is_not_the_item_count(void) {
    char body[1024];
    snprintf(body, sizeof body, "{\"items\":[%s,%s],\"total\":97}", ROLE_JSON, ROLE_JSON);
    mgmt_mount(200, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_page_t *page = NULL;

    axiam_roles_list(c, NULL, &page, &err);

    TEST_ASSERT_NOT_NULL(page);
    TEST_ASSERT_EQUAL_INT(97, (int) page->total);
    TEST_ASSERT_EQUAL_INT(2, (int) page->count);
    axiam_mgmt_role_page_free(page);
    axiam_client_free(c);
}

static void test_page_next_advances_by_the_limit(void) {
    axiam_mgmt_page_req_t first = { 0, 25 };
    axiam_mgmt_page_req_t second = axiam_mgmt_page_next(first);
    axiam_mgmt_page_req_t third = axiam_mgmt_page_next(second);

    TEST_ASSERT_EQUAL_INT(25, (int) second.offset);
    TEST_ASSERT_EQUAL_INT(25, (int) second.limit);
    TEST_ASSERT_EQUAL_INT(50, (int) third.offset);
}

static void test_page_next_clamps_nonsense(void) {
    axiam_mgmt_page_req_t weird = { -10, 0 };
    axiam_mgmt_page_req_t next = axiam_mgmt_page_next(weird);

    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_DEFAULT_LIMIT, (int) next.limit);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_DEFAULT_LIMIT, (int) next.offset);
}

static void test_paging_reaches_the_query_string(void) {
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_page_req_t page_req = { 100, 25 };
    axiam_mgmt_role_page_t *page = NULL;

    axiam_roles_list(c, &page_req, &page, &err);

    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_url(), "offset=100"));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_url(), "limit=25"));
    axiam_mgmt_role_page_free(page);
    axiam_client_free(c);
}

/* A bare-array endpoint returns a LIST, never a page (§27.4 rule 4). The type system
 * carries the distinction here: there is no `total` to misread. */
static void test_a_bare_array_is_a_list_not_a_page(void) {
    char body[1024];
    snprintf(body, sizeof body, "[%s]", ROLE_JSON);
    mgmt_mount(200, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_user_assignment_list_t *list = NULL;

    axiam_error_kind_t rc = axiam_roles_list_users(c, UUID, &list, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_NOT_NULL(list);
    TEST_ASSERT_EQUAL_INT(1, (int) list->count);
    axiam_mgmt_role_user_assignment_list_free(list);
    axiam_client_free(c);
}

/* ---- rule 5: sparse bodies ---------------------------------------------- */

static void test_a_sparse_update_sends_only_what_you_set(void) {
    mgmt_mount(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_update_role_t body;
    memset(&body, 0, sizeof body);
    body.name = (char *) "renamed";
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_update(c, UUID, &body, &out, &err);

    TEST_ASSERT_EQUAL_STRING("{\"name\":\"renamed\"}", mgmt_last_body());
    axiam_mgmt_role_free(out);
    axiam_client_free(c);
}

/*
 * An optional scalar left alone is OMITTED, and setting it to 0 is NOT the same thing.
 * This is why optional scalars carry a `has_` flag instead of a sentinel: `is_global`
 * false is a value a caller means, and no sentinel could represent both it and "unset".
 */
static void test_an_optional_false_is_sent_not_swallowed(void) {
    mgmt_mount(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_update_role_t body;
    memset(&body, 0, sizeof body);
    body.is_global = 0;
    body.has_is_global = 1;
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_update(c, UUID, &body, &out, &err);

    TEST_ASSERT_EQUAL_STRING("{\"is_global\":false}", mgmt_last_body());
    axiam_mgmt_role_free(out);
    axiam_client_free(c);
}

static void test_an_empty_sparse_body_sends_nothing(void) {
    mgmt_mount(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_update_role_t body;
    memset(&body, 0, sizeof body);
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_update(c, UUID, &body, &out, &err);

    TEST_ASSERT_EQUAL_STRING("{}", mgmt_last_body());
    axiam_mgmt_role_free(out);
    axiam_client_free(c);
}

/* ---- rule 6 + rule 7: deletes and the classification table -------------- */

static void test_a_second_delete_is_not_found(void) {
    mgmt_mount(204, NULL);
    mgmt_mount_next(404, NULL);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_roles_delete(c, UUID, &err));

    axiam_error_kind_t rc = axiam_roles_delete(c, UUID, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    axiam_client_free(c);
}

/*
 * Rule 7's parent column, which is the counter-intuitive half and the one a port gets
 * wrong. 404 and 409 are AUTHZ -- a multi-tenant server answers 404 for another tenant's
 * object precisely so a caller cannot enumerate it -- while 400/422 are NETWORK.
 */
static void test_every_classification_keeps_its_rule7_parent(void) {
    struct { long status; axiam_error_kind_t kind; axiam_mgmt_error_class_t cls; } cases[] = {
        { 404, AXIAM_ERR_AUTHZ,   AXIAM_MGMT_ERR_NOT_FOUND },
        { 409, AXIAM_ERR_AUTHZ,   AXIAM_MGMT_ERR_CONFLICT },
        { 400, AXIAM_ERR_NETWORK, AXIAM_MGMT_ERR_VALIDATION },
        { 422, AXIAM_ERR_NETWORK, AXIAM_MGMT_ERR_VALIDATION },
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        mgmt_reset();
        mgmt_mount(cases[i].status, NULL);
        axiam_client_t *c = mgmt_signed_in_client();
        axiam_error_t err;
        axiam_mgmt_role_t *out = NULL;

        axiam_error_kind_t rc = axiam_roles_get(c, UUID, &out, &err);

        TEST_ASSERT_EQUAL_INT(cases[i].kind, rc);
        TEST_ASSERT_EQUAL_INT(cases[i].cls, axiam_mgmt_error_class(&err));
        TEST_ASSERT_NULL(out);
        axiam_client_free(c);
    }
}

/* A status rule 7 does not name keeps the §2 mapping and reports no class. */
static void test_an_unrelated_status_has_no_management_class(void) {
    mgmt_mount(403, NULL);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_error_kind_t rc = axiam_roles_get(c, UUID, &out, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NONE, axiam_mgmt_error_class(&err));
    axiam_client_free(c);
}

/* The global §2 mapper is deliberately NOT changed: a bare 404 is still NETWORK there,
 * because that is right for every non-management call in the SDK. */
static void test_the_global_status_mapper_is_untouched(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(404));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_error_kind_from_http_status(409));
}

static void test_error_class_of_null_and_success_is_none(void) {
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NONE, axiam_mgmt_error_class(NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NONE, axiam_mgmt_error_class(&err));
}

/* ---- rule 8: only GET is retried ---------------------------------------- */

static void test_a_failed_get_is_retried(void) {
    mgmt_mount(503, NULL);
    mgmt_mount_next(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_error_kind_t rc = axiam_roles_get(c, UUID, &out, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, rc);
    TEST_ASSERT_EQUAL_INT(3, mgmt_request_count());  /* login + two GET attempts */
    axiam_mgmt_role_free(out);
    axiam_client_free(c);
}

static void test_a_failed_write_is_not_retried(void) {
    mgmt_mount(503, NULL);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_update_role_t body;
    memset(&body, 0, sizeof body);
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_update(c, UUID, &body, &out, &err);

    TEST_ASSERT_EQUAL_INT(2, mgmt_request_count());  /* login + exactly one attempt */
    axiam_client_free(c);
}

/* A 4xx is a decisive answer, not a transport failure -- re-sending it just spends the
 * caller's rate limit to be told the same thing again. */
static void test_a_rejected_get_is_not_retried(void) {
    mgmt_mount(422, NULL);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_get(c, UUID, &out, &err);

    TEST_ASSERT_EQUAL_INT(2, mgmt_request_count());
    axiam_client_free(c);
}

/* ---- rule 10: nothing is cached ----------------------------------------- */

static void test_the_same_read_twice_is_two_wire_calls(void) {
    mgmt_mount(200, ROLE_JSON);
    mgmt_mount_next(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *a = NULL, *b = NULL;

    axiam_roles_get(c, UUID, &a, &err);
    axiam_roles_get(c, UUID, &b, &err);

    TEST_ASSERT_EQUAL_INT(3, mgmt_request_count());
    axiam_mgmt_role_free(a);
    axiam_mgmt_role_free(b);
    axiam_client_free(c);
}

/* ---- §27.5: one-time secrets -------------------------------------------- */

/* A Sensitive reaches the wire in the clear -- otherwise the server would receive the
 * literal redaction placeholder as somebody's password. */
static void test_a_secret_reaches_the_wire_unredacted(void) {
    mgmt_mount(200, "{\"id\":\"" UUID "\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_create_user_request_t body;
    memset(&body, 0, sizeof body);
    body.username = (char *) "alice";
    body.email = (char *) "alice@example.com";
    body.password = axiam_sensitive_new("hunter2");
    axiam_mgmt_user_response_t *out = NULL;

    axiam_users_create(c, &body, &out, &err);

    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "hunter2"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "[SENSITIVE]"));
    axiam_sensitive_free(body.password);
    axiam_mgmt_user_response_free(out);
    axiam_client_free(c);
}

/* ...and the same value stringifies redacted everywhere else (§7 rule 3). */
static void test_the_same_secret_is_redacted_in_an_ordinary_rendering(void) {
    axiam_sensitive_t *s = axiam_sensitive_new("hunter2");

    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(s));
    TEST_ASSERT_EQUAL_STRING("hunter2", axiam_sensitive_reveal(s));

    axiam_sensitive_free(s);
}

/* ---- transport edges ----------------------------------------------------- */

static void test_a_non_json_body_is_a_network_error(void) {
    mgmt_mount(200, "not json at all");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_error_kind_t rc = axiam_roles_get(c, UUID, &out, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
    TEST_ASSERT_NULL(out);
    axiam_client_free(c);
}

/* A path parameter is URL-encoded: an identifier is caller-supplied, and a raw '/' in
 * one would silently retarget the request at a different route. */
static void test_a_path_parameter_is_url_encoded(void) {
    mgmt_mount(200, ROLE_JSON);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_role_t *out = NULL;

    axiam_roles_get(c, "a/b", &out, &err);

    TEST_ASSERT_NULL(strstr(mgmt_last_path(), "roles/a/b"));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_path(), "a%2Fb"));
    axiam_mgmt_role_free(out);
    axiam_client_free(c);
}

/* An unknown enum value is reported, never mapped to whichever constant is first. */
static void test_an_unknown_enum_value_is_refused(void) {
    axiam_mgmt_user_status_t status;
    TEST_ASSERT_EQUAL_INT(0, axiam_mgmt_user_status_from_wire("Active", &status));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_USER_STATUS_ACTIVE, status);
    TEST_ASSERT_EQUAL_INT(-1, axiam_mgmt_user_status_from_wire("Ascended", &status));
    TEST_ASSERT_EQUAL_INT(-1, axiam_mgmt_user_status_from_wire(NULL, &status));
    TEST_ASSERT_EQUAL_STRING("Active", axiam_mgmt_user_status_to_wire(AXIAM_MGMT_USER_STATUS_ACTIVE));
}

/* Every free is NULL-safe, so a failed parse's cleanup path is not itself a crash. */
static void test_frees_tolerate_null(void) {
    axiam_mgmt_role_free(NULL);
    axiam_mgmt_role_page_free(NULL);
    axiam_mgmt_role_user_assignment_list_free(NULL);
    TEST_PASS();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_without_a_session_nothing_is_sent);
    RUN_TEST(test_org_id_is_implicit_from_the_client);
    RUN_TEST(test_a_scope_overrides_the_implicit_org_id);
    RUN_TEST(test_a_scope_does_not_leak_into_the_next_call);
    RUN_TEST(test_page_total_is_not_the_item_count);
    RUN_TEST(test_page_next_advances_by_the_limit);
    RUN_TEST(test_page_next_clamps_nonsense);
    RUN_TEST(test_paging_reaches_the_query_string);
    RUN_TEST(test_a_bare_array_is_a_list_not_a_page);
    RUN_TEST(test_a_sparse_update_sends_only_what_you_set);
    RUN_TEST(test_an_optional_false_is_sent_not_swallowed);
    RUN_TEST(test_an_empty_sparse_body_sends_nothing);
    RUN_TEST(test_a_second_delete_is_not_found);
    RUN_TEST(test_every_classification_keeps_its_rule7_parent);
    RUN_TEST(test_an_unrelated_status_has_no_management_class);
    RUN_TEST(test_the_global_status_mapper_is_untouched);
    RUN_TEST(test_error_class_of_null_and_success_is_none);
    RUN_TEST(test_a_failed_get_is_retried);
    RUN_TEST(test_a_failed_write_is_not_retried);
    RUN_TEST(test_a_rejected_get_is_not_retried);
    RUN_TEST(test_the_same_read_twice_is_two_wire_calls);
    RUN_TEST(test_a_secret_reaches_the_wire_unredacted);
    RUN_TEST(test_the_same_secret_is_redacted_in_an_ordinary_rendering);
    RUN_TEST(test_a_non_json_body_is_a_network_error);
    RUN_TEST(test_a_path_parameter_is_url_encoded);
    RUN_TEST(test_an_unknown_enum_value_is_refused);
    RUN_TEST(test_frees_tolerate_null);
    return UNITY_END();
}
