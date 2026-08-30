/*
 * Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the principal
 * tenant, and tenant-scoped role assignments.
 *
 * Two of these rules are the kind an SDK breaks silently rather than loudly, which is
 * why they are pinned here rather than left to the generated conformance suite:
 *
 * - §5.2.2 rule 2. A registration record for the caller's OWN password is sealed
 *   against the tenant the account lives in, not the one the client is pointed at. Get
 *   it wrong and the server answers "the OPAQUE session was issued for a different
 *   tenant" -- but only for an organization-level principal that has switched tenant,
 *   so it passes every test written against an ordinary account.
 * - §5.2.3 rule 1. `tenant_scope: []` is refused with 400. A NULL check alone does not
 *   prevent it: C's optional-array guard is `if (value->field)`, and a pointer to a
 *   list that filtered down to nothing is not NULL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_ops.h"
#include "internal.h"
#include "test_util.h"
#include "management_test_util.h"
#include "opaque_fake.h"

fake_opaque_t g_fake_opaque;

#define ACTING_TENANT   "33333333-3333-4333-8333-333333333333"
#define PRINCIPAL_TENANT "55555555-5555-4555-8555-555555555555"
#define ORG_ID          "11111111-1111-4111-8111-111111111111"
#define REACHABLE_TENANT "66666666-6666-4666-8666-666666666666"
#define SCOPED_TENANT   "88888888-8888-4888-8888-888888888888"
#define SOME_ID         "99999999-9999-4999-8999-999999999999"

#define WIRE_REGISTRATION_RESPONSE "726573703a"

/* Minted per run; nothing here depends on the value -- the login stub answers 200
 * regardless, so what is under test is which tenant the body names, never whether a
 * credential matched -- and a literal that reads like a credential is a finding for
 * every secret scanner that looks at this repository. */
static char g_password[32];

/* The `user` object the login stub answers with, set per case. */
static const char *g_login_user = "{}";
static char g_register_start_body[2048];
static int g_register_start_count;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void)ctx;
    const char *url = req->url ? req->url : "";

    if (strstr(url, "/auth/opaque/register/start")) {
        g_register_start_count++;
        snprintf(g_register_start_body, sizeof(g_register_start_body), "%s",
                 req->body ? req->body : "");
        resp_fill(resp, 200,
                  "{\"opaque_session\":\"reg-handle\",\"registration_response\":\""
                  WIRE_REGISTRATION_RESPONSE "\",\"ksf\":\"argon2id\","
                  "\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1}",
                  NULL);
        return 0;
    }

    if (strstr(url, "/api/v1/auth/login")) {
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"session_id\":\"22222222-2222-4222-8222-222222222222\","
                 "\"expires_in\":900,\"user\":%s}", g_login_user);
        resp_fill(resp, 200, body, "csrf-abc");
        return 0;
    }

    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

/* A client pointed at the acting tenant by UUID. */
static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, ACTING_TENANT);
    axiam_client_config_set_org_id(cfg, ORG_ID);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/*
 * The same, pointed at the acting tenant by SLUG.
 *
 * A slug rather than the UUID on purpose for the two §23 cases: the workspace writes
 * `tenant_slug` for one and `tenant_id` for the other, and §5.2.2 rule 2's override has
 * to REPLACE the slug it finds. Against a UUID tenant there is no slug to displace, so
 * "no tenant_slug in the body" would pass against an implementation that never
 * displaced anything.
 */
static axiam_client_t *make_slug_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_id(cfg, ORG_ID);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {
    g_login_user = "{}";
    g_register_start_body[0] = '\0';
    g_register_start_count = 0;
    fake_opaque_install();
    mgmt_reset();
    unsigned char raw[8];
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)(rand() & 0xff);
    size_t at = (size_t)snprintf(g_password, sizeof(g_password), "fixture-");
    for (size_t i = 0; i < sizeof(raw) && at + 2 < sizeof(g_password); i++, at += 2)
        snprintf(g_password + at, sizeof(g_password) - at, "%02x", raw[i]);
}

void tearDown(void) {
    axiam_opaque_native_reset_for_tests();
}

/* Signs in against `user` and returns the result; the caller disposes it. */
static void sign_in(axiam_client_t *c, const char *user, axiam_login_result_t *out) {
    g_login_user = user;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_login(c, "alice@example.com", g_password, out, &err));
}

/* ------------------------------------------------------------------------
 * §5.2.2 -- acting tenant vs principal tenant
 * ---------------------------------------------------------------------- */

static void test_an_absent_principal_tenant_reads_as_the_acting_tenant(void) {
    /* A server older than contract 1.34 omits `principal_tenant_id` and cannot switch
     * the acting tenant either, so reading `tenant_id` there is not a guess -- it is the
     * only value the field could have had. */
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    sign_in(c, "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\"}", &res);

    TEST_ASSERT_EQUAL_STRING(ACTING_TENANT, res.tenant_id);
    TEST_ASSERT_NOT_NULL(res.principal_tenant_id);
    TEST_ASSERT_EQUAL_STRING(ACTING_TENANT, res.principal_tenant_id);
    TEST_ASSERT_NULL(res.principal_tenant_slug);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_divergent_principal_tenant_is_reported_separately(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    sign_in(c,
            "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\","
            "\"principal_tenant_id\":\"" PRINCIPAL_TENANT "\","
            "\"principal_tenant_slug\":\"organization\","
            "\"org_id\":\"" ORG_ID "\",\"organization_level\":true}",
            &res);

    TEST_ASSERT_EQUAL_INT(1, res.organization_level);
    TEST_ASSERT_EQUAL_STRING(ACTING_TENANT, res.tenant_id);
    TEST_ASSERT_EQUAL_STRING(PRINCIPAL_TENANT, res.principal_tenant_id);
    TEST_ASSERT_EQUAL_STRING("organization", res.principal_tenant_slug);
    /* Rule 3: read the organization from the session rather than resolving a slug
     * through the `super-admin`-only GET /api/v1/organizations. */
    TEST_ASSERT_EQUAL_STRING(ORG_ID, res.org_id);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_reachable_tenant_ids_narrows_an_organization_level_principal(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    sign_in(c,
            "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\","
            "\"organization_level\":true,"
            "\"reachable_tenant_ids\":[\"" REACHABLE_TENANT "\"]}",
            &res);

    /* Still 1 -- which is exactly why gating a tenant switcher on this flag alone
     * offers tenants the server refuses at the header. */
    TEST_ASSERT_EQUAL_INT(1, res.organization_level);
    TEST_ASSERT_EQUAL_size_t(1, res.reachable_tenant_ids_count);
    TEST_ASSERT_EQUAL_STRING(REACHABLE_TENANT, res.reachable_tenant_ids[0]);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_absent_reach_is_unrestricted_not_empty(void) {
    /* NULL means UNRESTRICTED. An empty list would read as "reaches nothing", the
     * opposite of what an omitted field means here -- so a present-but-empty list on
     * the wire arrives as NULL too. */
    axiam_client_t *c = make_client();
    axiam_login_result_t absent;
    sign_in(c, "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\"}", &absent);
    TEST_ASSERT_NULL(absent.reachable_tenant_ids);
    TEST_ASSERT_EQUAL_size_t(0, absent.reachable_tenant_ids_count);
    axiam_login_result_dispose(&absent);

    axiam_login_result_t empty;
    sign_in(c,
            "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\","
            "\"reachable_tenant_ids\":[]}",
            &empty);
    TEST_ASSERT_NULL(empty.reachable_tenant_ids);
    TEST_ASSERT_EQUAL_size_t(0, empty.reachable_tenant_ids_count);
    axiam_login_result_dispose(&empty);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * §5.2.2 rule 2 -- which tenant a registration record is sealed against
 * ---------------------------------------------------------------------- */

static void test_enrolment_for_self_seals_against_the_principal_tenant(void) {
    axiam_client_t *c = make_slug_client();
    axiam_login_result_t res;
    sign_in(c,
            "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\","
            "\"principal_tenant_id\":\"" PRINCIPAL_TENANT "\","
            "\"organization_level\":true}",
            &res);
    axiam_login_result_dispose(&res);

    axiam_opaque_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_opaque_enrollment_for_self(c, g_password, &e, &err));

    TEST_ASSERT_EQUAL_INT(1, g_register_start_count);
    TEST_ASSERT_NOT_NULL(strstr(g_register_start_body, "\"tenant_id\":\"" PRINCIPAL_TENANT "\""));
    /* A slug naming the acting tenant would out-vote the principal tenant id
     * server-side, which is the exact confusion this entry point exists to avoid. */
    TEST_ASSERT_NULL(strstr(g_register_start_body, "tenant_slug"));
    /* The organization half of the workspace still applies: it identifies the
     * organization, not the tenant. */
    TEST_ASSERT_NOT_NULL(strstr(g_register_start_body, "\"org_id\":\"" ORG_ID "\""));
    TEST_ASSERT_EQUAL_STRING("reg-handle", e.opaque_session);

    axiam_opaque_enrollment_dispose(&e);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_plain_enrolment_still_seals_against_the_acting_tenant(void) {
    /* The other call site, unchanged: a record for ANOTHER account is sealed against
     * the tenant being acted on, which is what the client is already pointed at. */
    axiam_client_t *c = make_slug_client();
    axiam_login_result_t res;
    sign_in(c,
            "{\"id\":\"u-1\",\"tenant_id\":\"" ACTING_TENANT "\","
            "\"principal_tenant_id\":\"" PRINCIPAL_TENANT "\","
            "\"organization_level\":true}",
            &res);
    axiam_login_result_dispose(&res);

    axiam_opaque_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_opaque_enrollment(c, g_password, &e, &err));

    TEST_ASSERT_NOT_NULL(strstr(g_register_start_body, "\"tenant_slug\":\"acme\""));
    TEST_ASSERT_NULL(strstr(g_register_start_body, PRINCIPAL_TENANT));

    axiam_opaque_enrollment_dispose(&e);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_enrolment_for_self_refuses_before_a_login(void) {
    /* There is no principal tenant to seal against yet, and falling back to the acting
     * one is exactly the bug this entry point exists to prevent. */
    axiam_client_t *c = make_client();
    axiam_opaque_enrollment_t e;
    axiam_error_t err;

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
                          axiam_opaque_enrollment_for_self(c, g_password, &e, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "principal tenant"));
    /* The request that must NOT happen. */
    TEST_ASSERT_EQUAL_INT(0, g_register_start_count);

    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

/* ------------------------------------------------------------------------
 * §5.2.3 rules 1 and 2 -- tenant_scope on an assignment
 * ---------------------------------------------------------------------- */

static void test_an_empty_tenant_scope_never_reaches_the_wire(void) {
    /* `[]` is refused with 400, and a pointer to a list that filtered down to nothing
     * is what "no tenants named" naturally produces -- so both spellings of absent must
     * travel the same way: by not appearing. */
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    char *none[1] = {NULL};
    axiam_mgmt_assign_role_to_user_request_t body = {0};
    body.user_id = (char *)SOME_ID;
    body.tenant_scope = none;   /* non-NULL, count 0: the shape the ordinary guard misses */
    body.tenant_scope_count = 0;

    mgmt_mount(204, "");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_roles_assign_to_user(c, SOME_ID, &body, &err));

    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "tenant_scope"));
    /* ...and the rest of the body survives the removal. */
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"user_id\":\"" SOME_ID "\""));

    axiam_client_free(c);
}

static void test_a_named_tenant_scope_is_sent(void) {
    /* Dropping a scope the caller DID name would turn a refusal they need to see into a
     * success that silently applied no restriction. */
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char *scope[1] = {(char *)SCOPED_TENANT};

    axiam_mgmt_assign_role_to_user_request_t user_body = {0};
    user_body.user_id = (char *)SOME_ID;
    user_body.tenant_scope = scope;
    user_body.tenant_scope_count = 1;
    mgmt_mount(204, "");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_roles_assign_to_user(c, SOME_ID, &user_body, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"tenant_scope\":[\"" SCOPED_TENANT "\"]"));

    axiam_mgmt_assign_role_to_group_request_t group_body = {0};
    group_body.group_id = (char *)SOME_ID;
    group_body.tenant_scope = scope;
    group_body.tenant_scope_count = 1;
    mgmt_mount(204, "");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_roles_assign_to_group(c, SOME_ID, &group_body, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"tenant_scope\":[\"" SCOPED_TENANT "\"]"));

    axiam_mgmt_assign_role_to_service_account_request_t sa_body = {0};
    sa_body.service_account_id = (char *)SOME_ID;
    sa_body.tenant_scope = scope;
    sa_body.tenant_scope_count = 1;
    mgmt_mount(204, "");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_roles_assign_to_service_account(c, SOME_ID, &sa_body, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"tenant_scope\":[\"" SCOPED_TENANT "\"]"));

    axiam_client_free(c);
}

static void test_other_empty_lists_are_still_sent(void) {
    /* The allowlist is one field wide on purpose: elsewhere an empty array is
     * meaningful -- a replacement body clearing a list -- and dropping it would make
     * "remove every entry" inexpressible. */
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char *none[1] = {NULL};

    axiam_mgmt_update_webhook_request_t body = {0};
    body.events = none;
    body.events_count = 0;

    mgmt_mount(200, "{\"id\":\"" SOME_ID "\",\"url\":\"https://hook.example\","
                    "\"events\":[],\"enabled\":true,"
                    "\"created_at\":\"2026-08-30T00:00:00Z\","
                    "\"updated_at\":\"2026-08-30T00:00:00Z\"}");
    axiam_mgmt_webhook_response_t *out = NULL;
    axiam_webhooks_update(c, SOME_ID, &body, &out, &err);

    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"events\":[]"));

    axiam_mgmt_webhook_response_free(out);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_absent_principal_tenant_reads_as_the_acting_tenant);
    RUN_TEST(test_a_divergent_principal_tenant_is_reported_separately);
    RUN_TEST(test_reachable_tenant_ids_narrows_an_organization_level_principal);
    RUN_TEST(test_absent_reach_is_unrestricted_not_empty);

    RUN_TEST(test_enrolment_for_self_seals_against_the_principal_tenant);
    RUN_TEST(test_plain_enrolment_still_seals_against_the_acting_tenant);
    RUN_TEST(test_enrolment_for_self_refuses_before_a_login);

    RUN_TEST(test_an_empty_tenant_scope_never_reaches_the_wire);
    RUN_TEST(test_a_named_tenant_scope_is_sent);
    RUN_TEST(test_other_empty_lists_are_still_sent);
    return UNITY_END();
}
