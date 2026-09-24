/*
 * CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant helper.
 *
 * The rule in one sentence: X-Axiam-Tenant is sent on every /api/v1 REST call
 * exactly when set, absent byte for byte when it is not, and the on-client setter
 * refuses client-side (zero wire calls) whenever what THIS client knows about the
 * signed-in principal says the server would refuse it anyway.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

#define ORG_TENANT "11111111-1111-1111-1111-111111111111"
#define OTHER_TENANT "22222222-2222-2222-2222-222222222222"
#define UNREACHABLE_TENANT "33333333-3333-3333-3333-333333333333"

/* --- Programmable fake transport, capturing every header of every request --- */
typedef struct {
    long next_status;
    const char *next_body;
    int request_count;
    /* The X-Axiam-Tenant header of the LAST request, or "" when absent. */
    char last_acting_tenant[128];
    int last_had_acting_tenant_header; /* distinguishes absent from empty */
} fake_state_t;

static fake_state_t g_fake;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    st->request_count++;
    const char *at = axiam_kv_get(req->headers, "X-Axiam-Tenant");
    st->last_had_acting_tenant_header = at != NULL;
    snprintf(st->last_acting_tenant, sizeof(st->last_acting_tenant), "%s", at ? at : "");
    memset(resp, 0, sizeof(*resp));
    resp->status = st->next_status;
    if (st->next_body) resp->body = strdup(st->next_body);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, ORG_TENANT);
    axiam_client_config_set_org_id(cfg, "44444444-4444-4444-4444-444444444444");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g_fake, 0, sizeof(g_fake)); }
void tearDown(void) {}

static const char *org_level_login_body(const char *reachable_ids_json /* may be NULL */) {
    static char buf[1024];
    if (reachable_ids_json) {
        snprintf(buf, sizeof(buf),
                 "{\"session_id\":\"s1\",\"expires_in\":900,"
                 "\"user\":{\"id\":\"u1\",\"username\":\"root\",\"email\":\"r@x.io\","
                 "\"tenant_id\":\"%s\",\"organization_level\":true,"
                 "\"reachable_tenant_ids\":%s}}",
                 ORG_TENANT, reachable_ids_json);
    } else {
        snprintf(buf, sizeof(buf),
                 "{\"session_id\":\"s1\",\"expires_in\":900,"
                 "\"user\":{\"id\":\"u1\",\"username\":\"root\",\"email\":\"r@x.io\","
                 "\"tenant_id\":\"%s\",\"organization_level\":true}}",
                 ORG_TENANT);
    }
    return buf;
}

static const char *tenant_login_body(void) {
    return "{\"session_id\":\"s1\",\"expires_in\":900,"
           "\"user\":{\"id\":\"u1\",\"username\":\"alice\",\"email\":\"a@x.io\","
           "\"tenant_id\":\"" ORG_TENANT "\"}}"; /* organization_level absent -> false */
}

/* ------------------------------------------------------------------------
 * 1. Construction-time form: axiam_client_config_set_acting_tenant.
 * ---------------------------------------------------------------------- */

static void test_config_setter_rejects_non_uuid(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_acting_tenant(cfg, "acme"));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_config_set_acting_tenant(cfg, "not-a-uuid"));
    axiam_client_config_free(cfg);
}

static void test_config_setter_accepts_uuid_and_clears_on_empty(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_config_set_acting_tenant(cfg, ORG_TENANT));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_acting_tenant(cfg, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_acting_tenant(cfg, ""));
    axiam_client_config_free(cfg);
}

/* A client BUILT with an acting tenant already set sends it from the first
 * request, with no separate call needed. */
static void test_construction_time_acting_tenant_is_sent(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, ORG_TENANT);
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_config_set_acting_tenant(cfg, OTHER_TENANT));
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    g_fake.next_status = 200;
    g_fake.next_body = "{\"keys\":[]}";
    char *body = NULL;
    axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_TRUE(g_fake.last_had_acting_tenant_header);
    TEST_ASSERT_EQUAL_STRING(OTHER_TENANT, g_fake.last_acting_tenant);
    free(body);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 2. Present-when-set, absent-when-not: refresh, logout, a self-service POST,
 *    and check_access. (management is exercised via check_access/raw_get, since
 *    the generated ops all funnel through the same build_headers().)
 * ---------------------------------------------------------------------- */

static void test_header_absent_by_default_on_refresh(void) {
    axiam_client_t *c = make_client();
    g_fake.next_status = 200;
    g_fake.next_body = tenant_login_body();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_login(c, "alice", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_refresh(c, &err);
    TEST_ASSERT_FALSE_MESSAGE(g_fake.last_had_acting_tenant_header,
                              "no X-Axiam-Tenant when none was ever set");
    axiam_client_free(c);
}

static void test_header_present_when_set_on_refresh_logout_and_self_service(void) {
    axiam_client_t *c = make_client();
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_refresh(c, &err);
    TEST_ASSERT_TRUE_MESSAGE(g_fake.last_had_acting_tenant_header, "refresh");
    TEST_ASSERT_EQUAL_STRING(OTHER_TENANT, g_fake.last_acting_tenant);

    /* A self-service POST: MFA enrollment (account.c, axiam_client_send_raw ->
     * the SAME build_headers() every other call goes through). CONTRACT.md
     * §5.2.2 rule 4: an SDK MUST NOT clear or rewrite the header for these --
     * it is sent exactly as for any other call, and the server decides. */
    g_fake.next_status = 200;
    g_fake.next_body = "{\"secret\":\"x\",\"qr_code_url\":\"y\"}";
    axiam_http_response_t raw_resp;
    axiam_client_send_raw(c, "POST", "/api/v1/auth/mfa/enroll", "{}", &raw_resp);
    axiam_http_response_dispose(&raw_resp);
    TEST_ASSERT_TRUE_MESSAGE(g_fake.last_had_acting_tenant_header, "self-service POST");
    TEST_ASSERT_EQUAL_STRING(OTHER_TENANT, g_fake.last_acting_tenant);

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_logout(c, &err);
    TEST_ASSERT_TRUE_MESSAGE(g_fake.last_had_acting_tenant_header, "logout");
    TEST_ASSERT_EQUAL_STRING(OTHER_TENANT, g_fake.last_acting_tenant);

    axiam_client_free(c);
}

static void test_header_absent_after_clear(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    axiam_client_clear_acting_tenant(c);

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_refresh(c, &err);
    TEST_ASSERT_FALSE(g_fake.last_had_acting_tenant_header);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 3. axiam_client_set_acting_tenant() client-side gates — every negative with
 *    its zero-wire-calls twin.
 * ---------------------------------------------------------------------- */

static void test_set_acting_tenant_rejects_non_uuid_with_zero_wire_calls(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    int before = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_set_acting_tenant(c, "not-a-uuid", &err));
    TEST_ASSERT_EQUAL_INT(before, g_fake.request_count);
    axiam_client_free(c);
}

/* The I4 twin: the SAME tenant, spelled as a real UUID, is accepted (subject to
 * the other gates) -- the rejection above is about the SHAPE, not the value. */
static void test_set_acting_tenant_accepts_uuid_shape(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    axiam_client_free(c);
}

static void test_set_acting_tenant_refused_for_non_organization_level(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = tenant_login_body(); /* organization_level absent -> false */
    axiam_login_result_t res;
    axiam_login(c, "alice", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    int before = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, g_fake.request_count,
                                  "zero wire calls on refusal");
    axiam_client_free(c);
}

/* I4 twin of the above: an organization-level principal IS allowed. */
static void test_set_acting_tenant_allowed_for_organization_level(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    axiam_client_free(c);
}

static void test_set_acting_tenant_refused_outside_reachable_tenant_ids(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body("[\"" OTHER_TENANT "\"]");
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    int before = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT(
        AXIAM_ERR_NETWORK,
        axiam_client_set_acting_tenant(c, UNREACHABLE_TENANT, &err));
    TEST_ASSERT_EQUAL_INT(before, g_fake.request_count);
    axiam_client_free(c);
}

/* I4 twin: the tenant NAMED in reachable_tenant_ids is allowed. */
static void test_set_acting_tenant_allowed_within_reachable_tenant_ids(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body("[\"" OTHER_TENANT "\"]");
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    axiam_client_free(c);
}

/* A client holding NO login result (nothing to gate on) sends the header as
 * asked; the server's answer -- simulated here as a 403 on the next call -- is
 * the only refusal. */
static void test_set_acting_tenant_with_no_login_result_sends_header(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    /* No login call at all: axiam_client_has_session() is false, and this is
     * exactly what a device-login-adopted or injected-token client looks like
     * to the gate. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));

    g_fake.next_status = 200;
    g_fake.next_body = "{\"keys\":[]}";
    char *body = NULL;
    axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_TRUE(g_fake.last_had_acting_tenant_header);
    TEST_ASSERT_EQUAL_STRING(OTHER_TENANT, g_fake.last_acting_tenant);
    free(body);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 4. Gate reset on a new session that reports no LoginUserInfo (the
 *    C-4/C-5 lesson): WebAuthn AUTHENTICATE completes a session through
 *    axiam_client_adopt_session(), which carries no `user` object at all.
 *    A stale organization_level=true from an EARLIER session on this same
 *    client object must not leak into the new one.
 * ---------------------------------------------------------------------- */

static void test_gate_resets_on_session_with_no_login_user_info(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;

    /* First, an organization-level login RESTRICTED to OTHER_TENANT. If the
     * gate from THIS session survives into the next one, a later set to
     * UNREACHABLE_TENANT would be refused by the (stale) old gate -- which is
     * exactly the assertion this test needs to distinguish "correctly reset"
     * from "incorrectly still true": both an unrestricted stale gate and a
     * correctly-reset one would allow the call, so restricting it here is
     * what makes the mutation observable. */
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body("[\"" OTHER_TENANT "\"]");
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));

    /* Now a WebAuthn AUTHENTICATE completes a DIFFERENT session -- no `user`
     * object in this response at all. */
    g_fake.next_status = 200;
    g_fake.next_body =
        "{\"access_token\":\"at\",\"refresh_token\":\"rt\","
        "\"session_id\":\"s2\",\"expires_in\":900}";
    axiam_webauthn_login_t login;
    axiam_sensitive_t *state = axiam_sensitive_new("state-token");
    axiam_webauthn_authenticate_finish(c, state, "{}", &login, &err);
    axiam_sensitive_free(state);
    axiam_webauthn_login_dispose(&login);

    /* The gate must now read "nothing to gate on", NOT "still
     * organization_level=true from the password login". */
    int before = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        AXIAM_OK, axiam_client_set_acting_tenant(c, UNREACHABLE_TENANT, &err),
        "a session with no LoginUserInfo has nothing to gate on -- it must not "
        "inherit the PREVIOUS session's organization_level");
    TEST_ASSERT_EQUAL_INT(before, g_fake.request_count);

    axiam_client_free(c);
}

/* logout drops both the acting tenant AND the gate. */
static void test_logout_clears_acting_tenant_and_gate(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_logout(c, &err);

    g_fake.next_status = 200;
    g_fake.next_body = "{\"keys\":[]}";
    char *body = NULL;
    axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_FALSE_MESSAGE(g_fake.last_had_acting_tenant_header,
                              "logout clears the acting tenant");
    free(body);
    axiam_client_free(c);
}

/* Same reset, but with a NON-EMPTY reachable_tenant_ids to free -- the test above
 * logs in with none at all (org_level_login_body(NULL)), so it never exercises the
 * array-free loop reset_acting_tenant_and_gate() runs when there IS one. */
static void test_logout_frees_a_populated_reachable_tenant_ids(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body("[\"" OTHER_TENANT "\"]");
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));

    g_fake.next_status = 200;
    g_fake.next_body = NULL;
    axiam_logout(c, &err);

    /* The gate itself resets to "unknown" along with the freed array (the same
     * "no session to gate on" shape as test_set_acting_tenant_with_no_login_
     * result_sends_header above): the call succeeds -- it no longer consults the
     * PREVIOUS session's reachable_tenant_ids at all, freed or not. Read under
     * ASan/valgrind, this is also the check that the free left no dangling read:
     * a stale gate that still thought organization_level was true would instead
     * dereference the just-freed array while re-checking membership. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        AXIAM_OK, axiam_client_set_acting_tenant(c, OTHER_TENANT, &err),
        "post-logout the gate is unknown, not a stale organization_level=true "
        "still pointing at the freed array");
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 5. §17 memo key includes the acting tenant (contract 1.51; the memo key
 *    predates §5.2 rule 1 and, before this, could answer tenant B's question
 *    with tenant A's cached decision within the TTL).
 * ---------------------------------------------------------------------- */

static axiam_client_t *make_memo_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, ORG_TENANT);
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_client_config_set_decision_memo_ttl(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static void test_memo_key_includes_acting_tenant(void) {
    axiam_client_t *c = make_memo_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body(NULL);
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);

    g_fake.next_status = 200;
    g_fake.next_body = "{\"allowed\":true}";
    axiam_check_result_t out;

    /* Acting on OTHER_TENANT: a check for "read"/"r1" is memoized. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_check_access(c, "read", "r1", NULL, NULL, &out, &err));
    axiam_check_result_dispose(&out);
    int after_first = g_fake.request_count;

    /* The SAME question, but now acting on UNREACHABLE_TENANT, must NOT hit the
     * memo entry the first call wrote -- a wire call is required, proving the
     * two are DIFFERENT keys. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, UNREACHABLE_TENANT, &err));
    g_fake.next_status = 200;
    g_fake.next_body = "{\"allowed\":false}";
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_check_access(c, "read", "r1", NULL, NULL, &out, &err));
    TEST_ASSERT_FALSE(out.allowed);
    axiam_check_result_dispose(&out);
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        after_first + 1, g_fake.request_count,
        "a different acting tenant must not hit the other tenant's memo entry");

    /* Switching BACK to OTHER_TENANT within the TTL hits the original entry
     * again -- no third wire call. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, OTHER_TENANT, &err));
    int before_third = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_check_access(c, "read", "r1", NULL, NULL, &out, &err));
    TEST_ASSERT_TRUE_MESSAGE(out.allowed, "the OTHER_TENANT entry is still allowed=true");
    axiam_check_result_dispose(&out);
    TEST_ASSERT_EQUAL_INT_MESSAGE(before_third, g_fake.request_count,
                                  "memo hit: no wire call");

    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * 6. SSO/federation completions reset the gate exactly as a WebAuthn
 *    AUTHENTICATE ceremony does (C-12 question 5's stale-principal case,
 *    orchestrator review of C-10): axiam_sso_complete(), axiam_sso_complete_
 *    oauth2() and axiam_sso_complete_handoff() all establish a NEW session
 *    whose response carries no LoginUserInfo at all (§12.1 note 6), so a
 *    PREVIOUS session's organization_level/reachable_tenant_ids must not
 *    still gate the acting-tenant setter afterward.
 * ---------------------------------------------------------------------- */

/* §12.1 note 6: SsoLoginSuccessResponse — no `user` object, ever. */
static const char *SSO_SUCCESS_BODY =
    "{\"user_id\":\"u1\",\"session_id\":\"s1\",\"expires_in\":900}";

/* A restricted first login: organization_level=true but reachable to OTHER_TENANT
 * only, so a stale gate (never reset) and a correctly-reset gate ("unknown", sends
 * the header and lets the server's 403 decide) produce an OBSERVABLY DIFFERENT
 * result for UNREACHABLE_TENANT -- the same reason test_gate_resets_on_session_
 * with_no_login_user_info uses a restricted first login rather than an
 * unrestricted one. */
static axiam_client_t *make_client_restricted_to_other_tenant(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    g_fake.next_status = 200;
    g_fake.next_body = org_level_login_body("[\"" OTHER_TENANT "\"]");
    axiam_login_result_t res;
    axiam_login(c, "root", "pw", &res, &err);
    axiam_login_result_dispose(&res);
    return c;
}

static void assert_refused_for_unreachable_tenant(axiam_client_t *c, const char *why) {
    axiam_error_t err;
    int before = g_fake.request_count;
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK,
                                  axiam_client_set_acting_tenant(c, UNREACHABLE_TENANT, &err), why);
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, g_fake.request_count, "refused: zero wire calls");
}

/* Accepted, AND the header actually reaches a subsequent request -- not just an
 * AXIAM_OK return code, since the setter's own success is silent about WHY. */
static void assert_accepted_and_header_sent(axiam_client_t *c) {
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_set_acting_tenant(c, UNREACHABLE_TENANT, &err));
    g_fake.next_status = 200;
    g_fake.next_body = "{\"keys\":[]}";
    char *body = NULL;
    axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_TRUE_MESSAGE(g_fake.last_had_acting_tenant_header,
                             "the gate must be unknown, not still refusing on the "
                             "PREVIOUS session's organization_level/reachable_tenant_ids");
    TEST_ASSERT_EQUAL_STRING(UNREACHABLE_TENANT, g_fake.last_acting_tenant);
    free(body);
}

static void test_sso_complete_resets_a_stale_restrictive_gate(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the SSO completion");

    g_fake.next_status = 200;
    g_fake.next_body = SSO_SUCCESS_BODY;
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_complete(c, "code", "state", &r, &err));
    axiam_sso_complete_result_dispose(&r);

    assert_accepted_and_header_sent(c);
    axiam_client_free(c);
}

/* I4 twin: a REFUSED completion (a 400) must leave the gate exactly as it was --
 * still refusing on the previous, still-current principal's restricted report. */
static void test_failed_sso_complete_leaves_the_gate_unchanged(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the SSO completion");

    g_fake.next_status = 400;
    g_fake.next_body = "{\"error\":\"invalid_grant\"}";
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_sso_complete(c, "code", "state", &r, &err));

    assert_refused_for_unreachable_tenant(c, "still refused after a FAILED completion");
    axiam_client_free(c);
}

static void test_sso_complete_oauth2_resets_a_stale_restrictive_gate(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the oauth2 completion");

    g_fake.next_status = 200;
    g_fake.next_body = SSO_SUCCESS_BODY;
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_complete_oauth2(c, "code", "state", &r, &err));
    axiam_sso_complete_result_dispose(&r);

    assert_accepted_and_header_sent(c);
    axiam_client_free(c);
}

static void test_failed_sso_complete_oauth2_leaves_the_gate_unchanged(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the oauth2 completion");

    g_fake.next_status = 400;
    g_fake.next_body = "{\"error\":\"invalid_grant\"}";
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_sso_complete_oauth2(c, "code", "state", &r, &err));

    assert_refused_for_unreachable_tenant(c, "still refused after a FAILED completion");
    axiam_client_free(c);
}

static void test_sso_complete_handoff_resets_a_stale_restrictive_gate(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the handoff completion");

    g_fake.next_status = 200;
    g_fake.next_body = SSO_SUCCESS_BODY;
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_complete_handoff(c, "code", &r, &err));
    axiam_sso_complete_result_dispose(&r);

    assert_accepted_and_header_sent(c);
    axiam_client_free(c);
}

/* Handoff's own I4: a 401 here is TERMINAL (the code is spent either way), and
 * still must not touch the gate. */
static void test_failed_sso_complete_handoff_leaves_the_gate_unchanged(void) {
    axiam_client_t *c = make_client_restricted_to_other_tenant();
    assert_refused_for_unreachable_tenant(c, "refused before the handoff completion");

    g_fake.next_status = 401;
    g_fake.next_body = "{\"error\":\"invalid_grant\"}";
    axiam_sso_complete_result_t r;
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_sso_complete_handoff(c, "code", &r, &err));

    assert_refused_for_unreachable_tenant(c, "still refused after a FAILED (terminal) completion");
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_config_setter_rejects_non_uuid);
    RUN_TEST(test_config_setter_accepts_uuid_and_clears_on_empty);
    RUN_TEST(test_construction_time_acting_tenant_is_sent);
    RUN_TEST(test_header_absent_by_default_on_refresh);
    RUN_TEST(test_header_present_when_set_on_refresh_logout_and_self_service);
    RUN_TEST(test_header_absent_after_clear);
    RUN_TEST(test_set_acting_tenant_rejects_non_uuid_with_zero_wire_calls);
    RUN_TEST(test_set_acting_tenant_accepts_uuid_shape);
    RUN_TEST(test_set_acting_tenant_refused_for_non_organization_level);
    RUN_TEST(test_set_acting_tenant_allowed_for_organization_level);
    RUN_TEST(test_set_acting_tenant_refused_outside_reachable_tenant_ids);
    RUN_TEST(test_set_acting_tenant_allowed_within_reachable_tenant_ids);
    RUN_TEST(test_set_acting_tenant_with_no_login_result_sends_header);
    RUN_TEST(test_gate_resets_on_session_with_no_login_user_info);
    RUN_TEST(test_logout_clears_acting_tenant_and_gate);
    RUN_TEST(test_logout_frees_a_populated_reachable_tenant_ids);
    RUN_TEST(test_memo_key_includes_acting_tenant);
    RUN_TEST(test_sso_complete_resets_a_stale_restrictive_gate);
    RUN_TEST(test_failed_sso_complete_leaves_the_gate_unchanged);
    RUN_TEST(test_sso_complete_oauth2_resets_a_stale_restrictive_gate);
    RUN_TEST(test_failed_sso_complete_oauth2_leaves_the_gate_unchanged);
    RUN_TEST(test_sso_complete_handoff_resets_a_stale_restrictive_gate);
    RUN_TEST(test_failed_sso_complete_handoff_leaves_the_gate_unchanged);
    return UNITY_END();
}
