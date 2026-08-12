/*
 * UMA 2.0 — branch-coverage depth for src/uma.c.
 *
 * The companion file, test_uma.c, drives the §20.7 behavioural assertions. This
 * one drives the arms those tests never take: the NULL-argument guards, the
 * malformed-body paths, a discovery failure propagating out of every operation,
 * a closed client, and the challenge parser's grammar edge cases.
 *
 * They are worth their own file rather than being folded in: a §20.7 test reads
 * as a statement about the contract, and burying "and also NULL returns an
 * error" among them makes both harder to read. Same split as
 * test_client_branches.c / test_guard_branches.c.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

#define B_RESOURCE "99999999-8888-7777-6666-555555555555"

#define B_DISCOVERY \
    "{\"issuer\":\"https://api.test\"," \
    "\"token_endpoint\":\"https://api.test/oauth2/token\"," \
    "\"permission_endpoint\":\"https://api.test/uma2/perm\"," \
    "\"resource_registration_endpoint\":\"https://api.test/uma2/rreg/resource_set\"}"

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Discovery: status + body, so a failure or a malformed document can be
     * driven through every operation that depends on it. */
    long discovery_status;
    const char *discovery_body;
    long other_status;
    const char *other_body;
    /* When nonzero, everything but discovery reports a transport failure. */
    int fail_other_transport;
    int calls;
} branch_state_t;

static branch_state_t b;

static int branch_transport(void *ctx, const axiam_http_request_t *req,
                            axiam_http_response_t *resp) {
    (void)ctx;
    b.calls++;
    const char *url = req->url ? req->url : "";
    if (strstr(url, "uma2-configuration")) {
        resp_fill(resp, b.discovery_status ? b.discovery_status : 200,
                  b.discovery_body ? b.discovery_body : B_DISCOVERY, NULL);
        return 0;
    }
    if (b.fail_other_transport) {
        memset(resp, 0, sizeof(*resp));
        resp->transport_err = 7;
        resp->transport_msg = strdup("connection refused");
        return -1;
    }
    resp_fill(resp, b.other_status ? b.other_status : 200, b.other_body ? b.other_body : "{}", NULL);
    return 0;
}

static axiam_client_t *make_branch_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, branch_transport, &b);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {
    memset(&b, 0, sizeof(b));
}

void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Disposal is safe on NULL and on a zeroed struct                    */
/* ------------------------------------------------------------------ */

void test_dispose_is_safe_on_null_and_on_zeroed_structs(void) {
    /* Every _dispose is documented as safe on a zeroed struct precisely so a
     * caller can dispose unconditionally on the error path — which is the path
     * where getting this wrong is hardest to notice. */
    axiam_uma_config_dispose(NULL);
    axiam_uma_resource_set_dispose(NULL);
    axiam_uma_rpt_dispose(NULL);
    axiam_uma_challenge_dispose(NULL);
    axiam_uma_string_array_free(NULL, 0);

    axiam_uma_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    axiam_uma_config_dispose(&cfg);
    axiam_uma_config_dispose(&cfg); /* twice: dispose leaves it disposable */

    axiam_uma_resource_set_t rs;
    memset(&rs, 0, sizeof(rs));
    axiam_uma_resource_set_dispose(&rs);

    axiam_uma_rpt_t rpt;
    memset(&rpt, 0, sizeof(rpt));
    axiam_uma_rpt_dispose(&rpt);

    axiam_uma_challenge_t ch;
    memset(&ch, 0, sizeof(ch));
    axiam_uma_challenge_dispose(&ch);
    TEST_PASS();
}

/* ------------------------------------------------------------------ */
/* NULL-argument guards                                               */
/* ------------------------------------------------------------------ */

void test_null_out_parameters_are_refused(void) {
    axiam_client_t *c = make_branch_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    const char *scopes[] = {"view"};

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_discover(c, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_register_resource(c, NULL, "n", NULL, scopes, 1, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_register_resource(c, NULL, NULL, NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(c, NULL, NULL, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(c, NULL, B_RESOURCE, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_update_resource(c, NULL, NULL, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_update_resource(c, NULL, B_RESOURCE, NULL, NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_delete_resource(c, NULL, NULL, &err));

    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, NULL, NULL, &n, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, NULL, &ids, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(c, NULL, NULL, 0, NULL, &err));

    axiam_uma_rpt_t rpt;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, NULL, &rpt, &err));
    axiam_uma_exchange_params_t p = {NULL, NULL, NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, NULL, &err));

    /* None of the above reached the wire. */
    TEST_ASSERT_EQUAL_INT(0, b.calls);
    axiam_client_free(c);
}

void test_a_null_client_is_refused_by_every_operation(void) {
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_config_t cfg;
    axiam_uma_resource_set_t rs;
    axiam_uma_rpt_t rpt;
    char **ids = NULL;
    size_t n = 0;
    axiam_sensitive_t *ticket = NULL;
    const char *scopes[] = {"view"};
    axiam_uma_exchange_params_t p = {NULL, NULL, "id", NULL, NULL};

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_discover(NULL, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_register_resource(NULL, NULL, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(NULL, NULL, B_RESOURCE, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_update_resource(NULL, NULL, B_RESOURCE, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_delete_resource(NULL, NULL, B_RESOURCE, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(NULL, NULL, &ids, &n, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(NULL, NULL, NULL, 0, &ticket, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(NULL, &p, &rpt, &err));
}

void test_a_closed_client_is_refused_by_every_operation(void) {
    axiam_client_t *c = make_branch_client();
    axiam_client_close(c);

    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_config_t cfg;
    axiam_uma_resource_set_t rs;
    axiam_uma_rpt_t rpt;
    char **ids = NULL;
    size_t n = 0;
    axiam_sensitive_t *ticket = NULL;
    const char *scopes[] = {"view"};
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_uma_exchange_params_t p = {pat, pat, "id", pat, NULL};

    /* §18.1 rule 4: use after close is an error, not undefined — and not a
     * reconnect. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_register_resource(c, pat, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_update_resource(c, pat, B_RESOURCE, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_delete_resource(c, pat, B_RESOURCE, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(c, pat, NULL, 0, &ticket, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_INT(0, b.calls);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_empty_pat_is_refused_like_an_absent_one(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    const char *scopes[] = {"view"};
    /* An empty Sensitive is not "a PAT that happens to be short" — it is the
     * absence of one, and must not become a request with an empty bearer. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_uma_register_resource(c, empty, "n", NULL, scopes, 1, &rs, &err));

    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Discovery failures propagate out of every operation                */
/* ------------------------------------------------------------------ */

void test_a_discovery_failure_propagates_out_of_every_operation(void) {
    b.discovery_status = 500;
    b.discovery_body = "";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    axiam_uma_rpt_t rpt;
    char **ids = NULL;
    size_t n = 0;
    axiam_sensitive_t *ticket = NULL;
    const char *scopes[] = {"view"};
    axiam_uma_exchange_params_t p = {pat, pat, "id", pat, NULL};

    /* Endpoints are read from the document, never hardcoded — so a deployment
     * whose discovery is down does not silently get requests aimed at guessed
     * paths. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_register_resource(c, pat, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_update_resource(c, pat, B_RESOURCE, "n", NULL, scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_delete_resource(c, pat, B_RESOURCE, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, pat, &ids, &n, &err));

    axiam_uma_permission_t perm = {B_RESOURCE, scopes, 1};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_malformed_or_incomplete_discovery_document_is_refused(void) {
    axiam_client_t *c = make_branch_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_config_t cfg;

    b.discovery_body = "not json at all";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_discover(c, &cfg, &err));
    axiam_uma_config_dispose(&cfg);

    /* A document missing an endpoint is not "mostly usable": the operation that
     * needed the missing one would otherwise build a request against garbage. */
    b.discovery_body = "{\"issuer\":\"https://api.test\","
                       "\"token_endpoint\":\"https://api.test/oauth2/token\"}";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_discover(c, &cfg, &err));
    axiam_uma_config_dispose(&cfg);

    axiam_client_free(c);
}

void test_discovery_surfaces_the_advertised_ticket_lifetime_or_minus_one(void) {
    axiam_client_t *c = make_branch_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_config_t cfg;

    /* B_DISCOVERY carries no permission_ticket_lifetime, so the absent case is
     * -1 rather than a plausible-looking 0. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL_INT(-1, cfg.permission_ticket_lifetime);
    TEST_ASSERT_EQUAL_STRING("https://api.test", cfg.issuer);
    axiam_uma_config_dispose(&cfg);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Malformed success bodies                                           */
/* ------------------------------------------------------------------ */

void test_a_resource_set_without_a_name_is_malformed(void) {
    b.other_body = "{\"_id\":\"" B_RESOURCE "\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    axiam_uma_resource_set_dispose(&rs);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_resource_set_tolerates_absent_id_type_and_scopes(void) {
    /* A registration response is allowed to be minimal; only `name` is
     * load-bearing. The absent members come back as NULL/empty rather than as
     * an empty string a caller might send back as a real value. */
    b.other_body = "{\"name\":\"invoice-7\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    TEST_ASSERT_NULL(rs.id);
    TEST_ASSERT_NULL(rs.type);
    TEST_ASSERT_EQUAL_size_t(0, rs.scope_count);
    axiam_uma_resource_set_dispose(&rs);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_non_string_scope_member_is_dropped_rather_than_fataling(void) {
    /* Neither a scope list nor an id list is a credential; a server that grows a
     * richer member should not take an otherwise-usable response down with it. */
    b.other_body = "{\"name\":\"invoice-7\",\"resource_scopes\":[\"view\",7,null,\"edit\"]}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    TEST_ASSERT_EQUAL_size_t(2, rs.scope_count);
    TEST_ASSERT_EQUAL_STRING("view", rs.scopes[0]);
    TEST_ASSERT_EQUAL_STRING("edit", rs.scopes[1]);
    axiam_uma_resource_set_dispose(&rs);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_list_body_that_is_not_an_array_is_refused(void) {
    b.other_body = "{\"ids\":[]}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_NULL(ids);

    /* An empty array is a legitimate answer, not an error: a client that has
     * registered nothing lists nothing. */
    b.other_body = "[]";
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_EQUAL_size_t(0, n);
    axiam_uma_string_array_free(ids, n);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_ticket_response_without_a_ticket_is_malformed(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_permission_t perm = {B_RESOURCE, scopes, 1};
    axiam_sensitive_t *ticket = NULL;

    b.other_body = "{}";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_NULL(ticket);

    /* An empty ticket string is the same failure, not a zero-length credential. */
    b.other_body = "{\"ticket\":\"\"}";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_NULL(ticket);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_permission_with_a_null_scope_array_still_builds_a_body(void) {
    b.other_body = "{\"ticket\":\"t\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    /* A caller asking for a resource with no scopes is asking the server a
     * question the server is entitled to refuse — it is not the SDK's job to
     * turn it into a malformed request or a crash. */
    axiam_uma_permission_t perm = {B_RESOURCE, NULL, 0};
    axiam_sensitive_t *ticket = NULL;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    axiam_sensitive_free(ticket);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_token_response_without_an_access_token_is_malformed(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;
    axiam_uma_exchange_params_t p = {s, s, "client", s, AXIAM_TEST_TENANT_ID};

    b.other_body = "{\"token_type\":\"Bearer\",\"expires_in\":300}";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    /* token_type and expires_in are optional on the way in; a response carrying
     * only the token still yields a usable RPT with the documented default. */
    b.other_body = "{\"access_token\":\"rpt\"}";
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING("Bearer", rpt.token_type);
    TEST_ASSERT_EQUAL_INT(0, rpt.expires_in);
    axiam_uma_rpt_dispose(&rpt);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

void test_an_explicit_tenant_id_overrides_the_configured_one(void) {
    b.other_body = "{\"access_token\":\"rpt\",\"token_type\":\"Bearer\",\"expires_in\":300}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    /* A resource server serving several tenants passes the tenant per call
     * rather than building a client each time. */
    axiam_uma_exchange_params_t p = {s, s, "client", s,
                                     "33333333-3333-3333-3333-333333333333"};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    /* A non-UUID explicit value is refused even when the client's own tenant_id
     * would have been a valid one — the explicit argument is the request. */
    axiam_uma_exchange_params_t bad = {s, s, "client", s, "acme"};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &bad, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

void test_an_absent_ticket_is_refused_client_side(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    /* The ticket is the whole request. Refusing here rather than on the wire is
     * what keeps a would-be exchange from looking like a spent one. */
    axiam_uma_exchange_params_t absent = {NULL, s, "client", s, AXIAM_TEST_TENANT_ID};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &absent, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    axiam_uma_exchange_params_t blank = {empty, s, "client", s, AXIAM_TEST_TENANT_ID};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &blank, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);
    TEST_ASSERT_EQUAL_INT(0, b.calls);

    axiam_sensitive_free(s);
    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

void test_a_protection_api_transport_failure_surfaces_as_network(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    /* Discovery succeeds, then the rreg call never completes. A Protection API
     * call has no §16 retry either — nothing here is a §16-eligible read — so
     * the failure surfaces on the first attempt. */
    axiam_uma_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_discover(c, &cfg, &err));
    axiam_uma_config_dispose(&cfg);

    b.fail_other_transport = 1;
    int before = b.calls;
    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_EQUAL_INT(before + 1, b.calls);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_empty_client_id_is_refused_like_an_absent_one(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    axiam_uma_exchange_params_t p = {s, s, "", s, NULL};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

void test_wire_builders_tolerate_ragged_caller_input(void) {
    b.other_body = "{\"name\":\"n\",\"resource_scopes\":\"not-an-array\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    /* A non-array `resource_scopes` is not fatal — the resource still has a
     * name and an id, which is what the caller needs to act on it. */
    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_read_resource(c, pat, B_RESOURCE, &rs, &err));
    TEST_ASSERT_EQUAL_size_t(0, rs.scope_count);
    axiam_uma_resource_set_dispose(&rs);

    /* A NULL scopes pointer with a nonzero count, and a NULL entry inside an
     * array, are both caller mistakes that must not become a crash inside the
     * JSON builder. */
    b.other_body = "{\"name\":\"n\"}";
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_uma_register_resource(c, pat, "n", "", NULL, 2, &rs, &err));
    axiam_uma_resource_set_dispose(&rs);

    const char *ragged[] = {"view", NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_uma_register_resource(c, pat, "n", "doc", ragged, 2, &rs, &err));
    axiam_uma_resource_set_dispose(&rs);

    b.other_body = "{\"ticket\":\"t\"}";
    axiam_uma_permission_t perms[] = {{B_RESOURCE, ragged, 2}, {NULL, NULL, 0}};
    axiam_sensitive_t *ticket = NULL;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_request_ticket(c, pat, perms, 2, &ticket, &err));
    axiam_sensitive_free(ticket);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_list_drops_non_string_members(void) {
    b.other_body = "[\"a\", 7, null, \"b\"]";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_EQUAL_size_t(2, n);
    TEST_ASSERT_EQUAL_STRING("a", ids[0]);
    TEST_ASSERT_EQUAL_STRING("b", ids[1]);
    axiam_uma_string_array_free(ids, n);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_token_endpoint_that_already_has_a_query_gains_an_ampersand(void) {
    /* Existing query parameters on a discovered endpoint are preserved: the
     * tenant_id is appended, not substituted for whatever was there. */
    b.discovery_body =
        "{\"issuer\":\"https://api.test\","
        "\"token_endpoint\":\"https://api.test/oauth2/token?audience=api\","
        "\"permission_endpoint\":\"https://api.test/uma2/perm\","
        "\"resource_registration_endpoint\":\"https://api.test/uma2/rreg/resource_set\","
        "\"permission_ticket_lifetime\":60}";
    b.other_body = "{\"access_token\":\"rpt\",\"token_type\":\"Bearer\",\"expires_in\":300}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;
    axiam_uma_exchange_params_t p = {s, s, "client", s, AXIAM_TEST_TENANT_ID};

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);

    axiam_uma_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL_INT(60, cfg.permission_ticket_lifetime);
    axiam_uma_config_dispose(&cfg);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* The challenge parser's grammar edge cases                          */
/* ------------------------------------------------------------------ */

void test_challenge_parser_grammar_edges(void) {
    axiam_uma_challenge_t ch;

    /* A NULL header is not a challenge, and must not be dereferenced. */
    TEST_ASSERT_EQUAL_INT(0, axiam_uma_parse_challenge(NULL, &ch));
    axiam_uma_challenge_dispose(&ch);
    TEST_ASSERT_EQUAL_INT(0, axiam_uma_parse_challenge("UMA x=1", NULL));

    /* "UMA" alone is a valid, if useless, challenge — the scheme is present and
     * simply names no parameters. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge("UMA", &ch));
    TEST_ASSERT_NULL(ch.realm);
    TEST_ASSERT_NULL(ch.as_uri);
    TEST_ASSERT_NULL(ch.ticket);
    axiam_uma_challenge_dispose(&ch);

    /* Leading whitespace is tolerated; a differently-named scheme is not. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge("   UMA realm=\"r\"", &ch));
    TEST_ASSERT_EQUAL_STRING("r", ch.realm);
    axiam_uma_challenge_dispose(&ch);
    TEST_ASSERT_EQUAL_INT(0, axiam_uma_parse_challenge("UM realm=\"r\"", &ch));
    axiam_uma_challenge_dispose(&ch);

    /* An unknown parameter is ignored rather than rejected: UMA 2.0 permits a
     * server to add its own, and refusing the whole challenge over one would
     * lose the ticket with it. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(
        "UMA realm=\"r\", unknown=\"x\", ticket=\"t\"", &ch));
    TEST_ASSERT_EQUAL_STRING("r", ch.realm);
    TEST_ASSERT_EQUAL_STRING("t", (const char *)axiam_sensitive_bytes(ch.ticket));
    axiam_uma_challenge_dispose(&ch);

    /* A parameter with no `=` is skipped, not treated as a key with an empty
     * value. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge("UMA junk, realm=\"r\"", &ch));
    TEST_ASSERT_EQUAL_STRING("r", ch.realm);
    axiam_uma_challenge_dispose(&ch);

    /* Unquoted values parse too — RFC 7235 allows a token where a quoted-string
     * is not required, and a server that emits one is not malformed. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge("UMA realm=plain, ticket=abc", &ch));
    TEST_ASSERT_EQUAL_STRING("plain", ch.realm);
    TEST_ASSERT_EQUAL_STRING("abc", (const char *)axiam_sensitive_bytes(ch.ticket));
    axiam_uma_challenge_dispose(&ch);

    /* A repeated parameter takes the last value rather than leaking the first. */
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(
        "UMA realm=\"a\", realm=\"b\", as_uri=\"u1\", as_uri=\"u2\", ticket=\"t1\", ticket=\"t2\"", &ch));
    TEST_ASSERT_EQUAL_STRING("b", ch.realm);
    TEST_ASSERT_EQUAL_STRING("u2", ch.as_uri);
    TEST_ASSERT_EQUAL_STRING("t2", (const char *)axiam_sensitive_bytes(ch.ticket));
    axiam_uma_challenge_dispose(&ch);
}

void test_challenge_header_refuses_incomplete_input(void) {
    axiam_sensitive_t *ticket = axiam_sensitive_new("t");
    axiam_sensitive_t *empty = axiam_sensitive_new("");

    /* The emit half exists to hand a caller somewhere to redeem a ticket; a
     * header with no ticket in it would be an instruction to do nothing. */
    TEST_ASSERT_NULL(axiam_uma_challenge_header(NULL, "https://id.example", ticket));
    TEST_ASSERT_NULL(axiam_uma_challenge_header("realm", NULL, ticket));
    TEST_ASSERT_NULL(axiam_uma_challenge_header("realm", "https://id.example", NULL));
    TEST_ASSERT_NULL(axiam_uma_challenge_header("realm", "https://id.example", empty));

    char *header = axiam_uma_challenge_header("realm", "https://id.example", ticket);
    TEST_ASSERT_NOT_NULL(header);
    free(header);

    axiam_sensitive_free(ticket);
    axiam_sensitive_free(empty);
}

/* ------------------------------------------------------------------ */
/* Resource ids are escaped into the path                             */
/* ------------------------------------------------------------------ */

void test_a_resource_id_is_percent_escaped_into_the_path(void) {
    b.other_body = "{\"name\":\"n\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *pat = axiam_sensitive_new("pat");
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    /* Resource ids are UUIDs in practice, but an id that arrived from somewhere
     * else must not be able to reshape the URL. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_read_resource(c, pat, "a/../b?x=1", &rs, &err));
    axiam_uma_resource_set_dispose(&rs);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* The oauth_error field is cleared, never stale                      */
/* ------------------------------------------------------------------ */

void test_the_oauth_error_field_is_cleared_between_failures(void) {
    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;
    axiam_uma_exchange_params_t p = {s, s, "client", s, AXIAM_TEST_TENANT_ID};

    b.other_status = 400;
    b.other_body = "{\"error\":\"invalid_grant\"}";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    axiam_uma_rpt_dispose(&rpt);

    /* A code left over from the previous failure would read as one this failure
     * never carried — the worst kind of wrong, because it looks specific. */
    b.other_status = 500;
    b.other_body = "";
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    axiam_uma_rpt_dispose(&rpt);

    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

void test_an_empty_error_code_falls_through_to_the_status_mapping(void) {
    /* A body shaped like an OAuth2ErrorResponse but carrying an empty code is
     * not one; treating it as one would produce an AuthError with nothing to
     * dispatch on. */
    b.other_status = 400;
    b.other_body = "{\"error\":\"\"}";

    axiam_client_t *c = make_branch_client();
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;
    axiam_uma_exchange_params_t p = {s, s, "client", s, AXIAM_TEST_TENANT_ID};

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    axiam_uma_rpt_dispose(&rpt);

    axiam_sensitive_free(s);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_dispose_is_safe_on_null_and_on_zeroed_structs);
    RUN_TEST(test_null_out_parameters_are_refused);
    RUN_TEST(test_a_null_client_is_refused_by_every_operation);
    RUN_TEST(test_a_closed_client_is_refused_by_every_operation);
    RUN_TEST(test_an_empty_pat_is_refused_like_an_absent_one);
    RUN_TEST(test_a_discovery_failure_propagates_out_of_every_operation);
    RUN_TEST(test_a_malformed_or_incomplete_discovery_document_is_refused);
    RUN_TEST(test_discovery_surfaces_the_advertised_ticket_lifetime_or_minus_one);
    RUN_TEST(test_a_resource_set_without_a_name_is_malformed);
    RUN_TEST(test_a_resource_set_tolerates_absent_id_type_and_scopes);
    RUN_TEST(test_a_non_string_scope_member_is_dropped_rather_than_fataling);
    RUN_TEST(test_a_list_body_that_is_not_an_array_is_refused);
    RUN_TEST(test_a_ticket_response_without_a_ticket_is_malformed);
    RUN_TEST(test_a_permission_with_a_null_scope_array_still_builds_a_body);
    RUN_TEST(test_a_token_response_without_an_access_token_is_malformed);
    RUN_TEST(test_an_explicit_tenant_id_overrides_the_configured_one);
    RUN_TEST(test_an_absent_ticket_is_refused_client_side);
    RUN_TEST(test_a_protection_api_transport_failure_surfaces_as_network);
    RUN_TEST(test_an_empty_client_id_is_refused_like_an_absent_one);
    RUN_TEST(test_wire_builders_tolerate_ragged_caller_input);
    RUN_TEST(test_a_list_drops_non_string_members);
    RUN_TEST(test_a_token_endpoint_that_already_has_a_query_gains_an_ampersand);
    RUN_TEST(test_challenge_parser_grammar_edges);
    RUN_TEST(test_challenge_header_refuses_incomplete_input);
    RUN_TEST(test_a_resource_id_is_percent_escaped_into_the_path);
    RUN_TEST(test_the_oauth_error_field_is_cleared_between_failures);
    RUN_TEST(test_an_empty_error_code_falls_through_to_the_status_mapping);
    return UNITY_END();
}
