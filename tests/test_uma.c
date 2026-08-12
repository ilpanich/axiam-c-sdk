/*
 * UMA 2.0 — CONTRACT.md §20.7 required assertions.
 *
 * Most of §20 is a list of things an SDK must NOT helpfully do, so most of
 * these tests assert an absence. The centrepiece is §20.2 rule 6: a permission
 * ticket is never retried.
 *
 * That rule is the one documented exception to §16, and the only way to assert
 * it is to count requests. A ticket is consumed BEFORE the exchange is
 * evaluated, so a failed exchange has already spent it — and under concurrency
 * a retry is precisely the second redemption ilpanich/axiam#302's measured
 * residual describes. "Exactly one request" is a security assertion here, not a
 * performance one.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

#define UMA_PAT      "pat-token-value"
#define UMA_TICKET   "ticket-value"
#define UMA_CLAIM    "claim-token-value"
#define UMA_RPT      "rpt-token-value"
#define UMA_RESOURCE "99999999-8888-7777-6666-555555555555"

#define DISCOVERY_BODY \
    "{\"issuer\":\"https://api.test\"," \
    "\"token_endpoint\":\"https://api.test/oauth2/token\"," \
    "\"introspection_endpoint\":\"https://api.test/oauth2/introspect\"," \
    "\"permission_endpoint\":\"https://api.test/uma2/perm\"," \
    "\"resource_registration_endpoint\":\"https://api.test/uma2/rreg/resource_set\"," \
    "\"jwks_uri\":\"https://api.test/.well-known/jwks.json\"," \
    "\"grant_types_supported\":[\"" AXIAM_UMA_TICKET_GRANT_TYPE "\"]," \
    "\"uma_profiles_supported\":[]," \
    "\"permission_ticket_lifetime\":60}"

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

#define MAX_CALLS 16

typedef struct {
    int discovery_calls;
    int rreg_calls;
    int perm_calls;
    int token_calls;

    long rreg_status;
    const char *rreg_body;
    long perm_status;
    const char *perm_body;
    long token_status;
    const char *token_body;
    /* When nonzero, the token endpoint reports a transport failure instead of
     * an HTTP response — the timeout case §20.2 rule 6 names explicitly. */
    int token_transport_fails;

    /* Every request that reached the transport, in order. */
    char methods[MAX_CALLS][8];
    char urls[MAX_CALLS][512];
    char auth[MAX_CALLS][512];
    char bodies[MAX_CALLS][2048];
    int n_calls;
} uma_state_t;

static uma_state_t g;

static void record(const axiam_http_request_t *req) {
    if (g.n_calls >= MAX_CALLS) return;
    int i = g.n_calls++;
    snprintf(g.methods[i], sizeof(g.methods[i]), "%s", req->method ? req->method : "");
    snprintf(g.urls[i], sizeof(g.urls[i]), "%s", req->url ? req->url : "");
    const char *a = axiam_kv_get(req->headers, "Authorization");
    snprintf(g.auth[i], sizeof(g.auth[i]), "%s", a ? a : "");
    snprintf(g.bodies[i], sizeof(g.bodies[i]), "%s", req->body ? req->body : "");
}

static int uma_transport_fake(void *ctx, const axiam_http_request_t *req,
                              axiam_http_response_t *resp) {
    (void)ctx;
    record(req);
    const char *url = req->url ? req->url : "";

    if (strstr(url, "uma2-configuration")) {
        g.discovery_calls++;
        resp_fill(resp, 200, DISCOVERY_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/oauth2/token")) {
        g.token_calls++;
        if (g.token_transport_fails) {
            memset(resp, 0, sizeof(*resp));
            resp->transport_err = 7;
            resp->transport_msg = strdup("connection refused");
            return -1;
        }
        resp_fill(resp, g.token_status ? g.token_status : 200,
                  g.token_body ? g.token_body : "", NULL);
        return 0;
    }
    if (strstr(url, "/uma2/perm")) {
        g.perm_calls++;
        resp_fill(resp, g.perm_status ? g.perm_status : 201, g.perm_body ? g.perm_body : "", NULL);
        return 0;
    }
    if (strstr(url, "/uma2/rreg/resource_set")) {
        g.rreg_calls++;
        resp_fill(resp, g.rreg_status ? g.rreg_status : 200, g.rreg_body ? g.rreg_body : "", NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, uma_transport_fake, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
}

void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* §20.1 the Protection API                                           */
/* ------------------------------------------------------------------ */

void test_registration_round_trips_and_the_id_is_a_ticket_resource_id(void) {
    g.rreg_status = 201;
    g.rreg_body = "{\"_id\":\"" UMA_RESOURCE "\",\"name\":\"invoice-7\","
                  "\"type\":\"document\",\"resource_scopes\":[\"view\"]}";
    g.perm_body = "{\"ticket\":\"" UMA_TICKET "\"}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_uma_register_resource(c, pat, "invoice-7", "document", scopes, 1, &rs, &err));
    TEST_ASSERT_EQUAL_STRING(UMA_RESOURCE, rs.id);
    TEST_ASSERT_EQUAL_size_t(1, rs.scope_count);
    TEST_ASSERT_EQUAL_STRING("view", rs.scopes[0]);

    /* §20.1: `_id` IS the AXIAM resource id, not a parallel identifier — it
     * goes straight back out as a requested permission with no translation. */
    axiam_uma_permission_t perm = {rs.id, scopes, 1};
    axiam_sensitive_t *ticket = NULL;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_NOT_NULL(ticket);
    TEST_ASSERT_EQUAL_STRING(UMA_TICKET, (const char *)axiam_sensitive_bytes(ticket));

    /* The permission body names the id verbatim. */
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[g.n_calls - 1], UMA_RESOURCE));

    axiam_sensitive_free(ticket);
    axiam_uma_resource_set_dispose(&rs);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_omitted_type_is_left_out_rather_than_sent_empty(void) {
    g.rreg_status = 201;
    g.rreg_body = "{\"_id\":\"" UMA_RESOURCE "\",\"name\":\"invoice-7\",\"resource_scopes\":[\"view\"]}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_uma_register_resource(c, pat, "invoice-7", NULL, scopes, 1, &rs, &err));

    /* §12.1: an absent optional field is omitted, never sent empty — here so
     * the server applies its own `uma_resource` default rather than storing "". */
    TEST_ASSERT_NULL(strstr(g.bodies[g.n_calls - 1], "\"type\""));

    axiam_uma_resource_set_dispose(&rs);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_update_sends_exactly_the_scopes_given_with_no_read_first(void) {
    g.rreg_body = "{\"_id\":\"" UMA_RESOURCE "\",\"name\":\"invoice-7\","
                  "\"type\":\"document\",\"resource_scopes\":[\"view\"]}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_uma_update_resource(c, pat, UMA_RESOURCE, "invoice-7", "document", scopes, 1, &rs, &err));

    /* §20.2 rule 8: the update replaces the scope list. A read-modify-write
     * would show up here as a second rreg call, and would silently make
     * removing a scope impossible through the SDK. */
    TEST_ASSERT_EQUAL_INT(1, g.rreg_calls);
    TEST_ASSERT_EQUAL_STRING("PUT", g.methods[g.n_calls - 1]);
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[g.n_calls - 1], "\"resource_scopes\":[\"view\"]"));

    axiam_uma_resource_set_dispose(&rs);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_undeclared_scope_surfaces_the_400_unchanged(void) {
    g.perm_status = 400;
    g.perm_body = "{\"message\":\"scope not declared on resource\"}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"delete"};
    axiam_uma_permission_t perm = {UMA_RESOURCE, scopes, 1};
    axiam_sensitive_t *ticket = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_NULL(ticket);
    TEST_ASSERT_EQUAL_INT(1, g.perm_calls);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_token_that_is_not_a_pat_surfaces_the_403(void) {
    g.perm_status = 403;
    g.perm_body = "{\"error\":\"authorization_denied\","
                  "\"message\":\"the protection API requires the 'uma_protection' scope\"}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *not_a_pat = axiam_sensitive_new("a-user-token");
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_permission_t perm = {UMA_RESOURCE, scopes, 1};
    axiam_sensitive_t *ticket = NULL;
    /* §20.2 rule 1: a user access token is not a PAT. The SDK does not
     * pre-judge the token's subject kind — it lets the server's refusal through
     * as the §2 mapping for a 403, rather than an OAuth2 protocol error (those
     * rows belong to the token endpoint, §20.4). */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTHZ,
        axiam_uma_request_ticket(c, not_a_pat, &perm, 1, &ticket, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);

    axiam_sensitive_free(not_a_pat);
    axiam_client_free(c);
}

void test_the_protection_api_carries_the_pat(void) {
    g.rreg_body = "[\"" UMA_RESOURCE "\"]";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_STRING(UMA_RESOURCE, ids[0]);

    /* §20.2 rule 1: a minted ticket is bound to the client_id that minted it,
     * so the Protection API credential is the caller's explicit PAT. */
    TEST_ASSERT_EQUAL_STRING("Bearer " UMA_PAT, g.auth[g.n_calls - 1]);

    axiam_uma_string_array_free(ids, n);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_an_absent_pat_is_refused_client_side_with_no_wire_call(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_delete_resource(c, NULL, UMA_RESOURCE, &err));
    /* An omitted PAT must not become "send it with whatever credential is
     * lying around", nor a request with no credential at all. Discovery may
     * have run; the rreg call must not have. */
    TEST_ASSERT_EQUAL_INT(0, g.rreg_calls);

    axiam_client_free(c);
}

void test_read_and_delete_use_their_own_methods(void) {
    g.rreg_body = "{\"_id\":\"" UMA_RESOURCE "\",\"name\":\"invoice-7\","
                  "\"type\":\"document\",\"resource_scopes\":[\"view\",\"edit\"]}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_uma_resource_set_t rs;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_read_resource(c, pat, UMA_RESOURCE, &rs, &err));
    /* §20.6: scopes and the resource id are NOT sensitive and must stay
     * readable — an application cannot act on a resource it may not inspect. */
    TEST_ASSERT_EQUAL_size_t(2, rs.scope_count);
    TEST_ASSERT_EQUAL_STRING("GET", g.methods[g.n_calls - 1]);
    TEST_ASSERT_NOT_NULL(strstr(g.urls[g.n_calls - 1], UMA_RESOURCE));

    g.rreg_status = 204;
    g.rreg_body = "";
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_delete_resource(c, pat, UMA_RESOURCE, &err));
    TEST_ASSERT_EQUAL_STRING("DELETE", g.methods[g.n_calls - 1]);

    axiam_uma_resource_set_dispose(&rs);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_discovery_is_fetched_once_and_cached(void) {
    g.rreg_body = "[]";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    char **ids = NULL;
    size_t n = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    axiam_uma_string_array_free(ids, n);
    ids = NULL;
    n = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_list_resources(c, pat, &ids, &n, &err));
    axiam_uma_string_array_free(ids, n);

    /* An endpoint map is not a credential; re-fetching it on every guarded
     * request is a self-inflicted round trip. */
    TEST_ASSERT_EQUAL_INT(1, g.discovery_calls);

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §20.2 rule 6 — the ticket grant is never retried                   */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t exchange(axiam_client_t *c, axiam_uma_rpt_t *rpt,
                                   axiam_error_t *err) {
    axiam_sensitive_t *ticket = axiam_sensitive_new(UMA_TICKET);
    axiam_sensitive_t *claim = axiam_sensitive_new(UMA_CLAIM);
    axiam_sensitive_t *secret = axiam_sensitive_new("resource-server-secret");
    axiam_uma_exchange_params_t p = {ticket, claim, "orders-resource-server", secret, NULL};
    axiam_error_kind_t kind = axiam_uma_exchange_ticket(c, &p, rpt, err);
    axiam_sensitive_free(ticket);
    axiam_sensitive_free(claim);
    axiam_sensitive_free(secret);
    return kind;
}

void test_the_ticket_grant_is_not_retried_on_a_5xx(void) {
    g.token_status = 500;
    g.token_body = "";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, exchange(c, &rpt, &err));
    /* Retrying a spent ticket is the concurrent redemption
     * ilpanich/axiam#302 describes. */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_the_ticket_grant_is_not_retried_on_a_transport_failure(void) {
    g.token_transport_fails = 1;

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, exchange(c, &rpt, &err));
    /* §20.2 rule 6 names the timeout explicitly: a request that never answered
     * may well have reached the server and spent the ticket. Silence is not
     * evidence it did not. */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_the_ticket_grant_is_not_retried_on_invalid_grant(void) {
    g.token_status = 400;
    g.token_body = "{\"error\":\"invalid_grant\",\"error_description\":\"already used\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, &rpt, &err));
    /* §20.4: unknown, expired, already-used and wrong-client all collapse into
     * this one code, and the SDK must not re-derive which — the server withheld
     * the distinction because it lets a caller probe for live ticket handles. */
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_a_403_access_denied_is_surfaced_and_not_auto_narrowed(void) {
    g.token_status = 403;
    g.token_body = "{\"error\":\"access_denied\","
                   "\"error_description\":\"not authorized for every requested permission\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    axiam_error_kind_t kind = exchange(c, &rpt, &err);

    /* §20.4: access_denied answers HTTP 403 here where RFC 8628's answers 400.
     * Dispatching on the `error` field rather than the status is what keeps
     * this correct — the plain §2 status mapping would have produced
     * AXIAM_ERR_AUTHZ with no code to read. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, kind);
    TEST_ASSERT_EQUAL_STRING("access_denied", err.oauth_error);
    /* §20.2 rule 3: a partial grant is refused whole. Whether two-of-three
     * permissions is useful is the application's judgement, not this SDK's. */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_a_non_oauth2_error_body_still_gets_the_status_mapping(void) {
    g.token_status = 502;
    g.token_body = "<html>gateway</html>";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    /* The widened `error`-field dispatch must not turn a proxy's HTML 502 into
     * an authentication error with an empty code. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, exchange(c, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §20.1/§20.2 — what the grant sends, and what the result is not     */
/* ------------------------------------------------------------------ */

void test_the_grant_sends_the_required_claim_token_and_its_format(void) {
    g.token_body = "{\"access_token\":\"" UMA_RPT "\",\"token_type\":\"Bearer\",\"expires_in\":300}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, &rpt, &err));

    const char *body = g.bodies[g.n_calls - 1];
    TEST_ASSERT_NOT_NULL(strstr(body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket"));
    TEST_ASSERT_NOT_NULL(strstr(body, "ticket=" UMA_TICKET));
    /* §20.2 rule 2: required, never defaulted — it is the only channel that
     * names the requesting party, and defaulting it to the resource server's
     * own PAT would mint an RPT for the resource server instead of the user. */
    TEST_ASSERT_NOT_NULL(strstr(body, "claim_token=" UMA_CLAIM));
    TEST_ASSERT_NOT_NULL(strstr(body, "claim_token_format="));
    /* A token-endpoint grant: the client authenticates through the body, and
     * carries no Authorization header. */
    TEST_ASSERT_NOT_NULL(strstr(body, "client_secret=resource-server-secret"));
    TEST_ASSERT_EQUAL_STRING("", g.auth[g.n_calls - 1]);
    /* §12.1 note 2, which §20.1 applies to this grant unchanged. */
    TEST_ASSERT_NOT_NULL(strstr(g.urls[g.n_calls - 1], "tenant_id=" AXIAM_TEST_TENANT_ID));

    TEST_ASSERT_EQUAL_STRING(UMA_RPT, (const char *)axiam_sensitive_bytes(rpt.access_token));
    TEST_ASSERT_EQUAL_INT(300, rpt.expires_in);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_an_absent_claim_token_is_refused_client_side_with_no_wire_call(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_sensitive_t *ticket = axiam_sensitive_new(UMA_TICKET);
    axiam_sensitive_t *secret = axiam_sensitive_new("resource-server-secret");
    axiam_uma_exchange_params_t p = {ticket, NULL, "orders-resource-server", secret, NULL};
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    /* Refusing client-side keeps the ticket unspent for a request that could
     * not have succeeded (§20.2 rules 2 and 6 together). */
    TEST_ASSERT_EQUAL_INT(0, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_sensitive_free(ticket);
    axiam_sensitive_free(secret);
    axiam_client_free(c);
}

void test_a_public_client_is_refused_client_side(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_sensitive_t *ticket = axiam_sensitive_new(UMA_TICKET);
    axiam_sensitive_t *claim = axiam_sensitive_new(UMA_CLAIM);
    axiam_uma_exchange_params_t p = {ticket, claim, "orders-resource-server", NULL, NULL};
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_uma_exchange_ticket(c, &p, &rpt, &err));
    TEST_ASSERT_EQUAL_INT(0, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_sensitive_free(ticket);
    axiam_sensitive_free(claim);
    axiam_client_free(c);
}

void test_a_tenant_slug_cannot_be_substituted_for_the_uuid(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, uma_transport_fake, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    axiam_uma_rpt_t rpt;

    /* §12.3 rule 4: the query parameter is a UUID and a slug is not one.
     * Failing here rather than on the wire is what keeps the ticket unspent. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, &rpt, &err));
    TEST_ASSERT_EQUAL_INT(0, g.token_calls);

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

void test_a_server_sent_refresh_token_is_not_surfaced(void) {
    /* Deliberately hostile fixture: the grant issues no refresh token, so the
     * result type has no member for one and there is nothing to synthesise. */
    g.token_body = "{\"access_token\":\"" UMA_RPT "\",\"token_type\":\"Bearer\","
                   "\"expires_in\":300,\"refresh_token\":\"should-not-exist\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, &rpt, &err));
    TEST_ASSERT_EQUAL_STRING(UMA_RPT, (const char *)axiam_sensitive_bytes(rpt.access_token));
    /* sizeof is the assertion: axiam_uma_rpt_t has exactly three members and no
     * room for a fourth the caller could mistake for a refresh token. */
    TEST_ASSERT_EQUAL_size_t(sizeof(axiam_sensitive_t *) + sizeof(char *) + sizeof(long),
                             sizeof(axiam_uma_rpt_t));

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §20.3 the challenge helpers                                        */
/* ------------------------------------------------------------------ */

void test_parses_a_well_formed_challenge(void) {
    axiam_uma_challenge_t ch;
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(
        "UMA realm=\"example\", as_uri=\"https://id.example\", ticket=\"" UMA_TICKET "\"", &ch));
    TEST_ASSERT_EQUAL_STRING("example", ch.realm);
    TEST_ASSERT_EQUAL_STRING("https://id.example", ch.as_uri);
    TEST_ASSERT_EQUAL_STRING(UMA_TICKET, (const char *)axiam_sensitive_bytes(ch.ticket));
    axiam_uma_challenge_dispose(&ch);
}

void test_rejects_a_scheme_that_merely_starts_with_uma(void) {
    axiam_uma_challenge_t ch;
    TEST_ASSERT_EQUAL_INT(0, axiam_uma_parse_challenge("Bearer realm=\"example\"", &ch));
    axiam_uma_challenge_dispose(&ch);
    TEST_ASSERT_EQUAL_INT(0, axiam_uma_parse_challenge("UMAX realm=\"example\"", &ch));
    axiam_uma_challenge_dispose(&ch);
}

void test_parsing_performs_no_exchange(void) {
    axiam_client_t *c = make_client();
    axiam_uma_challenge_t ch;

    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(
        "UMA realm=\"example\", as_uri=\"https://api.test\", ticket=\"" UMA_TICKET "\"", &ch));

    /* §20.3: the as_uri names an authorization server this client has not
     * chosen to trust. Auto-exchanging would send the requesting party's
     * claim_token to whatever host answered the 401. */
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_uma_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_round_trips_through_the_emit_half(void) {
    axiam_sensitive_t *ticket = axiam_sensitive_new(UMA_TICKET);
    char *header = axiam_uma_challenge_header("example", "https://id.example", ticket);
    TEST_ASSERT_NOT_NULL(header);

    axiam_uma_challenge_t ch;
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge(header, &ch));
    TEST_ASSERT_EQUAL_STRING("https://id.example", ch.as_uri);
    TEST_ASSERT_EQUAL_STRING(UMA_TICKET, (const char *)axiam_sensitive_bytes(ch.ticket));

    axiam_uma_challenge_dispose(&ch);
    free(header);
    axiam_sensitive_free(ticket);
}

/* ------------------------------------------------------------------ */
/* §20.6 redaction                                                    */
/* ------------------------------------------------------------------ */

void test_no_secret_renders_through_the_public_surface(void) {
    g.perm_body = "{\"ticket\":\"" UMA_TICKET "\"}";
    g.token_body = "{\"access_token\":\"" UMA_RPT "\",\"token_type\":\"Bearer\",\"expires_in\":300}";

    axiam_client_t *c = make_client();
    axiam_sensitive_t *pat = axiam_sensitive_new(UMA_PAT);
    axiam_error_t err;
    axiam_error_reset(&err);

    const char *scopes[] = {"view"};
    axiam_uma_permission_t perm = {UMA_RESOURCE, scopes, 1};
    axiam_sensitive_t *ticket = NULL;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_request_ticket(c, pat, &perm, 1, &ticket, &err));

    axiam_uma_rpt_t rpt;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, &rpt, &err));

    axiam_uma_challenge_t ch;
    TEST_ASSERT_EQUAL_INT(1, axiam_uma_parse_challenge("UMA ticket=\"" UMA_TICKET "\"", &ch));

    /* §20.6: the ticket's 60-second lifetime is exactly what invites treating
     * it as harmless. For those 60 seconds it is the credential that converts
     * into an RPT. The only public rendering of any of them is the placeholder. */
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(ticket));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(rpt.access_token));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(ch.ticket));

    axiam_uma_challenge_dispose(&ch);
    axiam_uma_rpt_dispose(&rpt);
    axiam_sensitive_free(ticket);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

void test_a_failed_exchange_never_echoes_the_ticket_or_claim_token(void) {
    g.token_status = 400;
    g.token_body = "{\"error\":\"invalid_grant\",\"error_description\":\"" UMA_TICKET " is spent\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_uma_rpt_t rpt;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, &rpt, &err));

    /* A failed exchange is exactly when a naive implementation copies the
     * server's free text — which here contains the ticket — into its own error
     * message. Only the bounded `error` code is lifted out. */
    TEST_ASSERT_NULL(strstr(err.message, UMA_TICKET));
    TEST_ASSERT_NULL(strstr(err.message, UMA_CLAIM));
    TEST_ASSERT_NULL(strstr(err.oauth_error, UMA_TICKET));

    axiam_uma_rpt_dispose(&rpt);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_registration_round_trips_and_the_id_is_a_ticket_resource_id);
    RUN_TEST(test_an_omitted_type_is_left_out_rather_than_sent_empty);
    RUN_TEST(test_an_update_sends_exactly_the_scopes_given_with_no_read_first);
    RUN_TEST(test_an_undeclared_scope_surfaces_the_400_unchanged);
    RUN_TEST(test_a_token_that_is_not_a_pat_surfaces_the_403);
    RUN_TEST(test_the_protection_api_carries_the_pat);
    RUN_TEST(test_an_absent_pat_is_refused_client_side_with_no_wire_call);
    RUN_TEST(test_read_and_delete_use_their_own_methods);
    RUN_TEST(test_discovery_is_fetched_once_and_cached);
    RUN_TEST(test_the_ticket_grant_is_not_retried_on_a_5xx);
    RUN_TEST(test_the_ticket_grant_is_not_retried_on_a_transport_failure);
    RUN_TEST(test_the_ticket_grant_is_not_retried_on_invalid_grant);
    RUN_TEST(test_a_403_access_denied_is_surfaced_and_not_auto_narrowed);
    RUN_TEST(test_a_non_oauth2_error_body_still_gets_the_status_mapping);
    RUN_TEST(test_the_grant_sends_the_required_claim_token_and_its_format);
    RUN_TEST(test_an_absent_claim_token_is_refused_client_side_with_no_wire_call);
    RUN_TEST(test_a_public_client_is_refused_client_side);
    RUN_TEST(test_a_tenant_slug_cannot_be_substituted_for_the_uuid);
    RUN_TEST(test_a_server_sent_refresh_token_is_not_surfaced);
    RUN_TEST(test_parses_a_well_formed_challenge);
    RUN_TEST(test_rejects_a_scheme_that_merely_starts_with_uma);
    RUN_TEST(test_parsing_performs_no_exchange);
    RUN_TEST(test_round_trips_through_the_emit_half);
    RUN_TEST(test_no_secret_renders_through_the_public_surface);
    RUN_TEST(test_a_failed_exchange_never_echoes_the_ticket_or_claim_token);
    return UNITY_END();
}
