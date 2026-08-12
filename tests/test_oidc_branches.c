/*
 * §12 / §12.7 / §14 / §15 — the refusal paths.
 *
 * The suites next door assert what the SDK does when a server behaves. This one
 * asserts what it does when nothing does: NULL out-parameters, a closed client,
 * a discovery document missing the endpoints everything else reads, a token
 * endpoint that answers HTML, a transport that never connects.
 *
 * Two properties are worth stating, because both are easy to lose and neither
 * is visible from a happy-path test:
 *
 *   - EVERY refusal is a typed error, never a crash and never a silent success.
 *     A resource server that mis-parses a logout token must reject it, not
 *     segfault on the socket the OP is still holding open.
 *   - Every out-parameter is left ZEROED on failure, so a caller can dispose
 *     unconditionally on the error path. That is what the _dispose contract in
 *     oidc.h promises, and the only way to check it is to look afterwards.
 */

#include "unity.h"
#include "oidc_test_util.h"

/* A discovery document with only the four members parse_discovery requires —
 * no introspection, revocation, end_session or device endpoint. */
#define MINIMAL_DISCOVERY                                                   \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                      \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","        \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                    \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\"}"

static int g_serve_minimal_discovery;
static int g_discovery_status;
static const char *g_discovery_body;
static int g_discovery_transport_fails;

/* A transport that can also break discovery itself — the one endpoint the
 * shared harness always serves successfully. */
static int branches_transport(void *ctx, const axiam_http_request_t *req,
                              axiam_http_response_t *resp) {
    if (strstr(req->url ? req->url : "", "/.well-known/openid-configuration")) {
        oidc_record(req);
        g_oidc.discovery_calls++;
        if (g_discovery_transport_fails) {
            memset(resp, 0, sizeof(*resp));
            resp->transport_err = 7;
            resp->transport_msg = strdup("connection refused");
            return -1;
        }
        resp_fill(resp, g_discovery_status ? g_discovery_status : 200,
                  g_discovery_body ? g_discovery_body
                                   : (g_serve_minimal_discovery ? MINIMAL_DISCOVERY
                                                                : OIDC_DISCOVERY_BODY),
                  NULL);
        return 0;
    }
    return oidc_fake_transport(ctx, req, resp);
}

static axiam_client_t *branches_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_transport(cfg, branches_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (c) {
        c->sleep_fn = oidc_fake_sleep;
        c->clock_fn = oidc_fake_clock;
    }
    return c;
}

void setUp(void) {
    oidc_reset();
    g_serve_minimal_discovery = 0;
    g_discovery_status = 0;
    g_discovery_body = NULL;
    g_discovery_transport_fails = 0;
}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* NULL out-parameters                                                */
/* ------------------------------------------------------------------ */

void test_every_entry_point_refuses_a_null_out_parameter(void) {
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_begin(c, NULL, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_exchange(c, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_refresh(c, tok, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_login_client_credentials(c, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(c, tok, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_complete(c, "c", "s", NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_poll(c, tok, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_device_login(c, NULL, NULL, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(c, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_verify_logout_token(c, "tok", NULL, &err));
    /* Not one of those reached the wire. */
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_a_null_client_is_refused_rather_than_dereferenced(void) {
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_token_set_t set;
    axiam_introspection_result_t ir;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_token_exchange_params_t xp = {0};
    xp.subject_token = tok;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(NULL, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_refresh(NULL, tok, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_login_client_credentials(NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(NULL, tok, NULL, NULL, &ir, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_revoke(NULL, tok, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(NULL, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(NULL, &xp, NULL, &err));
    axiam_sensitive_free(tok);
}

/* ------------------------------------------------------------------ */
/* §18.1 rule 4 — use after close                                     */
/* ------------------------------------------------------------------ */

void test_every_entry_point_refuses_a_closed_client(void) {
    /* §18.1 rule 4: use after close is an ERROR, not undefined. The transport
     * pointer is gone by then, so anything that slipped past this check would
     * dereference a freed libcurl context. */
    axiam_client_t *c = branches_client();
    axiam_client_close(c);
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_oidc_config_t cfg;
    axiam_oidc_token_set_t set;
    axiam_introspection_result_t ir;
    axiam_sso_start_result_t ss;
    axiam_sso_complete_result_t sc;
    axiam_device_authorization_t da;
    axiam_exchanged_token_t xt;
    axiam_verified_logout_token_t vl;
    axiam_oidc_exchange_params_t ep = {0};
    ep.code = "c";
    ep.code_verifier = tok;
    ep.redirect_uri = OIDC_REDIRECT_URI;
    ep.nonce = "n";
    axiam_token_exchange_params_t xp = {0};
    xp.subject_token = tok;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_exchange(c, &ep, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_refresh(c, tok, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(c, tok, NULL, NULL, &ir, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_revoke(c, tok, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", &ss, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_complete(c, "c", "s", &sc, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &da, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_poll(c, tok, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(c, &xp, &xt, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_verify_logout_token(c, "tok", &vl, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Discovery failures                                                 */
/* ------------------------------------------------------------------ */

void test_a_non_json_discovery_body_is_a_network_error(void) {
    g_discovery_body = "<html>gateway timeout</html>";
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_NULL(cfg.token_endpoint);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_discovery_document_missing_a_required_endpoint_is_refused(void) {
    /* The four §12 cannot work without. Failing here beats failing later with a
     * NULL endpoint nobody can trace back to the document. */
    g_discovery_body = "{\"issuer\":\"" OIDC_ISSUER "\"}";
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "token_endpoint"));
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_discovery_transport_failure_propagates(void) {
    g_discovery_transport_fails = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
    /* And the failure does not poison the cache: a later success still works. */
    g_discovery_transport_fails = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_discovery_error_status_propagates(void) {
    g_discovery_status = 500;
    g_discovery_body = "{}";
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Endpoints the document did not advertise                           */
/* ------------------------------------------------------------------ */

void test_device_authorize_without_an_advertised_endpoint_is_refused(void) {
    g_serve_minimal_discovery = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "device_authorization_endpoint"));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.device_authorize_calls);
    axiam_client_free(c);
}

void test_logout_url_without_an_advertised_end_session_endpoint_is_null(void) {
    /* §12.7.2 rule 1 leaves no fallback: an SDK that concatenated one onto the
     * issuer would work against AXIAM and break against every other OP. NULL is
     * the honest answer. */
    g_serve_minimal_discovery = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_NULL(axiam_logout_url(&cfg, "tok", NULL, NULL));
    TEST_ASSERT_NULL(axiam_logout_url(NULL, "tok", NULL, NULL));
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_introspect_falls_back_to_the_base_url_when_discovery_omits_the_endpoint(void) {
    /* Joined onto the CLIENT'S BASE URL, never onto the issuer — the issuer may
     * legitimately be some other origin behind a proxy (§12.3 rule 6). */
    g_serve_minimal_discovery = 1;
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":true}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_introspection_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_introspect(c, tok, NULL, NULL, &r, &err));
    int i = oidc_last_call("/oauth2/introspect");
    TEST_ASSERT_EQUAL_INT(0, strncmp(g_oidc.urls[i], OIDC_BASE, strlen(OIDC_BASE)));
    axiam_introspection_result_dispose(&r);
    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Malformed and unhelpful server answers                             */
/* ------------------------------------------------------------------ */

void test_a_token_response_without_an_access_token_is_malformed(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200, "{\"token_type\":\"Bearer\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_login_client_credentials(c, "openid", NULL, &set, &err));
    /* Left zeroed, so the caller can dispose unconditionally. */
    TEST_ASSERT_NULL(set.access_token);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_a_non_oauth2_error_body_falls_back_to_the_status_mapping(void) {
    /* §12.3 rule 3 dispatches on the `error` field — but a proxy's HTML 502 has
     * none, and inventing an auth error with no code would be worse than the §2
     * status mapping it deserves. */
    g_oidc.token_script[0] = (oidc_answer_t){502, "<html>bad gateway</html>", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    axiam_client_free(c);
}

void test_an_error_body_without_a_description_still_carries_its_code(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"invalid_client\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_client", err.oauth_error);
    axiam_client_free(c);
}

void test_a_token_endpoint_transport_failure_is_a_network_error(void) {
    g_oidc.token_script[0] = (oidc_answer_t){0, NULL, 1};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("connection refused", err.message);
    axiam_client_free(c);
}

void test_a_malformed_device_authorization_response_is_refused(void) {
    g_oidc.device_answer = (oidc_answer_t){200, "{\"user_code\":\"ABCD\"}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_NULL(a.device_code);
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_a_device_authorization_error_and_transport_failure_propagate(void) {
    g_oidc.device_answer = (oidc_answer_t){400, "{\"error\":\"invalid_client\"}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_client", err.oauth_error);
    axiam_client_free(c);

    oidc_reset();
    g_oidc.device_answer = (oidc_answer_t){0, NULL, 1};
    c = branches_client();
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    axiam_client_free(c);
}

void test_device_login_surfaces_an_authorize_failure_without_polling(void) {
    g_oidc.device_answer = (oidc_answer_t){400, "{\"error\":\"invalid_client\"}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_a_malformed_sso_response_is_refused(void) {
    g_oidc.sso_start_answer = (oidc_answer_t){200, "{\"state\":\"s\"}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sso_start_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", &r, &err));
    TEST_ASSERT_NULL(r.authorize_url);
    axiam_sso_start_result_dispose(&r);

    oidc_reset();
    g_oidc.sso_start_answer = (oidc_answer_t){200, "not json", 0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", &r, &err));

    oidc_reset();
    g_oidc.sso_complete_answer = (oidc_answer_t){200, "{\"user_id\":\"u\"}", 0};
    axiam_sso_complete_result_t sc;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_complete(c, "c", "s", &sc, &err));
    axiam_sso_complete_result_dispose(&sc);

    oidc_reset();
    g_oidc.sso_complete_answer = (oidc_answer_t){200, "not json", 0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_complete(c, "c", "s", &sc, &err));
    axiam_client_free(c);
}

void test_an_sso_error_status_and_transport_failure_propagate(void) {
    g_oidc.sso_start_answer = (oidc_answer_t){403, "{}", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sso_start_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTHZ, axiam_sso_start(c, "f", "r", &r, &err));

    oidc_reset();
    g_oidc.sso_complete_answer = (oidc_answer_t){0, NULL, 1};
    axiam_sso_complete_result_t sc;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_complete(c, "c", "s", &sc, &err));
    axiam_client_free(c);
}

void test_a_malformed_introspection_body_is_refused(void) {
    g_oidc.introspect_answer = (oidc_answer_t){200, "not json", 0};
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_introspection_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(c, tok, NULL, NULL, &r, &err));

    oidc_reset();
    g_oidc.introspect_answer = (oidc_answer_t){0, NULL, 1};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(c, tok, NULL, NULL, &r, &err));

    oidc_reset();
    g_oidc.revoke_answer = (oidc_answer_t){0, NULL, 1};
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_revoke(c, tok, NULL, NULL, &err));

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_a_malformed_token_exchange_response_is_refused(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200, "{\"token_type\":\"Bearer\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("s");
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    p.audience = "https://svc.test";
    p.resource = "https://svc.test/api";
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(c, &p, &t, &err));
    /* The optional pair still went out when supplied. */
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/token", "audience"));
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/token", "resource"));
    TEST_ASSERT_NULL(t.access_token);
    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Missing caller input                                               */
/* ------------------------------------------------------------------ */

void test_missing_credentials_are_refused_before_any_request(void) {
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_exchanged_token_t xt;
    axiam_verified_logout_token_t vl;
    axiam_sensitive_t *empty = axiam_sensitive_new("");

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_refresh(c, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_refresh(c, empty, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, NULL, NULL, &set, &err));

    axiam_token_exchange_params_t xp = {0};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_token_exchange(c, &xp, &xt, &err));

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, NULL, &vl, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, "", &vl, &err));
    /* A token that is not even three dot-separated parts: §12.3 rule 3 folds
     * that into `invalid_alg`, because the algorithm cannot be established. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, "garbage", &vl, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_ALG, err.id_token_reason);

    axiam_sensitive_free(empty);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_exchange_refuses_incomplete_parameters(void) {
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("v");
    axiam_oidc_token_set_t set;

    axiam_oidc_exchange_params_t p = {0};
    p.redirect_uri = OIDC_REDIRECT_URI;
    p.code_verifier = verifier;
    p.nonce = "n";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err)); /* no code */

    p.code = "c";
    p.code_verifier = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err)); /* no verifier */

    p.code_verifier = verifier;
    p.redirect_uri = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err)); /* no redirect */

    /* An empty string is not a value. Sending `code=` or `redirect_uri=` would
     * be an `invalid_grant` the caller has to decode; refusing here names it. */
    p.redirect_uri = "";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));
    p.redirect_uri = OIDC_REDIRECT_URI;
    p.code = "";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));
    p.code = "c";
    p.nonce = "";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));

    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

void test_begin_refuses_a_missing_configuration_or_redirect_uri(void) {
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);
    axiam_authorization_request_t req;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_oidc_begin(c, NULL, OIDC_REDIRECT_URI, NULL, &req, &err));
    /* A document that carries no authorization_endpoint cannot produce a URL,
     * and guessing one from the issuer is the §12.7.2 rule 1 mistake in
     * another place. */
    {
        axiam_oidc_config_t bare = {0};
        TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
            axiam_oidc_begin(c, &bare, OIDC_REDIRECT_URI, NULL, &req, &err));
    }
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_begin(c, &cfg, NULL, NULL, &req, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_begin(c, &cfg, "", NULL, &req, &err));

    /* A caller who already asked for `openid` does not get it twice. */
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid email", &req, &err));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "scope=openid%20email"));
    axiam_authorization_request_dispose(&req);

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_operations_without_a_client_id_fail_fast(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, branches_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_oidc_token_set_t set;
    axiam_device_authorization_t da;
    axiam_verified_logout_token_t vl;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_refresh(c, tok, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_authorize(c, NULL, NULL, &da, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, tok, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, "a.b.c", &vl, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_a_slug_only_client_cannot_reach_any_of_the_five_scoped_operations(void) {
    /* §12.1 note 2 names exactly five, and all five refuse before the wire. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_transport(cfg, branches_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_oidc_token_set_t set;
    axiam_introspection_result_t ir;
    axiam_exchanged_token_t xt;
    axiam_device_authorization_t da;
    axiam_token_exchange_params_t xp = {0};
    xp.subject_token = tok;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_refresh(c, tok, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, tok, NULL, NULL, &ir, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_revoke(c, tok, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_token_exchange(c, &xp, &xt, &err));
    /* §14.1 applies the same rule to the device pair. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_authorize(c, NULL, NULL, &da, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, tok, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    /* ...but an explicit per-call UUID unblocks them, which is the documented
     * remedy rather than a workaround. */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_login_client_credentials(c, NULL, AXIAM_TEST_TENANT_ID, &set, &err));
    /* §5 rule 2 still emits the SLUG header alongside the UUID query parameter,
     * and §12.1 note 2 says that disagreement is correct: the /oauth2 paths read the
     * tenant only from the query. */
    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_EQUAL_STRING("acme", g_oidc.tenant_headers[i]);
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=" AXIAM_TEST_TENANT_ID));
    axiam_oidc_token_set_dispose(&set);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_introspect_and_revoke_refuse_an_empty_token(void) {
    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_introspection_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, empty, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_revoke(c, empty, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, NULL, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.introspect_calls + g_oidc.revoke_calls);
    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

void test_a_form_body_larger_than_the_initial_buffer_is_built_intact(void) {
    /* The form builder starts at 512 bytes and grows. A subject token is
     * routinely a JWT well past that, and a truncated one produces an
     * `invalid_grant` that looks like a server problem rather than a client
     * bug — so the whole value has to survive the growth. */
    char big[1200];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN
        "\",\"token_type\":\"Bearer\",\"expires_in\":300}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new(big);
    const char *scopes[] = {"scope-one", "scope-two", "scope-three"};
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    p.scopes = scopes;
    p.scope_count = 3;
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_token_exchange(c, &p, &t, &err));

    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], big));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "scope-one%20scope-two%20scope-three"));

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_device_login_stops_on_a_terminal_refusal_and_reports_its_code(void) {
    /* §14.2 rule 3 through the composed helper: `access_denied` means a human
     * said no, so the loop stops with that code intact rather than polling on
     * in the hope the human changes their mind. */
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc\",\"user_code\":\"WDJB\",\"verification_uri\":"
        "\"https://id.test/d\",\"expires_in\":600,\"interval\":1}", 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"access_denied\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = branches_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("access_denied", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    TEST_ASSERT_NULL(set.access_token);
    axiam_client_free(c);
}

void test_device_login_on_a_slug_only_client_is_refused(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_transport(cfg, branches_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.device_authorize_calls);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Disposal is safe on zeroed and NULL                                */
/* ------------------------------------------------------------------ */

void test_every_dispose_is_safe_on_null_and_on_a_zeroed_struct(void) {
    /* The promise oidc.h makes so a caller can dispose unconditionally on the
     * error path — which every test above relies on. */
    axiam_oidc_config_dispose(NULL);
    axiam_authorization_request_dispose(NULL);
    axiam_id_token_claims_free(NULL);
    axiam_oidc_token_set_dispose(NULL);
    axiam_introspection_result_dispose(NULL);
    axiam_sso_start_result_dispose(NULL);
    axiam_sso_complete_result_dispose(NULL);
    axiam_verified_logout_token_dispose(NULL);
    axiam_device_authorization_dispose(NULL);
    axiam_exchanged_token_dispose(NULL);

    axiam_oidc_config_t a = {0};
    axiam_authorization_request_t b = {0};
    axiam_oidc_token_set_t c = {0};
    axiam_introspection_result_t d = {0};
    axiam_sso_start_result_t e = {0};
    axiam_sso_complete_result_t f = {0};
    axiam_verified_logout_token_t h = {0};
    axiam_device_authorization_t i = {0};
    axiam_exchanged_token_t j = {0};
    axiam_oidc_config_dispose(&a);
    axiam_authorization_request_dispose(&b);
    axiam_oidc_token_set_dispose(&c);
    axiam_introspection_result_dispose(&d);
    axiam_sso_start_result_dispose(&e);
    axiam_sso_complete_result_dispose(&f);
    axiam_verified_logout_token_dispose(&h);
    axiam_device_authorization_dispose(&i);
    axiam_exchanged_token_dispose(&j);
    TEST_PASS();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_every_entry_point_refuses_a_null_out_parameter);
    RUN_TEST(test_a_null_client_is_refused_rather_than_dereferenced);
    RUN_TEST(test_every_entry_point_refuses_a_closed_client);
    RUN_TEST(test_a_non_json_discovery_body_is_a_network_error);
    RUN_TEST(test_a_discovery_document_missing_a_required_endpoint_is_refused);
    RUN_TEST(test_a_discovery_transport_failure_propagates);
    RUN_TEST(test_a_discovery_error_status_propagates);
    RUN_TEST(test_device_authorize_without_an_advertised_endpoint_is_refused);
    RUN_TEST(test_logout_url_without_an_advertised_end_session_endpoint_is_null);
    RUN_TEST(test_introspect_falls_back_to_the_base_url_when_discovery_omits_the_endpoint);
    RUN_TEST(test_a_token_response_without_an_access_token_is_malformed);
    RUN_TEST(test_a_non_oauth2_error_body_falls_back_to_the_status_mapping);
    RUN_TEST(test_an_error_body_without_a_description_still_carries_its_code);
    RUN_TEST(test_a_token_endpoint_transport_failure_is_a_network_error);
    RUN_TEST(test_a_malformed_device_authorization_response_is_refused);
    RUN_TEST(test_a_device_authorization_error_and_transport_failure_propagate);
    RUN_TEST(test_device_login_surfaces_an_authorize_failure_without_polling);
    RUN_TEST(test_a_malformed_sso_response_is_refused);
    RUN_TEST(test_an_sso_error_status_and_transport_failure_propagate);
    RUN_TEST(test_a_malformed_introspection_body_is_refused);
    RUN_TEST(test_a_malformed_token_exchange_response_is_refused);
    RUN_TEST(test_missing_credentials_are_refused_before_any_request);
    RUN_TEST(test_exchange_refuses_incomplete_parameters);
    RUN_TEST(test_begin_refuses_a_missing_configuration_or_redirect_uri);
    RUN_TEST(test_operations_without_a_client_id_fail_fast);
    RUN_TEST(test_a_slug_only_client_cannot_reach_any_of_the_five_scoped_operations);
    RUN_TEST(test_introspect_and_revoke_refuse_an_empty_token);
    RUN_TEST(test_a_form_body_larger_than_the_initial_buffer_is_built_intact);
    RUN_TEST(test_device_login_stops_on_a_terminal_refusal_and_reports_its_code);
    RUN_TEST(test_device_login_on_a_slug_only_client_is_refused);
    RUN_TEST(test_every_dispose_is_safe_on_null_and_on_a_zeroed_struct);
    return UNITY_END();
}
