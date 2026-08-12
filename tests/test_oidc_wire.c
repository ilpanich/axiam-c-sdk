/*
 * §12 / §14 / §15 — wire-level oddities the shared request builder has to get
 * right.
 *
 * Everything in these four sections funnels through three small functions: the
 * form builder, `oidc_endpoint_with_tenant`, and the one POST that carries them.
 * A bug in any of the three shows up as an unexplained `invalid_request` from
 * the server, in every operation at once — so the cases below are the ones
 * where those three have a decision to make that the ordinary tests never force:
 * an endpoint that already carries a query string, a retry switch that is off,
 * an error body with an empty `error`, a 2xx with nothing in it.
 *
 * The other half of the file is the failure the whole section is built on top
 * of: discovery. Nine operations read their endpoint from that document, and
 * every one of them has to surface its failure rather than proceeding with a
 * NULL endpoint.
 */

#include "unity.h"
#include "oidc_test_util.h"

/* A document whose token endpoint already has a query string, and whose
 * "supported" arrays are the shapes a permissive server sends: one empty, one
 * containing a non-string. */
#define ODD_DISCOVERY                                                          \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token?v=2\","                   \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"introspection_endpoint\":\"" OIDC_BASE "/oauth2/introspect\","          \
    "\"device_authorization_endpoint\":\"" OIDC_BASE "/oauth2/device_authorization\"," \
    "\"scopes_supported\":[],"                                                 \
    "\"response_types_supported\":[\"code\",7,null],"                          \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"]}"

static const char *g_discovery_body;
static int g_discovery_fails;

static int wire_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    if (strstr(req->url ? req->url : "", "/.well-known/openid-configuration")) {
        oidc_record(req);
        g_oidc.discovery_calls++;
        if (g_discovery_fails) {
            resp_fill(resp, 503, "upstream down", NULL);
            return 0;
        }
        resp_fill(resp, 200, g_discovery_body ? g_discovery_body : ODD_DISCOVERY, NULL);
        return 0;
    }
    return oidc_fake_transport(ctx, req, resp);
}

static axiam_client_t *wire_client(int retry_enabled) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_retry_enabled(cfg, retry_enabled);
    axiam_client_config_set_transport(cfg, wire_transport, &g_oidc);
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
    g_discovery_body = NULL;
    g_discovery_fails = 0;
}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* The tenant query parameter                                         */
/* ------------------------------------------------------------------ */

void test_a_token_endpoint_that_already_has_a_query_gets_an_ampersand(void) {
    /*
     * §12.1 note 2 requires `?tenant_id=<uuid>` on five operations, and the
     * endpoint comes from a discovery document the SDK does not control. A
     * server that publishes a versioned token endpoint would otherwise receive
     * "…?v=2?tenant_id=…", which is not a URL — and the resulting
     * `invalid_request` names nothing a caller could act on.
     */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));

    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "?v=2&tenant_id=" AXIAM_TEST_TENANT_ID));
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_an_empty_explicit_tenant_id_falls_back_to_the_configured_one(void) {
    /* An empty string is not an override. Treating it as one would send
     * `?tenant_id=` and produce a server error for something the client already
     * knew the answer to. */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, NULL, "", &set, &err));
    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=" AXIAM_TEST_TENANT_ID));
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §16.1's disable switch                                             */
/* ------------------------------------------------------------------ */

void test_disabling_retry_makes_an_eligible_operation_a_single_attempt(void) {
    /*
     * §16.1 permits lowering the policy to exactly one attempt — "the right
     * choice for a caller who owns their own retry layer and knows their own
     * deadline". Introspection is the one §12 operation §16.2 makes eligible,
     * so it is where the switch is observable: three attempts with it on, one
     * with it off.
     */
    g_oidc.introspect_answer = (oidc_answer_t){503, "", 0};
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_error_t err;
    axiam_introspection_result_t r;

    axiam_client_t *on = wire_client(1);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(on, tok, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_RETRY_MAX_ATTEMPTS, g_oidc.introspect_calls);
    axiam_client_free(on);

    oidc_reset();
    g_oidc.introspect_answer = (oidc_answer_t){503, "", 0};
    axiam_client_t *off = wire_client(0);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(off, tok, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.introspect_calls);
    axiam_client_free(off);

    axiam_sensitive_free(tok);
}

/* ------------------------------------------------------------------ */
/* Answers that carry nothing useful                                  */
/* ------------------------------------------------------------------ */

void test_an_error_body_with_an_empty_error_field_falls_back_to_the_status(void) {
    /* §12.3 rule 3 dispatches on `error`. A present-but-empty one names no
     * failure, so the §2 status mapping is the honest answer rather than an
     * auth error with a blank code a caller would switch on. */
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    axiam_client_free(c);
}

void test_an_error_with_an_empty_description_still_names_its_code(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400,
        "{\"error\":\"invalid_scope\",\"error_description\":\"\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_scope", err.oauth_error);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "invalid_scope"));
    axiam_client_free(c);
}

void test_a_failure_with_no_body_at_all_is_still_typed(void) {
    g_oidc.token_script[0] = (oidc_answer_t){403, NULL, 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTHZ,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    axiam_client_free(c);

    /* And a 2xx with no body is malformed rather than an empty success. */
    oidc_reset();
    g_oidc.token_script[0] = (oidc_answer_t){200, NULL, 0};
    g_oidc.token_script_len = 1;
    c = wire_client(1);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    axiam_client_free(c);
}

void test_a_device_response_with_no_body_or_no_expiry_is_handled(void) {
    g_oidc.device_answer = (oidc_answer_t){200, NULL, 0};
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);

    oidc_reset();
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc\",\"user_code\":\"U\","
        "\"verification_uri\":\"https://id.test/d\"}", 0};
    c = wire_client(1);
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    /* No `expires_in` means the grant has no stated deadline; 0 is what the
     * §14.2 rule 4 loop will read, and it stops immediately rather than
     * polling forever. */
    TEST_ASSERT_EQUAL_INT(0, a.expires_in);
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_a_token_exchange_response_with_no_body_is_refused(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200, NULL, 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("s");
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    /* An EMPTY actor token is not an actor token: it must not flip the request
     * from impersonation to delegation (§15.2 rule 1). */
    p.actor_token = empty;
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(c, &p, &t, &err));
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "actor_token"));

    /* An empty subject token is refused before the wire. */
    oidc_reset();
    p.subject_token = empty;
    p.actor_token = NULL;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_token_exchange(c, &p, &t, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);

    axiam_sensitive_free(subject);
    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

void test_an_empty_device_code_is_refused_before_the_wire(void) {
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, empty, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_sensitive_free(empty);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Discovery-document shapes and failures                             */
/* ------------------------------------------------------------------ */

void test_supported_arrays_of_awkward_shapes_are_parsed_defensively(void) {
    /* These lists are informational — §12.4 rule 1 pins verification to EdDSA
     * whatever `id_token_signing_alg_values_supported` claims — so an empty
     * list or a stray non-string in one must not fail the whole document and
     * take every operation down with it. */
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL_size_t(0, cfg.scopes_supported_count);
    /* The non-strings are skipped, the string survives. */
    TEST_ASSERT_EQUAL_size_t(1, cfg.response_types_supported_count);
    TEST_ASSERT_EQUAL_STRING("code", cfg.response_types_supported[0]);
    axiam_oidc_config_dispose(&cfg);

    /* The cached copy round-trips the same shapes. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL_size_t(1, cfg.response_types_supported_count);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.discovery_calls);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_each_required_discovery_member_is_required_on_its_own(void) {
    const char *bodies[] = {
        /* no authorization_endpoint */
        "{\"issuer\":\"i\",\"token_endpoint\":\"t\",\"jwks_uri\":\"j\"}",
        /* no jwks_uri */
        "{\"issuer\":\"i\",\"authorization_endpoint\":\"a\",\"token_endpoint\":\"t\"}",
        /* no issuer — which §12.4 rule 3 compares against, so its absence
         * would silently disable the issuer check rather than fail loudly */
        "{\"authorization_endpoint\":\"a\",\"token_endpoint\":\"t\",\"jwks_uri\":\"j\"}",
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
        oidc_reset();
        g_discovery_body = bodies[i];
        axiam_client_t *c = wire_client(1);
        axiam_error_t err;
        axiam_oidc_config_t cfg;
        TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_discover(c, &cfg, &err));
        axiam_oidc_config_dispose(&cfg);
        axiam_client_free(c);
    }
}

void test_a_discovery_failure_stops_every_operation_that_depends_on_it(void) {
    /*
     * Nine operations read an endpoint from that document. None of them may
     * proceed with a NULL endpoint and turn a discovery outage into a
     * mysterious request against the wrong host — so each surfaces the
     * discovery failure, and none reaches its own endpoint.
     */
    g_discovery_fails = 1;
    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_oidc_token_set_t set;
    axiam_introspection_result_t ir;
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

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_exchange(c, &ep, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_oidc_refresh(c, tok, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_introspect(c, tok, NULL, NULL, &ir, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_revoke(c, tok, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_authorize(c, NULL, NULL, &da, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_device_poll(c, tok, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_token_exchange(c, &xp, &xt, &err));
    /* Logout-token verification reaches discovery only after the signature
     * check, so it fails at the JWKS fetch instead — either way, not accepted. */
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_verify_logout_token(c, "a.b.c", &vl, &err));

    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.introspect_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.revoke_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.device_authorize_calls);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 rule 4/5 — scope handling and URL assembly in oidc_begin      */
/* ------------------------------------------------------------------ */

void test_the_openid_scope_check_matches_whole_tokens_only(void) {
    /*
     * §12.1 rule 4 says the requested scope MUST contain `openid` and the
     * helper adds it when the caller omits it. A substring test would see
     * `openid` inside `openid_connect_admin` and skip the addition — producing
     * an authorization request the OP treats as a plain OAuth2 one, with no ID
     * token, and therefore no §12.4 validation at all. The failure is silent
     * until something downstream reads `id_claims` and finds nothing.
     */
    struct { const char *requested; const char *expect; } cases[] = {
        {NULL,                   "scope=openid"},
        {"",                     "scope=openid"},
        {"openid",               "scope=openid"},
        {"profile openid email", "scope=profile%20openid%20email"},
        {"openid_connect_admin", "scope=openid%20openid_connect_admin"},
        {"notopenid",            "scope=openid%20notopenid"},
        /* Six characters, so a length check alone would not separate it. */
        {"emails",               "scope=openid%20emails"},
    };

    axiam_client_t *c = wire_client(1);
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        axiam_authorization_request_t req;
        TEST_ASSERT_EQUAL(AXIAM_OK,
            axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, cases[i].requested, &req, &err));
        TEST_ASSERT_NOT_NULL(strstr(req.url, cases[i].expect));
        axiam_authorization_request_dispose(&req);
    }

    /* An authorization endpoint that already carries a query gets an `&`, the
     * same way the token endpoint does. */
    free(cfg.authorization_endpoint);
    cfg.authorization_endpoint = strdup(OIDC_BASE "/oauth2/authorize?theme=dark");
    axiam_authorization_request_t req;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, NULL, &req, &err));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "?theme=dark&response_type=code"));
    axiam_authorization_request_dispose(&req);

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §5.1 context on the federation pair                                */
/* ------------------------------------------------------------------ */

static axiam_client_t *sso_client(const char *tenant_id, const char *tenant_slug,
                                  const char *org_id, const char *org_slug) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE "/");
    if (tenant_id) axiam_client_config_set_tenant_id(cfg, tenant_id);
    if (tenant_slug) axiam_client_config_set_tenant_slug(cfg, tenant_slug);
    if (org_id) axiam_client_config_set_org_id(cfg, org_id);
    if (org_slug) axiam_client_config_set_org_slug(cfg, org_slug);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_transport(cfg, wire_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void test_sso_start_sends_whichever_tenant_and_org_form_the_client_carries(void) {
    /*
     * §5.1: ONE tenant form and ONE org form. Which one is not the SDK's
     * choice — it is whichever the application constructed the client with —
     * and sending both, or neither, is a server-side rejection. The base URL
     * here also carries a trailing slash, because a caller pasting one from a
     * config file is the normal case and "https://api.test//api/v1/..." is not
     * a path the server routes.
     */
    const char *body =
        "{\"authorize_url\":\"https://idp.test/a\",\"state\":\"s\",\"expires_in_secs\":600}";

    g_oidc.sso_start_answer = (oidc_answer_t){200, body, 0};
    axiam_client_t *c = sso_client(AXIAM_TEST_TENANT_ID, NULL,
                                   "22222222-2222-2222-2222-222222222222", NULL);
    axiam_error_t err;
    axiam_sso_start_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_start(c, "fed-1", OIDC_REDIRECT_URI, &r, &err));
    int i = oidc_last_call("/federation/oidc/start");
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "//api/v1"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"org_id\":"));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "\"tenant_slug\""));
    axiam_sso_start_result_dispose(&r);
    axiam_client_free(c);

    oidc_reset();
    g_oidc.sso_start_answer = (oidc_answer_t){200, body, 0};
    c = sso_client(NULL, "acme", NULL, "globex");
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_start(c, "fed-1", OIDC_REDIRECT_URI, &r, &err));
    i = oidc_last_call("/federation/oidc/start");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"tenant_slug\":\"acme\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"org_slug\":\"globex\""));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "\"org_id\""));
    axiam_sso_start_result_dispose(&r);

    /* No org configured at all: the member is omitted rather than sent empty,
     * and the server decides whether it needed one. */
    oidc_reset();
    g_oidc.sso_start_answer = (oidc_answer_t){200, body, 0};
    axiam_client_free(c);
    c = sso_client(NULL, "acme", NULL, NULL);
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_start(c, "fed-1", OIDC_REDIRECT_URI, &r, &err));
    i = oidc_last_call("/federation/oidc/start");
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "\"org_"));
    axiam_sso_start_result_dispose(&r);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_token_endpoint_that_already_has_a_query_gets_an_ampersand);
    RUN_TEST(test_an_empty_explicit_tenant_id_falls_back_to_the_configured_one);
    RUN_TEST(test_disabling_retry_makes_an_eligible_operation_a_single_attempt);
    RUN_TEST(test_an_error_body_with_an_empty_error_field_falls_back_to_the_status);
    RUN_TEST(test_an_error_with_an_empty_description_still_names_its_code);
    RUN_TEST(test_a_failure_with_no_body_at_all_is_still_typed);
    RUN_TEST(test_a_device_response_with_no_body_or_no_expiry_is_handled);
    RUN_TEST(test_a_token_exchange_response_with_no_body_is_refused);
    RUN_TEST(test_an_empty_device_code_is_refused_before_the_wire);
    RUN_TEST(test_supported_arrays_of_awkward_shapes_are_parsed_defensively);
    RUN_TEST(test_each_required_discovery_member_is_required_on_its_own);
    RUN_TEST(test_a_discovery_failure_stops_every_operation_that_depends_on_it);
    RUN_TEST(test_the_openid_scope_check_matches_whole_tokens_only);
    RUN_TEST(test_sso_start_sends_whichever_tenant_and_org_form_the_client_carries);
    return UNITY_END();
}
