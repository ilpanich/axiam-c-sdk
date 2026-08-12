/*
 * CONTRACT.md §12 — the nine OIDC relying-party operations.
 *
 * These are the assertions §12 makes hard requirements of, and most of them are
 * about REQUESTS rather than return values: what encoding went out, which
 * parameter carried the tenant, whether a secret was sent, and — repeatedly —
 * whether a request was made at all. §12's failure modes are things an SDK does
 * too eagerly (retrying a single-use code, sending a slug the server will
 * reject, storing correlation values the caller owns), so the tests that catch
 * them count wire calls.
 */

#include "unity.h"
#include "oidc_test_util.h"
#include "oidc_internal.h"

void setUp(void) { oidc_reset(); }
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* §12.1 / §12.3 rule 6 — discovery                                   */
/* ------------------------------------------------------------------ */

void test_discovery_reads_every_endpoint_from_the_document(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    /* §12.3 rule 6: the document's own `issuer` is authoritative, and it
     * legitimately differs from the base URL behind a proxy — an SDK MUST NOT
     * reject a document over that mismatch. This fixture makes them differ. */
    TEST_ASSERT_EQUAL_STRING(OIDC_ISSUER, cfg.issuer);
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/token", cfg.token_endpoint);
    /* Read from the document rather than hardcoded to /oauth2/jwks. */
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/jwks", cfg.jwks_uri);
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/end_session", cfg.end_session_endpoint);
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/device_authorization",
                             cfg.device_authorization_endpoint);

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_discovery_is_cached_so_a_second_call_makes_no_request(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t a, b;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &a, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &b, &err));
    /* §12.3 rule 6: at least a 5-minute TTL. Two calls, one fetch. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.discovery_calls);
    TEST_ASSERT_EQUAL_STRING(a.token_endpoint, b.token_endpoint);
    axiam_oidc_config_dispose(&a);
    axiam_oidc_config_dispose(&b);
    axiam_client_free(c);
}

void test_a_configured_discovery_ttl_below_the_floor_is_raised(void) {
    /* §12.3 rule 6: 5 minutes is a MINIMUM. A smaller configured value is
     * raised to it, not honoured — an SDK that honoured 1 second would turn the
     * cache into a per-request fetch. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_discovery_ttl(cfg, 1);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_EQUAL(AXIAM_OIDC_DISCOVERY_TTL_FLOOR_S, c->cfg->oidc_discovery_ttl_s);
    axiam_client_config_free(cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_begin                                                   */
/* ------------------------------------------------------------------ */

void test_rfc7636_appendix_b_pkce_vector(void) {
    /*
     * §12.1 rule 3 requires this vector by name. It is the one part of PKCE
     * where a plausible-looking implementation (base64 with padding, or hex, or
     * SHA-256 of the base64 rather than of the ASCII) produces a challenge the
     * server silently rejects at exchange time with `invalid_grant`.
     */
    char *challenge = oidc_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    TEST_ASSERT_NOT_NULL(challenge);
    TEST_ASSERT_EQUAL_STRING("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    free(challenge);
}

void test_begin_performs_no_network_io_and_builds_the_eight_parameters(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    int before = g_oidc.n_calls;

    axiam_authorization_request_t req;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "profile", &req, &err));

    /* §12.1: PURE LOCAL COMPUTATION. Not one request. */
    TEST_ASSERT_EQUAL_INT(before, g_oidc.n_calls);

    /* The endpoint comes from the document, never hardcoded. */
    TEST_ASSERT_EQUAL_INT(0, strncmp(req.url, OIDC_BASE "/oauth2/authorize?",
                                     strlen(OIDC_BASE "/oauth2/authorize?")));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "response_type=code"));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "client_id=" OIDC_CLIENT_ID));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "code_challenge_method=S256"));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "code_challenge="));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "state="));
    TEST_ASSERT_NOT_NULL(strstr(req.url, "nonce="));
    /* §12.1 rule 4: `openid` is added when the caller omits it. */
    TEST_ASSERT_NOT_NULL(strstr(req.url, "scope=openid%20profile"));
    /* Rule 5 permits no parameters of the SDK's own beyond the eight. */
    TEST_ASSERT_NULL(strstr(req.url, "prompt="));
    TEST_ASSERT_NULL(strstr(req.url, "response_mode="));

    /* The URL carries the CHALLENGE; the verifier stays behind Sensitive. */
    char *expected = oidc_s256_challenge(axiam_sensitive_reveal(req.code_verifier));
    char needle[128];
    snprintf(needle, sizeof(needle), "code_challenge=%s", expected);
    TEST_ASSERT_NOT_NULL(strstr(req.url, needle));
    TEST_ASSERT_NULL(strstr(req.url, axiam_sensitive_reveal(req.code_verifier)));
    free(expected);

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_begin_is_stateless_and_every_call_draws_fresh_values(void) {
    /* §12.3 rule 1: the SDK stores no state/nonce/code_verifier. Two calls
     * produce three independently random values each, and neither call can
     * observe the other — which is what makes the CALLER responsible for
     * keeping them. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);

    axiam_authorization_request_t a, b;
    axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, NULL, &a, &err);
    axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, NULL, &b, &err);

    TEST_ASSERT_NOT_EQUAL(0, strcmp(a.state, b.state));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(a.nonce, b.nonce));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(axiam_sensitive_reveal(a.code_verifier),
                                    axiam_sensitive_reveal(b.code_verifier)));
    /* §12.1 rule 1: at least 16 bytes of entropy, base64url WITHOUT padding. */
    TEST_ASSERT_GREATER_OR_EQUAL(22, strlen(a.state));
    TEST_ASSERT_NULL(strchr(a.state, '='));
    TEST_ASSERT_NULL(strchr(a.nonce, '='));
    /* §12.1 rule 2: 43-128 characters from the RFC 7636 unreserved set. */
    size_t vlen = strlen(axiam_sensitive_reveal(a.code_verifier));
    TEST_ASSERT_GREATER_OR_EQUAL(43, vlen);
    TEST_ASSERT_LESS_OR_EQUAL(128, vlen);

    axiam_authorization_request_dispose(&a);
    axiam_authorization_request_dispose(&b);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_begin_without_a_client_id_fails_fast_with_no_wire_call(void) {
    axiam_client_t *c = oidc_make_client_ex(NULL, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);
    int before = g_oidc.n_calls;

    axiam_authorization_request_t req;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, NULL, &req, &err));
    /* §12.1: a missing client registration is a deployment mistake, so it fails
     * fast rather than producing a URL the server will reject. */
    TEST_ASSERT_EQUAL_INT(before, g_oidc.n_calls);
    TEST_ASSERT_NULL(req.url);

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_exchange                                                */
/* ------------------------------------------------------------------ */

static axiam_oidc_exchange_params_t exchange_params(const axiam_sensitive_t *verifier) {
    axiam_oidc_exchange_params_t p = {0};
    p.code = "the-code";
    p.code_verifier = verifier;
    p.redirect_uri = OIDC_REDIRECT_URI;
    p.nonce = "the-nonce";
    return p;
}

void test_exchange_is_form_encoded_with_the_tenant_in_the_query(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = exchange_params(verifier);
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_exchange(c, &p, &set, &err));

    int i = oidc_last_call("/oauth2/token");
    /* §12.1 rule 1: form-encoded, not JSON. An SDK that posts JSON here is
     * non-conformant. */
    TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", g_oidc.content_types[i]);
    /* Rule 2: tenant_id is a QUERY parameter and never a body field. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "?tenant_id=" AXIAM_TEST_TENANT_ID));
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "tenant_id"));
    /* ...and §5 rule 2 still emits the header alongside it, unconditionally. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_TEST_TENANT_ID, g_oidc.tenant_headers[i]);
    /* Rule 3: client_secret_post. No Authorization: Basic. */
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[i]);
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/token", "client_secret"));
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/token", "code_verifier"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "grant_type=authorization_code"));

    TEST_ASSERT_EQUAL_STRING("at", axiam_sensitive_reveal(set.access_token));
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

void test_a_slug_only_client_is_refused_client_side_with_no_wire_call(void) {
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, NULL, "acme");
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = exchange_params(verifier);
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));
    /*
     * §12.3 rule 4 / §12.1 note 2: five of the nine operations need a tenant
     * UUID, and a slug is never a substitute. The SDK MUST raise its taxonomy
     * error CLIENT-SIDE — not even the discovery fetch happens, because the
     * request could not have succeeded.
     */
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "slug"));

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

void test_exchange_requires_the_nonce_because_rule_6_is_mandatory_here(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = exchange_params(verifier);
    p.nonce = NULL;
    axiam_oidc_token_set_t set;

    /* §12.4 rule 6 is mandatory for oidc_exchange: the helper always requests
     * `openid`, so the server always issues a nonce, and a caller with nothing
     * to compare against has silently lost replay protection. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

void test_an_oauth2_error_body_surfaces_its_code_rather_than_the_generic_400(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400,
        "{\"error\":\"invalid_grant\",\"error_description\":\"code already used\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = exchange_params(verifier);
    axiam_oidc_token_set_t set;

    /* §12.3 rule 3: a 400 from /oauth2/token MUST NOT surface as the generic
     * §2 400 row (which would be AXIAM_ERR_NETWORK). The machine-readable code
     * is what §14.2 rule 5 and §15.3 tell callers to dispatch on. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &p, &set, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    TEST_ASSERT_EQUAL_STRING("invalid_grant: code already used", err.message);

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

void test_exchange_is_never_retried_because_the_code_is_single_use(void) {
    g_oidc.token_script[0] = (oidc_answer_t){503, "{}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = exchange_params(verifier);
    axiam_oidc_token_set_t set;

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_oidc_exchange(c, &p, &set, &err));
    /*
     * §16.2 names `oidc_exchange` ineligible, twice over: it changes state, and
     * its credential is single-use. Retrying replays a spent authorization code
     * and turns a recoverable 503 into a hard `invalid_grant` the caller cannot
     * interpret. EXACTLY ONE request, on every outcome.
     */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 login_client_credentials                                     */
/* ------------------------------------------------------------------ */

void test_client_credentials_omits_an_absent_scope_and_adopts_nothing(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"m2m\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));

    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "grant_type=client_credentials"));
    /* §12.1: an optional field the caller did not supply is OMITTED, never sent
     * empty. A service account registers no scopes at all, so `scope=` would
     * answer `invalid_scope`. */
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "scope"));
    /* §12.1's adoption MAY: this SDK does not, so nothing installs a session. */
    TEST_ASSERT_EQUAL_INT(0, c->authenticated);
    TEST_ASSERT_EQUAL_STRING("m2m", axiam_sensitive_reveal(set.access_token));

    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 introspect / revoke                                          */
/* ------------------------------------------------------------------ */

void test_introspect_refuses_a_public_client_with_no_wire_call(void) {
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("some-token");
    axiam_introspection_result_t r;

    /* §12.1 rule 4: IntrospectRequest marks client_id AND client_secret
     * required, so a public client cannot call this. Refusing here beats
     * sending a request that cannot succeed. */
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, token, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.introspect_calls);

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_introspect_surfaces_the_full_result(void) {
    g_oidc.introspect_answer = (oidc_answer_t){200,
        "{\"active\":true,\"sub\":\"user-1\",\"client_id\":\"rp-client\","
        "\"scope\":\"openid profile\",\"exp\":1893456000,\"iat\":1893452400,"
        "\"token_type\":\"Bearer\",\"jti\":\"jti-1\"}", 0};

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("some-token");
    axiam_introspection_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_introspect(c, token, "access_token", NULL, &r, &err));

    TEST_ASSERT_EQUAL_INT(1, r.active);
    TEST_ASSERT_EQUAL_STRING("user-1", r.subject);
    TEST_ASSERT_EQUAL_STRING("openid profile", r.scope);
    TEST_ASSERT_EQUAL_STRING("jti-1", r.jwt_id);
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/introspect", "token_type_hint"));

    axiam_introspection_result_dispose(&r);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_an_inactive_token_is_a_successful_answer_not_an_error(void) {
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":false}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("stale");
    axiam_introspection_result_t r;
    /* `active` is the only guaranteed field, and false is the endpoint doing
     * its job — not a failure. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_introspect(c, token, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(0, r.active);
    axiam_introspection_result_dispose(&r);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_401_from_introspect_does_not_enter_the_refresh_guard(void) {
    g_oidc.introspect_answer = (oidc_answer_t){401, "{\"error\":\"invalid_client\"}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("some-token");
    axiam_introspection_result_t r;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, token, NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_client", err.oauth_error);
    /*
     * §12.3 rule 3: client-credential failure is not a session expiry, and
     * refreshing cannot fix a wrong client secret. Asserted as a count, because
     * "did not refresh" is only observable on the wire.
     */
    TEST_ASSERT_EQUAL_UINT(0, axiam_client_refresh_count(c));

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_revoke_is_idempotent_for_a_token_the_server_never_issued(void) {
    /* §12.1 rule 5: RFC 7009 answers 200 for unknown, expired and
     * already-revoked tokens, and that idempotence is the point of the
     * endpoint. Every implementing SDK MUST carry this test. */
    g_oidc.revoke_answer = (oidc_answer_t){200, "", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("never-issued");
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_revoke(c, token, NULL, NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_revoke(c, token, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT(2, g_oidc.revoke_calls);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_5xx_on_revoke_is_still_a_failure(void) {
    /* The correction contract 1.5 made to 1.4: returning void does not turn a
     * server error into a silent success. */
    g_oidc.revoke_answer = (oidc_answer_t){503, "upstream down", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("some-token");
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_revoke(c, token, NULL, NULL, &err));
    /* And it is not retried — §16.2 names `oidc_revoke` ineligible. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.revoke_calls);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 sso_start / sso_complete                                     */
/* ------------------------------------------------------------------ */

void test_sso_start_carries_slug_context_in_a_json_body(void) {
    g_oidc.sso_start_answer = (oidc_answer_t){200,
        "{\"authorize_url\":\"https://idp.test/authorize?x=1\",\"state\":\"st-1\","
        "\"expires_in_secs\":600}", 0};

    /* A slug-only client CAN call this pair — §12.1 note 2's five-operation
     * restriction covers only the /oauth2 endpoints. */
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, NULL, "acme");
    axiam_error_t err;
    axiam_sso_start_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_start(c, "fed-1", OIDC_REDIRECT_URI, &r, &err));

    int i = oidc_last_call("/federation/oidc/start");
    TEST_ASSERT_EQUAL_STRING("application/json", g_oidc.content_types[i]);
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"tenant_slug\":\"acme\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"federation_config_id\":\"fed-1\""));
    TEST_ASSERT_EQUAL_STRING("st-1", r.state);
    /* §12.1 note 7: no nonce comes back and the SDK must not synthesise one. */
    axiam_sso_start_result_dispose(&r);
    axiam_client_free(c);
}

void test_sso_complete_round_trips_state_and_returns_no_token_material(void) {
    g_oidc.sso_complete_answer = (oidc_answer_t){200,
        "{\"user_id\":\"u-1\",\"session_id\":\"s-1\",\"expires_in\":900,"
        "\"redirect_uri\":\"https://app.test/home\"}", 0};

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sso_complete_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_complete(c, "the-code", "st-1", &r, &err));

    int i = oidc_last_call("/federation/oidc/callback");
    /* Rule: `state` is round-tripped UNMODIFIED. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"state\":\"st-1\""));
    TEST_ASSERT_EQUAL_STRING("u-1", r.user_id);
    TEST_ASSERT_EQUAL_STRING("s-1", r.session_id);
    /* §12.1 note 6: SsoLoginSuccessResponse carries NO token material — the
     * session is a Set-Cookie the §4 jar keeps. The struct has nowhere to put
     * one, which is the assertion. */
    axiam_sso_complete_result_dispose(&r);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.3 rule 5                                                       */
/* ------------------------------------------------------------------ */

void test_no_operation_calls_the_userinfo_endpoint(void) {
    /* §12.3 rule 5: §12 adds no userinfo operation, and SDKs MUST NOT call
     * GET /oauth2/userinfo or substitute it for anything. A relying party's
     * claims come from the validated ID token. The discovery document
     * advertises the endpoint; nothing here may follow it. */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_login_client_credentials(c, NULL, NULL, &set, &err);
    axiam_oidc_token_set_dispose(&set);

    for (int i = 0; i < g_oidc.n_calls; i++) {
        TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "/oauth2/userinfo"));
    }
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_discovery_reads_every_endpoint_from_the_document);
    RUN_TEST(test_discovery_is_cached_so_a_second_call_makes_no_request);
    RUN_TEST(test_a_configured_discovery_ttl_below_the_floor_is_raised);
    RUN_TEST(test_rfc7636_appendix_b_pkce_vector);
    RUN_TEST(test_begin_performs_no_network_io_and_builds_the_eight_parameters);
    RUN_TEST(test_begin_is_stateless_and_every_call_draws_fresh_values);
    RUN_TEST(test_begin_without_a_client_id_fails_fast_with_no_wire_call);
    RUN_TEST(test_exchange_is_form_encoded_with_the_tenant_in_the_query);
    RUN_TEST(test_a_slug_only_client_is_refused_client_side_with_no_wire_call);
    RUN_TEST(test_exchange_requires_the_nonce_because_rule_6_is_mandatory_here);
    RUN_TEST(test_an_oauth2_error_body_surfaces_its_code_rather_than_the_generic_400);
    RUN_TEST(test_exchange_is_never_retried_because_the_code_is_single_use);
    RUN_TEST(test_client_credentials_omits_an_absent_scope_and_adopts_nothing);
    RUN_TEST(test_introspect_refuses_a_public_client_with_no_wire_call);
    RUN_TEST(test_introspect_surfaces_the_full_result);
    RUN_TEST(test_an_inactive_token_is_a_successful_answer_not_an_error);
    RUN_TEST(test_a_401_from_introspect_does_not_enter_the_refresh_guard);
    RUN_TEST(test_revoke_is_idempotent_for_a_token_the_server_never_issued);
    RUN_TEST(test_a_5xx_on_revoke_is_still_a_failure);
    RUN_TEST(test_sso_start_carries_slug_context_in_a_json_body);
    RUN_TEST(test_sso_complete_round_trips_state_and_returns_no_token_material);
    RUN_TEST(test_no_operation_calls_the_userinfo_endpoint);
    return UNITY_END();
}
