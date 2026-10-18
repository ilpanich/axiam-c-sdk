/*
 * CONTRACT.md §14.1 and §14.2 rules 5 and 8 (contract 1.62; maintainer, 2026-10-16) -- the
 * device authorization grant authenticates its client. §14.6's required tests, against a
 * mocked server:
 *
 *  - a client configured with a secret sends it (`client_secret`, in the body) at BOTH
 *    `device_authorize` and EVERY `device_poll`, and sends no `Authorization` header at
 *    either, whichever of `client_secret_post` and `client_secret_basic` it is registered
 *    for -- this SDK has no registration knob and no Basic code path, so the one
 *    configuration below is every registration;
 *  - a client configured with a §6.1 certificate and no secret presents the certificate (the
 *    mTLS alias is chosen at both endpoints) and sends `client_id` only;
 *  - a client configured with none sends neither a `client_secret` nor any other credential at
 *    either, and is not refused client-side;
 *  - `device_poll` sends `client_id` on every poll;
 *  - a `401` with `{"error":"invalid_client"}` from either operation is an
 *    OAuthProtocolError carrying that `error`, makes exactly one request (no retry) and does
 *    not enter the §9 refresh guard.
 *
 * Not applicable to this SDK, and said so rather than skipped: `private_key_jwt` (this SDK has
 * no assertion signer, see axiam/ciba.h) and a DPoP proof per poll (it declines §21.7.2 and
 * generates none; a bound client's refusal is the `401` above).
 */

#include "unity.h"
#include "oidc_test_util.h"

void setUp(void) { oidc_reset(); }
void tearDown(void) {}

#define DEVICE_AUTH "{\"device_code\":\"the-device-code\",\"user_code\":\"WDJB-MJHT\"," \
                    "\"verification_uri\":\"https://id.test/device\",\"expires_in\":600,\"interval\":1}"
#define SUCCESS_TOKENS "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\",\"expires_in\":900}"
#define PENDING "{\"error\":\"authorization_pending\"}"

#define MTLS_BASE "https://mtls.api.test"
#define TEST_CERT_PEM                                                          \
    "-----BEGIN CERTIFICATE-----\n"                                            \
    "MIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n"      \
    "-----END CERTIFICATE-----\n"
#define TEST_KEY_PEM                                                           \
    "-----BEGIN AXIAM TEST PLACEHOLDER-----\n"                                 \
    "bm90LWtleS1tYXRlcmlhbA==\n"                                               \
    "-----END AXIAM TEST PLACEHOLDER-----\n"
#define ALIAS_DISCOVERY                                                        \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"device_authorization_endpoint\":\"" OIDC_BASE "/oauth2/device_authorization\"," \
    "\"mtls_endpoint_aliases\":{"                                              \
    "\"token_endpoint\":\"" MTLS_BASE "/oauth2/token\","                       \
    "\"device_authorization_endpoint\":\"" MTLS_BASE "/oauth2/device_authorization\"},"  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\"]}"

static axiam_client_t *cert_client(const char *secret) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    if (secret) axiam_client_config_set_oidc_client_secret(cfg, secret);
    axiam_client_config_set_client_cert(cfg, TEST_CERT_PEM, TEST_KEY_PEM);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (c) {
        c->sleep_fn = oidc_fake_sleep;
        c->clock_fn = oidc_fake_clock;
    }
    return c;
}

/* The value of `field` in the i-th recorded form body, or "" when it is absent. */
static const char *field_in(int i, const char *field, char *buf, size_t cap) {
    char pattern[64];
    snprintf(pattern, sizeof pattern, "%s=", field);
    const char *body = g_oidc.bodies[i];
    const char *at = NULL;
    if (strncmp(body, pattern, strlen(pattern)) == 0) at = body;
    else {
        char amped[66];
        snprintf(amped, sizeof amped, "&%s=", field);
        const char *p = strstr(body, amped);
        if (p) at = p + 1;
    }
    buf[0] = '\0';
    if (!at) return buf;
    at += strlen(pattern);
    size_t n = strcspn(at, "&");
    if (n >= cap) n = cap - 1;
    memcpy(buf, at, n);
    buf[n] = '\0';
    return buf;
}

/* Every credential member the grant could carry beyond `client_secret`. */
static void assert_no_assertion_and_no_authorization(int i) {
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "client_assertion"));
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", g_oidc.authorizations[i], "no Authorization header (§12.1 rule 3)");
}

/* ---- a client configured with a secret ------------------------------------------- */

void test_a_secret_goes_in_the_form_body_at_authorize_and_at_every_poll(void) {
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, PENDING, 0};
    g_oidc.token_script[1] = (oidc_answer_t){400, "{\"error\":\"slow_down\"}", 0};
    g_oidc.token_script[2] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 3;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));

    int device_calls = 0, token_calls = 0;
    for (int i = 0; i < g_oidc.n_calls; i++) {
        int device = strstr(g_oidc.urls[i], "/oauth2/device_authorization") != NULL;
        int token = strstr(g_oidc.urls[i], "/oauth2/token") != NULL;
        if (!device && !token) continue;
        device_calls += device;
        token_calls += token;
        char v[128];
        TEST_ASSERT_EQUAL_STRING_MESSAGE(OIDC_CLIENT_SECRET, field_in(i, "client_secret", v, sizeof v),
                                         g_oidc.urls[i]);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(OIDC_CLIENT_ID, field_in(i, "client_id", v, sizeof v), g_oidc.urls[i]);
        assert_no_assertion_and_no_authorization(i);
    }
    TEST_ASSERT_EQUAL_INT(1, device_calls);
    TEST_ASSERT_EQUAL_INT_MESSAGE(3, token_calls, "every poll carried it, not only the first");
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_a_secret_never_goes_in_the_query_or_a_header(void) {
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    int i = oidc_last_call("/oauth2/device_authorization");
    TEST_ASSERT_NULL_MESSAGE(strstr(g_oidc.urls[i], OIDC_CLIENT_SECRET), "not in the URL");
    TEST_ASSERT_NULL_MESSAGE(strstr(g_oidc.urls[i], "client_secret"), "not in the query");
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[i]);
    /* The tenant is a QUERY parameter and never a body field (§12.1). */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id="));
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/device_authorization", "tenant_id"));
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

/* ---- a client configured with none (public) --------------------------------------- */

void test_a_public_client_sends_no_credential_at_either_endpoint_and_is_not_refused(void) {
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, PENDING, 0};
    g_oidc.token_script[1] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 2;
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));

    int seen = 0;
    for (int i = 0; i < g_oidc.n_calls; i++) {
        if (!strstr(g_oidc.urls[i], "/oauth2/device_authorization") && !strstr(g_oidc.urls[i], "/oauth2/token"))
            continue;
        seen++;
        char v[128];
        TEST_ASSERT_EQUAL_STRING_MESSAGE(OIDC_CLIENT_ID, field_in(i, "client_id", v, sizeof v), "client_id is sent");
        TEST_ASSERT_NULL_MESSAGE(strstr(g_oidc.bodies[i], "client_secret"), "no secret");
        assert_no_assertion_and_no_authorization(i);
    }
    TEST_ASSERT_EQUAL_INT(3, seen); /* authorize, two polls */
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ---- a client configured with a certificate -------------------------------------- */

void test_a_certificate_client_presents_it_at_both_endpoints_and_sends_client_id_only(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY;
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, PENDING, 0};
    g_oidc.token_script[1] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 2;
    axiam_client_t *c = cert_client(NULL); /* a certificate and NO secret */
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));

    int seen = 0;
    for (int i = 0; i < g_oidc.n_calls; i++) {
        int device = strstr(g_oidc.urls[i], "/oauth2/device_authorization") != NULL;
        int token = strstr(g_oidc.urls[i], "/oauth2/token") != NULL;
        if (!device && !token) continue;
        seen++;
        /* The connection that carries the certificate is the alias's (§21.3 rule 2). */
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(g_oidc.urls[i], MTLS_BASE, strlen(MTLS_BASE)), g_oidc.urls[i]);
        char v[128];
        TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_ID, field_in(i, "client_id", v, sizeof v));
        TEST_ASSERT_NULL_MESSAGE(strstr(g_oidc.bodies[i], "client_secret"), "none was configured: none is invented");
        assert_no_assertion_and_no_authorization(i);
    }
    TEST_ASSERT_EQUAL_INT(3, seen);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_a_certificate_and_a_secret_both_go_as_the_other_token_requests_do(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY;
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    g_oidc.token_script[0] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = cert_client(OIDC_CLIENT_SECRET);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    int i = oidc_last_call("/oauth2/device_authorization");
    char v[128];
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_SECRET, field_in(i, "client_secret", v, sizeof v));
    i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_SECRET, field_in(i, "client_secret", v, sizeof v));
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ---- client_id on every poll ------------------------------------------------------ */

void test_every_poll_sends_client_id(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400, PENDING, 0};
    g_oidc.token_script[1] = (oidc_answer_t){400, PENDING, 0};
    g_oidc.token_script[2] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 3;
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_sensitive_t *code = axiam_sensitive_new("the-device-code");
    axiam_oidc_token_set_t set;
    for (int k = 0; k < 3; k++) {
        axiam_error_kind_t rc = axiam_device_poll(c, code, NULL, &set, &err);
        TEST_ASSERT_EQUAL_INT(k < 2 ? AXIAM_ERR_AUTH : AXIAM_OK, rc);
        int i = oidc_last_call("/oauth2/token");
        char v[128];
        TEST_ASSERT_EQUAL_STRING_MESSAGE(OIDC_CLIENT_ID, field_in(i, "client_id", v, sizeof v), "client_id on every poll");
        TEST_ASSERT_EQUAL_STRING("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
                                 field_in(i, "grant_type", v, sizeof v));
    }
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(code);
    axiam_client_free(c);
}

/* ---- 401 invalid_client ----------------------------------------------------------- */

static void assert_invalid_client(axiam_error_kind_t rc, const axiam_error_t *err) {
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, rc);
    TEST_ASSERT_EQUAL_STRING("invalid_client", err->oauth_error);
    TEST_ASSERT_EQUAL_INT(401, (int) err->transport_cause);
    for (int i = 0; i < g_oidc.n_calls; i++)
        TEST_ASSERT_NULL_MESSAGE(strstr(g_oidc.urls[i], "/refresh"), "a 401 here is not an expired session: no §9 refresh");
}

void test_a_401_invalid_client_at_authorize_is_one_request_and_no_refresh(void) {
    g_oidc.device_answer = (oidc_answer_t){401, "{\"error\":\"invalid_client\"}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    assert_invalid_client(axiam_device_authorize(c, NULL, NULL, &a, &err), &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_oidc.device_authorize_calls, "never retried");
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_a_401_invalid_client_at_the_poll_is_one_request_and_no_refresh(void) {
    g_oidc.token_script[0] = (oidc_answer_t){401, "{\"error\":\"invalid_client\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *code = axiam_sensitive_new("the-device-code");
    axiam_oidc_token_set_t set;
    assert_invalid_client(axiam_device_poll(c, code, NULL, &set, &err), &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_oidc.token_calls, "never retried");
    axiam_sensitive_free(code);
    axiam_client_free(c);
}

void test_a_401_invalid_client_ends_device_login_without_another_poll(void) {
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH, 0};
    g_oidc.token_script[0] = (oidc_answer_t){401, "{\"error\":\"invalid_client\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    assert_invalid_client(axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err), &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_oidc.token_calls, "terminal: the loop does not poll again");
    axiam_client_free(c);
}

void test_a_400_unauthorized_client_at_authorize_keeps_its_error(void) {
    g_oidc.device_answer = (oidc_answer_t){400, "{\"error\":\"unauthorized_client\"}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL_STRING("unauthorized_client", err.oauth_error);
    axiam_client_free(c);
}

/* A token set read as the response says: `token_type` is never assumed to be Bearer
 * (§14.2 rule 8, §21.7.1), even though this SDK generates no proof itself. */
void test_a_token_type_of_dpop_is_surfaced_as_the_response_says(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"the-access-token\",\"token_type\":\"DPoP\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *code = axiam_sensitive_new("the-device-code");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_poll(c, code, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("DPoP", set.token_type);
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(code);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_secret_goes_in_the_form_body_at_authorize_and_at_every_poll);
    RUN_TEST(test_a_secret_never_goes_in_the_query_or_a_header);
    RUN_TEST(test_a_public_client_sends_no_credential_at_either_endpoint_and_is_not_refused);
    RUN_TEST(test_a_certificate_client_presents_it_at_both_endpoints_and_sends_client_id_only);
    RUN_TEST(test_a_certificate_and_a_secret_both_go_as_the_other_token_requests_do);
    RUN_TEST(test_every_poll_sends_client_id);
    RUN_TEST(test_a_401_invalid_client_at_authorize_is_one_request_and_no_refresh);
    RUN_TEST(test_a_401_invalid_client_at_the_poll_is_one_request_and_no_refresh);
    RUN_TEST(test_a_401_invalid_client_ends_device_login_without_another_poll);
    RUN_TEST(test_a_400_unauthorized_client_at_authorize_keeps_its_error);
    RUN_TEST(test_a_token_type_of_dpop_is_surfaced_as_the_response_says);
    return UNITY_END();
}
