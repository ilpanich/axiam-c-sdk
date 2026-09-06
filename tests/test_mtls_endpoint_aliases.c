/*
 * RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
 *
 * The rule has one sentence and three named ways to get it wrong, and this file
 * is organised around them rather than around the SDK's function list:
 *
 *  - a call going over mTLS prefers the alias;
 *  - a call NOT going over mTLS keeps the top-level entry;
 *  - an ABSENT member means "no separate mTLS host", never "unsupported";
 *  - only the six listed endpoints are ever aliased — not
 *    `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`;
 *  - `issuer` is not an endpoint, does not move, and still governs `iss`
 *    validation by exact string.
 *
 * The fake transport routes by path and RECORDS THE FULL URL, so choosing the
 * wrong host is a recorded call the assertion can name. The §6.1 identity is a
 * PEM pair on the config: no handshake ever runs against it, and none needs to
 * — what is under test is WHICH URL the SDK builds, which the configured
 * identity and the document decide, not the socket.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "oidc_test_util.h"

#define MTLS_BASE "https://mtls.api.test"

/*
 * A PEM-shaped placeholder pair. axiam_client_config_set_client_cert accepts
 * anything containing "-----BEGIN" and stores the bytes; the fake transport
 * never opens a socket, so no real key material is needed — and deliberately
 * none is present. The key half is labelled PLACEHOLDER rather than shaped like
 * a real key so CI's committed-private-key gate stays a gate: a test that had
 * to whitelist itself past that grep would have taught the next author the
 * wrong lesson.
 */
#define TEST_CERT_PEM                                                          \
    "-----BEGIN CERTIFICATE-----\n"                                            \
    "MIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n"      \
    "-----END CERTIFICATE-----\n"
#define TEST_KEY_PEM                                                           \
    "-----BEGIN AXIAM TEST PLACEHOLDER-----\n"                                 \
    "bm90LWtleS1tYXRlcmlhbA==\n"                                               \
    "-----END AXIAM TEST PLACEHOLDER-----\n"

/* The conventional document, plus all six aliases on the mTLS host. */
#define ALIAS_DISCOVERY_BODY                                                   \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"userinfo_endpoint\":\"" OIDC_BASE "/oauth2/userinfo\","                 \
    "\"introspection_endpoint\":\"" OIDC_BASE "/oauth2/introspect\","          \
    "\"revocation_endpoint\":\"" OIDC_BASE "/oauth2/revoke\","                 \
    "\"end_session_endpoint\":\"" OIDC_BASE "/oauth2/end_session\","           \
    "\"device_authorization_endpoint\":\"" OIDC_BASE "/oauth2/device_authorization\"," \
    "\"pushed_authorization_request_endpoint\":\"" OIDC_BASE "/oauth2/par\","  \
    "\"mtls_endpoint_aliases\":{"                                              \
    "\"token_endpoint\":\"" MTLS_BASE "/oauth2/token\","                       \
    "\"userinfo_endpoint\":\"" MTLS_BASE "/oauth2/userinfo\","                 \
    "\"revocation_endpoint\":\"" MTLS_BASE "/oauth2/revoke\","                 \
    "\"introspection_endpoint\":\"" MTLS_BASE "/oauth2/introspect\","          \
    "\"device_authorization_endpoint\":\"" MTLS_BASE "/oauth2/device_authorization\"," \
    "\"pushed_authorization_request_endpoint\":\"" MTLS_BASE "/oauth2/par\"},"  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\",\"profile\"]}"

/* An object naming ONLY token_endpoint — which RFC 8705 §5 permits. */
#define PARTIAL_ALIAS_DISCOVERY_BODY                                           \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"introspection_endpoint\":\"" OIDC_BASE "/oauth2/introspect\","          \
    "\"revocation_endpoint\":\"" OIDC_BASE "/oauth2/revoke\","                 \
    "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"" MTLS_BASE "/oauth2/token\"},"  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\"]}"

/* Aliases published, but NEITHER level names the device endpoint. */
#define NO_DEVICE_DISCOVERY_BODY                                               \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"" MTLS_BASE "/oauth2/token\"},"  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\"]}"

void setUp(void) { oidc_reset(); }
void tearDown(void) {}

/* A client with the §6.1 identity configured, so §21.3 rule 2 applies to every
 * call it makes. */
static axiam_client_t *mtls_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_client_cert(cfg, TEST_CERT_PEM, TEST_KEY_PEM);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* The host of the most recent request whose URL contains `needle`. */
static const char *host_of_last_call(const char *needle) {
    int i = oidc_last_call(needle);
    if (i < 0) return NULL;
    return strncmp(g_oidc.urls[i], MTLS_BASE, strlen(MTLS_BASE)) == 0 ? MTLS_BASE : OIDC_BASE;
}

static void assert_went_to(const char *needle, const char *expected_host) {
    const char *host = host_of_last_call(needle);
    TEST_ASSERT_NOT_NULL_MESSAGE(host, needle);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected_host, host, needle);
}

/* ------------------------------------------------------------------ */
/* The document round-trips the member                                */
/* ------------------------------------------------------------------ */

void test_discovery_exposes_the_member_when_the_server_publishes_it(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t cfg;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    TEST_ASSERT_EQUAL_INT(1, cfg.has_mtls_endpoint_aliases);
    TEST_ASSERT_EQUAL_STRING(MTLS_BASE "/oauth2/token", cfg.mtls_endpoint_aliases.token_endpoint);
    /* Alongside, never instead of: the conventional entry is untouched. */
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/token", cfg.token_endpoint);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_an_absent_member_leaves_the_flag_clear_rather_than_failing(void) {
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t cfg;
    axiam_error_t err;
    axiam_error_reset(&err);

    /* The default fixture publishes no aliases: a valid document, not an error. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    TEST_ASSERT_EQUAL_INT(0, cfg.has_mtls_endpoint_aliases);
    TEST_ASSERT_NULL(cfg.mtls_endpoint_aliases.token_endpoint);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_the_cached_document_keeps_the_aliases(void) {
    /* §12.3 rule 6 caches the document; the aliases are part of it, so the
     * second (cached) read must carry them too. */
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t first, second;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &first, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &second, &err));

    TEST_ASSERT_EQUAL_INT(1, g_oidc.discovery_calls);
    TEST_ASSERT_EQUAL_INT(1, second.has_mtls_endpoint_aliases);
    TEST_ASSERT_EQUAL_STRING(MTLS_BASE "/oauth2/token",
                             second.mtls_endpoint_aliases.token_endpoint);
    axiam_oidc_config_dispose(&first);
    axiam_oidc_config_dispose(&second);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* A call over mTLS prefers the alias                                 */
/* ------------------------------------------------------------------ */

void test_the_token_endpoint_call_goes_to_the_alias_host(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    g_oidc.token_script[0] = (oidc_answer_t){
        200, "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = mtls_client();
    axiam_oidc_token_set_t set;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_login_client_credentials(c, NULL, AXIAM_TEST_TENANT_ID, &set, &err));

    assert_went_to("/oauth2/token", MTLS_BASE);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_introspect_revoke_and_device_all_go_to_their_aliases(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":true}", 0};
    g_oidc.device_answer = (oidc_answer_t){
        200,
        "{\"device_code\":\"d\",\"user_code\":\"WDJB-MJHT\","
        "\"verification_uri\":\"https://x.test/device\",\"expires_in\":30,\"interval\":1}",
        0};
    axiam_client_t *c = mtls_client();
    axiam_sensitive_t *token = axiam_sensitive_new("a-token");
    axiam_introspection_result_t result;
    axiam_device_authorization_t device;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_introspect(c, token, NULL, AXIAM_TEST_TENANT_ID, &result, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_revoke(c, token, NULL, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_device_authorize(c, NULL, AXIAM_TEST_TENANT_ID, &device, &err));

    assert_went_to("/oauth2/introspect", MTLS_BASE);
    assert_went_to("/oauth2/revoke", MTLS_BASE);
    assert_went_to("/oauth2/device_authorization", MTLS_BASE);

    axiam_introspection_result_dispose(&result);
    axiam_device_authorization_dispose(&device);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_the_par_push_goes_to_the_alias_host(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    g_oidc.par_answer = (oidc_answer_t){
        201, "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:x\",\"expires_in\":60}", 0};
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI, "openid",
                                               AXIAM_TEST_TENANT_ID, &par, &err));

    assert_went_to("/oauth2/par", MTLS_BASE);
    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Consequence 1: absence means "no separate host"                    */
/* ------------------------------------------------------------------ */

void test_an_mtls_client_with_no_aliases_keeps_the_top_level_endpoints(void) {
    /* Not an error, and not the alias origin: a deployment running
     * `client_auth = optional` on one listener serves both populations at the
     * conventional endpoints and correctly publishes nothing. */
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":true}", 0};
    axiam_client_t *c = mtls_client();
    axiam_sensitive_t *token = axiam_sensitive_new("a-token");
    axiam_introspection_result_t result;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_introspect(c, token, NULL, AXIAM_TEST_TENANT_ID, &result, &err));

    assert_went_to("/oauth2/introspect", OIDC_BASE);
    axiam_introspection_result_dispose(&result);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_client_not_doing_mtls_keeps_the_top_level_endpoints(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":true}", 0};
    axiam_client_t *c = oidc_make_client(); /* no §6.1 identity */
    axiam_sensitive_t *token = axiam_sensitive_new("a-token");
    axiam_introspection_result_t result;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_introspect(c, token, NULL, AXIAM_TEST_TENANT_ID, &result, &err));

    assert_went_to("/oauth2/introspect", OIDC_BASE);
    axiam_introspection_result_dispose(&result);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_partial_alias_object_falls_back_per_endpoint(void) {
    /* RFC 8705 §5 does not require an OP to alias all six, and the shape of this
     * member must never be why a client stops working: an object naming only
     * token_endpoint is a valid document, and every endpoint it does not name
     * falls back to the top-level entry. */
    g_oidc.discovery_body = PARTIAL_ALIAS_DISCOVERY_BODY;
    g_oidc.token_script[0] = (oidc_answer_t){
        200, "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;
    g_oidc.introspect_answer = (oidc_answer_t){200, "{\"active\":true}", 0};
    axiam_client_t *c = mtls_client();
    axiam_oidc_token_set_t set;
    axiam_sensitive_t *token = axiam_sensitive_new("a-token");
    axiam_introspection_result_t result;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_login_client_credentials(c, NULL, AXIAM_TEST_TENANT_ID, &set, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_introspect(c, token, NULL, AXIAM_TEST_TENANT_ID, &result, &err));

    assert_went_to("/oauth2/token", MTLS_BASE);
    assert_went_to("/oauth2/introspect", OIDC_BASE);

    axiam_introspection_result_dispose(&result);
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_an_unsupported_grant_is_still_reported_when_neither_level_names_it(void) {
    g_oidc.discovery_body = NO_DEVICE_DISCOVERY_BODY;
    axiam_client_t *c = mtls_client();
    axiam_device_authorization_t device;
    axiam_error_t err;
    axiam_error_reset(&err);

    /* Neither level names the endpoint, so the answer is still "this server does
     * not support the device grant" — never a URL built by concatenation. */
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
                          axiam_device_authorize(c, NULL, AXIAM_TEST_TENANT_ID, &device, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.device_authorize_calls);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Consequence 2: no alias is ever synthesised                        */
/* ------------------------------------------------------------------ */

void test_the_front_channel_and_jwks_endpoints_are_never_aliased(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));

    /* A browser sent to an mTLS host raises a native certificate-chooser dialog
     * most users cannot answer, and jwks_uri is public key material that gains
     * nothing from a handshake. */
    TEST_ASSERT_EQUAL_INT(0, strncmp(req.url, OIDC_BASE "/oauth2/authorize",
                                     strlen(OIDC_BASE "/oauth2/authorize")));
    TEST_ASSERT_EQUAL_STRING(OIDC_BASE "/oauth2/jwks", cfg.jwks_uri);

    char *logout = axiam_logout_url(&cfg, "not-a-real-token", NULL, NULL);
    TEST_ASSERT_NOT_NULL(logout);
    TEST_ASSERT_EQUAL_INT(0, strncmp(logout, OIDC_BASE "/oauth2/end_session",
                                     strlen(OIDC_BASE "/oauth2/end_session")));
    free(logout);

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Consequence 3: issuer is never aliased                             */
/* ------------------------------------------------------------------ */

void test_the_issuer_does_not_move_with_the_endpoints(void) {
    g_oidc.discovery_body = ALIAS_DISCOVERY_BODY;
    axiam_client_t *c = mtls_client();
    axiam_oidc_config_t cfg;
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    /* §12.4 rule 3 compares `iss` against THIS value by exact string, for every
     * token — including one minted at an alias endpoint. An SDK that derived an
     * expected issuer from the host it called would reject every token it
     * obtains over mTLS. */
    TEST_ASSERT_EQUAL_STRING(OIDC_ISSUER, cfg.issuer);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(cfg.issuer, MTLS_BASE));
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_discovery_exposes_the_member_when_the_server_publishes_it);
    RUN_TEST(test_an_absent_member_leaves_the_flag_clear_rather_than_failing);
    RUN_TEST(test_the_cached_document_keeps_the_aliases);
    RUN_TEST(test_the_token_endpoint_call_goes_to_the_alias_host);
    RUN_TEST(test_introspect_revoke_and_device_all_go_to_their_aliases);
    RUN_TEST(test_the_par_push_goes_to_the_alias_host);
    RUN_TEST(test_an_mtls_client_with_no_aliases_keeps_the_top_level_endpoints);
    RUN_TEST(test_a_client_not_doing_mtls_keeps_the_top_level_endpoints);
    RUN_TEST(test_a_partial_alias_object_falls_back_per_endpoint);
    RUN_TEST(test_an_unsupported_grant_is_still_reported_when_neither_level_names_it);
    RUN_TEST(test_the_front_channel_and_jwks_endpoints_are_never_aliased);
    RUN_TEST(test_the_issuer_does_not_move_with_the_endpoints);
    return UNITY_END();
}
