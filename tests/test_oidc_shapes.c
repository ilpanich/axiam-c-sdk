/*
 * §12 / §12.7 / §14 / §15 — the shapes a real server actually sends.
 *
 * Every optional field in these sections has two states, and the parser has a
 * branch for each. The suites next door drive the happy path and the refusals;
 * this one walks the OTHER side of each of those branches — the token response
 * with no `token_type`, the ID token with no optional claims, the `aud` array
 * with a number in it, the tenant id that is one character short of a UUID.
 *
 * None of these is exotic. `token_type` omitted is what a minimal OP sends;
 * `verification_uri_complete` present is what an OP that supports QR codes
 * sends; a not-quite-UUID tenant id is what a copy-paste error looks like. The
 * point of the file is that an SDK's parser meets all of them eventually, and
 * the ones it has never been run against are the ones that crash.
 */

#include "unity.h"
#include "jwt_fixture.h"
#include "oidc_test_util.h"
#include "oidc_internal.h"

static char *g_token;
static char *g_jwks;

void setUp(void) {
    oidc_reset();
    g_token = NULL;
    g_jwks = NULL;
}
void tearDown(void) {
    free(g_token);
    free(g_jwks);
}

static void mint(const char *payload) {
    free(g_token);
    free(g_jwks);
    g_token = NULL;
    g_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;
}

/* ------------------------------------------------------------------ */
/* §12.3 rule 4 — what counts as a UUID                               */
/* ------------------------------------------------------------------ */

void test_only_a_well_formed_uuid_satisfies_the_tenant_rule(void) {
    /* The guard that stands between a slug and the `?tenant_id=` query
     * parameter. Each rejection below is a different way to be almost-right,
     * and "almost" is what produces a server-side error the caller has to
     * decode instead of a client-side one that names the problem. */
    TEST_ASSERT_TRUE(oidc_is_uuid("11111111-1111-1111-1111-111111111111"));
    TEST_ASSERT_TRUE(oidc_is_uuid("AbCdEf01-2345-6789-abcd-ef0123456789"));
    TEST_ASSERT_FALSE(oidc_is_uuid(NULL));
    TEST_ASSERT_FALSE(oidc_is_uuid(""));
    TEST_ASSERT_FALSE(oidc_is_uuid("acme"));
    /* One character short. */
    TEST_ASSERT_FALSE(oidc_is_uuid("11111111-1111-1111-1111-11111111111"));
    /* One character long — trailing junk after a valid UUID. */
    TEST_ASSERT_FALSE(oidc_is_uuid("11111111-1111-1111-1111-1111111111112"));
    /* Non-hex in the last group. */
    TEST_ASSERT_FALSE(oidc_is_uuid("11111111-1111-1111-1111-11111111111z"));
    /* Right length, wrong separators — the 32-hex-with-underscores form. */
    TEST_ASSERT_FALSE(oidc_is_uuid("11111111_1111_1111_1111_111111111111"));
    /* Unbracketed hex, no separators at all. */
    TEST_ASSERT_FALSE(oidc_is_uuid("11111111111111111111111111111111"));
}

/* ------------------------------------------------------------------ */
/* TokenResponse shapes                                               */
/* ------------------------------------------------------------------ */

void test_a_token_response_without_a_token_type_defaults_to_bearer(void) {
    /* RFC 6749 makes `token_type` required, but a minimal OP omits it and the
     * only value AXIAM issues is `Bearer`. Defaulting beats returning NULL for
     * a field every caller concatenates into a header. */
    g_oidc.token_script[0] = (oidc_answer_t){200, "{\"access_token\":\"at\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("Bearer", set.token_type);
    TEST_ASSERT_EQUAL_INT(0, set.expires_in);
    TEST_ASSERT_NULL(set.scope);
    TEST_ASSERT_NULL(set.refresh_token);
    TEST_ASSERT_NULL(set.id_token);
    TEST_ASSERT_NULL(set.id_claims);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_a_refresh_token_without_an_id_token_is_carried(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900,"
        "\"scope\":\"openid profile\",\"refresh_token\":\"rt\"}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, "openid", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("rt", axiam_sensitive_reveal(set.refresh_token));
    TEST_ASSERT_EQUAL_STRING("openid profile", set.scope);
    TEST_ASSERT_NULL(set.id_claims);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* ID-token claim shapes                                              */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t exchange_id(axiam_client_t *c, const char *nonce,
                                      axiam_oidc_token_set_t *out, axiam_error_t *err) {
    static char body[8192];
    snprintf(body, sizeof(body),
             "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900,"
             "\"id_token\":\"%s\"}", g_token);
    g_oidc.token_script[0] = (oidc_answer_t){200, body, 0};
    g_oidc.token_script_len = 1;
    axiam_sensitive_t *verifier = axiam_sensitive_new("v");
    axiam_oidc_exchange_params_t p = {0};
    p.code = "c";
    p.code_verifier = verifier;
    p.redirect_uri = OIDC_REDIRECT_URI;
    p.nonce = nonce;
    axiam_error_kind_t k = axiam_oidc_exchange(c, &p, out, err);
    axiam_sensitive_free(verifier);
    return k;
}

void test_an_id_token_with_every_optional_claim_is_surfaced_whole(void) {
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nbf\":%lld,\"nonce\":\"n\","
             "\"azp\":\"" OIDC_CLIENT_ID "\",\"email\":\"a@b.test\","
             "\"preferred_username\":\"ada\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\","
             "\"roles\":[\"admin\",\"auditor\"]}", now + 900, now - 5, now - 10);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_STRING("ada", set.id_claims->preferred_username);
    TEST_ASSERT_EQUAL_STRING(AXIAM_TEST_TENANT_ID, set.id_claims->tenant_id);
    TEST_ASSERT_EQUAL_size_t(2, set.id_claims->roles_count);
    /* `nbf` in the past is honoured rather than ignored. */
    TEST_ASSERT_EQUAL_STRING("n", set.id_claims->nonce);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_an_id_token_with_no_optional_claims_still_validates(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_NULL(set.id_claims->email);
    TEST_ASSERT_NULL(set.id_claims->tenant_id);
    TEST_ASSERT_NULL(set.id_claims->authorized_party);
    TEST_ASSERT_EQUAL_size_t(0, set.id_claims->roles_count);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_empty_claim_arrays_read_as_no_members(void) {
    /* `"roles":[]` is what a user with no roles looks like, and `"aud":[]` is
     * what a misconfigured client registration looks like. The first is
     * ordinary; the second must fail rule 4 rather than pass an empty search. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"n\",\"roles\":[]}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_size_t(0, set.id_claims->roles_count);
    TEST_ASSERT_NULL(set.id_claims->roles);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);

    oidc_reset();
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[],\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);
    c = oidc_make_client();
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_AUDIENCE, err.id_token_reason);
    axiam_client_free(c);
}

void test_a_same_length_nonce_that_differs_is_still_rejected(void) {
    /* The constant-time comparison's interesting case. A length check alone
     * would accept this, and the whole point of §12.4 rule 6 is that an
     * attacker chooses the nonce in the token. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"aaaaaaaa\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_id(c, "aaaaaaab", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_NONCE_MISMATCH, err.id_token_reason);
    axiam_client_free(c);
}

void test_an_audience_array_with_non_string_members_is_handled(void) {
    /* A JSON array is not a string array. Skipping the non-strings rather than
     * aborting keeps a server that adds a structured audience entry from
     * breaking a client that only cares whether its own id is present. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[42,\"" OIDC_CLIENT_ID "\",null],"
             "\"azp\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,"
             "\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_id(c, "n", &set, &err));
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_an_id_token_with_no_issuer_claim_at_all_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,"
             "\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_ISSUER, err.id_token_reason);
    axiam_client_free(c);
}

void test_an_id_token_with_no_audience_claim_at_all_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,"
             "\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_AUDIENCE, err.id_token_reason);
    axiam_client_free(c);
}

void test_a_malformed_nbf_is_rejected_rather_than_ignored(void) {
    /* An `nbf` the SDK cannot read is not the same as no `nbf`: honouring it
     * means honouring it, and a string where a number belongs is a token this
     * relying party does not understand. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nbf\":\"soon\",\"nonce\":\"n\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_id(c, "n", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_TOKEN_EXPIRED, err.id_token_reason);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §14 response shapes                                                */
/* ------------------------------------------------------------------ */

void test_a_verification_uri_complete_is_surfaced_when_the_server_sends_one(void) {
    /* The QR-code case §14.3 exists for: a device that can render one does not
     * make the user type anything. */
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc\",\"user_code\":\"WDJB-MJHT\","
        "\"verification_uri\":\"https://id.test/device\","
        "\"verification_uri_complete\":\"https://id.test/device?user_code=WDJB-MJHT\","
        "\"expires_in\":600,\"interval\":2}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, "openid", NULL, &a, &err));
    TEST_ASSERT_EQUAL_STRING("https://id.test/device?user_code=WDJB-MJHT",
                             a.verification_uri_complete);
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/device_authorization", "scope"));
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_a_nonsensical_interval_falls_back_to_the_rfc_default(void) {
    /* A zero or negative interval would mean "poll as fast as you can", which
     * is the one thing §14.2 rule 2 forbids hard-coding. It is treated as
     * absent. */
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://id.test/d\","
        "\"expires_in\":600,\"interval\":0}", 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_DEVICE_DEFAULT_INTERVAL_S, a.interval);
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §15 request shapes                                                 */
/* ------------------------------------------------------------------ */

void test_null_entries_in_the_scope_list_are_skipped(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"token_type\":\"Bearer\",\"expires_in\":300}", 0};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("s");
    const char *scopes[] = {"read", NULL, "write"};
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    p.scopes = scopes;
    p.scope_count = 3;
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_token_exchange(c, &p, &t, &err));

    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "scope=read%20write"));
    /* Defaults applied when the server omits them, so a caller never has to
     * null-check what RFC 8693 makes mandatory. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_TOKEN_TYPE_ACCESS_TOKEN, t.issued_token_type);
    TEST_ASSERT_NULL(t.scope);

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.7 logout-token shapes                                          */
/* ------------------------------------------------------------------ */

void test_a_logout_token_with_only_a_sub_and_no_jti_is_accepted(void) {
    /* Rule 5 asks for AT LEAST ONE of `sid` and `sub`, and rule 7 asks for
     * `jti` to be surfaced — surfaced, not required. An OP that omits it leaves
     * the RP unable to dedup, which is the OP's choice to make. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"user-9\","
             "\"exp\":%lld,\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}}", now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_verify_logout_token(c, g_token, &t, &err));
    TEST_ASSERT_NULL(t.sid);
    TEST_ASSERT_EQUAL_STRING("user-9", t.subject);
    TEST_ASSERT_NULL(t.jwt_id);
    TEST_ASSERT_EQUAL_INT(0, t.issued_at);
    axiam_verified_logout_token_dispose(&t);
    axiam_client_free(c);
}

void test_an_events_member_that_is_not_an_object_is_rejected(void) {
    /* Rule 3 requires the key with an OBJECT value. A server (or an attacker)
     * that supplies the key with a string value has not sent a logout event. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sid\":\"s\","
             "\"exp\":%lld,\"events\":\"" AXIAM_LOGOUT_EVENT_KEY "\"}", now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, g_token, &t, &err));

    /* The same, with an object that carries some OTHER event key. */
    oidc_reset();
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sid\":\"s\","
             "\"exp\":%lld,\"events\":{\"http://example.test/other\":{}}}", now + 120);
    mint(payload);
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, g_token, &t, &err));

    axiam_client_free(c);
}

void test_a_logout_token_with_a_numeric_audience_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":42,\"sid\":\"s\",\"exp\":%lld,"
             "\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}}", now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, g_token, &t, &err));
    axiam_client_free(c);
}

void test_a_logout_token_with_no_exp_is_rejected(void) {
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sid\":\"s\","
             "\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}}");
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, g_token, &t, &err));
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Empty strings, which are how many servers spell "absent"           */
/* ------------------------------------------------------------------ */

void test_empty_string_fields_are_treated_as_absent(void) {
    /*
     * A field present with an empty value is the third state every one of these
     * parsers has to handle, and the one that produces the worst failures if it
     * is not: an empty `token_type` concatenated into "Authorization:  at",
     * an empty `refresh_token` handed to a caller who will redeem it, an empty
     * `verification_uri_complete` rendered as a QR code pointing nowhere.
     * Treating it as absent is the only reading that keeps those from
     * happening.
     */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"\",\"expires_in\":900,"
        "\"scope\":\"\",\"refresh_token\":\"\",\"id_token\":\"\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, "", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("Bearer", set.token_type);
    TEST_ASSERT_NULL(set.scope);
    TEST_ASSERT_NULL(set.refresh_token);
    /* An empty `id_token` is not an ID token, so §12.4 is not run against it
     * and the set is returned rather than discarded. */
    TEST_ASSERT_NULL(set.id_token);
    TEST_ASSERT_NULL(set.id_claims);
    /* An empty scope was never sent, per §12.1's omit-rather-than-send rule. */
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "scope"));
    axiam_oidc_token_set_dispose(&set);

    oidc_reset();
    g_oidc.introspect_answer = (oidc_answer_t){200,
        "{\"active\":true,\"sub\":\"\",\"scope\":\"\",\"client_id\":\"\",\"jti\":\"\","
        "\"exp\":\"soon\"}", 0};
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_introspection_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_introspect(c, tok, "", NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(1, r.active);
    TEST_ASSERT_NULL(r.subject);
    TEST_ASSERT_NULL(r.scope);
    /* A non-numeric `exp` is not a time; 0 means "the server told us nothing
     * usable", which is what a caller can act on. */
    TEST_ASSERT_EQUAL_INT(0, r.expires_at);
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/introspect", "token_type_hint"));
    axiam_introspection_result_dispose(&r);

    oidc_reset();
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://id.test/d\","
        "\"verification_uri_complete\":\"\",\"expires_in\":600}", 0};
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_NULL(a.verification_uri_complete);
    axiam_device_authorization_dispose(&a);

    oidc_reset();
    g_oidc.sso_start_answer = (oidc_answer_t){200,
        "{\"authorize_url\":\"\",\"state\":\"s\",\"expires_in_secs\":600}", 0};
    axiam_sso_start_result_t ss;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", &ss, &err));
    axiam_sso_start_result_dispose(&ss);

    oidc_reset();
    g_oidc.sso_complete_answer = (oidc_answer_t){200,
        "{\"user_id\":\"u\",\"session_id\":\"s\",\"redirect_uri\":\"\",\"expires_in\":\"nope\"}", 0};
    axiam_sso_complete_result_t sc;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_sso_complete(c, "c", "s", &sc, &err));
    TEST_ASSERT_NULL(sc.redirect_uri);
    TEST_ASSERT_EQUAL_INT(0, sc.expires_in);
    axiam_sso_complete_result_dispose(&sc);

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_a_discovery_document_with_empty_optional_endpoints_reads_as_absent(void) {
    /* An empty `end_session_endpoint` must not become a URL of "?state=x" — the
     * §12.7.2 rule 1 refusal is the right answer, same as if the member were
     * missing. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_oidc_config_t doc;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &doc, &err));
    /* Simulate the empty-member document by clearing what the fixture sent. */
    free(doc.end_session_endpoint);
    doc.end_session_endpoint = NULL;
    TEST_ASSERT_NULL(axiam_logout_url(&doc, "tok", NULL, NULL));

    axiam_oidc_config_dispose(&doc);
    axiam_client_free(c);
}

void test_every_operation_tolerates_a_null_error_out_parameter(void) {
    /*
     * `err` is an out-parameter, not a requirement. A caller that only cares
     * whether an operation succeeded should be able to pass NULL — and every
     * failure path here writes through that pointer, so this is the one test
     * that proves none of them dereferences it.
     */
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"invalid_grant\"}", 0};
    g_oidc.token_script_len = 1;
    g_oidc.device_answer = (oidc_answer_t){400, "{\"error\":\"invalid_client\"}", 0};
    g_oidc.introspect_answer = (oidc_answer_t){401, "{\"error\":\"invalid_client\"}", 0};
    g_oidc.sso_start_answer = (oidc_answer_t){500, "{}", 0};

    axiam_client_t *c = oidc_make_client();
    axiam_sensitive_t *tok = axiam_sensitive_new("t");
    axiam_oidc_config_t doc;
    axiam_oidc_token_set_t set;
    axiam_introspection_result_t ir;
    axiam_sso_start_result_t ss;
    axiam_device_authorization_t da;
    axiam_exchanged_token_t xt;
    axiam_verified_logout_token_t vl;
    axiam_authorization_request_t ar;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &doc, NULL));
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &doc, OIDC_REDIRECT_URI, NULL, &ar, NULL));
    axiam_authorization_request_dispose(&ar);

    axiam_oidc_exchange_params_t ep = {0};
    ep.code = "c";
    ep.code_verifier = tok;
    ep.redirect_uri = OIDC_REDIRECT_URI;
    ep.nonce = "n";
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_exchange(c, &ep, &set, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_oidc_refresh(c, tok, NULL, NULL, &set, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_login_client_credentials(c, NULL, NULL, &set, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_introspect(c, tok, NULL, NULL, &ir, NULL));
    /* Revocation answers 200 for a token it has never issued (§12.1 rule 5), so
     * the NULL-`err` path through the success branch is the one exercised here. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_revoke(c, tok, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_sso_start(c, "f", "r", &ss, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_authorize(c, NULL, NULL, &da, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, tok, NULL, &set, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_device_login(c, NULL, NULL, NULL, NULL, &set, NULL));

    axiam_token_exchange_params_t xp = {0};
    xp.subject_token = tok;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_token_exchange(c, &xp, &xt, NULL));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_verify_logout_token(c, "a.b.c", &vl, NULL));

    axiam_oidc_config_dispose(&doc);
    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

void test_the_sensitive_accessor_is_safe_on_a_null_handle(void) {
    /* §7 rule 3's accessor is called at every point of use in this SDK, often
     * on an optional handle (`actor_token`, `client_secret`). NULL in, NULL
     * out — never a dereference and never an empty string that would read as a
     * configured-but-blank credential. */
    TEST_ASSERT_NULL(axiam_sensitive_reveal(NULL));
    axiam_sensitive_t *s = axiam_sensitive_new("value");
    TEST_ASSERT_EQUAL_STRING("value", axiam_sensitive_reveal(s));
    /* ...and the redacted rendering is unaffected by the accessor existing. */
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(s));
    axiam_sensitive_free(s);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_only_a_well_formed_uuid_satisfies_the_tenant_rule);
    RUN_TEST(test_a_token_response_without_a_token_type_defaults_to_bearer);
    RUN_TEST(test_a_refresh_token_without_an_id_token_is_carried);
    RUN_TEST(test_an_id_token_with_every_optional_claim_is_surfaced_whole);
    RUN_TEST(test_an_id_token_with_no_optional_claims_still_validates);
    RUN_TEST(test_empty_claim_arrays_read_as_no_members);
    RUN_TEST(test_a_same_length_nonce_that_differs_is_still_rejected);
    RUN_TEST(test_an_audience_array_with_non_string_members_is_handled);
    RUN_TEST(test_an_id_token_with_no_issuer_claim_at_all_is_rejected);
    RUN_TEST(test_an_id_token_with_no_audience_claim_at_all_is_rejected);
    RUN_TEST(test_a_malformed_nbf_is_rejected_rather_than_ignored);
    RUN_TEST(test_a_verification_uri_complete_is_surfaced_when_the_server_sends_one);
    RUN_TEST(test_a_nonsensical_interval_falls_back_to_the_rfc_default);
    RUN_TEST(test_null_entries_in_the_scope_list_are_skipped);
    RUN_TEST(test_a_logout_token_with_only_a_sub_and_no_jti_is_accepted);
    RUN_TEST(test_an_events_member_that_is_not_an_object_is_rejected);
    RUN_TEST(test_a_logout_token_with_a_numeric_audience_is_rejected);
    RUN_TEST(test_a_logout_token_with_no_exp_is_rejected);
    RUN_TEST(test_empty_string_fields_are_treated_as_absent);
    RUN_TEST(test_a_discovery_document_with_empty_optional_endpoints_reads_as_absent);
    RUN_TEST(test_every_operation_tolerates_a_null_error_out_parameter);
    RUN_TEST(test_the_sensitive_accessor_is_safe_on_a_null_handle);
    return UNITY_END();
}
