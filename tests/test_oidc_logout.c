/*
 * CONTRACT.md §12.7.6 — the required logout tests.
 *
 * The `logout_url` half is a URL builder and its tests are about what it
 * refuses to invent: an endpoint by concatenation, a `state` of its own, a
 * client-side allow-list for `post_logout_redirect_uri`.
 *
 * The `verify_logout_token` half is where the security weight sits. Its input
 * arrives unsolicited, from the network, and instructs the relying party to
 * terminate a session — so the two tests that matter most are the two an
 * implementer is most likely to skip: a token with no `events` member, and an
 * otherwise-valid ID TOKEN replayed as a logout instruction. §12.7.6 names both
 * explicitly, and the second one says to assert it with a real ID token,
 * because that is the actual attack.
 */

#include "unity.h"
#include "jwt_fixture.h"
#include "oidc_test_util.h"

#define LOGOUT_EVENTS "\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}"

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

/* A logout-token payload that passes every §12.7.3 rule, with `overrides`
 * spliced in verbatim so a test can break exactly one thing. */
static const char *logout_claims(char *buf, size_t n, const char *overrides) {
    long long now = (long long)time(NULL);
    snprintf(buf, n,
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sid\":\"session-1\",\"sub\":\"user-1\",\"jti\":\"jti-1\","
             "\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "%s}",
             now - 5, now + 120, overrides ? overrides : "");
    return buf;
}

static axiam_error_kind_t verify(axiam_client_t *c, axiam_verified_logout_token_t *out,
                                 axiam_error_t *err) {
    return axiam_verify_logout_token(c, g_token, out, err);
}

/* ------------------------------------------------------------------ */
/* §12.7.2 logout_url                                                 */
/* ------------------------------------------------------------------ */

void test_logout_url_uses_the_discovered_endpoint_not_concatenation(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));

    char *url = axiam_logout_url(&cfg, "the-id-token", "https://app.test/bye", "st-1");
    TEST_ASSERT_NOT_NULL(url);

    /*
     * §12.7.2 rule 1. The fixture's issuer is https://issuer.test while the
     * end_session_endpoint is on https://api.test, so an implementation that
     * built "{issuer}/oauth2/end_session" would produce a different host — the
     * exact failure that works against AXIAM and breaks against every other OP
     * the same code is pointed at.
     */
    TEST_ASSERT_EQUAL_INT(0, strncmp(url, OIDC_BASE "/oauth2/end_session?",
                                     strlen(OIDC_BASE "/oauth2/end_session?")));
    TEST_ASSERT_NULL(strstr(url, OIDC_ISSUER));
    TEST_ASSERT_NOT_NULL(strstr(url, "id_token_hint=the-id-token"));
    TEST_ASSERT_NOT_NULL(strstr(url, "post_logout_redirect_uri=https%3A%2F%2Fapp.test%2Fbye"));
    /* Rule 2: passed through unmodified. */
    TEST_ASSERT_NOT_NULL(strstr(url, "state=st-1"));

    free(url);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_logout_url_omits_what_the_caller_did_not_supply(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);

    char *url = axiam_logout_url(&cfg, "the-id-token", NULL, NULL);
    TEST_ASSERT_NOT_NULL(url);
    TEST_ASSERT_NOT_NULL(strstr(url, "id_token_hint="));
    TEST_ASSERT_NULL(strstr(url, "post_logout_redirect_uri="));
    /* Rule 2: the SDK never INVENTS a state — the value only means something to
     * the application that will receive it back. */
    TEST_ASSERT_NULL(strstr(url, "state="));

    free(url);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_logout_url_does_not_pre_validate_the_redirect_uri(void) {
    /* §12.7.2 rule 3: the allow-list lives in the client's server-side
     * registration. A client-side copy would drift and would reject a URI an
     * operator had just registered — so an unfamiliar host is passed through. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);

    char *url = axiam_logout_url(&cfg, "tok", "https://somewhere-else.example/bye", NULL);
    TEST_ASSERT_NOT_NULL(url);
    TEST_ASSERT_NOT_NULL(strstr(url, "somewhere-else.example"));

    free(url);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_logout_url_has_no_hintless_mode(void) {
    /* §12.7.1: there is no parameter on the wire that names the user some other
     * way, and inventing one would encourage exactly the request the server
     * refuses to act on. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);
    TEST_ASSERT_NULL(axiam_logout_url(&cfg, NULL, "https://app.test/bye", "st"));
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_logout_url_appends_to_an_endpoint_that_already_has_a_query(void) {
    /* The same assembly problem the token endpoint has: `end_session_endpoint`
     * comes from a document the SDK does not control, and a deployment that
     * publishes a versioned or themed one would otherwise get two `?`. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(c, &cfg, &err);
    free(cfg.end_session_endpoint);
    cfg.end_session_endpoint = strdup(OIDC_BASE "/oauth2/end_session?theme=dark");

    char *url = axiam_logout_url(&cfg, "tok", NULL, NULL);
    TEST_ASSERT_NOT_NULL(url);
    TEST_ASSERT_NOT_NULL(strstr(url, "?theme=dark&id_token_hint=tok"));
    free(url);

    /* Empty strings are omitted, exactly as NULL is — an empty `state=` means
     * nothing to the application that receives it back. */
    url = axiam_logout_url(&cfg, "tok", "", "");
    TEST_ASSERT_NOT_NULL(url);
    TEST_ASSERT_NULL(strstr(url, "state="));
    TEST_ASSERT_NULL(strstr(url, "post_logout_redirect_uri="));
    free(url);

    /* And an empty ID token is no ID token (§12.7.1's no-hintless-mode rule). */
    TEST_ASSERT_NULL(axiam_logout_url(&cfg, "", NULL, NULL));

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.7.3 verify_logout_token                                        */
/* ------------------------------------------------------------------ */

void test_a_valid_logout_token_surfaces_sid_sub_and_jti(void) {
    char payload[1024];
    mint(logout_claims(payload, sizeof(payload), NULL));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, verify(c, &t, &err));

    /* §12.7.3: NEVER a bare boolean. The RP has to know WHICH session to end,
     * and when `sid` is present it must end that one only. */
    TEST_ASSERT_EQUAL_STRING("session-1", t.sid);
    TEST_ASSERT_EQUAL_STRING("user-1", t.subject);
    TEST_ASSERT_EQUAL_STRING("jti-1", t.jwt_id);

    axiam_verified_logout_token_dispose(&t);
    axiam_client_free(c);
}

void test_the_same_token_verifying_twice_does_not_raise(void) {
    /*
     * §12.7.3 rule 7 / §12.7.6. Delivery is at-least-once with retry, so a
     * valid token legitimately arrives twice. This SDK deliberately does NOT
     * dedup internally — it has no durable store and would silently drop a real
     * second logout after a restart — so `jti` is surfaced and dedup is the
     * RP's job. An SDK that failed the second delivery would break a legitimate
     * retry.
     */
    char payload[1024];
    mint(logout_claims(payload, sizeof(payload), NULL));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t a, b;
    TEST_ASSERT_EQUAL(AXIAM_OK, verify(c, &a, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, verify(c, &b, &err));
    TEST_ASSERT_EQUAL_STRING(a.jwt_id, b.jwt_id);

    axiam_verified_logout_token_dispose(&a);
    axiam_verified_logout_token_dispose(&b);
    axiam_client_free(c);
}

void test_a_missing_events_member_is_rejected(void) {
    /*
     * §12.7.3 rule 3, and the one that makes the rest matter: `events` is what
     * distinguishes a logout token from an ID token. An SDK that skips it will
     * accept a replayed ID token as a logout instruction.
     */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sid\":\"session-1\",\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld}",
             now - 5, now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "events"));
    /* Rule 8: the error must not echo the token. */
    TEST_ASSERT_NULL(strstr(err.message, g_token));
    axiam_client_free(c);
}

void test_a_replayed_id_token_is_rejected_for_carrying_a_nonce(void) {
    /*
     * §12.7.6 names this test and says to assert it with an OTHERWISE-VALID ID
     * token, because that is the actual attack: an attacker who captures an ID
     * token and POSTs it to the RP's back-channel endpoint. Back-Channel Logout
     * 1.0 §2.4 forbids a `nonce`, and its presence is the documented signature
     * of the replay — so this rejects rather than ignoring.
     */
    char payload[1024];
    mint(logout_claims(payload, sizeof(payload), ",\"nonce\":\"n-1\""));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "nonce"));
    axiam_client_free(c);
}

void test_a_token_naming_neither_sid_nor_sub_is_rejected(void) {
    /* Rule 5: it identifies nothing, so there is nothing the RP could do with
     * it except guess. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"jti\":\"j\","
             "\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}", now - 5, now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    axiam_client_free(c);
}

void test_a_wrong_audience_is_rejected(void) {
    /* Rule 2: a token minted for another RP must not be accepted here. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"some-other-rp\",\"sid\":\"s\","
             "\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}", now - 5, now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "aud"));
    axiam_client_free(c);
}

void test_an_array_audience_naming_this_client_is_accepted(void) {
    /* RFC 7519 §4.1.3 permits `aud` as a string or an array, and a deployment
     * where the OP names several relying parties on one token is legitimate.
     * Rule 2 asks whether THIS client is among them, not whether it is alone. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[\"other-rp\",\"" OIDC_CLIENT_ID "\"],"
             "\"sid\":\"s\",\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}",
             now - 5, now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, verify(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING("s", t.sid);
    /* `sub` was absent, which rule 5 allows as long as `sid` is present. */
    TEST_ASSERT_NULL(t.subject);
    axiam_verified_logout_token_dispose(&t);

    /* An array that does NOT name this client is still refused. */
    oidc_reset();
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[\"other-rp\",\"third-rp\"],"
             "\"sid\":\"s\",\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}",
             now - 5, now + 120);
    mint(payload);
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    axiam_client_free(c);
}

void test_a_wrong_issuer_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"https://evil.test\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sid\":\"s\","
             "\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}", now - 5, now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "iss"));
    axiam_client_free(c);
}

void test_an_expired_logout_token_is_rejected(void) {
    /* Rule 6: AXIAM issues a 120 s lifetime, and a stale one is a replay
     * candidate rather than a late delivery. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sid\":\"s\","
             "\"jti\":\"j\",\"iat\":%lld,\"exp\":%lld," LOGOUT_EVENTS "}",
             now - 3600, now - 1800);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    axiam_client_free(c);
}

void test_empty_and_awkwardly_typed_members_are_treated_as_absent(void) {
    /* `sid` and `sub` present but empty name nothing, so rule 5 refuses the
     * token exactly as it does when both are missing. An `aud` array with a
     * non-string member is skipped rather than fatal, and a non-numeric `iat`
     * simply yields 0 — it is informational, not a check. */
    long long now = (long long)time(NULL);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[7,\"" OIDC_CLIENT_ID "\"],"
             "\"sid\":\"\",\"sub\":\"\",\"jti\":\"\",\"iat\":\"recently\",\"exp\":%lld,"
             LOGOUT_EVENTS "}", now + 120);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));

    /* With a real `sid` the same token verifies, and the empty `jti` and
     * unreadable `iat` come back as "not supplied" rather than as junk. A fresh
     * client, because the fixture mints a new key pair under the same `kid` and
     * the first client's JWKS cache is warm with the old one. */
    axiam_client_free(c);
    oidc_reset();
    c = oidc_make_client();
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[7,\"" OIDC_CLIENT_ID "\"],"
             "\"sid\":\"s-1\",\"sub\":\"\",\"jti\":\"\",\"iat\":\"recently\",\"exp\":%lld,"
             LOGOUT_EVENTS "}", now + 120);
    mint(payload);
    TEST_ASSERT_EQUAL(AXIAM_OK, verify(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING("s-1", t.sid);
    TEST_ASSERT_NULL(t.subject);
    TEST_ASSERT_NULL(t.jwt_id);
    TEST_ASSERT_EQUAL_INT(0, t.issued_at);
    axiam_verified_logout_token_dispose(&t);
    axiam_client_free(c);
}

void test_a_logout_token_payload_that_is_not_an_object_is_rejected(void) {
    /* A signature-valid JWT whose payload is a JSON array. The signature check
     * passes and everything after it has nothing to read — fail closed. */
    free(g_token);
    free(g_jwks);
    g_token = NULL;
    g_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, "[1,2,3]", &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    axiam_client_free(c);
}

void test_a_bad_signature_is_rejected(void) {
    /* Rule 1: verified against the OP's JWKS, through the same §12.4 verifier —
     * no second key-fetching path, so it fails the same way an ID token would. */
    char payload[1024];
    mint(logout_claims(payload, sizeof(payload), NULL));
    char *first = strchr(g_token, '.');
    first[3] = (first[3] == 'a') ? 'b' : 'a';

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_verified_logout_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, verify(c, &t, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_SIGNATURE, err.id_token_reason);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_logout_url_uses_the_discovered_endpoint_not_concatenation);
    RUN_TEST(test_logout_url_omits_what_the_caller_did_not_supply);
    RUN_TEST(test_logout_url_does_not_pre_validate_the_redirect_uri);
    RUN_TEST(test_logout_url_has_no_hintless_mode);
    RUN_TEST(test_logout_url_appends_to_an_endpoint_that_already_has_a_query);
    RUN_TEST(test_a_valid_logout_token_surfaces_sid_sub_and_jti);
    RUN_TEST(test_the_same_token_verifying_twice_does_not_raise);
    RUN_TEST(test_a_missing_events_member_is_rejected);
    RUN_TEST(test_a_replayed_id_token_is_rejected_for_carrying_a_nonce);
    RUN_TEST(test_a_token_naming_neither_sid_nor_sub_is_rejected);
    RUN_TEST(test_a_wrong_audience_is_rejected);
    RUN_TEST(test_an_array_audience_naming_this_client_is_accepted);
    RUN_TEST(test_a_wrong_issuer_is_rejected);
    RUN_TEST(test_an_expired_logout_token_is_rejected);
    RUN_TEST(test_empty_and_awkwardly_typed_members_are_treated_as_absent);
    RUN_TEST(test_a_logout_token_payload_that_is_not_an_object_is_rejected);
    RUN_TEST(test_a_bad_signature_is_rejected);
    return UNITY_END();
}
