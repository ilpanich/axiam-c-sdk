/*
 * CONTRACT.md §12.4 — the ID-token validation checklist.
 *
 * Seven rules, and §12.4 requires ONE FAILING TEST PER RULE. That requirement
 * is not bureaucracy: each rule, skipped, has a name. Rule 1 skipped is
 * algorithm confusion. Rule 3 loosened is another OP's token. Rule 4 skipped is
 * another relying party's token. Rule 6 skipped is a replay. Rule 7 is the one
 * an implementer is most tempted to soften — "only the ID token was bad, the
 * access token is probably fine" — and it is the reason the positive assertion
 * here is that the WHOLE token set is gone.
 *
 * Every failure also carries a reason code from §12.3 rule 3's CLOSED
 * seven-value vocabulary, so these tests assert the code as well as the
 * rejection: a caller that cannot tell `nonce_mismatch` from `invalid_issuer`
 * cannot tell an attack from a misconfiguration.
 */

#include "unity.h"
#include "jwt_fixture.h"
#include "oidc_test_util.h"

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

/* Mint a signed ID token from a claims payload and publish its key. */
static void mint(const char *payload) {
    free(g_token);
    free(g_jwks);
    g_token = NULL;
    g_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;
}

/* A claims payload that PASSES every rule, with `extra` spliced in verbatim. */
static const char *good_claims(char *buf, size_t n, const char *extra) {
    long long now = (long long)time(NULL);
    snprintf(buf, n,
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sub\":\"user-1\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"%s}",
             now + 900, now - 5, extra ? extra : "");
    return buf;
}

/* Run an exchange whose token response carries `id_token`, and return the kind. */
static axiam_error_kind_t exchange_with_id_token(axiam_client_t *c, const char *id_token,
                                                 const char *nonce,
                                                 axiam_oidc_token_set_t *out,
                                                 axiam_error_t *err) {
    static char body[8192];
    snprintf(body, sizeof(body),
             "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\","
             "\"expires_in\":900,\"refresh_token\":\"the-refresh-token\","
             "\"id_token\":\"%s\"}", id_token);
    g_oidc.token_script[0] = (oidc_answer_t){200, body, 0};
    g_oidc.token_script_len = 1;

    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    axiam_oidc_exchange_params_t p = {0};
    p.code = "the-code";
    p.code_verifier = verifier;
    p.redirect_uri = OIDC_REDIRECT_URI;
    p.nonce = nonce;
    axiam_error_kind_t kind = axiam_oidc_exchange(c, &p, out, err);
    axiam_sensitive_free(verifier);
    return kind;
}

/* Assert that a token minted from `payload` is rejected with `reason`, and that
 * §12.4 rule 7 discarded the whole set with it. */
static void assert_rejected(const char *payload, const char *reason, const char *nonce) {
    mint(payload);
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange_with_id_token(c, g_token, nonce, &set, &err));
    TEST_ASSERT_EQUAL_STRING(reason, err.id_token_reason);
    /* Rule 7, every time: no partial success. The access and refresh tokens
     * from the same response never reach the caller. */
    TEST_ASSERT_NULL(set.access_token);
    TEST_ASSERT_NULL(set.refresh_token);
    TEST_ASSERT_NULL(set.id_claims);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* The happy path                                                     */
/* ------------------------------------------------------------------ */

void test_a_valid_id_token_yields_claims_and_preserves_unknown_ones(void) {
    char payload[1024];
    /* `department` is not in openapi.json — the ID token's claim set is not
     * enumerated there, so §12.1 forbids rejecting what an SDK does not
     * recognise and requires preserving it. */
    mint(good_claims(payload, sizeof(payload),
                     ",\"email\":\"a@b.test\",\"roles\":[\"admin\"],\"department\":\"ops\""));

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_with_id_token(c, g_token, "the-nonce", &set, &err));

    TEST_ASSERT_NOT_NULL(set.id_claims);
    TEST_ASSERT_EQUAL_STRING("user-1", set.id_claims->subject);
    TEST_ASSERT_EQUAL_STRING(OIDC_ISSUER, set.id_claims->issuer);
    TEST_ASSERT_EQUAL_size_t(1, set.id_claims->audience_count);
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_ID, set.id_claims->audience[0]);
    TEST_ASSERT_EQUAL_STRING("a@b.test", set.id_claims->email);
    TEST_ASSERT_EQUAL_size_t(1, set.id_claims->roles_count);
    TEST_ASSERT_NOT_NULL(strstr(set.id_claims->raw_claims_json, "\"department\":\"ops\""));
    /* The whole set survives together — the other half of rule 7. */
    TEST_ASSERT_EQUAL_STRING("the-access-token", axiam_sensitive_reveal(set.access_token));
    TEST_ASSERT_EQUAL_STRING("the-refresh-token", axiam_sensitive_reveal(set.refresh_token));

    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Rule 1 — algorithm                                                 */
/* ------------------------------------------------------------------ */

void test_rule_1_alg_none_is_rejected(void) {
    char payload[512];
    good_claims(payload, sizeof(payload), NULL);
    TEST_ASSERT_EQUAL_INT(0, jwt_make_confused(OIDC_KID, "none", payload, &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_ALG, err.id_token_reason);
    axiam_client_free(c);
}

void test_rule_1_hs256_confusion_is_rejected_before_any_key_is_consulted(void) {
    /* The classic HS/EdDSA confusion: the attacker's "secret" is the published
     * verification key. §12.4 rule 1 requires `alg` read from the header and
     * checked BEFORE any signature work — an SDK must not let a token select
     * its own verification algorithm. */
    char payload[512];
    good_claims(payload, sizeof(payload), NULL);
    TEST_ASSERT_EQUAL_INT(0, jwt_make_confused(OIDC_KID, "HS256", payload, &g_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_ALG, err.id_token_reason);
    /* No key was fetched, because the algorithm was refused first. */
    TEST_ASSERT_EQUAL_INT(0, g_oidc.jwks_calls);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Rule 2 — signature and kid                                         */
/* ------------------------------------------------------------------ */

void test_rule_2_a_kid_no_key_matches_is_rejected(void) {
    char payload[512];
    good_claims(payload, sizeof(payload), NULL);
    /* Signed under one kid; the served JWKS publishes another. */
    TEST_ASSERT_EQUAL_INT(0, jwt_make("rotated-away", payload, &g_token, &g_jwks));
    char *other_token = NULL;
    char *other_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &other_token, &other_jwks));
    g_oidc.jwks_body = other_jwks;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, err.id_token_reason);

    free(other_token);
    free(other_jwks);
    axiam_client_free(c);
}

void test_rule_2_an_unknown_kid_refetches_once_per_cooldown_window(void) {
    /*
     * §12.4 rule 2 as contract 1.5 corrected it: "one re-fetch then fail" is per
     * WINDOW, not per token. Taken literally against a warm cache it is
     * unimplementable without handing an attacker one JWKS fetch per forged
     * `kid` — which is the amplification the rule exists to prevent.
     *
     * Asserted the only way it can be: by counting JWKS fetches across two
     * verifications with unknown kids. The first opens the window and costs one
     * extra fetch; the second re-consults the cached set with none.
     */
    char payload[512];
    good_claims(payload, sizeof(payload), NULL);
    TEST_ASSERT_EQUAL_INT(0, jwt_make("rotated-away", payload, &g_token, &g_jwks));
    char *other_token = NULL;
    char *other_jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &other_token, &other_jwks));
    g_oidc.jwks_body = other_jwks;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    char *claims = NULL;
    char reason[32];

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_jwt_verify_reasoned(c, g_token, &claims, reason, sizeof(reason), &err));
    int after_first = g_oidc.jwks_calls;
    /* The initial cache fill plus exactly one re-fetch. */
    TEST_ASSERT_EQUAL_INT(2, after_first);

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_jwt_verify_reasoned(c, g_token, &claims, reason, sizeof(reason), &err));
    /* Inside the window: no network call at all. Not "never re-fetch" (key
     * rotation would break) and not "always re-fetch" (the amplifier). */
    TEST_ASSERT_EQUAL_INT(after_first, g_oidc.jwks_calls);
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_UNKNOWN_KID, reason);

    free(claims);
    free(other_token);
    free(other_jwks);
    axiam_client_free(c);
}

void test_rule_2_a_tampered_payload_fails_the_signature(void) {
    char payload[512];
    mint(good_claims(payload, sizeof(payload), NULL));
    /* Flip one character of the payload segment. */
    char *first = strchr(g_token, '.');
    first[3] = (first[3] == 'a') ? 'b' : 'a';

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_INVALID_SIGNATURE, err.id_token_reason);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Rule 3 — issuer                                                    */
/* ------------------------------------------------------------------ */

void test_rule_3_a_foreign_issuer_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"https://evil.test\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}",
             now + 900, now - 5);
    assert_rejected(payload, AXIAM_OIDC_REASON_INVALID_ISSUER, "the-nonce");
}

void test_rule_3_a_trailing_slash_is_not_tolerated(void) {
    /* EXACT string comparison: no normalization, no trailing-slash tolerance,
     * no prefix matching. Each of those has been an OP-confusion CVE. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "/\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}",
             now + 900, now - 5);
    assert_rejected(payload, AXIAM_OIDC_REASON_INVALID_ISSUER, "the-nonce");
}

/* ------------------------------------------------------------------ */
/* Rule 4 — audience                                                  */
/* ------------------------------------------------------------------ */

void test_rule_4_a_token_for_another_relying_party_is_rejected(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"some-other-rp\","
             "\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}",
             now + 900, now - 5);
    assert_rejected(payload, AXIAM_OIDC_REASON_INVALID_AUDIENCE, "the-nonce");
}

void test_rule_4_multiple_audiences_require_a_matching_azp(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[\"" OIDC_CLIENT_ID "\",\"other\"],"
             "\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}",
             now + 900, now - 5);
    /* `aud` names this client, but with more than one audience §12.4 rule 4
     * additionally requires `azp` — and it is absent. */
    assert_rejected(payload, AXIAM_OIDC_REASON_INVALID_AUDIENCE, "the-nonce");
}

void test_rule_4_multiple_audiences_with_a_correct_azp_are_accepted(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":[\"" OIDC_CLIENT_ID "\",\"other\"],"
             "\"azp\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld,"
             "\"nonce\":\"the-nonce\"}", now + 900, now - 5);
    mint(payload);

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_ID, set.id_claims->authorized_party);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Rule 5 — time (one code for four distinct failures)                */
/* ------------------------------------------------------------------ */

void test_rule_5_every_time_failure_reports_token_expired(void) {
    /*
     * The closed-vocabulary consequence, spelled out in §12.3 rule 3: a past
     * `exp`, an ABSENT `exp`, an absent or future `iat`, and a future `nbf` all
     * report the SAME code. There is no `token_not_yet_valid`, no
     * `iat_in_future` and no `missing_exp` — a caller needing finer granularity
     * reads the message, not the code.
     */
    long long now = (long long)time(NULL);
    char payload[512];

    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}", now - 3600, now - 4000);
    assert_rejected(payload, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "the-nonce");

    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"iat\":%lld,\"nonce\":\"the-nonce\"}", now - 5);
    assert_rejected(payload, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "the-nonce");

    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"nonce\":\"the-nonce\"}", now + 900);
    assert_rejected(payload, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "the-nonce");

    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nbf\":%lld,\"nonce\":\"the-nonce\"}",
             now + 900, now - 5, now + 600);
    assert_rejected(payload, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "the-nonce");
}

void test_rule_5_an_id_token_issued_in_the_future_is_rejected(void) {
    /* An `iat` ahead of now by more than the skew means one of the two clocks
     * is wrong, and accepting it would widen every other time check by the same
     * amount. Same code as the rest of rule 5 — the vocabulary is closed. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}", now + 900, now + 600);
    assert_rejected(payload, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "the-nonce");
}

void test_rule_5_a_configured_skew_inside_the_ceiling_is_honoured(void) {
    /* A tighter window than 60 s is a legitimate deployment choice and is used
     * as given — the clamp is one-directional. Here 5 s of tolerance accepts a
     * token that expired 2 s ago and would reject one 3600 s stale. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\"}", now - 2, now - 60);
    mint(payload);

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_oidc_clock_skew(cfg, 5);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_EQUAL(5, c->cfg->oidc_clock_skew_s);

    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_with_id_token(c, g_token, "the-nonce", &set, &err));
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_rule_5_the_clock_skew_ceiling_is_clamped_down_not_rejected(void) {
    /* §12.4 rule 5: at most 60 seconds, and a larger configured value is
     * CLAMPED rather than refused — an operator who asked for five minutes gets
     * a working client with a conformant window, not a construction failure
     * they will route around by disabling something. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_oidc_clock_skew(cfg, 3600);
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_EQUAL(AXIAM_OIDC_MAX_CLOCK_SKEW_S, c->cfg->oidc_clock_skew_s);
    axiam_client_config_free(cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Rule 6 — nonce                                                     */
/* ------------------------------------------------------------------ */

void test_rule_6_a_mismatched_nonce_is_rejected(void) {
    char payload[512];
    good_claims(payload, sizeof(payload), NULL);
    assert_rejected(payload, AXIAM_OIDC_REASON_NONCE_MISMATCH, "a-different-nonce");
}

void test_rule_6_an_absent_nonce_is_rejected_for_the_exchange(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld}", now + 900, now - 5);
    assert_rejected(payload, AXIAM_OIDC_REASON_NONCE_MISMATCH, "the-nonce");
}

void test_rule_6_is_skipped_for_a_refresh_issued_id_token(void) {
    /* §12.4 rule 6: for `oidc_refresh` and `login_client_credentials` rules 1-5
     * and 7 apply and rule 6 is skipped — OIDC Core §12.2 does not require a
     * nonce in a refresh-issued ID token, and there was no authorization
     * request to carry one. */
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"u\","
             "\"exp\":%lld,\"iat\":%lld}", now + 900, now - 5);
    mint(payload);

    char body[8192];
    snprintf(body, sizeof(body),
             "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900,"
             "\"id_token\":\"%s\"}", g_token);
    g_oidc.token_script[0] = (oidc_answer_t){200, body, 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    TEST_ASSERT_NOT_NULL(set.id_claims);
    TEST_ASSERT_NULL(set.id_claims->nonce);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_valid_id_token_yields_claims_and_preserves_unknown_ones);
    RUN_TEST(test_rule_1_alg_none_is_rejected);
    RUN_TEST(test_rule_1_hs256_confusion_is_rejected_before_any_key_is_consulted);
    RUN_TEST(test_rule_2_a_kid_no_key_matches_is_rejected);
    RUN_TEST(test_rule_2_an_unknown_kid_refetches_once_per_cooldown_window);
    RUN_TEST(test_rule_2_a_tampered_payload_fails_the_signature);
    RUN_TEST(test_rule_3_a_foreign_issuer_is_rejected);
    RUN_TEST(test_rule_3_a_trailing_slash_is_not_tolerated);
    RUN_TEST(test_rule_4_a_token_for_another_relying_party_is_rejected);
    RUN_TEST(test_rule_4_multiple_audiences_require_a_matching_azp);
    RUN_TEST(test_rule_4_multiple_audiences_with_a_correct_azp_are_accepted);
    RUN_TEST(test_rule_5_every_time_failure_reports_token_expired);
    RUN_TEST(test_rule_5_an_id_token_issued_in_the_future_is_rejected);
    RUN_TEST(test_rule_5_a_configured_skew_inside_the_ceiling_is_honoured);
    RUN_TEST(test_rule_5_the_clock_skew_ceiling_is_clamped_down_not_rejected);
    RUN_TEST(test_rule_6_a_mismatched_nonce_is_rejected);
    RUN_TEST(test_rule_6_an_absent_nonce_is_rejected_for_the_exchange);
    RUN_TEST(test_rule_6_is_skipped_for_a_refresh_issued_id_token);
    return UNITY_END();
}
