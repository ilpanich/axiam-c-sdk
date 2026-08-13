/*
 * CONTRACT.md §14 (RFC 8628 device grant) and §15 (RFC 8693 token exchange) —
 * the required tests each section names.
 *
 * §14.2 is titled "the part implementations get wrong", and the four rules it
 * lists are all about the SHAPE OF THE POLLING LOOP rather than about parsing:
 * whether `slow_down` sticks, where the initial interval comes from, whether
 * the two refusals stay distinguishable, and whether the deadline is honoured.
 * None of those is observable from a return value, so the assertions here read
 * the recorded sleeps and count requests.
 *
 * §15 is a list of things an SDK must NOT helpfully do. Every one of its tests
 * is therefore an assertion of ABSENCE: no retry, no rewritten request, no
 * auto-narrowed scope, no refresh token, no adopted session.
 */

#include "unity.h"
#include "oidc_test_util.h"

void setUp(void) { oidc_reset(); }
void tearDown(void) {}

#define DEVICE_AUTH_BODY(interval_json, expires)                                \
    "{\"device_code\":\"the-device-code\",\"user_code\":\"WDJB-MJHT\","         \
    "\"verification_uri\":\"https://id.test/device\",\"expires_in\":" #expires  \
    interval_json "}"

static const char *SUCCESS_TOKENS =
    "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\",\"expires_in\":900}";

/* What the §14.3 display callback saw, and when. */
typedef struct {
    char user_code[64];
    char verification_uri[128];
    int had_complete_uri;
    int polls_when_called;
    int calls;
} display_box_t;

static void record_display(void *ctx, const axiam_device_authorization_t *a) {
    display_box_t *box = ctx;
    box->calls++;
    snprintf(box->user_code, sizeof(box->user_code), "%s", a->user_code);
    snprintf(box->verification_uri, sizeof(box->verification_uri), "%s", a->verification_uri);
    box->had_complete_uri = a->verification_uri_complete != NULL;
    box->polls_when_called = g_oidc.token_calls;
}

/* ------------------------------------------------------------------ */
/* §14.1 device_authorize                                             */
/* ------------------------------------------------------------------ */

void test_device_authorize_sends_no_secret_and_works_without_one(void) {
    g_oidc.device_answer = (oidc_answer_t){200,
        DEVICE_AUTH_BODY(",\"interval\":3", 600), 0};

    /* A PUBLIC client — no secret configured at all. §14.1 forbids refusing to
     * call this from one, because a device that cannot show a browser also
     * cannot hold a secret. */
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));

    TEST_ASSERT_EQUAL_STRING("WDJB-MJHT", a.user_code);
    TEST_ASSERT_EQUAL_INT(3, a.interval);
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/device_authorization", "client_secret"));
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/device_authorization", "client_id"));

    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_device_authorize_never_sends_a_secret_even_when_one_is_configured(void) {
    /* The other half of §14.1: "SDKs MUST NOT send client_secret on it". A
     * confidential client calling this must still not leak its secret to an
     * unauthenticated endpoint. */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":3", 600), 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/device_authorization", "client_secret"));
    int i = oidc_last_call("/oauth2/device_authorization");
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], OIDC_CLIENT_SECRET));
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_an_omitted_interval_defaults_to_five_seconds(void) {
    /* §14.2 rule 2: the initial interval comes from the RESPONSE, and RFC 8628
     * §3.2's default is 5 s. No SDK may hard-code a faster floor. */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY("", 600), 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_DEVICE_DEFAULT_INTERVAL_S, a.interval);
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

void test_verification_uri_complete_is_never_synthesised(void) {
    /* §14.3: surfaced when present, and NOT concatenated when absent — its
     * format is the server's to choose. */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":3", 600), 0};
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_device_authorization_t a;
    axiam_device_authorize(c, NULL, NULL, &a, &err);
    TEST_ASSERT_NULL(a.verification_uri_complete);
    axiam_device_authorization_dispose(&a);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §14.2 polling                                                      */
/* ------------------------------------------------------------------ */

void test_the_two_refusals_stay_distinct(void) {
    /* §14.2 rule 3: `access_denied` means a human said no; `expired_token`
     * means nobody answered. Collapsing them loses the only information the
     * device can act on — retry versus stop asking. */
    const char *codes[] = {"access_denied", "expired_token", "invalid_grant"};
    for (int i = 0; i < 3; i++) {
        oidc_reset();
        char body[128];
        snprintf(body, sizeof(body), "{\"error\":\"%s\"}", codes[i]);
        g_oidc.token_script[0] = (oidc_answer_t){400, body, 0};
        g_oidc.token_script_len = 1;

        axiam_client_t *c = oidc_make_client();
        axiam_error_t err;
        axiam_sensitive_t *code = axiam_sensitive_new("the-device-code");
        axiam_oidc_token_set_t set;
        TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_poll(c, code, NULL, &set, &err));
        /* §14.2 rule 5: all five arrive as 400, which §2 would map to a generic
         * error. Dispatch is on the `error` field, and it survives verbatim. */
        TEST_ASSERT_EQUAL_STRING(codes[i], err.oauth_error);
        axiam_sensitive_free(code);
        axiam_client_free(c);
    }
}

void test_device_login_surfaces_the_codes_before_the_first_poll(void) {
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":1", 600), 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g_oidc.token_script[1] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 2;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    display_box_t box = {0};
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_device_login(c, NULL, NULL, record_display, &box, &set, &err));

    /* §14.3 rule 2: ordering, not just presence. A device must be able to
     * display the codes, and the SDK must not begin polling before the caller
     * has had the chance to. */
    TEST_ASSERT_EQUAL_INT(1, box.calls);
    TEST_ASSERT_EQUAL_INT(0, box.polls_when_called);
    TEST_ASSERT_EQUAL_STRING("WDJB-MJHT", box.user_code);
    /* `authorization_pending` LOOPS rather than raising. */
    TEST_ASSERT_EQUAL_INT(2, g_oidc.token_calls);
    TEST_ASSERT_EQUAL_STRING("the-access-token", axiam_sensitive_reveal(set.access_token));
    /* §14.3 rule 4: the token set is returned, NOT adopted. */
    TEST_ASSERT_EQUAL_INT(0, c->authenticated);

    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_slow_down_raises_the_interval_permanently(void) {
    /*
     * §14.2 rule 1. The interval starts at 1 s; the first poll is told to slow
     * down, which must take it to 6 s and KEEP it there. An SDK that backed off
     * for one round and returned to 1 s would show a 1000 ms third sleep here —
     * and in production would be told to slow down again, forever.
     */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":1", 600), 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"slow_down\"}", 0};
    g_oidc.token_script[1] = (oidc_answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g_oidc.token_script[2] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 3;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));

    TEST_ASSERT_EQUAL_INT(3, g_oidc.n_sleeps);
    TEST_ASSERT_EQUAL_INT(1000, g_oidc.sleeps[0]);
    /* +5 s, cumulative, applied to the CURRENT interval. */
    TEST_ASSERT_EQUAL_INT(6000, g_oidc.sleeps[1]);
    /* And it persists across the subsequent poll — never reset. */
    TEST_ASSERT_EQUAL_INT(6000, g_oidc.sleeps[2]);

    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_polling_stops_at_expires_in_even_without_an_expired_token_answer(void) {
    /*
     * §14.2 rule 4: the deadline is authoritative. This server never says
     * `expired_token` — it answers `authorization_pending` forever — and the
     * loop must stop anyway, because the extra requests are pure load.
     *
     * The subtlety this catches: it is the NEXT ATTEMPT that must fall inside
     * the deadline. A 10-second grant polled at 3 s allows attempts at t=3, 6
     * and 9; the t=12 attempt is refused BEFORE sleeping, not after.
     */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":3", 10), 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"authorization_pending\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    /* The SDK reports the grant's own expiry even though the server never did. */
    TEST_ASSERT_EQUAL_STRING("expired_token", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(3, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_a_slow_down_past_the_deadline_stops_the_loop_rather_than_overrunning(void) {
    /*
     * The case that makes rule 4's "next attempt" framing load-bearing. Interval
     * 1 s, a 3 s grant: the first poll lands at t=1 and is told to slow down,
     * taking the interval to 6 s — past what is left. A `now < deadline` check
     * before sleeping would pass here, sleep through the deadline, and poll
     * anyway. Exactly ONE poll is the assertion.
     */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":1", 3), 0};
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"slow_down\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("expired_token", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_a_500_mid_poll_is_retried_rather_than_treated_as_terminal(void) {
    /*
     * §14.2 rule 6, and §16.2's one token-endpoint exception. A server restart
     * mid-flow must not lose a grant the user has already approved. The §16
     * budget is PER POLL ATTEMPT: one poll that hits a 500 makes up to three
     * requests and then the loop continues — it does not consume the grant's
     * own `expires_in` window.
     */
    g_oidc.device_answer = (oidc_answer_t){200, DEVICE_AUTH_BODY(",\"interval\":1", 600), 0};
    g_oidc.token_script[0] = (oidc_answer_t){503, "", 0};
    g_oidc.token_script[1] = (oidc_answer_t){503, "", 0};
    g_oidc.token_script[2] = (oidc_answer_t){503, "", 0};
    g_oidc.token_script[3] = (oidc_answer_t){200, SUCCESS_TOKENS, 0};
    g_oidc.token_script_len = 4;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_device_login(c, NULL, NULL, NULL, NULL, &set, &err));
    /* Three attempts inside the first poll (§16.1's 1 + 2), then the loop's own
     * second poll succeeds. A terminal treatment would have stopped at one. */
    TEST_ASSERT_EQUAL_INT(4, g_oidc.token_calls);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §15 token exchange                                                 */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t exchange(axiam_client_t *c, const axiam_sensitive_t *subject,
                                   const axiam_sensitive_t *actor,
                                   const char *const *scopes, size_t n,
                                   axiam_exchanged_token_t *out, axiam_error_t *err) {
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    p.actor_token = actor;
    p.scopes = scopes;
    p.scope_count = n;
    return axiam_token_exchange(c, &p, out, err);
}

/* ------------------------------------------------------------------ */
/* §15.7 external-IdP subject tokens (X4)                             */
/*                                                                    */
/* No new operation: the same axiam_token_exchange carries a partner  */
/* IdP's token. What changes is which subject tokens the server       */
/* accepts and what its refusals mean, so these tests are about not   */
/* getting in the way of either.                                      */
/* ------------------------------------------------------------------ */

/* A token minted by a partner's IdP. Opaque to the SDK — deliberately not a
 * well-formed JWT, because nothing here may decode it. */
#define EXTERNAL_SUBJECT_TOKEN "partner-idp-subject-token"

/* The one normative error_description (§15.7). It means "fix the AXIAM trust
 * configuration", not "fix your token". */
#define ISSUER_NOT_CONFIGURED \
    "the subject token's issuer is not configured for token exchange"

/* Percent-encoded as form_append_encoded emits them: only alphanumerics and
 * -._~ survive, so every URN colon becomes %3A. */
#define ENC_JWT_TYPE "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"
#define ENC_ACCESS_TYPE "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"

/* exchange(), plus the §15.7 subject_token_type. */
static axiam_error_kind_t exchange_typed(axiam_client_t *c, const axiam_sensitive_t *subject,
                                         const char *subject_token_type,
                                         const axiam_sensitive_t *actor,
                                         axiam_exchanged_token_t *out, axiam_error_t *err) {
    axiam_token_exchange_params_t p = {0};
    p.subject_token = subject;
    p.subject_token_type = subject_token_type;
    p.actor_token = actor;
    return axiam_token_exchange(c, &p, out, err);
}

/* The body of the last /oauth2/token request, or "". */
static const char *last_token_body(void) {
    int i = oidc_last_call("/oauth2/token");
    return i < 0 ? "" : g_oidc.bodies[i];
}

void test_an_external_subject_token_type_is_sent_verbatim(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN "\","
        "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"read:orders\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new(EXTERNAL_SUBJECT_TOKEN);
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      exchange_typed(c, subject, AXIAM_TOKEN_TYPE_JWT, NULL, &t, &err));

    /* The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must
     * not inspect the subject token to pick this, and must not override it. */
    TEST_ASSERT_NOT_NULL(strstr(last_token_body(), "subject_token_type=" ENC_JWT_TYPE));
    /* Delegation across a trust boundary is unsupported; nothing may add one. */
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "actor_token"));

    /* The cross-domain path is not a different result shape, and §15.2
     * rules 6-7 still hold. */
    TEST_ASSERT_EQUAL_STRING("narrow", axiam_sensitive_reveal(t.access_token));
    TEST_ASSERT_EQUAL_STRING(AXIAM_TOKEN_TYPE_ACCESS_TOKEN, t.issued_token_type);
    TEST_ASSERT_EQUAL_STRING("read:orders", t.scope);

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_the_subject_token_type_is_never_inferred_from_the_token(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN "\","
        "\"token_type\":\"Bearer\",\"expires_in\":300}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    /* A subject token that *looks* exactly like a JWT. An SDK that sniffed the
     * token would send …:jwt here; §15.7 says it must not look, so the caller's
     * silence still means the §15.1 same-domain default. */
    axiam_sensitive_t *subject = axiam_sensitive_new(
        "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange_typed(c, subject, NULL, NULL, &t, &err));

    TEST_ASSERT_NOT_NULL(strstr(last_token_body(), "subject_token_type=" ENC_ACCESS_TYPE));

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_an_actor_token_with_an_external_subject_token_is_refused_without_retry(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400,
        "{\"error\":\"invalid_request\",\"error_description\":"
        "\"actor_token is not supported for an external subject token\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new(EXTERNAL_SUBJECT_TOKEN);
    axiam_sensitive_t *actor = axiam_sensitive_new("actor-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      exchange_typed(c, subject, AXIAM_TOKEN_TYPE_JWT, actor, &t, &err));

    TEST_ASSERT_EQUAL_STRING("invalid_request", err.oauth_error);
    /* §15.7: no retry, and no rewriting. Dropping the actor token and
     * re-sending would turn a delegation the caller asked for into an
     * impersonation they did not. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    TEST_ASSERT_TRUE(oidc_body_has_field("/oauth2/token", "actor_token"));
    TEST_ASSERT_NOT_NULL(strstr(last_token_body(), "subject_token_type=" ENC_JWT_TYPE));

    axiam_sensitive_free(actor);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_a_refused_subject_token_type_is_never_retried_as_another(void) {
    /* A refresh token is a re-authentication credential and an ID token is an
     * assertion to a client about a login; neither is a bearer credential for
     * an API, so both are refused BY NAME. Retrying as …:jwt would present one
     * as if it were. */
    static const char *refused[] = {
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
    };
    static const char *encoded[] = {
        "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
        "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token",
    };

    for (size_t i = 0; i < 2; i++) {
        oidc_reset();
        g_oidc.token_script[0] = (oidc_answer_t){400,
            "{\"error\":\"invalid_request\",\"error_description\":"
            "\"unsupported subject_token_type\"}", 0};
        g_oidc.token_script_len = 1;

        axiam_client_t *c = oidc_make_client();
        axiam_error_t err;
        axiam_sensitive_t *subject = axiam_sensitive_new(EXTERNAL_SUBJECT_TOKEN);
        axiam_exchanged_token_t t;
        TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                          exchange_typed(c, subject, refused[i], NULL, &t, &err));

        TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
        char expect[128];
        snprintf(expect, sizeof(expect), "subject_token_type=%s", encoded[i]);
        TEST_ASSERT_NOT_NULL(strstr(last_token_body(), expect));

        axiam_sensitive_free(subject);
        axiam_client_free(c);
    }
}

void test_the_issuer_not_configured_description_reaches_the_caller_intact(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400,
        "{\"error\":\"invalid_grant\",\"error_description\":\"" ISSUER_NOT_CONFIGURED "\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new(EXTERNAL_SUBJECT_TOKEN);
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      exchange_typed(c, subject, AXIAM_TOKEN_TYPE_JWT, NULL, &t, &err));

    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    /* This is the ONLY distinguishable external failure, and the whole point of
     * it is that an integrator can tell "fix the AXIAM trust config" from "fix
     * your token". Truncating or rewording it destroys that. §2 builds the
     * message as "<error>: <error_description>". */
    TEST_ASSERT_NOT_NULL(strstr(err.message, ISSUER_NOT_CONFIGURED));

    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_no_helper_re_exchanges_an_externally_exchanged_token(void) {
    /* Tokens minted from an external subject token carry ext_exchange, and BOTH
     * exchange paths refuse a subject token bearing it: exchanges do not
     * compose. The SDK's part is to never feed a result back in by itself. */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN "\","
        "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"read:orders\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new(EXTERNAL_SUBJECT_TOKEN);
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      exchange_typed(c, subject, AXIAM_TOKEN_TYPE_JWT, NULL, &t, &err));

    /* Exactly one exchange happened: nothing looped the result back in. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    /* §15.2 rule 5 restated for the cross-domain path: had the result been
     * adopted, the next exchange would carry it as a *subject* token, which is
     * exactly the re-exchange §15.7 forbids, arrived at by accident. */
    TEST_ASSERT_EQUAL_INT(0, c->authenticated);
    TEST_ASSERT_EQUAL_STRING("narrow", axiam_sensitive_reveal(t.access_token));

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_a_delegation_narrows_scopes_and_reports_what_was_granted(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN "\","
        "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"invoices:read\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    axiam_sensitive_t *actor = axiam_sensitive_new("actor-token");
    const char *scopes[] = {"invoices:read", "invoices:write"};
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, subject, actor, scopes, 2, &t, &err));

    int i = oidc_last_call("/oauth2/token");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "actor_token="));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "actor_token_type="));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "scope=invoices%3Aread%20invoices%3Awrite"));
    /* §15.2 rule 7: the response's scope is the GRANTED set, which may be
     * narrower than what was asked for even on success. */
    TEST_ASSERT_EQUAL_STRING("invoices:read", t.scope);
    /* §15.2 rule 6: surfaced, never dropped. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_TOKEN_TYPE_ACCESS_TOKEN, t.issued_token_type);

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_sensitive_free(actor);
    axiam_client_free(c);
}

void test_omitting_scope_inherits_the_subjects_and_omitting_the_actor_asks_for_impersonation(void) {
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"inherited\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN
        "\",\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"a b\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, subject, NULL, NULL, 0, &t, &err));

    /* Omitted, not sent empty. */
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "scope"));
    /*
     * §15.2 rule 1: the ABSENCE of an actor token is what selects
     * impersonation. This SDK supplies no default and never substitutes the
     * client's own session — the assertion is that nothing named `actor_token`
     * went out.
     */
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "actor_token"));
    TEST_ASSERT_EQUAL_STRING("a b", t.scope);

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_unauthorized_client_is_surfaced_verbatim_with_no_retry_or_rewrite(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400,
        "{\"error\":\"unauthorized_client\",\"error_description\":\"impersonation not granted\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, subject, NULL, NULL, 0, &t, &err));

    TEST_ASSERT_EQUAL_STRING("unauthorized_client", err.oauth_error);
    /*
     * §15.2 rule 2: it means either "this client may not exchange at all" or
     * "this client may not impersonate". Both are registration facts an
     * operator must fix. An SDK that retried, downgraded, or reworked the
     * request into a delegation would be sending a request the caller did not
     * write — so: exactly one request, and it still carries no actor_token.
     */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    TEST_ASSERT_FALSE(oidc_body_has_field("/oauth2/token", "actor_token"));

    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_invalid_scope_is_not_auto_narrowed_and_resent(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"invalid_scope\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    const char *scopes[] = {"a", "b", "c"};
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, subject, NULL, scopes, 3, &t, &err));

    /* §15.2 rule 3: the server refuses rather than silently narrowing precisely
     * so the caller finds out here. One request — no second attempt with fewer
     * scopes. */
    TEST_ASSERT_EQUAL_STRING("invalid_scope", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);

    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_a_cross_tenant_subject_token_answers_invalid_grant_unrefined(void) {
    g_oidc.token_script[0] = (oidc_answer_t){400, "{\"error\":\"invalid_grant\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("other-tenants-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, subject, NULL, NULL, 0, &t, &err));

    /* §15.3: the server collapses "wrong tenant" into "bad token" because
     * telling them apart is a tenant-enumeration signal. The SDK reports what
     * it was told and adds no guess — the message must not speculate about
     * tenancy. */
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    TEST_ASSERT_NULL(strstr(err.message, "tenant"));

    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_the_exchanged_token_is_not_adopted_and_carries_no_refresh_token(void) {
    /* §15.2 rules 4 and 5 together. The server sends a refresh_token it should
     * not; there is nowhere to put it, so it is dropped rather than
     * synthesised into the result — an exchange only ever narrows, and a
     * refresh token would let the holder re-widen later. And the client's own
     * session is untouched: this is a MUST NOT where adoption elsewhere is a
     * MAY. */
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"narrow\",\"issued_token_type\":\"" AXIAM_TOKEN_TYPE_ACCESS_TOKEN
        "\",\"token_type\":\"Bearer\",\"expires_in\":300,\"refresh_token\":\"nope\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_OK, exchange(c, subject, NULL, NULL, 0, &t, &err));

    TEST_ASSERT_EQUAL_INT(0, c->authenticated);
    TEST_ASSERT_EQUAL_UINT(0, axiam_client_refresh_count(c));
    TEST_ASSERT_EQUAL_STRING("narrow", axiam_sensitive_reveal(t.access_token));

    axiam_exchanged_token_dispose(&t);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

void test_token_exchange_refuses_a_public_client_with_no_wire_call(void) {
    /* §15.1: the exchanging client authenticates — unlike §14's device, this is
     * a confidential service. */
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token");
    axiam_exchanged_token_t t;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, exchange(c, subject, NULL, NULL, 0, &t, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);
    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_device_authorize_sends_no_secret_and_works_without_one);
    RUN_TEST(test_device_authorize_never_sends_a_secret_even_when_one_is_configured);
    RUN_TEST(test_an_omitted_interval_defaults_to_five_seconds);
    RUN_TEST(test_verification_uri_complete_is_never_synthesised);
    RUN_TEST(test_the_two_refusals_stay_distinct);
    RUN_TEST(test_device_login_surfaces_the_codes_before_the_first_poll);
    RUN_TEST(test_slow_down_raises_the_interval_permanently);
    RUN_TEST(test_polling_stops_at_expires_in_even_without_an_expired_token_answer);
    RUN_TEST(test_a_slow_down_past_the_deadline_stops_the_loop_rather_than_overrunning);
    RUN_TEST(test_a_500_mid_poll_is_retried_rather_than_treated_as_terminal);
    RUN_TEST(test_a_delegation_narrows_scopes_and_reports_what_was_granted);
    RUN_TEST(test_omitting_scope_inherits_the_subjects_and_omitting_the_actor_asks_for_impersonation);
    RUN_TEST(test_unauthorized_client_is_surfaced_verbatim_with_no_retry_or_rewrite);
    RUN_TEST(test_invalid_scope_is_not_auto_narrowed_and_resent);
    RUN_TEST(test_a_cross_tenant_subject_token_answers_invalid_grant_unrefined);
    RUN_TEST(test_the_exchanged_token_is_not_adopted_and_carries_no_refresh_token);
    RUN_TEST(test_token_exchange_refuses_a_public_client_with_no_wire_call);
    /* §15.7 — external-IdP subject tokens (X4). */
    RUN_TEST(test_an_external_subject_token_type_is_sent_verbatim);
    RUN_TEST(test_the_subject_token_type_is_never_inferred_from_the_token);
    RUN_TEST(test_an_actor_token_with_an_external_subject_token_is_refused_without_retry);
    RUN_TEST(test_a_refused_subject_token_type_is_never_retried_as_another);
    RUN_TEST(test_the_issuer_not_configured_description_reaches_the_caller_intact);
    RUN_TEST(test_no_helper_re_exchanges_an_externally_exchanged_token);
    return UNITY_END();
}
