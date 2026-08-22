/*
 * WebAuthn / passkeys — CONTRACT.md §24.
 *
 * §24.0 is the clause the rest of the section exists to protect: the server
 * chooses every option and verifies every response, and the SDK passes both
 * through byte for byte. Almost every assertion below is therefore an
 * assertion about BYTES ON THE WIRE — that a buffer arrived unchanged, that a
 * member order survived, that a field nobody modelled still made it across.
 * A test that round-tripped through a model and compared the model would pass
 * while the signature the server checks failed.
 *
 * The rest are about the three refusals §24 makes client-side (no session, a
 * response that is not a JSON object, a second-factor ceremony with no token)
 * and the two §24.4 overrides of the generic §2 mapping.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/webauthn.h"
#include "internal.h"
#include "test_util.h"

#define WA_STATE   "state-token-value"
#define WA_ACCESS  "access-token-value"
#define WA_REFRESH "refresh-token-value"

/*
 * The options exactly as a server sends them: a `publicKey` wrapper, base64url
 * buffers, and members in an order no alphabetical printer would produce. Both
 * facts are load-bearing — §24.6a rule 1 says the WRAPPER is dropped and
 * nothing else is, and the ordering is what catches a re-encode.
 */
#define WA_CREATE_OPTIONS                                                      \
    "{\"publicKey\":{\"challenge\":\"q83vAAAAAAAAAAAAAAAAAA\","                \
    "\"rp\":{\"id\":\"acme.test\",\"name\":\"Acme\"},"                         \
    "\"user\":{\"id\":\"dXNlci0x\",\"name\":\"ada\",\"displayName\":\"Ada\"}," \
    "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],"             \
    "\"timeout\":60000,\"attestation\":\"direct\"}}"

#define WA_GET_OPTIONS                                                         \
    "{\"publicKey\":{\"challenge\":\"Zm9vYmFyAAAAAAAAAAAAAA\","                \
    "\"rpId\":\"acme.test\",\"allowCredentials\":[],"                          \
    "\"userVerification\":\"required\",\"timeout\":60000}}"

/*
 * An authenticator response with members in a deliberately awkward order, a
 * member this SDK has never heard of, and a number that a round trip through a
 * double would render differently. If any of the three comes out changed, the
 * splice is not a splice.
 */
#define WA_RESPONSE                                                            \
    "{\"type\":\"public-key\",\"rawId\":\"Y3JlZC1pZA\",\"id\":\"Y3JlZC1pZA\"," \
    "\"response\":{\"clientDataJSON\":\"eyJ0eXAiOiJ3ZWJhdXRobi5jcmVhdGUifQ\"," \
    "\"attestationObject\":\"o2NmbXRkbm9uZQ\",\"transports\":[\"internal\"]}," \
    "\"clientExtensionResults\":{},\"authenticatorAttachment\":\"platform\","  \
    "\"unknownFutureMember\":1234567890123}"

#define LOGIN_OK_BODY                                                          \
    "{\"authenticated\":true,\"access_token\":\"initial-access\","             \
    "\"refresh_token\":\"initial-refresh\",\"session_id\":\"sess-1\","         \
    "\"expires_in\":900,\"user_id\":\"user-1\","                               \
    "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}"

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

#define MAX_CALLS 16

typedef struct {
    long status_register_start;
    const char *body_register_start;
    long status_register_finish;
    const char *body_register_finish;
    long status_auth_start;
    long status_auth_finish;
    const char *body_auth_finish;
    long status_disc_start;
    long status_disc_finish;
    /* Every webauthn call has a transport-failure arm, and a fake transport that
     * can only return HTTP statuses never reaches one. */
    int transport_fails;
    const char *body_auth_start;

    char methods[MAX_CALLS][8];
    char urls[MAX_CALLS][512];
    char bodies[MAX_CALLS][4096];
    int n_calls;
} wa_state_t;

static wa_state_t g;

static void record(const axiam_http_request_t *req) {
    if (g.n_calls >= MAX_CALLS) return;
    int i = g.n_calls++;
    snprintf(g.methods[i], sizeof(g.methods[i]), "%s", req->method ? req->method : "");
    snprintf(g.urls[i], sizeof(g.urls[i]), "%s", req->url ? req->url : "");
    snprintf(g.bodies[i], sizeof(g.bodies[i]), "%s", req->body ? req->body : "");
}

static int wa_transport(void *ctx, const axiam_http_request_t *req,
                        axiam_http_response_t *resp) {
    (void)ctx;
    record(req);
    const char *url = req->url ? req->url : "";

    if (g.transport_fails && !strstr(url, "/auth/login")) {
        memset(resp, 0, sizeof(*resp));
        resp->transport_err = 7;
        resp->transport_msg = strdup("connection refused");
        return -1;
    }

    if (strstr(url, "/auth/login")) {
        resp_fill(resp, 200, LOGIN_OK_BODY, "csrf-1");
        return 0;
    }
    if (strstr(url, "/webauthn/register/start")) {
        resp_fill(resp, g.status_register_start ? g.status_register_start : 200,
                  g.body_register_start
                      ? g.body_register_start
                      : "{\"challenge\":" WA_CREATE_OPTIONS ",\"state_token\":\"" WA_STATE "\"}",
                  NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/register/finish")) {
        resp_fill(resp, g.status_register_finish ? g.status_register_finish : 201,
                  g.body_register_finish
                      ? g.body_register_finish
                      : "{\"id\":\"cred-1\",\"credential_id\":\"Y3JlZC1pZA\","
                        "\"name\":\"Ada's laptop\",\"credential_type\":\"passkey\","
                        "\"created_at\":\"2026-08-22T10:00:00Z\",\"last_used_at\":null}",
                  NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/authenticate/discoverable/start")) {
        resp_fill(resp, g.status_disc_start ? g.status_disc_start : 200,
                  "{\"challenge\":" WA_GET_OPTIONS ",\"state_token\":\"" WA_STATE "\"}", NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/authenticate/discoverable/finish")) {
        resp_fill(resp, g.status_disc_finish ? g.status_disc_finish : 200,
                  "{\"access_token\":\"" WA_ACCESS "\",\"refresh_token\":\"" WA_REFRESH "\","
                  "\"session_id\":\"sess-disc\",\"expires_in\":900}",
                  "csrf-disc");
        return 0;
    }
    if (strstr(url, "/webauthn/authenticate/start")) {
        resp_fill(resp, g.status_auth_start ? g.status_auth_start : 200,
                  g.body_auth_start
                      ? g.body_auth_start
                      : "{\"challenge\":" WA_GET_OPTIONS ",\"state_token\":\"" WA_STATE "\"}",
                  NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/authenticate/finish")) {
        resp_fill(resp, g.status_auth_finish ? g.status_auth_finish : 200,
                  g.body_auth_finish
                      ? g.body_auth_finish
                      : "{\"access_token\":\"" WA_ACCESS "\",\"refresh_token\":\"" WA_REFRESH
                        "\",\"session_id\":\"sess-2\",\"expires_in\":900}",
                  "csrf-2");
        return 0;
    }
    if (strstr(url, "/authz/check")) {
        resp_fill(resp, 200, "{\"allowed\":true}", NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_org_slug(cfg, "acme-org");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    /* The §17 memo is OFF by default. Two tests here assert what a ceremony does
     * to it, and with the memo off both would pass for either behaviour — every
     * check would go to the wire regardless. Switching it on is what makes the
     * request counts mean something. */
    axiam_client_config_set_decision_memo_ttl(cfg, 5000);
    axiam_client_config_set_transport(cfg, wa_transport, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* A client that has actually completed a login, so §24.1's session requirement
 * is satisfied by the same state a real caller would have. */
static axiam_client_t *make_signed_in_client(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_login_result_t r;
    axiam_login(c, "ada@acme.test", "correct horse", &r, &err);
    axiam_login_result_dispose(&r);
    return c;
}

static int last_call_to(const char *needle) {
    for (int i = g.n_calls - 1; i >= 0; i--) {
        if (strstr(g.urls[i], needle)) return i;
    }
    return -1;
}

void setUp(void) { memset(&g, 0, sizeof(g)); }
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* §24.1 — the six wire operations                                    */
/* ------------------------------------------------------------------ */

void test_register_start_returns_the_options_untouched(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(c, &ch, &err));

    /* §24.0: what came back is what the server sent. Not "an equivalent
     * object" — the same one, wrapper and member order included. */
    TEST_ASSERT_EQUAL_STRING(WA_CREATE_OPTIONS, ch.challenge_json);
    TEST_ASSERT_EQUAL_STRING(WA_STATE, axiam_sensitive_reveal(ch.state_token));
    TEST_ASSERT_EQUAL_STRING("POST", g.methods[last_call_to("/register/start")]);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_register_start_without_a_session_makes_no_wire_call(void) {
    /* §24.1: register/… needs a session and the refusal is CLIENT-SIDE. The
     * assertion that matters is the call count, not the error kind: an SDK that
     * lets the request out and maps the 401 has told the caller the same thing
     * while leaking that the account exists. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_webauthn_register_start(c, &ch, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_register_finish_without_a_session_makes_no_wire_call(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_register_finish_splices_the_response_verbatim(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "Ada's laptop", WA_RESPONSE, &cred, &err));

    /* THE CENTRAL ASSERTION OF §24. The authenticator's bytes appear in the
     * request body as one contiguous, unmodified run — member order, the
     * unmodelled member and the large integer all intact. A parse-and-reprint
     * would reorder the members and render 1234567890123 as 1.2345678901e+12,
     * and this strstr is what refuses to let that pass. */
    int i = last_call_to("/register/finish");
    TEST_ASSERT_NOT_EQUAL(-1, i);
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], WA_RESPONSE));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"credential_name\":\"Ada's laptop\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], WA_STATE));

    TEST_ASSERT_EQUAL_STRING("cred-1", cred.id);
    TEST_ASSERT_EQUAL_STRING("passkey", cred.credential_type);
    /* A credential never used comes back with a null, and null is not "". */
    TEST_ASSERT_NULL(cred.last_used_at);

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_register_finish_accepts_the_201_rfc_status(void) {
    /* The enrolment endpoint answers Created. A success predicate written
     * `== 200` fails every real enrolment while passing everything else. */
    g.status_register_finish = 201;
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_response_that_is_not_json_is_refused_with_no_wire_call(void) {
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_register_finish(c, state, "laptop", "not json at all", &cred, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_response_that_is_a_json_array_is_refused(void) {
    /* Valid JSON, wrong shape. The check is "is it an object", not "does it
     * parse" — an array parses and the server can do nothing with it. */
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_register_finish(c, state, "laptop", "[1,2,3]", &cred, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_leading_whitespace_does_not_defeat_the_object_check(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "laptop", "\n  " WA_RESPONSE, &cred, &err));

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §24.2 — two ceremonies, not one with a flag                        */
/* ------------------------------------------------------------------ */

void test_authenticate_start_requires_the_challenge_token(void) {
    /* §24.2: the second-factor ceremony continues a login that was already
     * gated at its password step, so the token is not optional. Merging the two
     * ceremonies behind a nullable argument is the bug the clause names. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_authenticate_start(c, NULL, &ch, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_authenticate_start_sends_the_challenge_token_and_no_workspace(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("challenge-token-value");

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_authenticate_start(c, token, &ch, &err));

    int i = last_call_to("/authenticate/start");
    TEST_ASSERT_NOT_EQUAL(-1, i);
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"challenge_token\":\"challenge-token-value\""));
    /* A second factor knows its workspace from the token; sending one here
     * would be the SDK inventing a field the flow does not have. */
    TEST_ASSERT_NULL(strstr(g.bodies[i], "org_"));
    TEST_ASSERT_NULL(strstr(g.bodies[i], "tenant_"));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_discoverable_start_needs_no_token_and_carries_the_workspace(void) {
    /* The mirror image of the test above, and the reason §24.2 says these are
     * different flows: a usernameless ceremony has no prior step to have minted
     * a token, so the workspace has to travel explicitly. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(c, NULL, &ch, &err));

    int i = last_call_to("/discoverable/start");
    TEST_ASSERT_NOT_EQUAL(-1, i);
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"org_slug\":\"acme-org\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));
    TEST_ASSERT_NULL(strstr(g.bodies[i], "challenge_token"));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_discoverable_start_accepts_a_tenant_slug(void) {
    /* Unlike the five /oauth2 operations of §12.1 rule 2, this endpoint takes
     * slugs — so a slug-only client can run the ceremony at all. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_workspace_t ws = {NULL, "other-org", NULL, "other-tenant"};
    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(c, &ws, &ch, &err));

    int i = last_call_to("/discoverable/start");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"org_slug\":\"other-org\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_slug\":\"other-tenant\""));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_discoverable_start_without_a_workspace_is_refused_client_side(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, wa_transport, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_webauthn_discoverable_start(c, NULL, &ch, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §24.3 — both finish calls establish a session                      */
/* ------------------------------------------------------------------ */

void test_authenticate_finish_adopts_the_session(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_authenticate_finish(c, state, WA_RESPONSE, &login, &err));

    TEST_ASSERT_EQUAL_STRING(WA_ACCESS, axiam_sensitive_reveal(login.access_token));
    TEST_ASSERT_EQUAL_STRING(WA_REFRESH, axiam_sensitive_reveal(login.refresh_token));
    TEST_ASSERT_EQUAL_STRING("sess-2", login.session_id);
    TEST_ASSERT_EQUAL_INT(900, (int)login.expires_in);
    /* §24.3: the ceremony signed this client in, so register/… now works. */
    TEST_ASSERT_EQUAL_INT(1, axiam_client_has_session(c));

    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_discoverable_finish_adopts_the_session_the_same_way(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_discoverable_finish(c, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_EQUAL_STRING("sess-disc", login.session_id);
    TEST_ASSERT_EQUAL_INT(1, axiam_client_has_session(c));

    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_authenticate_finish_clears_the_decision_memo(void) {
    /* §24.3 rule 4 / §17.1 rule 9: memo entries are keyed by subject, and this
     * call changes the subject. Serving a decision cached for the previous user
     * is an authorization bug, so the assertion is a REQUEST COUNT: the second
     * check must go back to the wire. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_check_result_t r1;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r1, &err));
    axiam_check_result_dispose(&r1);
    int after_first = g.n_calls;

    /* Warm: served from the memo, no wire call. */
    axiam_check_result_t r2;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r2, &err));
    axiam_check_result_dispose(&r2);
    TEST_ASSERT_EQUAL_INT(after_first, g.n_calls);

    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);
    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_authenticate_finish(c, state, WA_RESPONSE, &login, &err));
    int after_ceremony = g.n_calls;

    axiam_check_result_t r3;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r3, &err));
    axiam_check_result_dispose(&r3);
    TEST_ASSERT_EQUAL_INT(after_ceremony + 1, g.n_calls);

    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §24.4 — the two overrides of the generic §2 mapping                */
/* ------------------------------------------------------------------ */

void test_a_403_on_register_finish_surfaces_the_policy_message(void) {
    /* §24.4 rule 1. The generic mapping would say "register/finish failed",
     * which tells the person holding the key nothing they can act on: the
     * tenant's attestation policy rejected THIS authenticator, and the server's
     * message is the only place that says which one would be accepted. */
    g.status_register_finish = 403;
    g.body_register_finish =
        "{\"error\":\"attestation_rejected\","
        "\"message\":\"This tenant requires a certified security key from an approved vendor.\"}";

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTHZ,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "certified security key"));

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_403_with_no_message_still_maps(void) {
    /* Only the NAMED `message` field is lifted; a body without one degrades to
     * the generic mapping rather than dumping the body into the error. */
    g.status_register_finish = 403;
    g.body_register_finish = "{\"error\":\"forbidden\",\"detail\":\"do-not-echo-me\"}";

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTHZ,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_NULL(strstr(err.message, "do-not-echo-me"));

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_503_on_register_start_is_not_retried(void) {
    /* §24.4 rule 2. A 503 here means the tenant's attestation policy needs FIDO
     * metadata the server cannot reach: a CONFIGURATION state, not a transient
     * one. Retrying it three times turns a clear error into a slow one. */
    g.status_register_start = 503;
    g.body_register_start = "{\"error\":\"metadata_unavailable\"}";

    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(c, &ch, &err));
    TEST_ASSERT_EQUAL_INT(before + 1, g.n_calls);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §24.6a — the JSON bridge                                           */
/* ------------------------------------------------------------------ */

void test_request_json_drops_the_publickey_wrapper_and_nothing_else(void) {
    /* §24.6a rule 1: this is the string a browser hands to
     * PublicKeyCredential.parseCreationOptionsFromJSON() and an Android app
     * hands to CreatePublicKeyCredentialRequest. Both want the INNER object —
     * the wrapper belongs to the DOM's CredentialCreationOptions. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(c, &ch, &err));

    char *json = axiam_webauthn_request_json(&ch);
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_NULL(strstr(json, "publicKey"));
    /* Everything inside survives, in order: this is a wrapper removal, not a
     * re-serialisation with a filter. */
    TEST_ASSERT_EQUAL_STRING(
        "{\"challenge\":\"q83vAAAAAAAAAAAAAAAAAA\","
        "\"rp\":{\"id\":\"acme.test\",\"name\":\"Acme\"},"
        "\"user\":{\"id\":\"dXNlci0x\",\"name\":\"ada\",\"displayName\":\"Ada\"},"
        "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],"
        "\"timeout\":60000,\"attestation\":\"direct\"}",
        json);

    free(json);
    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_request_json_passes_bare_options_through(void) {
    /* A server that sent the bare options rather than the wrapper is not wrong
     * for every consumer, and this call has one job. */
    axiam_webauthn_challenge_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.challenge_json = axiam_strdup0("{\"challenge\":\"abc\"}");

    char *json = axiam_webauthn_request_json(&ch);
    TEST_ASSERT_EQUAL_STRING("{\"challenge\":\"abc\"}", json);

    free(json);
    axiam_webauthn_challenge_dispose(&ch);
}

void test_request_json_is_null_safe(void) {
    TEST_ASSERT_NULL(axiam_webauthn_request_json(NULL));
    axiam_webauthn_challenge_t empty;
    memset(&empty, 0, sizeof(empty));
    TEST_ASSERT_NULL(axiam_webauthn_request_json(&empty));
}

/* ------------------------------------------------------------------ */
/* §24.6b rule 5 — the failure classification                         */
/* ------------------------------------------------------------------ */

void test_classification_covers_the_five_outcomes(void) {
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_CANCELLED, axiam_webauthn_classify("NotAllowedError"));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_ALREADY_REGISTERED,
                      axiam_webauthn_classify("InvalidStateError"));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_TIMEOUT, axiam_webauthn_classify("AbortError"));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_UNSUPPORTED, axiam_webauthn_classify("NotSupportedError"));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_UNSUPPORTED, axiam_webauthn_classify("SecurityError"));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_UNKNOWN, axiam_webauthn_classify("SomethingElseError"));
}

void test_classification_never_fails(void) {
    /* A classifier that can fail is one more thing for an error handler to
     * handle, at the moment the caller already has an error in hand. */
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_UNKNOWN, axiam_webauthn_classify(NULL));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_UNKNOWN, axiam_webauthn_classify(""));
    TEST_ASSERT_EQUAL(AXIAM_WEBAUTHN_CANCELLED, axiam_webauthn_classify("  notallowederror"));
}

void test_the_cancelled_message_does_not_accuse_the_user(void) {
    /* AXIAM_WEBAUTHN_CANCELLED covers BOTH an explicit refusal and a silent
     * timeout — the spec refuses to distinguish them, because telling a website
     * which happened leaks whether an authenticator was present. Copy that says
     * "you cancelled" is wrong half the time it is shown. */
    const char *msg = axiam_webauthn_failure_message(AXIAM_WEBAUTHN_CANCELLED);
    TEST_ASSERT_NOT_NULL(msg);
    TEST_ASSERT_NULL(strstr(msg, "You cancelled"));
    TEST_ASSERT_NOT_NULL(strstr(msg, "try again"));
}

void test_every_failure_has_a_message(void) {
    for (int f = AXIAM_WEBAUTHN_CANCELLED; f <= AXIAM_WEBAUTHN_UNKNOWN; f++) {
        const char *m = axiam_webauthn_failure_message((axiam_webauthn_failure_t)f);
        TEST_ASSERT_NOT_NULL(m);
        TEST_ASSERT_TRUE(strlen(m) > 0);
    }
    /* Including a value no version of this enum defines: a caller relaying an
     * integer from another process must not be able to crash a renderer. */
    TEST_ASSERT_NOT_NULL(axiam_webauthn_failure_message((axiam_webauthn_failure_t)99));
}

/* ------------------------------------------------------------------ */
/* §7 — no secret renders                                             */
/* ------------------------------------------------------------------ */

void test_no_state_token_renders_through_the_public_surface(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(c, &ch, &err));

    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(ch.state_token));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_dispose_is_safe_on_null_and_on_a_zeroed_struct(void) {
    /* Every caller disposes unconditionally on the error path; a dispose that
     * needs a successful call first is one every error handler gets wrong. */
    axiam_webauthn_challenge_dispose(NULL);
    axiam_webauthn_credential_dispose(NULL);
    axiam_webauthn_login_dispose(NULL);

    axiam_webauthn_challenge_t ch;
    memset(&ch, 0, sizeof(ch));
    axiam_webauthn_challenge_dispose(&ch);
    axiam_webauthn_credential_t cred;
    memset(&cred, 0, sizeof(cred));
    axiam_webauthn_credential_dispose(&cred);
    axiam_webauthn_login_t login;
    memset(&login, 0, sizeof(login));
    axiam_webauthn_login_dispose(&login);
}

void test_a_closed_client_refuses_every_operation(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_client_close(c);
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_challenge_t ch;
    axiam_webauthn_credential_t cred;
    axiam_webauthn_login_t login;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(c, &ch, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_authenticate_start(c, state, &ch, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_authenticate_finish(c, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(c, NULL, &ch, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_discoverable_finish(c, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_sensitive_free(state);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* The arms an HTTP-only fake never reaches                           */
/* ------------------------------------------------------------------ */

void test_a_transport_failure_is_reported_as_a_network_error(void) {
    /* A refused connection is not an HTTP status, and every one of the six
     * operations has to tell the difference: "the server said no" and "there
     * was no server" lead a caller to different places. */
    axiam_client_t *c = make_signed_in_client();
    g.transport_fails = 1;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_challenge_t ch;
    axiam_webauthn_credential_t cred;
    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_webauthn_register_start(c, &ch, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "connection refused"));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_webauthn_authenticate_start(c, state, &ch, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_webauthn_authenticate_finish(c, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_webauthn_discoverable_start(c, NULL, &ch, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_webauthn_discoverable_finish(c, state, WA_RESPONSE, &login, &err));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_webauthn_credential_dispose(&cred);
    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_start_body_that_is_not_json_is_a_network_error(void) {
    /* A 200 whose body cannot be parsed is not a challenge with missing fields;
     * there is nothing to hand an authenticator, and returning an empty options
     * object would send the caller into a ceremony that cannot succeed. */
    g.body_auth_start = "<html>gateway</html>";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("challenge-token-value");

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_webauthn_authenticate_start(c, token, &ch, &err));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_start_body_missing_the_challenge_still_yields_a_disposable_result(void) {
    /* A server that answered 200 with no `challenge` is broken, but the caller
     * still holds a struct it will dispose — so the members have to be valid,
     * not left uninitialised for an error path to walk. */
    g.body_auth_start = "{\"state_token\":\"" WA_STATE "\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("challenge-token-value");

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_authenticate_start(c, token, &ch, &err));
    TEST_ASSERT_EQUAL_STRING("{}", ch.challenge_json);

    axiam_webauthn_challenge_dispose(&ch);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_non_200_on_authenticate_finish_maps_through_section_2(void) {
    /* The authentication ceremonies get the GENERIC mapping — §24.4's two
     * overrides are both about register/*, and widening them here would dress a
     * failed assertion up as a policy problem. */
    g.status_auth_finish = 401;

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_authenticate_finish(c, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "axiam_webauthn_authenticate_finish failed"));
    /* And it did NOT sign the client in. */
    TEST_ASSERT_EQUAL_INT(0, axiam_client_has_session(c));

    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_null_response_string_is_refused_with_no_wire_call(void) {
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_login_t login;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_webauthn_authenticate_finish(c, state, NULL, &login, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_webauthn_login_dispose(&login);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_null_client_is_refused_by_every_operation(void) {
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_challenge_t ch;
    axiam_webauthn_credential_t cred;
    axiam_webauthn_login_t login;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_register_start(NULL, &ch, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(NULL, state, "laptop", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_authenticate_start(NULL, state, &ch, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_authenticate_finish(NULL, state, WA_RESPONSE, &login, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(NULL, NULL, &ch, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_sensitive_free(state);
}

void test_register_finish_without_a_credential_name_is_refused(void) {
    /* The label is what the user later recognises the key by in a list. An SDK
     * that defaulted it to "passkey" would produce an account with four
     * indistinguishable entries and no way to tell which device to remove. */
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, NULL, WA_RESPONSE, &cred, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_a_credential_that_has_been_used_reports_when(void) {
    g.body_register_finish =
        "{\"id\":\"cred-1\",\"credential_id\":\"Y3JlZC1pZA\",\"name\":\"key\","
        "\"credential_type\":\"security_key\",\"created_at\":\"2026-01-01T00:00:00Z\","
        "\"last_used_at\":\"2026-08-22T09:00:00Z\"}";

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(WA_STATE);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "key", WA_RESPONSE, &cred, &err));
    TEST_ASSERT_EQUAL_STRING("2026-08-22T09:00:00Z", cred.last_used_at);
    TEST_ASSERT_EQUAL_STRING("security_key", cred.credential_type);

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

void test_the_workspace_prefers_ids_over_slugs_when_both_are_given(void) {
    /* A UUID is unambiguous and a slug is only unique within its parent, so
     * when a caller supplies both the id wins — and only ONE form of each level
     * is sent, because a server given both has to decide which one it trusts. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_webauthn_workspace_t ws = {"org-uuid", "org-slug", "tenant-uuid", "tenant-slug"};
    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(c, &ws, &ch, &err));

    int i = last_call_to("/discoverable/start");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"org_id\":\"org-uuid\""));
    TEST_ASSERT_NULL(strstr(g.bodies[i], "org_slug"));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"tenant-uuid\""));
    TEST_ASSERT_NULL(strstr(g.bodies[i], "tenant_slug"));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_the_workspace_falls_back_to_a_configured_tenant_slug(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_org_slug(cfg, "acme-org");
    axiam_client_config_set_tenant_slug(cfg, "acme-tenant");
    axiam_client_config_set_transport(cfg, wa_transport, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_webauthn_challenge_t ch;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_webauthn_discoverable_start(c, NULL, &ch, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[last_call_to("/discoverable/start")],
                                "\"tenant_slug\":\"acme-tenant\""));

    axiam_webauthn_challenge_dispose(&ch);
    axiam_client_free(c);
}

void test_a_long_state_token_grows_the_body_builder(void) {
    /* The *_finish body is assembled as TEXT so the authenticator's bytes are
     * spliced rather than re-encoded, which makes the builder's growth path
     * load-bearing rather than incidental: a token longer than the first block
     * must extend the buffer, not truncate into it. State tokens are opaque and
     * this SDK never decodes them, so their length is entirely the server's
     * choice — nothing here may assume it stays small. */
    char long_token[512];
    memset(long_token, 'T', sizeof(long_token) - 1);
    long_token[sizeof(long_token) - 1] = '\0';

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *state = axiam_sensitive_new(long_token);

    axiam_webauthn_credential_t cred;
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_webauthn_register_finish(c, state, "laptop", WA_RESPONSE, &cred, &err));

    int i = last_call_to("/register/finish");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], long_token));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], WA_RESPONSE));

    axiam_webauthn_credential_dispose(&cred);
    axiam_sensitive_free(state);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_register_start_returns_the_options_untouched);
    RUN_TEST(test_register_start_without_a_session_makes_no_wire_call);
    RUN_TEST(test_register_finish_without_a_session_makes_no_wire_call);
    RUN_TEST(test_register_finish_splices_the_response_verbatim);
    RUN_TEST(test_register_finish_accepts_the_201_rfc_status);
    RUN_TEST(test_a_response_that_is_not_json_is_refused_with_no_wire_call);
    RUN_TEST(test_a_response_that_is_a_json_array_is_refused);
    RUN_TEST(test_leading_whitespace_does_not_defeat_the_object_check);
    RUN_TEST(test_authenticate_start_requires_the_challenge_token);
    RUN_TEST(test_authenticate_start_sends_the_challenge_token_and_no_workspace);
    RUN_TEST(test_discoverable_start_needs_no_token_and_carries_the_workspace);
    RUN_TEST(test_discoverable_start_accepts_a_tenant_slug);
    RUN_TEST(test_discoverable_start_without_a_workspace_is_refused_client_side);
    RUN_TEST(test_authenticate_finish_adopts_the_session);
    RUN_TEST(test_discoverable_finish_adopts_the_session_the_same_way);
    RUN_TEST(test_authenticate_finish_clears_the_decision_memo);
    RUN_TEST(test_a_403_on_register_finish_surfaces_the_policy_message);
    RUN_TEST(test_a_403_with_no_message_still_maps);
    RUN_TEST(test_a_503_on_register_start_is_not_retried);
    RUN_TEST(test_request_json_drops_the_publickey_wrapper_and_nothing_else);
    RUN_TEST(test_request_json_passes_bare_options_through);
    RUN_TEST(test_request_json_is_null_safe);
    RUN_TEST(test_classification_covers_the_five_outcomes);
    RUN_TEST(test_classification_never_fails);
    RUN_TEST(test_the_cancelled_message_does_not_accuse_the_user);
    RUN_TEST(test_every_failure_has_a_message);
    RUN_TEST(test_no_state_token_renders_through_the_public_surface);
    RUN_TEST(test_dispose_is_safe_on_null_and_on_a_zeroed_struct);
    RUN_TEST(test_a_closed_client_refuses_every_operation);
    RUN_TEST(test_a_transport_failure_is_reported_as_a_network_error);
    RUN_TEST(test_a_long_state_token_grows_the_body_builder);
    RUN_TEST(test_a_start_body_that_is_not_json_is_a_network_error);
    RUN_TEST(test_a_start_body_missing_the_challenge_still_yields_a_disposable_result);
    RUN_TEST(test_a_non_200_on_authenticate_finish_maps_through_section_2);
    RUN_TEST(test_a_null_response_string_is_refused_with_no_wire_call);
    RUN_TEST(test_a_null_client_is_refused_by_every_operation);
    RUN_TEST(test_register_finish_without_a_credential_name_is_refused);
    RUN_TEST(test_a_credential_that_has_been_used_reports_when);
    RUN_TEST(test_the_workspace_prefers_ids_over_slugs_when_both_are_given);
    RUN_TEST(test_the_workspace_falls_back_to_a_configured_tenant_slug);
    return UNITY_END();
}
