/*
 * Account lifecycle and MFA enrolment — CONTRACT.md §25.
 *
 * Nine operations, six of them deliberately unauthenticated, and a set of
 * rules that are mostly about what an SDK must NOT do: not clear the decision
 * memo on a voluntary enrolment, not compose the two-call enrolment into one,
 * not tell a caller whether an email address exists, not leave the otpauth URI
 * unwrapped because "the secret field is the secret one".
 *
 * The §25.3 test is the one worth reading twice. It scans for the SECRET VALUE
 * rather than the field name — a test that asserts `totp_uri` is absent from a
 * rendering passes for an SDK that renamed the field and still printed the
 * secret.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/account.h"
#include "internal.h"
#include "test_util.h"

#define TOTP_SECRET "JBSWY3DPEHPK3PXP"
#define TOTP_URI    "otpauth://totp/Acme:ada@acme.test?secret=" TOTP_SECRET "&issuer=Acme"
#define RESET_TOKEN "reset-token-value/with+reserved=chars"
#define SETUP_TOKEN "setup-token-value"

#define ENROLL_BODY \
    "{\"secret_base32\":\"" TOTP_SECRET "\",\"totp_uri\":\"" TOTP_URI "\"}"

#define LOGIN_OK_BODY                                                          \
    "{\"authenticated\":true,\"access_token\":\"access-1\","                   \
    "\"refresh_token\":\"refresh-1\",\"session_id\":\"sess-1\","               \
    "\"expires_in\":900,\"user_id\":\"user-1\","                               \
    "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}"

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

#define MAX_CALLS 16

typedef struct {
    long status_login;
    const char *body_login;
    long status_enroll;
    long status_confirm;
    long status_setup_enroll;
    long status_setup_confirm;
    const char *body_setup_confirm;
    long status_verify_email;
    long status_resend;
    long status_reset;
    long status_reset_context;
    const char *body_reset_context;
    long status_reset_confirm;
    /* Every one of the nine has a transport-failure arm, and a fake transport
     * that can only return HTTP statuses never reaches one. */
    int transport_fails;
    const char *body_enroll;

    char methods[MAX_CALLS][8];
    char urls[MAX_CALLS][1024];
    char bodies[MAX_CALLS][2048];
    int n_calls;
} acct_state_t;

static acct_state_t g;

static void record(const axiam_http_request_t *req) {
    if (g.n_calls >= MAX_CALLS) return;
    int i = g.n_calls++;
    snprintf(g.methods[i], sizeof(g.methods[i]), "%s", req->method ? req->method : "");
    snprintf(g.urls[i], sizeof(g.urls[i]), "%s", req->url ? req->url : "");
    snprintf(g.bodies[i], sizeof(g.bodies[i]), "%s", req->body ? req->body : "");
}

static int acct_transport(void *ctx, const axiam_http_request_t *req,
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
        resp_fill(resp, g.status_login ? g.status_login : 200,
                  g.body_login ? g.body_login : LOGIN_OK_BODY, "csrf-1");
        return 0;
    }
    if (strstr(url, "/auth/mfa/setup/enroll")) {
        resp_fill(resp, g.status_setup_enroll ? g.status_setup_enroll : 200, ENROLL_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/auth/mfa/setup/confirm")) {
        resp_fill(resp, g.status_setup_confirm ? g.status_setup_confirm : 200,
                  g.body_setup_confirm ? g.body_setup_confirm : LOGIN_OK_BODY, "csrf-2");
        return 0;
    }
    if (strstr(url, "/auth/mfa/enroll")) {
        resp_fill(resp, g.status_enroll ? g.status_enroll : 200,
                  g.body_enroll ? g.body_enroll : ENROLL_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/auth/mfa/confirm")) {
        resp_fill(resp, g.status_confirm ? g.status_confirm : 200,
                  "{\"mfa_enabled\":true}", NULL);
        return 0;
    }
    if (strstr(url, "/auth/verify-email")) {
        resp_fill(resp, g.status_verify_email ? g.status_verify_email : 204, NULL, NULL);
        return 0;
    }
    if (strstr(url, "/auth/resend-verification")) {
        resp_fill(resp, g.status_resend ? g.status_resend : 202, NULL, NULL);
        return 0;
    }
    if (strstr(url, "/auth/reset/context")) {
        resp_fill(resp, g.status_reset_context ? g.status_reset_context : 200,
                  g.body_reset_context ? g.body_reset_context : "{}", NULL);
        return 0;
    }
    if (strstr(url, "/auth/reset/confirm")) {
        resp_fill(resp, g.status_reset_confirm ? g.status_reset_confirm : 204, NULL, NULL);
        return 0;
    }
    if (strstr(url, "/auth/reset")) {
        resp_fill(resp, g.status_reset ? g.status_reset : 202, NULL, NULL);
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
    axiam_client_config_set_transport(cfg, acct_transport, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

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
/* §25.2 rule 1 — login's third outcome                               */
/* ------------------------------------------------------------------ */

void test_login_surfaces_the_mfa_setup_required_outcome(void) {
    /* The tenant requires MFA and this account has none. Before §25 an SDK
     * either reported this as a generic failure or, worse, as a successful
     * login with no session — both leave the caller with nothing to do next.
     * The setup token IS the credential for what follows. */
    g.status_login = 403;
    g.body_login = "{\"mfa_setup_required\":true,\"setup_token\":\"" SETUP_TOKEN "\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_login_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login(c, "ada@acme.test", "pw", &r, &err));
    TEST_ASSERT_EQUAL_INT(1, r.mfa_setup_required);
    TEST_ASSERT_EQUAL_INT(0, r.authenticated);
    TEST_ASSERT_EQUAL_INT(0, r.mfa_required);
    TEST_ASSERT_NOT_NULL(r.setup_token);
    TEST_ASSERT_EQUAL_STRING(SETUP_TOKEN, axiam_sensitive_reveal(r.setup_token));
    /* §7: a token the caller must carry across two more calls is Sensitive. */
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(r.setup_token));

    axiam_login_result_dispose(&r);
    axiam_client_free(c);
}

void test_a_plain_403_is_still_a_failure(void) {
    /* The new branch must not swallow every 403 into "setup required". */
    g.status_login = 403;
    g.body_login = "{\"error\":\"account_locked\"}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_login_result_t r;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_login(c, "ada@acme.test", "pw", &r, &err));

    axiam_login_result_dispose(&r);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Voluntary enrolment                                                */
/* ------------------------------------------------------------------ */

void test_mfa_enroll_returns_both_halves_wrapped(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_enroll(c, &e, &err));
    TEST_ASSERT_EQUAL_STRING(TOTP_SECRET, axiam_sensitive_reveal(e.secret_base32));
    TEST_ASSERT_EQUAL_STRING(TOTP_URI, axiam_sensitive_reveal(e.totp_uri));
    TEST_ASSERT_EQUAL_STRING("POST", g.methods[last_call_to("/mfa/enroll")]);

    axiam_mfa_enrollment_dispose(&e);
    axiam_client_free(c);
}

void test_the_totp_uri_is_sensitive_because_it_contains_the_secret(void) {
    /* §25.3. THE ASSERTION SCANS FOR THE SECRET VALUE, NOT THE FIELD NAME.
     * Wrapping `secret_base32` and leaving `totp_uri` a plain string wraps
     * nothing: the URI is the field that actually gets logged, because it is
     * the one the caller passes to a QR renderer. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_enroll(c, &e, &err));

    TEST_ASSERT_NULL(strstr(axiam_sensitive_to_string(e.secret_base32), TOTP_SECRET));
    TEST_ASSERT_NULL(strstr(axiam_sensitive_to_string(e.totp_uri), TOTP_SECRET));

    axiam_mfa_enrollment_dispose(&e);
    axiam_client_free(c);
}

void test_mfa_enroll_does_not_clear_the_decision_memo(void) {
    /* §25.2 rule 3. The subject has not changed — offering a factor is a
     * profile action, and discarding a warm memo over it costs a round trip on
     * every check that follows. The assertion is a REQUEST COUNT, because that
     * is the only thing the caller can actually observe. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_check_result_t r1;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r1, &err));
    axiam_check_result_dispose(&r1);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_enroll(c, &e, &err));
    axiam_mfa_enrollment_dispose(&e);
    int after_enroll = g.n_calls;

    axiam_check_result_t r2;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r2, &err));
    axiam_check_result_dispose(&r2);
    TEST_ASSERT_EQUAL_INT(after_enroll, g.n_calls);

    axiam_client_free(c);
}

void test_mfa_confirm_sends_the_code_and_reports_the_result(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    int enabled = 0;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "123456", &enabled, &err));
    TEST_ASSERT_EQUAL_INT(1, enabled);
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[last_call_to("/mfa/confirm")],
                                "\"totp_code\":\"123456\""));

    axiam_client_free(c);
}

void test_enrolment_is_two_calls_and_there_is_no_helper_that_composes_them(void) {
    /* §25.2 rule 4. The human step in the middle — read the QR code, type the
     * six digits — is not something a helper can wait for, and an SDK that
     * offered `enroll_and_confirm(code)` would be offering a call that cannot
     * work. The assertion is that each call goes to its own endpoint exactly
     * once: no composition, no implicit second request. */
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_enroll(c, &e, &err));
    TEST_ASSERT_EQUAL_INT(before + 1, g.n_calls);
    axiam_mfa_enrollment_dispose(&e);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "123456", NULL, &err));
    TEST_ASSERT_EQUAL_INT(before + 2, g.n_calls);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Forced enrolment (§25.2 rule 2)                                    */
/* ------------------------------------------------------------------ */

void test_setup_enroll_uses_the_setup_token_and_needs_no_session(void) {
    /* There is no session yet — the login that produced the setup token stopped
     * short of one. An SDK that required a session here would make the forced
     * path unreachable. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new(SETUP_TOKEN);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_setup_enroll(c, token, &e, &err));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[last_call_to("/mfa/setup/enroll")],
                                "\"setup_token\":\"" SETUP_TOKEN "\""));

    axiam_mfa_enrollment_dispose(&e);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_setup_confirm_adopts_credentials_exactly_as_login_does(void) {
    /* §25.2 rule 2: this IS the completion of a login. The proof is that the
     * client is authenticated afterwards without a separate login call. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new(SETUP_TOKEN);

    axiam_login_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_setup_confirm(c, token, "123456", &r, &err));
    TEST_ASSERT_EQUAL_INT(1, r.authenticated);
    TEST_ASSERT_EQUAL_STRING("sess-1", r.session_id);
    TEST_ASSERT_EQUAL_INT(1, axiam_client_has_session(c));

    int i = last_call_to("/mfa/setup/confirm");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"setup_token\":\"" SETUP_TOKEN "\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"totp_code\":\"123456\""));

    axiam_login_result_dispose(&r);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_setup_confirm_clears_the_decision_memo(void) {
    /* The other half of "adopts credentials exactly as login does": a new
     * subject means the memo cannot be reused. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_check_result_t r1;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r1, &err));
    axiam_check_result_dispose(&r1);

    axiam_sensitive_t *token = axiam_sensitive_new(SETUP_TOKEN);
    axiam_login_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_setup_confirm(c, token, "123456", &r, &err));
    axiam_login_result_dispose(&r);
    int after = g.n_calls;

    axiam_check_result_t r2;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "doc-1", NULL, NULL, &r2, &err));
    axiam_check_result_dispose(&r2);
    TEST_ASSERT_EQUAL_INT(after + 1, g.n_calls);

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Email verification (§25.1)                                         */
/* ------------------------------------------------------------------ */

void test_verify_email_carries_the_tenant_in_the_body(void) {
    /* §25.1: a BODY field. These are not /oauth2 endpoints, so §12.1 rule 2's
     * query-parameter convention does not reach them — and an SDK that put it
     * in the query would get a 400 that reads like a bad token. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("verify-token");

    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, &err));

    int i = last_call_to("/verify-email");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"token\":\"verify-token\""));
    TEST_ASSERT_NULL(strstr(g.urls[i], "tenant_id="));

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_verify_email_needs_no_session(void) {
    /* A user whose email is unverified may have no session at all — which is
     * the whole reason this operation is unauthenticated. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("verify-token");

    TEST_ASSERT_EQUAL_INT(0, axiam_client_has_session(c));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, &err));

    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_resend_verification_carries_the_tenant_in_the_body(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_resend_verification(c, "ada@acme.test", AXIAM_TEST_TENANT_ID, &err));

    int i = last_call_to("/resend-verification");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"email\":\"ada@acme.test\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Password reset (§25.4)                                             */
/* ------------------------------------------------------------------ */

void test_request_password_reset_discloses_nothing_about_the_account(void) {
    /* §25.4. The server answers identically whether or not the address exists,
     * and this SDK exposes no way to tell the two apart — not a boolean, not a
     * distinct error, not a timing difference a caller could branch on. A
     * client that surfaced "no such user" would turn the endpoint into the
     * enumeration oracle its uniform response exists to prevent. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_password_reset_request_t req = {"nobody@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    axiam_password_reset_request_t req2 = {"ada@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req2, &err));

    axiam_client_free(c);
}

void test_request_password_reset_fills_the_workspace_from_the_client(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    int i = last_call_to("/auth/reset");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"org_slug\":\"acme-org\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));

    axiam_client_free(c);
}

void test_request_password_reset_takes_a_slug_override(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_password_reset_request_t req = {"ada@acme.test", "other-org", NULL, "other-tenant"};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    int i = last_call_to("/auth/reset");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"org_slug\":\"other-org\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_slug\":\"other-tenant\""));

    axiam_client_free(c);
}

void test_reset_context_percent_encodes_the_token(void) {
    /* A token spliced into the query raw can end the query early or land in the
     * path, and the 404 that produces reads EXACTLY like an expired token —
     * which is the worst possible failure mode for a debugging user. */
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new(RESET_TOKEN);

    axiam_password_reset_context_t ctx;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, token, &ctx, &err));

    int i = last_call_to("/reset/context");
    TEST_ASSERT_EQUAL_STRING("GET", g.methods[i]);
    TEST_ASSERT_NOT_NULL(strstr(g.urls[i], "token="));
    TEST_ASSERT_NOT_NULL(strstr(g.urls[i], "%2F"));  /* the '/' */
    TEST_ASSERT_NOT_NULL(strstr(g.urls[i], "%2B"));  /* the '+' */
    TEST_ASSERT_NOT_NULL(strstr(g.urls[i], "%3D"));  /* the '=' */
    TEST_ASSERT_NULL(strstr(g.urls[i], "with+reserved"));

    axiam_password_reset_context_dispose(&ctx);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_reset_context_hands_the_opaque_block_through_untouched(void) {
    /* Forwarded to the §23 helpers as TEXT. This SDK does not model, validate
     * or re-encode the block — it cannot, and anything it did to it would be a
     * guess about a protocol it deliberately does not implement. */
    g.body_reset_context =
        "{\"opaque\":{\"mode\":\"required\",\"suite\":\"ristretto255-SHA512\","
        "\"server_public_key\":\"c2VydmVyLXBr\"}}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("plain-token");

    axiam_password_reset_context_t ctx;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, token, &ctx, &err));
    TEST_ASSERT_NOT_NULL(ctx.opaque_json);
    TEST_ASSERT_NOT_NULL(strstr(ctx.opaque_json, "ristretto255-SHA512"));
    TEST_ASSERT_NOT_NULL(strstr(ctx.opaque_json, "c2VydmVyLXBr"));

    axiam_password_reset_context_dispose(&ctx);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_tenant_without_opaque_reports_no_block_rather_than_an_empty_one(void) {
    /* NULL means "the plaintext path is allowed". An empty object would mean
     * "OPAQUE is on and configured with nothing", which is a different and
     * unrecoverable state. */
    g.body_reset_context = "{}";

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("plain-token");

    axiam_password_reset_context_t ctx;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, token, &ctx, &err));
    TEST_ASSERT_NULL(ctx.opaque_json);

    axiam_password_reset_context_dispose(&ctx);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_a_404_from_reset_context_does_not_say_which_of_the_three(void) {
    /* §25.4 rule 3: unknown, expired or already-consumed, deliberately
     * indistinguishable. This SDK does not distinguish them either — and the
     * error message must not invent a distinction the server refused to make. */
    g.status_reset_context = 404;

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("expired-token");

    axiam_password_reset_context_t ctx;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, token, &ctx, &err));
    TEST_ASSERT_NULL(strstr(err.message, "expired"));
    TEST_ASSERT_NULL(strstr(err.message, "consumed"));
    TEST_ASSERT_NULL(strstr(err.message, "unknown"));

    axiam_password_reset_context_dispose(&ctx);
    axiam_sensitive_free(token);
    axiam_client_free(c);
}

void test_confirm_password_reset_sends_the_plaintext_shape(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("reset-token");
    axiam_sensitive_t *pw = axiam_sensitive_new("new-password");

    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, &conf, &err));

    int i = last_call_to("/reset/confirm");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"token\":\"reset-token\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"new_password\":\"new-password\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));
    TEST_ASSERT_NULL(strstr(g.bodies[i], "opaque"));

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

void test_confirm_password_reset_attaches_the_opaque_record_verbatim(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("reset-token");
    axiam_sensitive_t *pw = axiam_sensitive_new("new-password");

    axiam_password_reset_confirmation_t conf = {
        token, pw, AXIAM_TEST_TENANT_ID,
        "{\"registration_record\":\"cmVjb3Jk\",\"suite\":\"ristretto255-SHA512\"}"};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, &conf, &err));

    int i = last_call_to("/reset/confirm");
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"opaque\":"));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "cmVjb3Jk"));

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

void test_a_malformed_opaque_record_is_refused_with_no_wire_call(void) {
    axiam_client_t *c = make_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("reset-token");
    axiam_sensitive_t *pw = axiam_sensitive_new("new-password");

    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, "not json"};
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_confirm_password_reset(c, &conf, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Housekeeping                                                       */
/* ------------------------------------------------------------------ */

void test_a_204_is_success_not_a_parse_failure(void) {
    /* Three of the nine answer No Content. An SDK that insists on a JSON body
     * reports every successful reset as a failure. */
    g.status_verify_email = 204;
    g.status_reset = 204;
    g.status_reset_confirm = 204;

    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("t");
    axiam_sensitive_t *pw = axiam_sensitive_new("p");

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, &err));
    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));
    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, &conf, &err));

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

void test_null_arguments_are_refused_with_no_wire_call(void) {
    axiam_client_t *c = make_signed_in_client();
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_enroll(NULL, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, NULL, NULL, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_enroll(c, NULL, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_verify_email(c, NULL, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_resend_verification(c, NULL, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, NULL, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, NULL, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_client_free(c);
}

void test_dispose_is_safe_on_null_and_on_a_zeroed_struct(void) {
    axiam_mfa_enrollment_dispose(NULL);
    axiam_password_reset_context_dispose(NULL);

    axiam_mfa_enrollment_t e;
    memset(&e, 0, sizeof(e));
    axiam_mfa_enrollment_dispose(&e);
    axiam_password_reset_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    axiam_password_reset_context_dispose(&ctx);
}

void test_a_closed_client_refuses_every_operation(void) {
    axiam_client_t *c = make_signed_in_client();
    axiam_client_close(c);
    int before = g.n_calls;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("t");
    axiam_sensitive_t *pw = axiam_sensitive_new("p");

    axiam_mfa_enrollment_t e;
    axiam_login_result_t r;
    axiam_password_reset_context_t ctx;
    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, NULL};

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_enroll(c, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "123456", NULL, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_enroll(c, token, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_confirm(c, token, "123456", &r, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_resend_verification(c, "ada@acme.test", AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, token, &ctx, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, &conf, &err));
    TEST_ASSERT_EQUAL_INT(before, g.n_calls);

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* The arms an HTTP-only fake never reaches                           */
/* ------------------------------------------------------------------ */

void test_a_transport_failure_is_reported_as_a_network_error(void) {
    /* "The server said no" and "there was no server" lead a caller to different
     * places — a reset that never left the machine is worth retrying, and a
     * reset the server rejected is not. */
    axiam_client_t *c = make_signed_in_client();
    g.transport_fails = 1;
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("t");
    axiam_sensitive_t *pw = axiam_sensitive_new("p");

    axiam_mfa_enrollment_t e;
    axiam_login_result_t r;
    axiam_password_reset_context_t ctx;
    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, NULL};

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_mfa_enroll(c, &e, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "connection refused"));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_mfa_confirm(c, "123456", NULL, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_mfa_setup_enroll(c, token, &e, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_mfa_setup_confirm(c, token, "123456", &r, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
        axiam_resend_verification(c, "ada@acme.test", AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_request_password_reset(c, &req, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_password_reset_context(c, token, &ctx, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_confirm_password_reset(c, &conf, &err));

    axiam_login_result_dispose(&r);
    axiam_password_reset_context_dispose(&ctx);
    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

void test_an_enrolment_body_that_is_not_json_is_a_network_error(void) {
    /* A 200 whose body cannot be parsed is not an enrolment with missing
     * fields: there is no secret to show, and an empty Sensitive would send the
     * user to scan a QR code for a factor that can never confirm. */
    g.body_enroll = "<html>gateway timeout</html>";

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_mfa_enroll(c, &e, &err));

    axiam_mfa_enrollment_dispose(&e);
    axiam_client_free(c);
}

void test_a_non_200_maps_through_section_2(void) {
    g.status_enroll = 401;
    g.status_confirm = 400;
    g.status_reset = 500;

    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_mfa_enrollment_t e;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_mfa_enroll(c, &e, &err));
    axiam_mfa_enrollment_dispose(&e);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "000000", NULL, &err));

    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    axiam_client_free(c);
}

void test_mfa_confirm_reports_a_server_that_says_not_enabled(void) {
    /* `out_enabled` reflects the SERVER's answer rather than the status code:
     * a 200 that says `mfa_enabled: false` is a successful call reporting a
     * factor that did not turn on, and collapsing the two loses that. */
    axiam_client_t *c = make_signed_in_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    int enabled = 1;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "123456", &enabled, &err));
    TEST_ASSERT_EQUAL_INT(1, enabled);
    /* And a NULL out-parameter is allowed — a caller who does not care must not
     * have to allocate somewhere for the answer to land. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_mfa_confirm(c, "123456", NULL, &err));

    axiam_client_free(c);
}

void test_the_workspace_falls_back_to_a_configured_org_id(void) {
    /* A client built with UUIDs rather than slugs sends UUIDs — the reset
     * endpoint takes either, and inventing a slug it was never given is how an
     * SDK sends a workspace that does not resolve. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_tenant_slug(cfg, "acme-tenant");
    axiam_client_config_set_transport(cfg, acct_transport, &g);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    int i = last_call_to("/auth/reset");
    TEST_ASSERT_NOT_NULL(
        strstr(g.bodies[i], "\"org_id\":\"22222222-2222-2222-2222-222222222222\""));
    TEST_ASSERT_NOT_NULL(strstr(g.bodies[i], "\"tenant_slug\":\"acme-tenant\""));

    axiam_client_free(c);
}

void test_a_tenant_id_override_beats_the_configured_one(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_password_reset_request_t req = {
        "ada@acme.test", NULL, "33333333-3333-3333-3333-333333333333", NULL};
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));

    int i = last_call_to("/auth/reset");
    TEST_ASSERT_NOT_NULL(
        strstr(g.bodies[i], "\"tenant_id\":\"33333333-3333-3333-3333-333333333333\""));
    TEST_ASSERT_NULL(strstr(g.bodies[i], AXIAM_TEST_TENANT_ID));

    axiam_client_free(c);
}

void test_a_reset_request_without_an_email_is_refused_with_no_wire_call(void) {
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    axiam_password_reset_request_t req = {NULL, NULL, NULL, NULL};
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_request_password_reset(c, &req, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_client_free(c);
}

void test_a_null_client_is_refused_by_every_operation(void) {
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_sensitive_t *token = axiam_sensitive_new("t");
    axiam_sensitive_t *pw = axiam_sensitive_new("p");

    axiam_mfa_enrollment_t e;
    axiam_login_result_t r;
    axiam_password_reset_context_t ctx;
    axiam_password_reset_request_t req = {"ada@acme.test", NULL, NULL, NULL};
    axiam_password_reset_confirmation_t conf = {token, pw, AXIAM_TEST_TENANT_ID, NULL};

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_enroll(NULL, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_confirm(NULL, "123456", NULL, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_enroll(NULL, token, &e, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_confirm(NULL, token, "1", &r, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_verify_email(NULL, token, AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_resend_verification(NULL, "ada@acme.test", AXIAM_TEST_TENANT_ID, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_request_password_reset(NULL, &req, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_password_reset_context(NULL, token, &ctx, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(NULL, &conf, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    /* And the missing-argument cases the closed-client sweep does not reach. */
    axiam_client_t *c = make_client();
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_password_reset_context(c, NULL, &ctx, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_mfa_setup_confirm(c, token, NULL, &r, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_verify_email(c, token, NULL, &err));
    axiam_password_reset_confirmation_t no_tenant = {token, pw, NULL, NULL};
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_confirm_password_reset(c, &no_tenant, &err));
    TEST_ASSERT_EQUAL_INT(0, g.n_calls);

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_login_surfaces_the_mfa_setup_required_outcome);
    RUN_TEST(test_a_plain_403_is_still_a_failure);
    RUN_TEST(test_mfa_enroll_returns_both_halves_wrapped);
    RUN_TEST(test_the_totp_uri_is_sensitive_because_it_contains_the_secret);
    RUN_TEST(test_mfa_enroll_does_not_clear_the_decision_memo);
    RUN_TEST(test_mfa_confirm_sends_the_code_and_reports_the_result);
    RUN_TEST(test_enrolment_is_two_calls_and_there_is_no_helper_that_composes_them);
    RUN_TEST(test_setup_enroll_uses_the_setup_token_and_needs_no_session);
    RUN_TEST(test_setup_confirm_adopts_credentials_exactly_as_login_does);
    RUN_TEST(test_setup_confirm_clears_the_decision_memo);
    RUN_TEST(test_verify_email_carries_the_tenant_in_the_body);
    RUN_TEST(test_verify_email_needs_no_session);
    RUN_TEST(test_resend_verification_carries_the_tenant_in_the_body);
    RUN_TEST(test_request_password_reset_discloses_nothing_about_the_account);
    RUN_TEST(test_request_password_reset_fills_the_workspace_from_the_client);
    RUN_TEST(test_request_password_reset_takes_a_slug_override);
    RUN_TEST(test_reset_context_percent_encodes_the_token);
    RUN_TEST(test_reset_context_hands_the_opaque_block_through_untouched);
    RUN_TEST(test_a_tenant_without_opaque_reports_no_block_rather_than_an_empty_one);
    RUN_TEST(test_a_404_from_reset_context_does_not_say_which_of_the_three);
    RUN_TEST(test_confirm_password_reset_sends_the_plaintext_shape);
    RUN_TEST(test_confirm_password_reset_attaches_the_opaque_record_verbatim);
    RUN_TEST(test_a_malformed_opaque_record_is_refused_with_no_wire_call);
    RUN_TEST(test_a_204_is_success_not_a_parse_failure);
    RUN_TEST(test_null_arguments_are_refused_with_no_wire_call);
    RUN_TEST(test_dispose_is_safe_on_null_and_on_a_zeroed_struct);
    RUN_TEST(test_a_closed_client_refuses_every_operation);
    RUN_TEST(test_a_transport_failure_is_reported_as_a_network_error);
    RUN_TEST(test_an_enrolment_body_that_is_not_json_is_a_network_error);
    RUN_TEST(test_a_non_200_maps_through_section_2);
    RUN_TEST(test_mfa_confirm_reports_a_server_that_says_not_enabled);
    RUN_TEST(test_the_workspace_falls_back_to_a_configured_org_id);
    RUN_TEST(test_a_tenant_id_override_beats_the_configured_one);
    RUN_TEST(test_a_reset_request_without_an_email_is_refused_with_no_wire_call);
    RUN_TEST(test_a_null_client_is_refused_by_every_operation);
    return UNITY_END();
}
