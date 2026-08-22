/*
 * account_lifecycle.c — the calls a user makes about their own account
 * (CONTRACT.md §25): TOTP enrolment, email verification, password reset.
 *
 * NONE OF THIS IS ADMINISTRATION, and six of the nine operations are
 * deliberately UNAUTHENTICATED. A user who cannot log in is the entire audience
 * for a password reset, and a user whose email is unverified may have no
 * session at all — an SDK that required one would make both unreachable.
 *
 * Two shapes in here are easy to get wrong and expensive to get wrong:
 *
 *  1. `verify_email`, `resend_verification` and `confirm_password_reset` take
 *     the tenant as a BODY field. These are not /oauth2 endpoints, so §12.1
 *     rule 2's query-parameter convention does not reach them, and sending it
 *     in the query gets a 400 that reads exactly like a bad token.
 *  2. The otpauth:// URI CONTAINS the secret. Wrapping `secret_base32` and
 *     leaving the URI a plain string wraps nothing — the URI is the field that
 *     actually gets logged, because it is the one you pass to a QR renderer.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/account_lifecycle
 */
#include <axiam/account.h>
#include <axiam/axiam.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

/* Stand-in for the human step. There is no way around it, which is exactly why
 * §25.2 rule 4 forbids an SDK helper that composes enrol and confirm: a helper
 * cannot wait for someone to read a QR code and type six digits. */
static const char *read_the_code_the_user_typed(void) {
    return getenv_or("AXIAM_TOTP_CODE", "000000");
}

static void enrol_a_totp_factor(axiam_client_t *client) {
    axiam_error_t err;
    axiam_mfa_enrollment_t enrollment;

    if (axiam_mfa_enroll(client, &enrollment, &err) != AXIAM_OK) {
        fprintf(stderr, "mfa/enroll failed: %s\n", err.message);
        axiam_mfa_enrollment_dispose(&enrollment);
        return;
    }

    /*
     * Both halves are Sensitive (§25.3). axiam_sensitive_reveal() is the single
     * explicit accessor §7 rule 3 permits — call it at the point of use, hand
     * the string straight to the QR renderer, and let the return value die
     * there. It must never reach a log, a trace or an error message.
     *
     * Note also what this call did NOT do: it did not clear the §17 decision
     * memo (§25.2 rule 3). The subject has not changed — offering a factor is a
     * profile action — and discarding a warm memo over it costs a round trip on
     * every authorization check that follows.
     */
    printf("  scan this: %s\n", axiam_sensitive_reveal(enrollment.totp_uri));
    printf("  (rendered in a log it would read: %s)\n",
           axiam_sensitive_to_string(enrollment.totp_uri));

    /* The factor is NOT active yet. Two calls, with a human in between. */
    int enabled = 0;
    if (axiam_mfa_confirm(client, read_the_code_the_user_typed(), &enabled, &err) == AXIAM_OK) {
        printf("  MFA is now %s\n", enabled ? "on" : "off");
    } else {
        fprintf(stderr, "mfa/confirm failed: %s\n", err.message);
    }

    axiam_mfa_enrollment_dispose(&enrollment);
}

/*
 * The forced path (§25.2 rule 2). Reached when login answers
 * `mfa_setup_required`: the tenant requires MFA and this account has none.
 *
 * There is no session yet — the setup token IS the credential — and
 * mfa_setup_confirm adopts credentials exactly as login does, because it IS the
 * completion of the login that was interrupted. Before §25 an SDK either
 * reported this as a generic failure or as a successful login with no session;
 * both leave the caller with nothing to do next.
 */
static void complete_forced_enrolment(axiam_client_t *client,
                                      const axiam_sensitive_t *setup_token) {
    axiam_error_t err;
    axiam_mfa_enrollment_t enrollment;

    if (axiam_mfa_setup_enroll(client, setup_token, &enrollment, &err) != AXIAM_OK) {
        fprintf(stderr, "mfa/setup/enroll failed: %s\n", err.message);
        axiam_mfa_enrollment_dispose(&enrollment);
        return;
    }
    printf("  scan this: %s\n", axiam_sensitive_reveal(enrollment.totp_uri));
    axiam_mfa_enrollment_dispose(&enrollment);

    axiam_login_result_t result = {0};
    if (axiam_mfa_setup_confirm(client, setup_token, read_the_code_the_user_typed(),
                                &result, &err) == AXIAM_OK &&
        result.authenticated) {
        printf("  enrolled and signed in, session %s\n", result.session_id);
    } else {
        fprintf(stderr, "mfa/setup/confirm failed: %s\n", err.message);
    }
    axiam_login_result_dispose(&result);
}

static void reset_a_password(axiam_client_t *client, const char *email,
                             const char *tenant_id) {
    axiam_error_t err;

    /*
     * §25.4: this returns success whether or not the address exists, and this
     * SDK exposes no way to tell the two apart — not a boolean, not a distinct
     * error. A client that surfaced "no such user", even inferred from timing,
     * would turn the endpoint into the account-enumeration oracle its uniform
     * response exists to prevent. Say "if that address is registered, check
     * your mail" and mean it.
     */
    axiam_password_reset_request_t request = {email, NULL, NULL, NULL};
    if (axiam_request_password_reset(client, &request, &err) != AXIAM_OK) {
        fprintf(stderr, "reset request failed: %s\n", err.message);
        return;
    }
    printf("  if %s is registered, a reset mail is on its way\n", email);

    const char *token_from_the_mail = getenv_or("AXIAM_RESET_TOKEN", "");
    if (!token_from_the_mail[0]) {
        printf("  (set AXIAM_RESET_TOKEN to continue past this point)\n");
        return;
    }
    axiam_sensitive_t *token = axiam_sensitive_new(token_from_the_mail);

    /*
     * Ask what the account's tenant expects BEFORE choosing a password path.
     * A tenant in `opaque_mode: required` refuses a plaintext password, and
     * refuses it late (§25.4 rule 1) — by which point the user has typed one.
     *
     * A 404 here means unknown, expired OR already-consumed, deliberately
     * without distinguishing them; do not invent a distinction the server
     * refused to make.
     */
    axiam_password_reset_context_t context;
    if (axiam_password_reset_context(client, token, &context, &err) != AXIAM_OK) {
        fprintf(stderr, "that reset link is not usable: %s\n", err.message);
        axiam_password_reset_context_dispose(&context);
        axiam_sensitive_free(token);
        return;
    }

    if (context.opaque_json) {
        /* Hand this block to the §23 helpers untouched — this SDK does not
         * model, validate or re-encode it, and anything it did to it would be a
         * guess about a protocol it deliberately does not implement. */
        printf("  this tenant uses OPAQUE: %s\n", context.opaque_json);
        printf("  build a registration record with the §23 helpers and pass it as opaque_json\n");
    } else {
        axiam_sensitive_t *new_password =
            axiam_sensitive_new(getenv_or("AXIAM_NEW_PASSWORD", "correct horse battery staple"));
        axiam_password_reset_confirmation_t confirmation = {token, new_password, tenant_id, NULL};
        if (axiam_confirm_password_reset(client, &confirmation, &err) == AXIAM_OK) {
            printf("  password changed\n");
        } else {
            fprintf(stderr, "reset confirm failed: %s\n", err.message);
        }
        axiam_sensitive_free(new_password);
    }

    axiam_password_reset_context_dispose(&context);
    axiam_sensitive_free(token);
}

int main(void) {
    const char *base_url    = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const char *tenant_slug = getenv_or("AXIAM_TENANT_SLUG", "acme");
    const char *tenant_id   = getenv_or("AXIAM_TENANT_ID",
                                        "00000000-0000-0000-0000-000000000000");
    const char *org_slug    = getenv_or("AXIAM_ORG_SLUG", "acme");
    const char *email       = getenv_or("AXIAM_EMAIL", "user@example.com");
    const char *password    = getenv_or("AXIAM_PASSWORD", "changeme");

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, tenant_slug); /* §5   */
    axiam_client_config_set_tenant_id(cfg, tenant_id);     /* body field, §25.1 */
    axiam_client_config_set_org_slug(cfg, org_slug);       /* §5.1 */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    /* Unauthenticated, and the tenant travels in the BODY. */
    printf("resending a verification mail (§25.1, unauthenticated):\n");
    if (axiam_resend_verification(client, email, tenant_id, &err) == AXIAM_OK) {
        printf("  requested\n");
    } else {
        fprintf(stderr, "  failed: %s\n", err.message);
    }

    printf("\npassword reset (§25.4):\n");
    reset_a_password(client, email, tenant_id);

    printf("\nlogin (§25.2 rule 1 — three outcomes, not two):\n");
    axiam_login_result_t login = {0};
    if (axiam_login(client, email, password, &login, &err) == AXIAM_OK) {
        if (login.authenticated) {
            printf("  signed in\n\nvoluntary TOTP enrolment (§25.1):\n");
            enrol_a_totp_factor(client);
        } else if (login.mfa_setup_required) {
            printf("  this tenant requires MFA and this account has none\n");
            complete_forced_enrolment(client, login.setup_token);
        } else if (login.mfa_required) {
            printf("  MFA required — see examples/login_mfa.c\n");
        }
    } else {
        fprintf(stderr, "  login failed: %s\n", err.message);
    }
    axiam_login_result_dispose(&login);

    axiam_client_free(client);
    return 0;
}
