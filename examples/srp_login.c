/*
 * srp_login.c — the SRP-6a login path (CONTRACT.md §23).
 *
 * SRP proves the password to the server without the password — or anything
 * from which it can be cheaply recovered — ever crossing the wire. What the
 * server receives is A and a proof, neither of which is useful without the
 * account's verifier, so a TLS-terminating proxy, an accidentally verbose
 * request log or a heap dump cannot capture a plaintext password.
 *
 * It does NOT protect against a compromised AXIAM server. Nothing client-side
 * can.
 *
 * Three things this example is built to show:
 *
 *   1. axiam_login_srp() fills the SAME axiam_login_result_t as axiam_login(),
 *      MFA branch included, so the result handling below is identical to
 *      examples/login_mfa.c.
 *   2. A tenant with srp_mode: disabled answers the challenge endpoint with
 *      404, which reaches the caller as AXIAM_ERR_NETWORK and NOT as a
 *      credential failure — so falling back to axiam_login() is correct.
 *   3. A tenant with srp_mode: required answers /auth/login with
 *      403 srp_required, which is AXIAM_ERR_AUTHZ. A user whose password is
 *      perfectly good must never be told it is invalid.
 *
 * §23.8 makes SRP CONDITIONAL for this SDK in one respect: Argon2id arrives as
 * an OpenSSL EVP_KDF in 3.2, so a build linked against an older libcrypto
 * cannot serve a tenant configured for it. axiam_srp_argon2_available() answers
 * that up front, and the login path refuses rather than substituting PBKDF2 —
 * which would derive a different x and report a good password as wrong.
 *
 * This example is illustrative — connection details come from environment
 * variables and it compiles/links without a live AXIAM server.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/srp_login
 */
#include <axiam/axiam.h>
#include <stdio.h>
#include <stdlib.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

int main(void) {
    const char *base_url    = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const char *tenant_slug = getenv_or("AXIAM_TENANT_SLUG", "acme");
    const char *org_slug    = getenv_or("AXIAM_ORG_SLUG", "acme");
    const char *username    = getenv_or("AXIAM_USERNAME", "alice");
    const char *password    = getenv_or("AXIAM_PASSWORD", "changeme");
    const char *totp_code   = getenv_or("AXIAM_TOTP_CODE", "000000");

    /* §23.1 puts this probe in every SDK's vocabulary. Here it is
     * unconditional; the Argon2 probe below is the one that can say no. */
    if (!axiam_srp_available()) {
        fprintf(stderr, "this build cannot perform SRP\n");
        return 1;
    }
    if (!axiam_srp_argon2_available()) {
        printf("note: this OpenSSL has no Argon2id (needs 3.2+); a tenant\n"
               "      configured for argon2id will be refused with a clear\n"
               "      message rather than served a wrong derivation.\n");
    }

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, tenant_slug); /* §5: required */
    axiam_client_config_set_org_slug(cfg, org_slug);       /* §5.1 */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    axiam_login_result_t login = {0};
    axiam_error_kind_t kind = axiam_login_srp(client, username, password, &login, &err);

    if (kind == AXIAM_ERR_NETWORK) {
        /* A tenant that has not enabled SRP, or a KDF this build cannot do, is
         * not a failed login. Fall back rather than reporting a credential
         * problem the user does not have. */
        printf("SRP unavailable here (%s) — falling back to password login\n", err.message);
        axiam_login_result_dispose(&login);
        kind = axiam_login(client, username, password, &login, &err);
        if (kind == AXIAM_ERR_AUTHZ) {
            /* srp_mode: required. The credentials were never examined. */
            fprintf(stderr, "this tenant refuses password login: %s\n", err.message);
            axiam_login_result_dispose(&login);
            axiam_client_free(client);
            return 1;
        }
    }

    if (kind != AXIAM_OK) {
        fprintf(stderr, "login failed: %s\n", err.message);
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 1;
    }

    if (login.mfa_required) {
        /* Identical to the non-SRP path — that is the point of §23.1's
         * same-result-type requirement. */
        axiam_login_result_t verified = {0};
        if (axiam_verify_mfa_sensitive(client, login.challenge_token, totp_code,
                                       &verified, &err) != AXIAM_OK) {
            fprintf(stderr, "verify_mfa failed: %s\n", err.message);
            axiam_login_result_dispose(&login);
            axiam_login_result_dispose(&verified);
            axiam_client_free(client);
            return 1;
        }
        axiam_login_result_dispose(&login);
        login = verified;
    }

    printf("authenticated: session=%s expires_in=%lds\n",
           login.session_id ? login.session_id : "(none)", login.expires_in);
    axiam_login_result_dispose(&login);

    /* Enrolment, for any request that SETS a password. The server cannot
     * compute a verifier — it never sees the plaintext — so it has to arrive
     * with the request or not at all. Read the tenant's parameters from
     * GET /api/v1/auth/me (or the reset context) rather than hard-coding them:
     * the server dictates the costs per exchange, and a verifier enrolled under
     * different costs stays valid. */
    const char *new_password = getenv("AXIAM_NEW_PASSWORD");
    if (new_password && new_password[0]) {
        axiam_srp_enrollment_t enrolment;
        axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_PBKDF2, 0, 0, 0 };
        /* The account's USERNAME, which is the canonical identity the challenge
         * endpoint hands back. An email here produces a verifier no login can
         * ever satisfy. */
        if (axiam_srp_enrollment(username, new_password, NULL, &params,
                                 &enrolment, &err) == AXIAM_OK) {
            /* Send this as the `srp` member of the change-password body. Never
             * log the salt or verifier: they are §23.3 rule 12 material, which
             * is why only the parameters are printed here. */
            printf("enrolment ready: group=%s kdf=%s iterations=%u\n",
                   enrolment.group, enrolment.kdf, enrolment.iterations);
            axiam_srp_enrollment_dispose(&enrolment);
        } else {
            fprintf(stderr, "enrolment skipped: %s\n", err.message);
        }
    }

    axiam_client_free(client);
    return 0;
}
