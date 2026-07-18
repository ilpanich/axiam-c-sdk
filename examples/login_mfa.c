/*
 * login_mfa.c — demonstrates the two-phase login / verify_mfa flow
 * (CONTRACT.md §1, §5, §5.1).
 *
 * It builds an axiam_client_config_t with a non-optional tenant slug (§5 —
 * there is no default tenant) AND an organization slug (§5.1 — login/refresh
 * require organization context; a tenant slug is only unique within an org).
 * It then calls axiam_login() and branches on login.mfa_required: when the
 * server returns an MFA challenge instead of a completed session, it calls
 * axiam_verify_mfa() with the challenge token and a TOTP code.
 *
 * This example is illustrative — connection details come from environment
 * variables and it compiles/links without a live AXIAM server. Running it
 * end-to-end requires a reachable AXIAM server at the configured base URL.
 * Strict TLS verification is always on (§6); for a self-signed dev server add
 * a custom CA with axiam_client_config_set_custom_ca().
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/login_mfa
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
    const char *email       = getenv_or("AXIAM_EMAIL", "user@example.com");
    const char *password    = getenv_or("AXIAM_PASSWORD", "changeme");
    const char *totp_code   = getenv_or("AXIAM_TOTP_CODE", "000000");

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, tenant_slug); /* §5: required */
    axiam_client_config_set_org_slug(cfg, org_slug);       /* §5.1: required for login/refresh */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    /* POST /api/v1/auth/login (CONTRACT.md §1). */
    axiam_login_result_t login = {0};
    if (axiam_login(client, email, password, &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login failed: %s\n", err.message);
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 1;
    }

    if (login.mfa_required) {
        printf("MFA required — completing the two-phase flow\n");
        /* POST /api/v1/auth/mfa/verify — completes the flow started by login().
         * The challenge token is Sensitive and is never logged (§7). */
        axiam_login_result_t verified = {0};
        if (axiam_verify_mfa(client, login.challenge_token, totp_code, &verified, &err) != AXIAM_OK) {
            fprintf(stderr, "MFA verification failed: %s\n", err.message);
            axiam_login_result_dispose(&verified);
            axiam_login_result_dispose(&login);
            axiam_client_free(client);
            return 1;
        }
        printf("MFA verified — session_id: %s, expires_in: %lds\n",
               verified.session_id ? verified.session_id : "(none)", verified.expires_in);
        axiam_login_result_dispose(&verified);
    } else if (login.mfa_setup_required) {
        printf("MFA enrollment required before this account can authenticate\n");
    } else {
        printf("Login complete (no MFA) — session_id: %s, expires_in: %lds\n",
               login.session_id ? login.session_id : "(none)", login.expires_in);
    }

    axiam_login_result_dispose(&login);

    /* POST /api/v1/auth/logout — clears local session state on success. */
    axiam_logout(client, &err);
    axiam_client_free(client);
    return 0;
}
