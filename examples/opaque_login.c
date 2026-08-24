/*
 * opaque_login.c — the OPAQUE login path, RFC 9807 (CONTRACT.md §23).
 *
 * OPAQUE proves the password to the server without the password — or anything
 * from which it can be cheaply recovered — ever crossing the wire. What the
 * server receives is a blinded group element and a MAC, neither of which is
 * useful without the account's registration record AND the tenant's OPRF seed.
 * So a TLS-terminating proxy, an accidentally verbose request log or a heap
 * dump cannot capture a plaintext password: the server never has one.
 *
 * It also does something the SRP-6a this replaces could not: a stolen record
 * database is not offline-crackable on its own. That is pre-computation
 * resistance, and it is the substantive reason for the migration.
 *
 * It does NOT protect against a compromised AXIAM server. Nothing client-side
 * can.
 *
 * Four things this example is built to show:
 *
 *   1. axiam_login_opaque() fills the SAME axiam_login_result_t as
 *      axiam_login(), MFA branch included, so the result handling below is
 *      identical to examples/login_mfa.c.
 *   2. A tenant with opaque_mode: disabled answers the two start endpoints with
 *      404, which reaches the caller as AXIAM_ERR_NETWORK and NOT as a
 *      credential failure — so falling back to axiam_login() is correct.
 *   3. AXIAM_ERR_AUTH means the envelope did not open. That is the whole
 *      credential check — RFC 9807's AKE authenticates the server during the
 *      handshake, so there is no separate M2 step of the kind SRP needed — and
 *      the CALLER must not retry it over axiam_login(). The one retry §23.4
 *      rule 7 allows is the SDK's own: under opaque_mode: optional
 *      axiam_login_opaque() has already made it, and what arrives here is that
 *      attempt's answer. Under required there is no retry to make.
 *   4. A tenant with opaque_mode: required answers /auth/login with
 *      403 opaque_required, which is AXIAM_ERR_AUTHZ. A user whose password is
 *      perfectly good must never be told it is invalid.
 *
 * WHAT CHANGED FOR THIS SDK. SRP was CONDITIONAL here: Argon2id arrives as an
 * OpenSSL EVP_KDF only in 3.2, so a build linked against an older libcrypto
 * could not serve a tenant on AXIAM's default KDF, and the login path had to
 * refuse rather than substitute PBKDF2. Key stretching now happens inside
 * libaxiam_opaque_ffi, so the OpenSSL version no longer decides which tenants
 * work. The one remaining condition is having that library, which
 * axiam_opaque_available() reports honestly — and unlike the old
 * axiam_srp_available(), a 1 from it IS a promise that every tenant works.
 *
 * The library is a per-platform GitHub release asset of ilpanich/axiam-opaque,
 * resolved with dlopen() at run time so a consumer who never uses OPAQUE is not
 * made to link it. Point AXIAM_OPAQUE_LIBRARY at it, or install it where the
 * dynamic loader already looks.
 *
 * This example is illustrative — connection details come from environment
 * variables and it compiles/links without a live AXIAM server.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/opaque_login
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

    /* §23.2 puts this probe in every SDK's vocabulary, and here it genuinely
     * can say no. Ask it BEFORE collecting a password: there is no point
     * prompting for one this installation cannot use. */
    if (!axiam_opaque_available()) {
        fprintf(stderr,
                "this installation cannot perform OPAQUE: libaxiam_opaque_ffi was not\n"
                "found. Install the release asset for this platform from\n"
                "ilpanich/axiam-opaque and set %s to its path.\n",
                AXIAM_OPAQUE_LIBRARY_ENV);
        return 1;
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
    axiam_error_kind_t kind = axiam_login_opaque(client, username, password, &login, &err);

    if (kind == AXIAM_ERR_NETWORK) {
        /* The ONLY case that may fall back. A tenant that has not enabled
         * OPAQUE, a missing library, a key-stretching function this SDK cannot
         * ask for, and a malformed response are all configuration facts, not
         * credential facts — reporting them as a bad password would send a user
         * off to reset one that works.
         *
         * AXIAM_ERR_AUTH is deliberately NOT in this branch. See point 3 in the
         * header. */
        printf("OPAQUE unavailable here (%s) — falling back to password login\n", err.message);
        axiam_login_result_dispose(&login);
        kind = axiam_login(client, username, password, &login, &err);
        if (kind == AXIAM_ERR_AUTHZ) {
            /* opaque_mode: required. The credentials were never examined. */
            fprintf(stderr, "this tenant refuses password login: %s\n", err.message);
            axiam_login_result_dispose(&login);
            axiam_client_free(client);
            return 1;
        }
    } else if (kind == AXIAM_ERR_AUTH) {
        /* The envelope did not open: a wrong password, an account that does not
         * exist, an account with no registration record, or a hostile endpoint
         * — indistinguishable by design. Nothing was sent to login/finish
         * (§23.4 rule 7), and under opaque_mode: optional the SDK has already
         * retried over /auth/login, so this is that attempt's answer and there
         * is nothing left for this program to try. */
        fprintf(stderr, "invalid credentials\n");
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 1;
    }

    if (kind != AXIAM_OK) {
        fprintf(stderr, "login failed: %s\n", err.message);
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 1;
    }

    if (login.mfa_required) {
        /* Identical to the non-OPAQUE path — that is the point of §23.1's
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
    } else if (login.mfa_setup_required) {
        printf("this account must complete MFA enrolment first\n");
    }

    printf("authenticated: session=%s expires_in=%lds\n",
           login.session_id ? login.session_id : "(none)", login.expires_in);
    axiam_login_result_dispose(&login);

    /* Enrolment, for any request that SETS a password. The server cannot build
     * a registration record — it never sees the plaintext — so it has to arrive
     * with the request or not at all.
     *
     * Unlike the SRP enrolment this replaces, it performs I/O: one
     * register/start round trip, because OPAQUE's envelope is sealed under the
     * server's oblivious PRF and there is no offline computation that produces
     * a valid record. That is why it takes a client.
     *
     * Note the arguments that are GONE. There is no identity: SRP needed the
     * account's canonical username, and an email there produced a verifier no
     * login could ever satisfy — a record binds to a credential identifier the
     * server chooses, so renaming a user no longer invalidates their credential.
     * There is no group and no kdf either: the server names the key-stretching
     * function per exchange, so a caller cannot pick a cost it will not honour.
     */
    const char *new_password = getenv("AXIAM_NEW_PASSWORD");
    if (new_password && new_password[0]) {
        axiam_opaque_enrollment_t enrolment;
        if (axiam_opaque_enrollment(client, new_password, &enrolment, &err) == AXIAM_OK) {
            /* Send this as the `opaque` member of the change-password body.
             * Never log registration_record: it is the credential material,
             * which is why only the session handle's presence is reported. */
            printf("enrolment ready: opaque_session=%s\n",
                   enrolment.opaque_session ? "<issued>" : "<missing>");
            axiam_opaque_enrollment_dispose(&enrolment);
        } else {
            fprintf(stderr, "enrolment skipped: %s\n", err.message);
        }
    }

    axiam_client_free(client);
    return 0;
}
