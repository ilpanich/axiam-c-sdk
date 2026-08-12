/*
 * token_exchange — RFC 8693 token exchange (CONTRACT.md §15).
 *
 * A backend holding a user's access token trades it for a NARROWER one before
 * calling the next service, so that service receives exactly the authority it
 * needs and no more.
 *
 * The distinction this example exists to make concrete is the one §15.2 rule 1
 * refuses to paper over:
 *
 *   DELEGATION    — actor token present. "I, service A, am acting on behalf of
 *                   this user." The downstream token names both.
 *   IMPERSONATION — actor token absent. "I am this user." The downstream
 *                   service cannot tell a real user request from this one.
 *
 * They are different operations with different risk, and the SDK supplies no
 * default actor token and never substitutes its own session for one. If you
 * pass nothing, you asked for impersonation, and the server refuses unless this
 * client is registered for it.
 *
 * Everything else here is about NOT helping:
 *
 *   - `unauthorized_client` is surfaced verbatim. It means "this client may not
 *     exchange" or "may not impersonate" — both registration facts an operator
 *     fixes, and reworking the request into a delegation would send one you did
 *     not write.
 *   - `invalid_scope` is not a hint to retry with fewer scopes. The server
 *     refuses rather than silently narrowing precisely so you find out here.
 *   - No refresh token comes back, ever. Re-run the exchange.
 *   - The result is NOT adopted as this client's credential. It is a token to
 *     hand onward in one outbound call.
 *
 * Build: cmake -DAXIAM_BUILD_EXAMPLES=ON && make token_exchange
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

int main(void) {
    const char *subject_raw = getenv("AXIAM_SUBJECT_TOKEN");
    if (!subject_raw || !*subject_raw) {
        fprintf(stderr,
                "Set AXIAM_SUBJECT_TOKEN to the user access token this service is holding.\n");
        return 2;
    }

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://localhost:8443"));
    axiam_client_config_set_tenant_id(
        cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"));
    /* §15.1: the exchanging client AUTHENTICATES — unlike §14's device, this is
     * a confidential service, and a client with no secret is refused
     * client-side. */
    axiam_client_config_set_oidc_client_id(cfg, env_or("AXIAM_OIDC_CLIENT_ID", "example-service"));
    axiam_client_config_set_oidc_client_secret(
        cfg, env_or("AXIAM_OIDC_CLIENT_SECRET", "example-secret"));

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "client construction failed: %s\n", err.message);
        return 1;
    }

    axiam_sensitive_t *subject = axiam_sensitive_new(subject_raw);
    /* Present → delegation. Absent → impersonation. Nothing in between, and no
     * default. */
    const char *actor_raw = getenv("AXIAM_ACTOR_TOKEN");
    axiam_sensitive_t *actor = (actor_raw && *actor_raw) ? axiam_sensitive_new(actor_raw) : NULL;

    const char *scopes[] = {"invoices:read"};
    axiam_token_exchange_params_t params = {0};
    params.subject_token = subject;
    params.actor_token = actor;
    params.scopes = scopes;
    params.scope_count = 1;
    params.audience = env_or("AXIAM_AUDIENCE", NULL);

    printf("Requesting %s of scope \"%s\"…\n",
           actor ? "DELEGATION (actor token present)"
                 : "IMPERSONATION (no actor token — the server will refuse unless "
                   "this client holds that grant)",
           scopes[0]);

    axiam_exchanged_token_t exchanged;
    if (axiam_token_exchange(client, &params, &exchanged, &err) != AXIAM_OK) {
        /* §15.3 dispatches on the `error` field, and each of these is a
         * different thing to do next — which is why the SDK surfaces the code
         * rather than a single "exchange failed". */
        if (strcmp(err.oauth_error, "unauthorized_client") == 0) {
            fprintf(stderr, "\nThis client is not registered for the exchange (or for "
                            "impersonation). An operator has to fix the registration; "
                            "there is nothing to retry.\n");
        } else if (strcmp(err.oauth_error, "invalid_scope") == 0) {
            fprintf(stderr, "\nThe subject does not hold that scope. The SDK did NOT "
                            "quietly retry with fewer — narrowing the ask is your "
                            "decision to make explicitly.\n");
        } else if (strcmp(err.oauth_error, "invalid_grant") == 0) {
            /* §15.3: a cross-tenant subject token answers exactly this, and the
             * server collapses "wrong tenant" into "bad token" deliberately —
             * telling them apart is a tenant-enumeration signal. Do not guess. */
            fprintf(stderr, "\nThe subject token is not usable here (expired, revoked, "
                            "or from another tenant — the server does not say which).\n");
        } else {
            fprintf(stderr, "\nexchange failed: %s\n", err.message);
        }
        axiam_sensitive_free(subject);
        axiam_sensitive_free(actor);
        axiam_client_free(client);
        return 1;
    }

    printf("\nExchanged.\n");
    printf("  issued_token_type %s\n", exchanged.issued_token_type);
    printf("  token_type        %s (expires in %lds)\n",
           exchanged.token_type, exchanged.expires_in);
    printf("  access_token      %s\n", axiam_sensitive_to_string(exchanged.access_token));
    /* §15.2 rule 7: READ THIS. The granted set may be narrower than the one you
     * asked for, even on success. */
    printf("  granted scope     %s\n", exchanged.scope ? exchanged.scope : "(inherited)");
    printf("\nHand this to the downstream service in one outbound call. It is not "
           "this client's session, and\nthere is no refresh token — re-run the "
           "exchange when it expires.\n");

    axiam_exchanged_token_dispose(&exchanged);
    axiam_sensitive_free(subject);
    axiam_sensitive_free(actor);
    axiam_client_free(client);
    return 0;
}
