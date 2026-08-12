/*
 * device_login — the RFC 8628 device grant (CONTRACT.md §14).
 *
 * The flow for a thing that cannot show a browser: a TV, a headless
 * commissioning tool, a CLI on a machine with no display. The device shows a
 * short code, the user types it somewhere else, and the device polls until they
 * have.
 *
 * WHAT THE SDK WILL NOT DO FOR YOU, and why each one is deliberate:
 *
 *   - It does not print the user code. §14.3 rule 2 forbids it, because only
 *     the application knows how this device can display anything — a screen, a
 *     QR code, an e-ink panel, a line of serial output. The callback below is
 *     where that decision lives, and polling does not start until it returns.
 *   - It does not send a client_secret on `device_authorize` (§14.1). A device
 *     that cannot show a browser also cannot hold a secret, and the SDK equally
 *     will not refuse to run from a client that has none.
 *   - It does not adopt the resulting token as this client's credential
 *     (§14.3 rule 4). The tokens are returned; installing them is the
 *     application's call.
 *
 * And what it DOES do, in the polling loop you never see: honour the server's
 * interval, add five seconds permanently on every `slow_down`, keep
 * `access_denied` and `expired_token` distinguishable, and stop at `expires_in`
 * even if the server never says so.
 *
 * Build: cmake -DAXIAM_BUILD_EXAMPLES=ON && make device_login
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

/*
 * §14.3 rule 2's callback. Called ONCE, before the first poll.
 *
 * A real device renders this however it can. The user code is not wrapped in
 * Sensitive (§14.5) precisely because it exists to be read aloud and typed —
 * but "not a secret" is not "log it": displaying is this function's job and
 * nothing else's.
 */
static void show_codes(void *ctx, const axiam_device_authorization_t *a) {
    (void)ctx;
    printf("\n  ┌──────────────────────────────────────────────┐\n");
    printf("  │  Visit: %-36s │\n", a->verification_uri);
    printf("  │  Code:  %-36s │\n", a->user_code);
    printf("  └──────────────────────────────────────────────┘\n");
    if (a->verification_uri_complete) {
        /* Surfaced when the server sends it, and never synthesised by
         * concatenation when it does not (§14.3) — its format is the server's
         * to choose. This is what a QR code should encode. */
        printf("  (QR target: %s)\n", a->verification_uri_complete);
    }
    printf("\nWaiting for approval — polling every %lds, giving up after %lds.\n",
           a->interval, a->expires_in);
}

int main(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://localhost:8443"));
    axiam_client_config_set_tenant_id(
        cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"));
    /* A public client: no secret configured, and §14.1 requires the grant to
     * work exactly like this. */
    axiam_client_config_set_oidc_client_id(cfg, env_or("AXIAM_OIDC_CLIENT_ID", "example-device"));

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "client construction failed: %s\n", err.message);
        return 1;
    }

    axiam_oidc_token_set_t tokens;
    axiam_error_kind_t kind =
        axiam_device_login(client, env_or("AXIAM_SCOPE", NULL), NULL, show_codes, NULL,
                           &tokens, &err);

    if (kind != AXIAM_OK) {
        /*
         * §14.2 rule 3: the two refusals are DISTINCT, and this is the only
         * place the difference matters. "A human said no" means stop asking.
         * "Nobody answered" means the codes went stale and a fresh grant might
         * work. An SDK that collapsed them would leave this switch unwritable.
         */
        if (err.oauth_error[0]) {
            if (strcmp(err.oauth_error, "access_denied") == 0) {
                fprintf(stderr, "\nThe user declined. Not retrying.\n");
            } else if (strcmp(err.oauth_error, "expired_token") == 0) {
                fprintf(stderr, "\nNobody approved in time. Start a new grant to try again.\n");
            } else {
                fprintf(stderr, "\nRefused: %s\n", err.oauth_error);
            }
        } else {
            fprintf(stderr, "\ndevice login failed: %s\n", err.message);
        }
        axiam_client_free(client);
        return 1;
    }

    printf("\nApproved.\n");
    printf("  token_type    %s (expires in %lds)\n", tokens.token_type, tokens.expires_in);
    /* §7: the token renders redacted, always. Reach it with
     * axiam_sensitive_reveal() at the point of use — building one outbound
     * Authorization header — and let the result die there. */
    printf("  access_token  %s\n", axiam_sensitive_to_string(tokens.access_token));
    if (tokens.refresh_token) {
        /* §14.3 rule 4: a refresh token from this grant is refreshed through
         * axiam_oidc_refresh(), which is §9 single-flighted like any other. */
        printf("  refresh_token %s\n", axiam_sensitive_to_string(tokens.refresh_token));
    }
    /* The client itself is NOT authenticated by this call — the tokens are
     * yours to install wherever your application keeps credentials. */

    axiam_oidc_token_set_dispose(&tokens);
    axiam_client_free(client);
    return 0;
}
