/*
 * AXIAM C SDK — the RFC 8628 device authorization grant (CONTRACT.md §14).
 *
 * Signing in a device that cannot show a browser: a TV, a CLI, a headless
 * commissioning tool. §14.2 is titled "the part implementations get wrong", so
 * the four rules this file is built around are worth stating before the code:
 *
 *   - `slow_down` raises the interval PERMANENTLY, by 5 s, and never resets it.
 *     An SDK that backs off for one round and returns to the original rate will
 *     be told to slow down again, forever.
 *   - The initial interval comes from the RESPONSE, not from a constant; 5 s
 *     when the server omits it. No faster floor may be hard-coded.
 *   - `access_denied` and `expired_token` are DISTINCT. One means a human said
 *     no; the other that nobody answered. Collapsing them loses the only thing
 *     the device can act on — retry versus stop asking.
 *   - Polling stops at `expires_in`, whether or not the server has said
 *     `expired_token` yet. The deadline is authoritative and the extra requests
 *     are pure load.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "oidc_internal.h"

axiam_error_kind_t axiam_device_authorize(axiam_client_t *client, const char *scope,
                                          const char *tenant_id,
                                          axiam_device_authorization_t *out,
                                          axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *client_id = oidc_require_client_id(client, "device_authorize", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, tenant_id, "device_authorize", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;
    if (!config.device_authorization_endpoint) {
        axiam_oidc_config_dispose(&config);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "the discovery document advertises no device_authorization_endpoint");
        return AXIAM_ERR_NETWORK;
    }

    oidc_form_t form;
    oidc_form_init(&form);
    /*
     * ONLY client_id. §14.1 is explicit on both halves: a device that cannot
     * show a browser also cannot hold a client secret, so an SDK MUST NOT send
     * one here AND MUST NOT refuse to call this from a client constructed
     * without one. Note that this deliberately does not route through
     * form_add_client_auth(), which would attach a configured secret.
     */
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "scope", scope);

    char *url = oidc_endpoint_with_tenant(config.device_authorization_endpoint, tenant);
    axiam_http_response_t resp;
    /* §16.2 names `device_authorize` ineligible: it mints a device code, and a
     * silent retry would strand a first one the user might already be typing. */
    int rc = (url && !form.failed) ? oidc_post(client, url, "application/x-www-form-urlencoded",
                                               form.buf, 0, &resp)
                                   : -1;
    oidc_form_dispose(&form);
    axiam_oidc_config_dispose(&config);
    if (!url) {
        free(url);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    free(url);
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (resp.status < 200 || resp.status >= 300) {
        kind = oidc_map_grant_error(&resp, "device authorization failed", err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    axiam_http_response_dispose(&resp);
    const cJSON *device_code = root ? cJSON_GetObjectItemCaseSensitive(root, "device_code") : NULL;
    const cJSON *user_code = root ? cJSON_GetObjectItemCaseSensitive(root, "user_code") : NULL;
    const cJSON *uri = root ? cJSON_GetObjectItemCaseSensitive(root, "verification_uri") : NULL;
    if (!cJSON_IsString(device_code) || !cJSON_IsString(user_code) || !cJSON_IsString(uri)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "malformed DeviceAuthorizationResponse");
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *complete = cJSON_GetObjectItemCaseSensitive(root, "verification_uri_complete");
    const cJSON *expires = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
    const cJSON *interval = cJSON_GetObjectItemCaseSensitive(root, "interval");

    /* §14.5: the device code is a bearer credential for the life of the grant
     * and is wrapped; the user code is NOT, because it exists to be read aloud
     * and typed and wrapping it would defeat that. */
    out->device_code = axiam_sensitive_new(device_code->valuestring);
    out->user_code = axiam_strdup0(user_code->valuestring);
    out->verification_uri = axiam_strdup0(uri->valuestring);
    /* §14.3: surfaced when present, and NEVER synthesised by concatenation when
     * absent — its format is the server's to choose. */
    out->verification_uri_complete =
        (cJSON_IsString(complete) && complete->valuestring[0])
            ? axiam_strdup0(complete->valuestring) : NULL;
    out->expires_in = cJSON_IsNumber(expires) ? (long)expires->valuedouble : 0;
    /* §14.2 rule 2: from the RESPONSE, with RFC 8628 §3.2's 5 s as the only
     * fallback. No faster floor. */
    out->interval = cJSON_IsNumber(interval) ? (long)interval->valuedouble
                                             : AXIAM_DEVICE_DEFAULT_INTERVAL_S;
    if (out->interval <= 0) out->interval = AXIAM_DEVICE_DEFAULT_INTERVAL_S;
    cJSON_Delete(root);

    if (!out->device_code || !out->user_code || !out->verification_uri) {
        axiam_device_authorization_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* One poll, against an already-fetched document. */
static axiam_error_kind_t device_poll_with(axiam_client_t *client,
                                           const axiam_oidc_config_t *config,
                                           const char *device_code, const char *client_id,
                                           const char *tenant,
                                           axiam_oidc_token_set_t *out,
                                           axiam_error_t *err) {
    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", AXIAM_DEVICE_CODE_GRANT_TYPE);
    oidc_form_add(&form, "device_code", device_code);
    oidc_form_add(&form, "client_id", client_id);
    /* A device client is public by definition (see axiam_device_authorize), but
     * a confidential one driving the same grant must still authenticate — the
     * secret goes out only when one is configured. */
    oidc_form_add(&form, "client_secret", axiam_sensitive_reveal(client->cfg->oidc_client_secret));

    char *body = NULL;
    /*
     * retryable=1, and this is the ONE token-endpoint call §16.2 allows it for:
     * a 5xx or transport failure mid-poll is not terminal, because a server
     * restart must not lose a grant the user has already approved. That budget
     * is per poll ATTEMPT and does not consume the grant's own `expires_in`
     * loop below.
     */
    axiam_error_kind_t kind = oidc_token_grant(client, &form, config, tenant, 1,
                                               "device poll failed", &body, err);
    oidc_form_dispose(&form);
    if (kind == AXIAM_OK) {
        /* §12.4 rules 1-5 and 7 apply to any id_token; rule 6 is skipped —
         * there was no authorization request in this flow to carry a nonce. */
        kind = oidc_parse_token_set(client, body, config, NULL, out, err);
    }
    free(body);
    return kind;
}

axiam_error_kind_t axiam_device_poll(axiam_client_t *client,
                                     const axiam_sensitive_t *device_code,
                                     const char *tenant_id, axiam_oidc_token_set_t *out,
                                     axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *raw = axiam_sensitive_reveal(device_code);
    if (!raw || !raw[0]) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "device_poll requires a device code");
        return AXIAM_ERR_AUTH;
    }
    const char *client_id = oidc_require_client_id(client, "device_poll", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, tenant_id, "device_poll", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;
    kind = device_poll_with(client, &config, raw, client_id, tenant, out, err);
    axiam_oidc_config_dispose(&config);
    return kind;
}

axiam_error_kind_t axiam_device_login(axiam_client_t *client, const char *scope,
                                      const char *tenant_id,
                                      axiam_device_display_fn display, void *display_ctx,
                                      axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_device_authorization_t authorization;
    axiam_error_kind_t kind =
        axiam_device_authorize(client, scope, tenant_id, &authorization, err);
    if (kind != AXIAM_OK) return kind;

    /* §14.3 rule 2: the caller gets the codes BEFORE the first poll, always. An
     * SDK must not print them to stdout on the caller's behalf — a device shows
     * them however it can, and only the application knows how. */
    if (display) display(display_ctx, &authorization);

    const char *client_id = client->cfg->oidc_client_id;
    const char *tenant = oidc_require_tenant_uuid(client, tenant_id, "device_login", err);
    axiam_oidc_config_t config;
    if (!tenant || axiam_oidc_discover(client, &config, err) != AXIAM_OK) {
        axiam_device_authorization_dispose(&authorization);
        return tenant ? AXIAM_ERR_NETWORK : AXIAM_ERR_AUTH;
    }

    long interval = authorization.interval;
    time_t deadline = client->clock_fn(client->clock_ctx) + (time_t)authorization.expires_in;
    const char *device_code = axiam_sensitive_reveal(authorization.device_code);

    for (;;) {
        /*
         * §14.2 rule 4, and the subtlety that makes it worth a comment: it is
         * the NEXT ATTEMPT that must fall inside the deadline, not the current
         * moment. Checking `now < deadline` before sleeping looks equivalent
         * and is not — after a `slow_down` takes the interval past the time
         * remaining, that check passes, the loop sleeps through the deadline,
         * and polls anyway. That request is exactly the "pure load" this rule
         * exists to prevent.
         */
        if (client->clock_fn(client->clock_ctx) + (time_t)interval >= deadline) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "expired_token: the device grant expired before the "
                            "user approved it");
            if (err) snprintf(err->oauth_error, sizeof(err->oauth_error), "expired_token");
            kind = AXIAM_ERR_AUTH;
            break;
        }
        client->sleep_fn(client->sleep_ctx, interval * 1000L);

        axiam_error_t poll_err;
        axiam_error_reset(&poll_err);
        kind = device_poll_with(client, &config, device_code, client_id, tenant, out, &poll_err);
        if (kind == AXIAM_OK) break;

        const char *code = poll_err.oauth_error;
        if (!code[0]) {
            /* §14.2 rule 6: a 5xx or transport failure is not terminal — it has
             * already been through the §16 bounded retry inside the poll. */
            continue;
        }
        if (strcmp(code, "authorization_pending") == 0) continue;
        if (strcmp(code, "slow_down") == 0) {
            /* Rule 1: permanent, cumulative, never reset. */
            interval += AXIAM_DEVICE_SLOW_DOWN_INCREMENT_S;
            continue;
        }
        /* access_denied, expired_token, invalid_grant — and anything else the
         * server names. All terminal, each surfacing with its own code intact
         * (rule 3: the two refusals stay distinguishable). */
        if (err) *err = poll_err;
        break;
    }

    axiam_oidc_config_dispose(&config);
    axiam_device_authorization_dispose(&authorization);
    if (kind != AXIAM_OK) axiam_oidc_token_set_dispose(out);
    /* §14.3 rule 4: the token set is RETURNED, not adopted — the same posture
     * axiam_login_client_credentials() takes, which that rule requires an SDK to
     * match rather than inventing a second one. */
    return kind;
}
