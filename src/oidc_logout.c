/*
 * AXIAM C SDK — OIDC RP-Initiated Logout 1.0 and Back-Channel Logout 1.0
 * (CONTRACT.md §12.7).
 *
 * Two operations on opposite sides of the flow. One builds a URL for the
 * browser and carries no security weight of its own. The other verifies
 * something the SERVER pushed to this relying party — input that arrives
 * unsolicited, from the network, and instructs the RP to terminate a session.
 * Every check in axiam_verify_logout_token() exists because skipping it has a
 * name, and the two that are easiest to skip are the two that matter most: the
 * `events` key is what distinguishes a logout token from an ID token, and a
 * present `nonce` is the documented signature of an ID token being replayed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "oidc_internal.h"

/* ------------------------------------------------------------------ */
/* §12.7.2 logout_url                                                 */
/* ------------------------------------------------------------------ */

/* Percent-encode into a growing buffer, using the shared form encoder so the
 * query parameters here and the ones in oidc_begin() cannot drift apart. */
char *axiam_logout_url(const axiam_oidc_config_t *config, const char *id_token,
                       const char *post_logout_redirect_uri, const char *state) {
    /* §12.7.2 rule 1: the endpoint comes from DISCOVERY. Building
     * "{issuer}/oauth2/end_session" happens to work against AXIAM and breaks
     * against every other OP the same code is pointed at, which is the whole
     * reason discovery exists. A server that advertises none gets NULL rather
     * than a guess. */
    if (!config || !config->end_session_endpoint || !config->end_session_endpoint[0]) return NULL;
    /* §12.7.1: there is no hint-less mode. `id_token_hint` is the only parameter
     * on the wire that names the user, and an SDK that invented a `sub`-based
     * alternative would be encouraging exactly the request the server refuses
     * to act on. */
    if (!id_token || !id_token[0]) return NULL;

    oidc_form_t q;
    oidc_form_init(&q);
    oidc_form_add(&q, "id_token_hint", id_token);
    /* §12.7.2 rule 3: NOT pre-validated against a local list. The allow-list
     * lives in the client's server-side registration; a client-side copy would
     * drift and would reject a URI an operator had just registered. */
    oidc_form_add(&q, "post_logout_redirect_uri", post_logout_redirect_uri);
    /* §12.7.2 rule 2: passed through unmodified, and never invented — the value
     * only means something to the application that will receive it back. */
    oidc_form_add(&q, "state", state);

    char *url = NULL;
    if (!q.failed) {
        size_t n = strlen(config->end_session_endpoint) + q.len + 2;
        url = malloc(n);
        if (url) {
            snprintf(url, n, "%s%c%s", config->end_session_endpoint,
                     strchr(config->end_session_endpoint, '?') ? '&' : '?', q.buf);
        }
    }
    /* oidc_form_dispose scrubs; the ID token was in there. */
    oidc_form_dispose(&q);
    return url;
}

/* ------------------------------------------------------------------ */
/* §12.7.3 verify_logout_token                                        */
/* ------------------------------------------------------------------ */

/* Every failure message here names the RULE, never the token (§12.7.3 rule 8). */
static axiam_error_kind_t logout_fail(axiam_error_t *err, const char *message) {
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, message);
    return AXIAM_ERR_AUTH;
}

/* §12.7.3 rule 2's audience check. `aud` may be a string or an array. */
static int aud_names(const cJSON *aud, const char *client_id) {
    if (cJSON_IsString(aud) && aud->valuestring)
        return strcmp(aud->valuestring, client_id) == 0;
    if (cJSON_IsArray(aud)) {
        const cJSON *e = NULL;
        cJSON_ArrayForEach(e, aud) {
            if (cJSON_IsString(e) && e->valuestring && strcmp(e->valuestring, client_id) == 0)
                return 1;
        }
    }
    return 0;
}

axiam_error_kind_t axiam_verify_logout_token(axiam_client_t *client, const char *logout_token,
                                             axiam_verified_logout_token_t *out,
                                             axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;
    if (!logout_token || !logout_token[0]) {
        return logout_fail(err, "verify_logout_token requires a token");
    }
    const char *client_id = oidc_require_client_id(client, "verify_logout_token", err);
    if (!client_id) return AXIAM_ERR_AUTH;

    /* Rule 1: the signature goes through the SAME §12.4 verifier the RP already
     * uses. There is no second key-fetching path, so key rotation, the EdDSA
     * pin and the unknown-`kid` cooldown all behave identically here. */
    char *payload = NULL;
    char reason[32] = {0};
    axiam_error_kind_t kind =
        axiam_jwt_verify_reasoned(client, logout_token, &payload, reason, sizeof(reason), err);
    if (kind != AXIAM_OK) {
        if (err && reason[0]) snprintf(err->id_token_reason, sizeof(err->id_token_reason), "%s", reason);
        free(payload);
        return kind;
    }

    /* The issuer comes from discovery, as it does for an ID token — the RP has
     * exactly one OP and the document is what names it. */
    axiam_oidc_config_t config;
    kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) { free(payload); return kind; }

    cJSON *root = cJSON_Parse(payload);
    free(payload);
    if (!root) {
        axiam_oidc_config_dispose(&config);
        return logout_fail(err, "logout token payload is not a JSON object");
    }

    const cJSON *iss = cJSON_GetObjectItemCaseSensitive(root, "iss");
    int iss_ok = cJSON_IsString(iss) && iss->valuestring && config.issuer &&
                 strcmp(iss->valuestring, config.issuer) == 0;
    axiam_oidc_config_dispose(&config);
    if (!iss_ok) {
        cJSON_Delete(root);
        return logout_fail(err, "logout token iss does not match the discovered issuer");
    }
    if (!aud_names(cJSON_GetObjectItemCaseSensitive(root, "aud"), client_id)) {
        cJSON_Delete(root);
        /* A token minted for another RP must not be accepted here. */
        return logout_fail(err, "logout token aud does not name this client");
    }

    /* Rule 3. Without this an SDK accepts a replayed ID token as a logout
     * instruction: an ID token has every other property this function checks. */
    const cJSON *events = cJSON_GetObjectItemCaseSensitive(root, "events");
    const cJSON *event = cJSON_IsObject(events)
                             ? cJSON_GetObjectItemCaseSensitive(events, AXIAM_LOGOUT_EVENT_KEY)
                             : NULL;
    if (!cJSON_IsObject(event)) {
        cJSON_Delete(root);
        return logout_fail(err,
                           "logout token has no backchannel-logout events member "
                           "(§12.7.3 rule 3)");
    }

    /* Rule 4. REJECT, do not ignore — Back-Channel Logout 1.0 §2.4 forbids a
     * nonce, and its presence is the documented signature of the replay above. */
    if (cJSON_GetObjectItemCaseSensitive(root, "nonce")) {
        cJSON_Delete(root);
        return logout_fail(err,
                           "logout token carries a nonce, which Back-Channel Logout "
                           "1.0 §2.4 forbids (§12.7.3 rule 4)");
    }

    /* Rule 6. AXIAM issues a 120 s lifetime; the same §13-style tolerance the
     * ID-token path uses applies. */
    const cJSON *exp = cJSON_GetObjectItemCaseSensitive(root, "exp");
    long skew = (client->cfg->oidc_clock_skew_s < 0) ? AXIAM_OIDC_MAX_CLOCK_SKEW_S
                                                     : client->cfg->oidc_clock_skew_s;
    if (!cJSON_IsNumber(exp) || (long long)time(NULL) > (long long)exp->valuedouble + skew) {
        cJSON_Delete(root);
        return logout_fail(err, "logout token has expired or carries no usable exp");
    }

    const cJSON *sid = cJSON_GetObjectItemCaseSensitive(root, "sid");
    const cJSON *sub = cJSON_GetObjectItemCaseSensitive(root, "sub");
    int have_sid = cJSON_IsString(sid) && sid->valuestring[0];
    int have_sub = cJSON_IsString(sub) && sub->valuestring[0];
    if (!have_sid && !have_sub) {
        cJSON_Delete(root);
        /* Rule 5: a token naming neither identifies nothing. */
        return logout_fail(err, "logout token names neither sid nor sub");
    }

    const cJSON *jti = cJSON_GetObjectItemCaseSensitive(root, "jti");
    const cJSON *iat = cJSON_GetObjectItemCaseSensitive(root, "iat");
    out->sid = have_sid ? axiam_strdup0(sid->valuestring) : NULL;
    out->subject = have_sub ? axiam_strdup0(sub->valuestring) : NULL;
    /* Rule 7: surfaced so the RP can dedup. This SDK deliberately does NOT dedup
     * internally — delivery is at-least-once, so a valid token legitimately
     * arrives twice, and a library with no durable store would silently drop a
     * real second logout after a restart. Verifying the same token twice
     * therefore succeeds both times, on purpose. */
    out->jwt_id = (cJSON_IsString(jti) && jti->valuestring[0])
                      ? axiam_strdup0(jti->valuestring) : NULL;
    out->issuer = axiam_strdup0(iss->valuestring);
    out->issued_at = cJSON_IsNumber(iat) ? (long long)iat->valuedouble : 0;
    cJSON_Delete(root);

    if (!out->issuer || (have_sid && !out->sid) || (have_sub && !out->subject)) {
        axiam_verified_logout_token_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}
