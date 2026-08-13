/*
 * AXIAM C SDK — RFC 8693 token exchange (CONTRACT.md §15).
 *
 * A backend holding a user's access token trades it for a NARROWER one before
 * calling the next service.
 *
 * The rule this file must not paper over: an exchange only ever narrows. The
 * server enforces that; this SDK's job is to not hide the refusals, because
 * every one of them is the server telling the caller their assumption about
 * their own privileges was wrong. So: no retry on `unauthorized_client`, no
 * auto-narrowing on `invalid_scope`, no refresh token, no adoption, and no
 * attempt to tell "wrong tenant" from "bad token" behind the server's back.
 */

#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "oidc_internal.h"

axiam_error_kind_t axiam_token_exchange(axiam_client_t *client,
                                        const axiam_token_exchange_params_t *params,
                                        axiam_exchanged_token_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !params) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *subject = axiam_sensitive_reveal(params->subject_token);
    if (!subject || !subject[0]) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "token_exchange requires a subject_token");
        return AXIAM_ERR_AUTH;
    }
    /*
     * §15.1: subject_token_type is required and has no default. C cannot demand
     * a struct member at compile time, so the demand lands here — client-side,
     * with no wire call, rather than sending …:access_token on the caller's
     * behalf and letting the server refuse a token they never described.
     */
    if (!params->subject_token_type || !params->subject_token_type[0]) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "token_exchange requires subject_token_type: pass "
                        "AXIAM_TOKEN_TYPE_ACCESS_TOKEN for an AXIAM access token, "
                        "or AXIAM_TOKEN_TYPE_JWT for a trusted external issuer's JWT");
        return AXIAM_ERR_AUTH;
    }
    const char *client_id = oidc_require_client_id(client, "token_exchange", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    /* §15.1: the exchanging client authenticates — unlike §14's device, this is
     * a confidential service. */
    const char *secret = oidc_require_client_secret(client, "token_exchange", err);
    if (!secret) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, params->tenant_id, "token_exchange", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;

    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", AXIAM_TOKEN_EXCHANGE_GRANT_TYPE);
    oidc_form_add(&form, "subject_token", subject);
    /*
     * Whatever the caller named, verbatim. The subject token is NEVER decoded to
     * pick this (§15.7): which kind of token the caller holds is the caller's to
     * know, and a guess here is the difference between a request that is refused
     * and one that is silently reinterpreted.
     */
    oidc_form_add(&form, "subject_token_type", params->subject_token_type);
    /*
     * §15.2 rule 1. The presence of an actor token selects DELEGATION; its
     * absence selects IMPERSONATION. Two different operations with different
     * risk, and this SDK supplies no default and never substitutes the client's
     * own session — passing nothing here asks for impersonation, and the server
     * refuses unless this client holds that grant.
     */
    const char *actor = axiam_sensitive_reveal(params->actor_token);
    if (actor && actor[0]) {
        oidc_form_add(&form, "actor_token", actor);
        oidc_form_add(&form, "actor_token_type", AXIAM_TOKEN_TYPE_ACCESS_TOKEN);
    }
    if (params->scopes && params->scope_count > 0) {
        size_t need = 1;
        for (size_t i = 0; i < params->scope_count; i++) {
            if (params->scopes[i]) need += strlen(params->scopes[i]) + 1;
        }
        char *joined = malloc(need);
        if (joined) {
            joined[0] = '\0';
            for (size_t i = 0; i < params->scope_count; i++) {
                if (!params->scopes[i]) continue;
                if (joined[0]) strcat(joined, " ");
                strcat(joined, params->scopes[i]);
            }
            oidc_form_add(&form, "scope", joined);
            free(joined);
        } else {
            form.failed = 1;
        }
    }
    oidc_form_add(&form, "audience", params->audience);
    oidc_form_add(&form, "resource", params->resource);
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "client_secret", secret);

    char *body = NULL;
    /* retryable=0: §16.2 names `token_exchange` ineligible outright. Combined
     * with §15.2 rule 2 that means a refusal is surfaced verbatim — no retry, no
     * downgrade, no rewriting the request into a delegation the caller never
     * wrote. */
    kind = oidc_token_grant(client, &form, &config, tenant, 0, "token exchange failed",
                            &body, err);
    oidc_form_dispose(&form);
    axiam_oidc_config_dispose(&config);
    if (kind != AXIAM_OK) {
        free(body);
        /* The `error` code — `unauthorized_client`, `invalid_scope`,
         * `invalid_grant`, `invalid_target`, … — is already in
         * err->oauth_error, verbatim. §15.3: a cross-tenant subject token
         * answers `invalid_grant` and this SDK does not try to refine it; the
         * server collapses "wrong tenant" into "bad token" because telling them
         * apart is a tenant-enumeration signal. */
        return kind;
    }

    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    const cJSON *access = root ? cJSON_GetObjectItemCaseSensitive(root, "access_token") : NULL;
    if (!cJSON_IsString(access) || !access->valuestring[0]) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "token exchange: malformed TokenExchangeResponse");
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *issued = cJSON_GetObjectItemCaseSensitive(root, "issued_token_type");
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "token_type");
    const cJSON *expires = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
    const cJSON *scope = cJSON_GetObjectItemCaseSensitive(root, "scope");

    out->access_token = axiam_sensitive_new(access->valuestring);
    /* §15.2 rule 6: surfaced, never dropped. */
    out->issued_token_type = axiam_strdup0(cJSON_IsString(issued) ? issued->valuestring
                                                                  : AXIAM_TOKEN_TYPE_ACCESS_TOKEN);
    out->token_type = axiam_strdup0(cJSON_IsString(type) ? type->valuestring : "Bearer");
    out->expires_in = cJSON_IsNumber(expires) ? (long)expires->valuedouble : 0;
    /* §15.2 rule 7: the GRANTED set, which may be narrower than the requested
     * one even on success. */
    out->scope = (cJSON_IsString(scope) && scope->valuestring[0])
                     ? axiam_strdup0(scope->valuestring) : NULL;
    /* §15.2 rule 4: any refresh_token the server sent is ignored — there is no
     * member for it, this result never enters the §9 guard, and re-running the
     * exchange is how a caller gets a fresh token. */
    cJSON_Delete(root);

    if (!out->access_token || !out->issued_token_type || !out->token_type) {
        axiam_exchanged_token_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    /* §15.2 rule 5: NOT adopted. This is a MUST NOT where adoption elsewhere is
     * a MAY — the exchanged token is one to hand onward in a single outbound
     * call, and adopting it would silently re-privilege every subsequent call
     * this client makes. Nothing above touches client state. */
    return AXIAM_OK;
}
