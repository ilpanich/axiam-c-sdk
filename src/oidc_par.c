/*
 * AXIAM C SDK — Pushed Authorization Requests, RFC 9126 (CONTRACT.md §26).
 *
 * PAR moves the authorization request off the browser. Instead of putting
 * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
 * agent carries, the client POSTs them straight to AXIAM over an authenticated
 * channel and puts an opaque `request_uri` in the redirect. What travels
 * through the browser is then a random string that cannot be edited into
 * meaning something else.
 *
 * THE ONE THING AN IMPLEMENTATION OF THIS SECTION GETS WRONG. The server
 * answers 201, not 200 — RFC 9126 §2.2 specifies Created. A success predicate
 * written `== 200` treats every successful push as a failure while passing
 * every other assertion, which is why the check here is on the 2xx range.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "axiam/oidc.h"
#include "oidc_internal.h"

#define FORM_CONTENT_TYPE "application/x-www-form-urlencoded"

/* §12.1 rule 4, applied to the push exactly as oidc_begin applies it: the scope
 * MUST contain `openid`, whole-token matched so "openid_extra" does not
 * accidentally satisfy the rule. */
static char *normalize_scope(const char *scope) {
    const char *requested = (scope && scope[0]) ? scope : "";
    int has_openid = 0;
    for (const char *p = requested; *p;) {
        const char *sp = strchr(p, ' ');
        size_t n = sp ? (size_t)(sp - p) : strlen(p);
        if (n == 6 && strncmp(p, "openid", 6) == 0) { has_openid = 1; break; }
        p = sp ? sp + 1 : p + n;
    }
    size_t need = strlen(requested) + 8;
    char *out = malloc(need);
    if (!out) return NULL;
    if (has_openid) snprintf(out, need, "%s", requested);
    else if (requested[0]) snprintf(out, need, "openid %s", requested);
    else snprintf(out, need, "openid");
    return out;
}

/**
 * §26.2 rule 2: the redirect URL carries EXACTLY `client_id` and `request_uri`.
 *
 * The server REFUSES a request carrying both a request_uri and any inline
 * authorization parameter rather than merging them: an attacker supplies the
 * inline value they want and lets the pushed copy satisfy whichever check reads
 * the other one. Re-adding them "for compatibility" restores the attack — which
 * is why any query the discovered endpoint already carried is DROPPED here
 * rather than merged.
 */
static char *build_redirect_url(const char *authorization_endpoint, const char *client_id,
                                const char *request_uri) {
    size_t base_len = strlen(authorization_endpoint);
    const char *q = strchr(authorization_endpoint, '?');
    if (q) base_len = (size_t)(q - authorization_endpoint);

    char *encoded_client = axiam_url_encode(client_id);
    char *encoded_uri = axiam_url_encode(request_uri);
    if (!encoded_client || !encoded_uri) {
        free(encoded_client);
        free(encoded_uri);
        return NULL;
    }

    size_t need = base_len + strlen("?client_id=&request_uri=") + strlen(encoded_client) +
                  strlen(encoded_uri) + 1;
    char *url = malloc(need);
    if (url) {
        snprintf(url, need, "%.*s?client_id=%s&request_uri=%s", (int)base_len,
                 authorization_endpoint, encoded_client, encoded_uri);
    }
    free(encoded_client);
    free(encoded_uri);
    return url;
}

axiam_error_kind_t axiam_oidc_par(axiam_client_t *client,
                                  const axiam_oidc_config_t *config,
                                  const axiam_authorization_request_t *request,
                                  const char *redirect_uri, const char *scope,
                                  const char *tenant_id,
                                  axiam_pushed_authorization_request_t *out,
                                  axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !config || !request || !redirect_uri || !redirect_uri[0] || !out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "oidc_par requires a discovery document, an authorization request "
                        "and a redirect_uri");
        return AXIAM_ERR_NETWORK;
    }
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    if (!config->pushed_authorization_request_endpoint ||
        !config->pushed_authorization_request_endpoint[0]) {
        /* §12.7.2 rule 1's discipline: never synthesise the URL from the issuer.
         * Client-side, with no wire call. */
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the authorization server's discovery document advertises no "
                        "pushed_authorization_request_endpoint: this server does not support "
                        "RFC 9126 (CONTRACT.md §26.1)");
        return AXIAM_ERR_AUTH;
    }

    const char *client_id = oidc_require_client_id(client, "oidc_par", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *tenant_uuid = oidc_require_tenant_uuid(client, tenant_id, "oidc_par", err);
    if (!tenant_uuid) return AXIAM_ERR_AUTH;

    char *scopes = normalize_scope(scope);
    const char *verifier = request->code_verifier
                               ? axiam_sensitive_reveal(request->code_verifier)
                               : NULL;
    char *challenge = verifier ? oidc_s256_challenge(verifier) : NULL;
    if (!scopes || !challenge) {
        free(scopes);
        free(challenge);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "oidc_par: the authorization request carries no code_verifier");
        return AXIAM_ERR_NETWORK;
    }

    /* §26.2 rule 1: everything below was computed by oidc_begin. There is no
     * second generator here, and there must not be — two sources for state or
     * the PKCE pair are two things that can disagree. */
    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "response_type", "code");
    oidc_form_add(&form, "redirect_uri", redirect_uri);
    oidc_form_add(&form, "scope", scopes);
    oidc_form_add(&form, "state", request->state);
    oidc_form_add(&form, "nonce", request->nonce);
    oidc_form_add(&form, "code_challenge", challenge);
    oidc_form_add(&form, "code_challenge_method", "S256");
    if (client->cfg->oidc_client_secret) {
        oidc_form_add(&form, "client_secret",
                      axiam_sensitive_reveal(client->cfg->oidc_client_secret));
    }
    free(scopes);
    free(challenge);

    char *url = oidc_endpoint_with_tenant(config->pushed_authorization_request_endpoint,
                                          tenant_uuid);
    if (!url || form.failed) {
        oidc_form_dispose(&form);
        free(url);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    /* retryable = 0: §26.2 rule 4. A POST that creates server state falls
     * outside §16.2's read-only eligibility, and the safe recovery is a fresh
     * push — which costs one round trip and cannot double-consume anything. */
    int rc = oidc_post(client, url, FORM_CONTENT_TYPE, form.buf, 0, &resp);
    oidc_form_dispose(&form);
    free(url);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    /* The 2xx range, not `== 200`: RFC 9126 §2.2 answers 201. */
    if (resp.status < 200 || resp.status >= 300) {
        axiam_error_kind_t kind =
            oidc_map_grant_error(&resp, "pushed authorization request failed", err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    const cJSON *request_uri = root
        ? cJSON_GetObjectItemCaseSensitive(root, "request_uri") : NULL;
    if (!cJSON_IsString(request_uri) || !request_uri->valuestring ||
        !request_uri->valuestring[0]) {
        if (root) cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status,
                        "pushed authorization response carried no request_uri");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *expires = cJSON_GetObjectItemCaseSensitive(root, "expires_in");

    out->url = build_redirect_url(config->authorization_endpoint, client_id,
                                  request_uri->valuestring);
    out->request_uri = axiam_sensitive_new(request_uri->valuestring);
    out->expires_in = cJSON_IsNumber(expires) ? (long)expires->valuedouble : 0L;
    out->state = axiam_strdup0(request->state);
    out->nonce = axiam_strdup0(request->nonce);
    out->code_verifier = axiam_sensitive_new(verifier);

    cJSON_Delete(root);
    axiam_http_response_dispose(&resp);

    if (!out->url || !out->request_uri || !out->code_verifier) {
        axiam_pushed_authorization_request_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}
