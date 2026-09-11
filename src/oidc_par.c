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
 * §26.2 rule 2: the redirect URL carries EXACTLY `client_id`, `request_uri` and
 * — when the server put one there — the tenant.
 *
 * The server REFUSES a request carrying both a request_uri and any inline
 * AUTHORIZATION parameter rather than merging them: an attacker supplies the
 * inline value they want and lets the pushed copy satisfy whichever check reads
 * the other one. Re-adding `scope`, `redirect_uri`, `state` or the PKCE
 * challenge "for compatibility" restores that attack, which is why the
 * discovered endpoint's query is dropped rather than merged.
 *
 * `tenant_id` IS NOT ONE OF THEM, and dropping it was a bug (contract 1.42).
 * It is not an authorization parameter — it does not appear in
 * `PushedAuthorizationRequest`, it was never pushed, and so there is no pushed
 * copy for an inline value to disagree with. It is routing: it selects which
 * tenant's `/oauth2/authorize` is being addressed. AXIAM's discovery document
 * publishes it inside `authorization_endpoint` whenever the discovery request
 * named a tenant or the deployment sets `oauth2_default_tenant_id`, and a
 * browser arriving without it has no session to match, so the server answers
 * 401 rather than rendering the login page.
 *
 * `tenant_uuid` — the tenant this push was actually made against — is what goes
 * on, not the string the endpoint carried. The `request_uri` is only valid for
 * the tenant that minted it, so those two must not be allowed to differ. When
 * the endpoint named no tenant, neither does the redirect: this builder does
 * not invent routing the server did not publish.
 */
static char *build_redirect_url(const char *authorization_endpoint, const char *client_id,
                                const char *request_uri, const char *tenant_uuid) {
    size_t base_len = strlen(authorization_endpoint);
    const char *q = strchr(authorization_endpoint, '?');
    if (q) base_len = (size_t)(q - authorization_endpoint);

    const char *tenant = oidc_endpoint_names_tenant(authorization_endpoint) ? tenant_uuid : NULL;

    char *encoded_client = axiam_url_encode(client_id);
    char *encoded_uri = axiam_url_encode(request_uri);
    char *encoded_tenant = tenant ? axiam_url_encode(tenant) : NULL;
    if (!encoded_client || !encoded_uri || (tenant && !encoded_tenant)) {
        free(encoded_client);
        free(encoded_uri);
        free(encoded_tenant);
        return NULL;
    }

    size_t need = base_len + strlen("?client_id=&request_uri=&tenant_id=") +
                  strlen(encoded_client) + strlen(encoded_uri) +
                  (encoded_tenant ? strlen(encoded_tenant) : 0) + 1;
    char *url = malloc(need);
    if (url) {
        int n = snprintf(url, need, "%.*s?client_id=%s&request_uri=%s", (int)base_len,
                         authorization_endpoint, encoded_client, encoded_uri);
        if (encoded_tenant) {
            snprintf(url + n, need - (size_t)n, "&tenant_id=%s", encoded_tenant);
        }
    }
    free(encoded_client);
    free(encoded_uri);
    free(encoded_tenant);
    return url;
}

axiam_error_kind_t axiam_oidc_par(axiam_client_t *client,
                                  const axiam_oidc_config_t *config,
                                  const axiam_authorization_request_t *request,
                                  const char *redirect_uri, const char *scope,
                                  const char *tenant_id,
                                  axiam_pushed_authorization_request_t *out,
                                  axiam_error_t *err) {
    return axiam_oidc_par_ex(client, config, request, redirect_uri, scope, tenant_id, NULL, out,
                             err);
}

axiam_error_kind_t axiam_oidc_par_ex(axiam_client_t *client,
                                     const axiam_oidc_config_t *config,
                                     const axiam_authorization_request_t *request,
                                     const char *redirect_uri, const char *scope,
                                     const char *tenant_id, const char *dpop_jkt,
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

    /* §21.3 rule 2: prefer the mTLS alias when this call presents a client
     * certificate. Absent at BOTH levels still means "unsupported" — never a
     * cue to build <issuer>/oauth2/par by concatenation (§26.1). */
    const char *par_endpoint = oidc_preferred_endpoint(
        client, config, config->mtls_endpoint_aliases.pushed_authorization_request_endpoint,
        config->pushed_authorization_request_endpoint);
    if (!par_endpoint || !par_endpoint[0]) {
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
    /* RFC 9449 §10.1 (contract 1.42): bind the eventual authorization code to a
     * DPoP key at push time, so the code cannot be redeemed by a client holding
     * a different one.
     *
     * CALLER-SUPPLIED, and only that. §21.9 records this SDK as declining
     * §21.7.2: it neither generates DPoP proofs nor verifies them, so the
     * thumbprint is computed by whatever does hold the key and is passed
     * through verbatim. Emitted only when set — an empty `dpop_jkt` on the wire
     * is not the same as no `dpop_jkt`, and the server would have to decide
     * which one it meant. */
    if (dpop_jkt && dpop_jkt[0]) oidc_form_add(&form, "dpop_jkt", dpop_jkt);
    if (client->cfg->oidc_client_secret) {
        oidc_form_add(&form, "client_secret",
                      axiam_sensitive_reveal(client->cfg->oidc_client_secret));
    }
    free(scopes);
    free(challenge);

    char *url = oidc_endpoint_with_tenant(par_endpoint,
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
                                  request_uri->valuestring, tenant_uuid);
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
