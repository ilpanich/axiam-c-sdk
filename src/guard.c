#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cJSON.h"
#include "internal.h"

/* Extract the bearer/cookie session token from request headers. Returns a
 * heap copy (caller frees) or NULL when absent. */
static char *extract_token(const axiam_headers_t *headers) {
    const char *auth = axiam_kv_get(headers, "Authorization");
    if (auth) {
        const char *p = auth;
        while (*p == ' ') p++;
        if (strncasecmp(p, "Bearer ", 7) == 0) {
            p += 7;
            while (*p == ' ') p++;
            if (*p) return axiam_strdup0(p);
        }
    }
    const char *cookie = axiam_kv_get(headers, "Cookie");
    if (cookie) {
        const char *needle = "axiam_access=";
        const char *pos = strstr(cookie, needle);
        if (pos) {
            pos += strlen(needle);
            const char *end = pos;
            while (*end && *end != ';' && *end != ' ') end++;
            if (end > pos) {
                size_t n = (size_t)(end - pos);
                char *tok = malloc(n + 1);
                if (tok) { memcpy(tok, pos, n); tok[n] = '\0'; return tok; }
            }
        }
    }
    return NULL;
}

/* Verify the request token and return its claims JSON (caller frees).
 * Sets *status to a guard status on failure.
 *
 * SEC-071 / CONTRACT §10.1: verification is AXIAM_JWT_VERIFY_STRICT — signature
 * AND lifetime (`exp`, plus `nbf` when present, with AXIAM_JWT_CLOCK_SKEW_SECS
 * of skew) AND the tenant binding AND the configured `iss`/`aud`. The JWKS
 * trust anchor is organization-wide, so without the tenant assertion a token
 * minted for a sibling tenant would be admitted; without the expiry check an
 * expired token would be admitted forever. Every one fails closed (401). */
static char *verify_and_claims(axiam_client_t *client, const axiam_headers_t *headers,
                               axiam_guard_status_t *status) {
    char *token = extract_token(headers);
    if (!token) { *status = AXIAM_GUARD_UNAUTHENTICATED; return NULL; }
    char *claims = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify_ex(client, token, AXIAM_JWT_VERIFY_STRICT,
                                               &claims, &err);
    free(token);
    if (k == AXIAM_OK) { *status = AXIAM_GUARD_ALLOW; return claims; }
    /* §11.2: transport failure fetching JWKS fails CLOSED (503). */
    *status = (k == AXIAM_ERR_NETWORK) ? AXIAM_GUARD_UNAVAILABLE
                                       : AXIAM_GUARD_UNAUTHENTICATED;
    return NULL;
}

axiam_guard_status_t axiam_require_auth(axiam_client_t *client,
                                        const axiam_headers_t *headers) {
    if (!client) return AXIAM_GUARD_UNAVAILABLE;
    axiam_guard_status_t st;
    char *claims = verify_and_claims(client, headers, &st);
    free(claims);
    return st; /* ALLOW / UNAUTHENTICATED / UNAVAILABLE */
}

/*
 * Mints one ticket for the pair that was just refused and formats the challenge,
 * or returns NULL when that fails.
 *
 * The requested scope is the AXIAM *action* (§20.2): asking for anything else
 * would offer the caller authority other than the one they were denied, and
 * would step outside the grants the engine just evaluated — deny rules included.
 *
 * Every failure returns NULL deliberately. A PAT that expired, a Protection API
 * that is down, a resource that declares none of the requested scopes — none of
 * these change the answer to the request, which was already "no". Letting them
 * turn a deny into a 503 would give the outage a second consequence; letting
 * them turn it into an allow would be a security bug.
 */
static char *mint_challenge(axiam_client_t *client,
                            const axiam_uma_challenger_t *challenger,
                            const char *action, const char *resource_id) {
    if (!challenger || !challenger->realm || !challenger->as_uri || !challenger->pat) {
        return NULL;
    }

    const char *scopes[1];
    scopes[0] = action;
    axiam_uma_permission_t permission;
    permission.resource_id = resource_id;
    permission.scopes = scopes;
    permission.scope_count = 1;

    axiam_sensitive_t *ticket = NULL;
    axiam_error_t err;
    if (axiam_uma_request_ticket(client, challenger->pat, &permission, 1, &ticket, &err)
            != AXIAM_OK || !ticket) {
        return NULL;
    }

    char *header = axiam_uma_challenge_header(challenger->realm, challenger->as_uri, ticket);
    axiam_sensitive_free(ticket);
    return header;
}

/*
 * The whole of require_access, with the §20.3 challenge as an optional extra on
 * the deny path. axiam_require_access() is this with no challenger; the public
 * axiam_require_access_uma() is this with one. One body, so the two entry points
 * cannot drift on the outcome mapping.
 */
static axiam_guard_status_t require_access_impl(axiam_client_t *client,
                                                const axiam_headers_t *headers,
                                                const char *action, const char *resource_id,
                                                const char *scope,
                                                const axiam_uma_challenger_t *challenger,
                                                char **out_challenge) {
    if (!client) return AXIAM_GUARD_UNAVAILABLE;
    /* §11.2(3): unresolvable/empty resource id is a 400, never a silent allow. */
    if (!resource_id || resource_id[0] == '\0') return AXIAM_GUARD_BAD_REQUEST;

    axiam_guard_status_t st;
    char *claims = verify_and_claims(client, headers, &st);
    if (!claims) return st; /* 401 or 503 */

    /* §11.2(2): subject propagation — check on behalf of the authenticated user. */
    char *subject = NULL;
    cJSON *root = cJSON_Parse(claims);
    if (root) {
        const cJSON *sub = cJSON_GetObjectItemCaseSensitive(root, "sub");
        if (cJSON_IsString(sub) && sub->valuestring) subject = axiam_strdup0(sub->valuestring);
        cJSON_Delete(root);
    }
    free(claims);

    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(client, action, resource_id, scope,
                                              subject, &res, &err);
    free(subject);

    axiam_guard_status_t out;
    if (k == AXIAM_OK) {
        out = res.allowed ? AXIAM_GUARD_ALLOW : AXIAM_GUARD_DENIED;
    } else if (k == AXIAM_ERR_AUTHZ) {
        out = AXIAM_GUARD_DENIED;
    } else if (k == AXIAM_ERR_AUTH) {
        out = AXIAM_GUARD_UNAUTHENTICATED;
    } else {
        out = AXIAM_GUARD_UNAVAILABLE; /* §11.2(5): fail closed on network error */
    }
    axiam_check_result_dispose(&res);

    if (out == AXIAM_GUARD_DENIED && challenger && out_challenge) {
        *out_challenge = mint_challenge(client, challenger, action, resource_id);
    }
    return out;
}

axiam_guard_status_t axiam_require_access(axiam_client_t *client,
                                          const axiam_headers_t *headers,
                                          const char *action, const char *resource_id,
                                          const char *scope) {
    return require_access_impl(client, headers, action, resource_id, scope, NULL, NULL);
}

axiam_guard_status_t axiam_require_access_uma(axiam_client_t *client,
                                              const axiam_headers_t *headers,
                                              const char *action, const char *resource_id,
                                              const char *scope,
                                              const axiam_uma_challenger_t *challenger,
                                              char **out_challenge) {
    if (out_challenge) *out_challenge = NULL;
    return require_access_impl(client, headers, action, resource_id, scope,
                               challenger, out_challenge);
}

axiam_guard_status_t axiam_require_role(axiam_client_t *client,
                                        const axiam_headers_t *headers,
                                        const char *const *roles, size_t n_roles) {
    if (!client) return AXIAM_GUARD_UNAVAILABLE;
    axiam_guard_status_t st;
    char *claims = verify_and_claims(client, headers, &st);
    if (!claims) return st;

    int matched = 0;
    cJSON *root = cJSON_Parse(claims);
    if (root) {
        const cJSON *jr = cJSON_GetObjectItemCaseSensitive(root, "roles");
        if (cJSON_IsArray(jr)) {
            const cJSON *item = NULL;
            cJSON_ArrayForEach(item, jr) {
                if (!cJSON_IsString(item) || !item->valuestring) continue;
                for (size_t i = 0; i < n_roles && !matched; i++) {
                    if (roles[i] && strcmp(roles[i], item->valuestring) == 0) matched = 1;
                }
                if (matched) break;
            }
        }
        cJSON_Delete(root);
    }
    free(claims);
    return matched ? AXIAM_GUARD_ALLOW : AXIAM_GUARD_DENIED;
}
