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
 * Sets *status to a guard status on failure. */
static char *verify_and_claims(axiam_client_t *client, const axiam_headers_t *headers,
                               axiam_guard_status_t *status) {
    char *token = extract_token(headers);
    if (!token) { *status = AXIAM_GUARD_UNAUTHENTICATED; return NULL; }
    char *claims = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_jwt_verify(client, token, &claims, &err);
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

axiam_guard_status_t axiam_require_access(axiam_client_t *client,
                                          const axiam_headers_t *headers,
                                          const char *action, const char *resource_id,
                                          const char *scope) {
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
    return out;
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
