/*
 * AXIAM C SDK — UMA 2.0 Protection API and ticket grant (CONTRACT.md §20).
 *
 * See include/axiam/uma.h for the design notes. The one rule worth repeating
 * where the code lives: axiam_uma_exchange_ticket() issues EXACTLY ONE request,
 * on every outcome. It does not enter the §16 retry loop, and it must not be
 * made to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "axiam/uma.h"
#include "internal.h"

/* The discovery document is an endpoint map, not a credential; §12.3 rule 6's
 * five-minute floor for the OIDC document is the right cadence for it too. */
#define AXIAM_UMA_CONFIG_TTL_SECONDS 300

/* ------------------------------------------------------------------ */
/* Disposal                                                           */
/* ------------------------------------------------------------------ */

void axiam_uma_string_array_free(char **items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

void axiam_uma_config_dispose(axiam_uma_config_t *cfg) {
    if (!cfg) return;
    free(cfg->issuer);
    free(cfg->token_endpoint);
    free(cfg->permission_endpoint);
    free(cfg->resource_registration_endpoint);
    memset(cfg, 0, sizeof(*cfg));
    cfg->permission_ticket_lifetime = -1;
}

void axiam_uma_resource_set_dispose(axiam_uma_resource_set_t *rs) {
    if (!rs) return;
    free(rs->id);
    free(rs->name);
    free(rs->type);
    axiam_uma_string_array_free(rs->scopes, rs->scope_count);
    memset(rs, 0, sizeof(*rs));
}

void axiam_uma_rpt_dispose(axiam_uma_rpt_t *rpt) {
    if (!rpt) return;
    axiam_sensitive_free(rpt->access_token);
    free(rpt->token_type);
    memset(rpt, 0, sizeof(*rpt));
}

void axiam_uma_challenge_dispose(axiam_uma_challenge_t *ch) {
    if (!ch) return;
    free(ch->realm);
    free(ch->as_uri);
    axiam_sensitive_free(ch->ticket);
    memset(ch, 0, sizeof(*ch));
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                     */
/* ------------------------------------------------------------------ */

/* The raw bytes of a Sensitive as a NUL-terminated string, or NULL when the
 * handle is absent or empty. Never logged (§20.6). */
static const char *pat_str(const axiam_sensitive_t *s) {
    if (!s || axiam_sensitive_len(s) == 0) return NULL;
    return (const char *)axiam_sensitive_bytes(s);
}

/*
 * §20.4 maps the ticket grant on the body's `error` field at ANY status, and
 * everything else by status. This fills both the kind and the machine-readable
 * code, and never copies the server's free text verbatim into a place a caller
 * might log next to a token — only the bounded `error` value and the SDK's own
 * context string.
 */
static axiam_error_kind_t map_oauth2_error(const axiam_http_response_t *resp,
                                           axiam_error_t *err) {
    cJSON *root = resp->body ? cJSON_Parse(resp->body) : NULL;
    const cJSON *code = root ? cJSON_GetObjectItemCaseSensitive(root, "error") : NULL;

    if (cJSON_IsString(code) && code->valuestring && code->valuestring[0]) {
        char msg[256];
        snprintf(msg, sizeof(msg), "uma ticket exchange refused: %s", code->valuestring);
        /* §12.3 rule 3's discipline: a protocol refusal is an authentication
         * failure, not an authorization one, so it never looks like a §11 deny
         * a caller might retry against a different resource. */
        axiam_error_set(err, AXIAM_ERR_AUTH, resp->status, msg);
        if (err) {
            snprintf(err->oauth_error, sizeof(err->oauth_error), "%s", code->valuestring);
        }
        cJSON_Delete(root);
        return AXIAM_ERR_AUTH;
    }

    cJSON_Delete(root);
    /* Not an OAuth2ErrorResponse — a proxy's HTML 502, say. The ordinary §2
     * status mapping still applies, rather than an auth error with no code. */
    axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp->status);
    axiam_error_set(err, kind, resp->status, "uma ticket exchange failed");
    return kind;
}

/* The §2 status mapping for a Protection API refusal (§20.4: 401 / 403 / 400). */
static axiam_error_kind_t map_status_error(const axiam_http_response_t *resp,
                                           const char *context,
                                           axiam_error_t *err) {
    axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp->status);
    axiam_error_set(err, kind, resp->status, context);
    return kind;
}

/*
 * One request against an ABSOLUTE url — an endpoint read from the discovery
 * document rather than joined onto the client's base URL — carrying exactly
 * `extra_headers` plus the §5 tenant header.
 *
 * Deliberately not routed through the §16 retry loop: every caller here is
 * either a Protection API write or the ticket grant, and the grant must issue
 * exactly one request (§20.2 rule 6).
 */
static int uma_transport(axiam_client_t *c, const char *method, const char *url,
                         const char *content_type, const char *bearer,
                         const char *body, axiam_http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));

    axiam_kv_t *headers = NULL;
    headers = axiam_kv_append(headers, "X-Tenant-ID",
                              c->cfg->tenant_id && c->cfg->tenant_id[0]
                                  ? c->cfg->tenant_id : c->cfg->tenant_slug);
    headers = axiam_kv_append(headers, "Accept", "application/json");
    if (content_type) headers = axiam_kv_append(headers, "Content-Type", content_type);
    if (bearer) {
        char value[2048];
        snprintf(value, sizeof(value), "Bearer %s", bearer);
        headers = axiam_kv_append(headers, "Authorization", value);
    }

    axiam_http_request_t req = {0};
    req.method = method;
    req.url = url;
    req.headers = headers;
    req.body = body;
    req.body_len = body ? strlen(body) : 0;

    int rc = c->transport(c->transport_ctx, &req, resp);
    axiam_kv_free(headers);
    return rc;
}

static int client_unusable(axiam_client_t *c, axiam_error_t *err) {
    if (!c) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return 1;
    }
    pthread_mutex_lock(&c->state_mtx);
    int closed = c->closed;
    pthread_mutex_unlock(&c->state_mtx);
    if (closed) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "client is closed (CONTRACT.md §18.1 rule 4)");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Discovery                                                          */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t parse_uma_config(const char *json, axiam_uma_config_t *out,
                                           axiam_error_t *err) {
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "uma discovery: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *token = cJSON_GetObjectItemCaseSensitive(root, "token_endpoint");
    const cJSON *perm = cJSON_GetObjectItemCaseSensitive(root, "permission_endpoint");
    const cJSON *rreg = cJSON_GetObjectItemCaseSensitive(root, "resource_registration_endpoint");
    const cJSON *iss = cJSON_GetObjectItemCaseSensitive(root, "issuer");
    const cJSON *ttl = cJSON_GetObjectItemCaseSensitive(root, "permission_ticket_lifetime");

    if (!cJSON_IsString(token) || !cJSON_IsString(perm) || !cJSON_IsString(rreg)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "uma discovery: missing token/permission/resource_registration endpoint");
        return AXIAM_ERR_NETWORK;
    }

    memset(out, 0, sizeof(*out));
    out->issuer = axiam_strdup0(cJSON_IsString(iss) ? iss->valuestring : NULL);
    out->token_endpoint = axiam_strdup0(token->valuestring);
    out->permission_endpoint = axiam_strdup0(perm->valuestring);
    out->resource_registration_endpoint = axiam_strdup0(rreg->valuestring);
    out->permission_ticket_lifetime = cJSON_IsNumber(ttl) ? (long)ttl->valuedouble : -1;
    cJSON_Delete(root);

    if (!out->token_endpoint || !out->permission_endpoint || !out->resource_registration_endpoint) {
        axiam_uma_config_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

static axiam_error_kind_t config_copy(const axiam_uma_config_t *src, axiam_uma_config_t *dst) {
    memset(dst, 0, sizeof(*dst));
    dst->issuer = axiam_strdup0(src->issuer);
    dst->token_endpoint = axiam_strdup0(src->token_endpoint);
    dst->permission_endpoint = axiam_strdup0(src->permission_endpoint);
    dst->resource_registration_endpoint = axiam_strdup0(src->resource_registration_endpoint);
    dst->permission_ticket_lifetime = src->permission_ticket_lifetime;
    if (!dst->token_endpoint || !dst->permission_endpoint || !dst->resource_registration_endpoint) {
        axiam_uma_config_dispose(dst);
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

axiam_error_kind_t axiam_uma_discover(axiam_client_t *client, axiam_uma_config_t *out,
                                      axiam_error_t *err) {
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    out->permission_ticket_lifetime = -1;
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    pthread_mutex_lock(&client->state_mtx);
    int fresh = client->uma_config_valid &&
                (time(NULL) - client->uma_config_fetched_at) < AXIAM_UMA_CONFIG_TTL_SECONDS;
    axiam_error_kind_t copied = fresh ? config_copy(&client->uma_config, out) : AXIAM_OK;
    pthread_mutex_unlock(&client->state_mtx);
    if (fresh) {
        if (copied != AXIAM_OK) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
        return AXIAM_OK;
    }

    char *body = NULL;
    axiam_error_kind_t kind =
        axiam_client_raw_get(client, "/.well-known/uma2-configuration", &body, err);
    if (kind != AXIAM_OK) return kind;

    kind = parse_uma_config(body, out, err);
    free(body);
    if (kind != AXIAM_OK) return kind;

    pthread_mutex_lock(&client->state_mtx);
    axiam_uma_config_dispose(&client->uma_config);
    if (config_copy(out, &client->uma_config) == AXIAM_OK) {
        client->uma_config_fetched_at = time(NULL);
        client->uma_config_valid = 1;
    } else {
        /* A cache that could not be populated is simply not populated; the
         * caller's copy is already built and the call succeeds. */
        client->uma_config_valid = 0;
    }
    pthread_mutex_unlock(&client->state_mtx);
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* Protection API                                                     */
/* ------------------------------------------------------------------ */

/*
 * §12.1's absent-optional rule: `type` is omitted rather than sent empty, so
 * the server applies its own `uma_resource` default. `resource_scopes` is
 * always present, because it is the complete new list (§20.2 rule 8) and an
 * absent one would read as "no change".
 */
static char *build_resource_set_body(const char *name, const char *type,
                                     const char *const *scopes, size_t scope_count) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddStringToObject(root, "name", name ? name : "");
    if (type && type[0]) cJSON_AddStringToObject(root, "type", type);
    cJSON *arr = cJSON_AddArrayToObject(root, "resource_scopes");
    if (!arr) { cJSON_Delete(root); return NULL; }
    for (size_t i = 0; i < scope_count; i++) {
        if (scopes && scopes[i]) cJSON_AddItemToArray(arr, cJSON_CreateString(scopes[i]));
    }
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return s;
}

static char *build_permissions_body(const axiam_uma_permission_t *permissions, size_t n) {
    cJSON *root = cJSON_CreateArray();
    if (!root) return NULL;
    for (size_t i = 0; i < n; i++) {
        cJSON *entry = cJSON_CreateObject();
        if (!entry) { cJSON_Delete(root); return NULL; }
        cJSON_AddStringToObject(entry, "resource_id",
                                permissions[i].resource_id ? permissions[i].resource_id : "");
        cJSON *arr = cJSON_AddArrayToObject(entry, "resource_scopes");
        for (size_t j = 0; arr && j < permissions[i].scope_count; j++) {
            if (permissions[i].scopes && permissions[i].scopes[j]) {
                cJSON_AddItemToArray(arr, cJSON_CreateString(permissions[i].scopes[j]));
            }
        }
        cJSON_AddItemToArray(root, entry);
    }
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return s;
}

static axiam_error_kind_t parse_resource_set(const char *json,
                                             axiam_uma_resource_set_t *out,
                                             axiam_error_t *err) {
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    const cJSON *name = root ? cJSON_GetObjectItemCaseSensitive(root, "name") : NULL;
    if (!cJSON_IsString(name)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "uma: malformed ResourceSet (missing name)");
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "_id");
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    const cJSON *scopes = cJSON_GetObjectItemCaseSensitive(root, "resource_scopes");

    memset(out, 0, sizeof(*out));
    out->name = axiam_strdup0(name->valuestring);
    if (cJSON_IsString(id) && id->valuestring[0]) out->id = axiam_strdup0(id->valuestring);
    if (cJSON_IsString(type) && type->valuestring[0]) out->type = axiam_strdup0(type->valuestring);

    if (cJSON_IsArray(scopes)) {
        int n = cJSON_GetArraySize(scopes);
        if (n > 0) {
            out->scopes = calloc((size_t)n, sizeof(char *));
            if (!out->scopes) {
                cJSON_Delete(root);
                axiam_uma_resource_set_dispose(out);
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
                return AXIAM_ERR_NETWORK;
            }
            for (int i = 0; i < n; i++) {
                const cJSON *item = cJSON_GetArrayItem(scopes, i);
                if (cJSON_IsString(item)) {
                    out->scopes[out->scope_count++] = axiam_strdup0(item->valuestring);
                }
            }
        }
    }
    cJSON_Delete(root);
    if (!out->name) {
        axiam_uma_resource_set_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* Percent-escape a path segment. Resource ids are UUIDs, but an id that
 * arrived from somewhere else must not be able to reshape the URL. */
static char *escape_segment(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *out = malloc(n * 3 + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        int unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                         ch == '_' || ch == '~';
        if (unreserved) {
            out[o++] = (char)ch;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            out[o++] = '%';
            out[o++] = hex[ch >> 4];
            out[o++] = hex[ch & 0xF];
        }
    }
    out[o] = '\0';
    return out;
}

static char *resource_url(const axiam_uma_config_t *cfg, const char *id) {
    char *escaped = escape_segment(id);
    if (!escaped) return NULL;
    size_t n = strlen(cfg->resource_registration_endpoint) + strlen(escaped) + 2;
    char *url = malloc(n);
    if (url) snprintf(url, n, "%s/%s", cfg->resource_registration_endpoint, escaped);
    free(escaped);
    return url;
}

/*
 * One Protection API call, PAT-authenticated (§20.2 rule 1).
 *
 * The PAT is an explicit Authorization header. A minted ticket is bound to the
 * client_id that minted it, so this credential must be the caller's PAT — and
 * an absent one is refused here rather than becoming a request with no
 * credential, or worse, one carrying something else.
 *
 * `out_body` receives the 2xx body when non-NULL (the DELETE 204 case passes
 * NULL).
 */
static axiam_error_kind_t protection_call(axiam_client_t *client,
                                          const axiam_sensitive_t *pat,
                                          const char *method, const char *url,
                                          const char *body, char **out_body,
                                          const char *context, axiam_error_t *err) {
    if (out_body) *out_body = NULL;
    const char *token = pat_str(pat);
    if (!token) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the UMA Protection API requires a PAT carrying the uma_protection "
                        "scope; the SDK does not substitute its own session (§20.2 rule 1)");
        return AXIAM_ERR_AUTH;
    }
    if (!url) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = uma_transport(client, method, url, body ? "application/json" : NULL,
                           token, body, &resp);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        if (out_body) *out_body = axiam_strdup0(resp.body ? resp.body : "");
    } else {
        kind = map_status_error(&resp, context, err);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_uma_register_resource(axiam_client_t *client,
                                               const axiam_sensitive_t *pat,
                                               const char *name, const char *type,
                                               const char *const *scopes, size_t scope_count,
                                               axiam_uma_resource_set_t *out,
                                               axiam_error_t *err) {
    if (!out || !name) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    char *body = build_resource_set_body(name, type, scopes, scope_count);
    char *response = NULL;
    kind = body ? protection_call(client, pat, "POST", cfg.resource_registration_endpoint,
                                  body, &response, "uma register resource failed", err)
                : AXIAM_ERR_NETWORK;
    if (!body) axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    free(body);
    axiam_uma_config_dispose(&cfg);
    if (kind != AXIAM_OK) return kind;

    kind = parse_resource_set(response, out, err);
    free(response);
    return kind;
}

axiam_error_kind_t axiam_uma_read_resource(axiam_client_t *client,
                                           const axiam_sensitive_t *pat, const char *id,
                                           axiam_uma_resource_set_t *out,
                                           axiam_error_t *err) {
    if (!out || !id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    char *url = resource_url(&cfg, id);
    char *response = NULL;
    kind = protection_call(client, pat, "GET", url, NULL, &response,
                           "uma read resource failed", err);
    free(url);
    axiam_uma_config_dispose(&cfg);
    if (kind != AXIAM_OK) return kind;

    kind = parse_resource_set(response, out, err);
    free(response);
    return kind;
}

axiam_error_kind_t axiam_uma_update_resource(axiam_client_t *client,
                                             const axiam_sensitive_t *pat, const char *id,
                                             const char *name, const char *type,
                                             const char *const *scopes, size_t scope_count,
                                             axiam_uma_resource_set_t *out,
                                             axiam_error_t *err) {
    if (!out || !id || !name) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    /* §20.2 rule 8: exactly the scopes given, with no read first. */
    char *url = resource_url(&cfg, id);
    char *body = build_resource_set_body(name, type, scopes, scope_count);
    char *response = NULL;
    kind = (url && body)
               ? protection_call(client, pat, "PUT", url, body, &response,
                                 "uma update resource failed", err)
               : AXIAM_ERR_NETWORK;
    if (!url || !body) axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    free(url);
    free(body);
    axiam_uma_config_dispose(&cfg);
    if (kind != AXIAM_OK) return kind;

    kind = parse_resource_set(response, out, err);
    free(response);
    return kind;
}

axiam_error_kind_t axiam_uma_delete_resource(axiam_client_t *client,
                                             const axiam_sensitive_t *pat, const char *id,
                                             axiam_error_t *err) {
    if (!id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    char *url = resource_url(&cfg, id);
    kind = protection_call(client, pat, "DELETE", url, NULL, NULL,
                           "uma delete resource failed", err);
    free(url);
    axiam_uma_config_dispose(&cfg);
    return kind;
}

axiam_error_kind_t axiam_uma_list_resources(axiam_client_t *client,
                                            const axiam_sensitive_t *pat,
                                            char ***out_ids, size_t *out_count,
                                            axiam_error_t *err) {
    if (!out_ids || !out_count) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    *out_ids = NULL;
    *out_count = 0;
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    char *response = NULL;
    kind = protection_call(client, pat, "GET", cfg.resource_registration_endpoint, NULL,
                           &response, "uma list resources failed", err);
    axiam_uma_config_dispose(&cfg);
    if (kind != AXIAM_OK) return kind;

    cJSON *root = response ? cJSON_Parse(response) : NULL;
    free(response);
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "uma list resources: body is not a JSON array");
        return AXIAM_ERR_NETWORK;
    }
    int n = cJSON_GetArraySize(root);
    if (n > 0) {
        *out_ids = calloc((size_t)n, sizeof(char *));
        if (!*out_ids) {
            cJSON_Delete(root);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
        for (int i = 0; i < n; i++) {
            const cJSON *item = cJSON_GetArrayItem(root, i);
            if (cJSON_IsString(item)) (*out_ids)[(*out_count)++] = axiam_strdup0(item->valuestring);
        }
    }
    cJSON_Delete(root);
    return AXIAM_OK;
}

axiam_error_kind_t axiam_uma_request_ticket(axiam_client_t *client,
                                            const axiam_sensitive_t *pat,
                                            const axiam_uma_permission_t *permissions,
                                            size_t permission_count,
                                            axiam_sensitive_t **out_ticket,
                                            axiam_error_t *err) {
    if (!out_ticket) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    *out_ticket = NULL;
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    char *body = build_permissions_body(permissions, permission_count);
    char *response = NULL;
    kind = body ? protection_call(client, pat, "POST", cfg.permission_endpoint, body,
                                  &response, "uma request ticket failed", err)
                : AXIAM_ERR_NETWORK;
    if (!body) axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    free(body);
    axiam_uma_config_dispose(&cfg);
    if (kind != AXIAM_OK) return kind;

    cJSON *root = response ? cJSON_Parse(response) : NULL;
    free(response);
    const cJSON *ticket = root ? cJSON_GetObjectItemCaseSensitive(root, "ticket") : NULL;
    if (!cJSON_IsString(ticket) || !ticket->valuestring[0]) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "uma request ticket: malformed PermissionTicketResponse");
        return AXIAM_ERR_NETWORK;
    }
    /* §20.6: wrapped on the way out. For its 60-second life the ticket IS the
     * credential that converts into an RPT. */
    *out_ticket = axiam_sensitive_new(ticket->valuestring);
    cJSON_Delete(root);
    if (!*out_ticket) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* The ticket grant                                                   */
/* ------------------------------------------------------------------ */

/* Percent-encode a form value (application/x-www-form-urlencoded). */
static size_t form_append(char *dst, size_t cap, size_t at, const char *s) {
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char ch = (unsigned char)s[i];
        int unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                         ch == '_' || ch == '~';
        if (unreserved) {
            if (at + 1 >= cap) return cap;
            dst[at++] = (char)ch;
        } else {
            if (at + 3 >= cap) return cap;
            dst[at++] = '%';
            dst[at++] = hex[ch >> 4];
            dst[at++] = hex[ch & 0xF];
        }
    }
    if (at < cap) dst[at] = '\0';
    return at;
}

static char *build_grant_form(const axiam_uma_exchange_params_t *p) {
    /* Generous but bounded: the four secrets plus the two fixed URNs. */
    size_t cap = 8192;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    size_t at = 0;
    buf[0] = '\0';

    const struct { const char *key; const char *value; } fields[] = {
        {"grant_type", AXIAM_UMA_TICKET_GRANT_TYPE},
        {"ticket", (const char *)axiam_sensitive_bytes(p->ticket)},
        {"claim_token", (const char *)axiam_sensitive_bytes(p->claim_token)},
        {"claim_token_format", AXIAM_UMA_CLAIM_TOKEN_FORMAT},
        {"client_id", p->client_id},
        {"client_secret", (const char *)axiam_sensitive_bytes(p->client_secret)},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (i > 0) {
            if (at + 1 >= cap) { free(buf); return NULL; }
            buf[at++] = '&';
        }
        at = form_append(buf, cap, at, fields[i].key);
        if (at + 1 >= cap) { free(buf); return NULL; }
        buf[at++] = '=';
        at = form_append(buf, cap, at, fields[i].value);
        if (at >= cap) { free(buf); return NULL; }
    }
    buf[at] = '\0';
    return buf;
}

/* Looks like a UUID: 8-4-4-4-12 hex. A tenant SLUG is not one, and §12.3
 * rule 4 forbids substituting it. */
static int looks_like_uuid(const char *s) {
    if (!s) return 0;
    static const int groups[] = {8, 4, 4, 4, 12};
    size_t at = 0;
    for (int g = 0; g < 5; g++) {
        for (int i = 0; i < groups[g]; i++) {
            char ch = s[at++];
            int hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                      (ch >= 'A' && ch <= 'F');
            if (!hex) return 0;
        }
        if (g < 4 && s[at++] != '-') return 0;
    }
    return s[at] == '\0';
}

axiam_error_kind_t axiam_uma_exchange_ticket(axiam_client_t *client,
                                             const axiam_uma_exchange_params_t *params,
                                             axiam_uma_rpt_t *out, axiam_error_t *err) {
    if (!out || !params) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    /* Everything that can be refused client-side is refused BEFORE the wire
     * call, so a request that could not have succeeded never spends a ticket
     * (§20.2 rules 2 and 6 together). */
    if (!pat_str(params->ticket)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "the UMA ticket grant requires a ticket (§20.1)");
        return AXIAM_ERR_AUTH;
    }
    if (!pat_str(params->claim_token)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the UMA ticket grant requires a claim_token naming the requesting "
                        "party; it is never defaulted (§20.2 rule 2)");
        return AXIAM_ERR_AUTH;
    }
    if (!params->client_id || !params->client_id[0] || !pat_str(params->client_secret)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the UMA ticket grant is a token-endpoint grant and requires "
                        "confidential-client credentials (§20.1)");
        return AXIAM_ERR_AUTH;
    }

    const char *tenant = params->tenant_id ? params->tenant_id : client->cfg->tenant_id;
    if (!looks_like_uuid(tenant)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the UMA ticket grant requires a tenant_id UUID for the /oauth2 query "
                        "parameter; a tenant slug cannot be substituted (§12.3 rule 4)");
        return AXIAM_ERR_AUTH;
    }

    axiam_uma_config_t cfg;
    axiam_error_kind_t kind = axiam_uma_discover(client, &cfg, err);
    if (kind != AXIAM_OK) return kind;

    /* §12.1 note 2, which §20.1 applies to this grant unchanged. */
    size_t url_len = strlen(cfg.token_endpoint) + strlen(tenant) + 16;
    char *url = malloc(url_len);
    if (url) {
        snprintf(url, url_len, "%s%ctenant_id=%s", cfg.token_endpoint,
                 strchr(cfg.token_endpoint, '?') ? '&' : '?', tenant);
    }
    char *form = build_grant_form(params);
    if (!url || !form) {
        free(url);
        free(form);
        axiam_uma_config_dispose(&cfg);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    /*
     * ONE REQUEST. No retry loop, on any outcome — §20.2 rule 6. The ticket is
     * consumed before the request is evaluated, so a retry is a second
     * redemption, which is the concurrency case ilpanich/axiam#302 measures.
     * The client authenticates through the form body, so no Authorization
     * header goes with it.
     */
    axiam_http_response_t resp;
    int rc = uma_transport(client, "POST", url, "application/x-www-form-urlencoded",
                           NULL, form, &resp);

    /* The form carries four secrets; scrub before release rather than leaving
     * them in a freed heap block (§7). */
    axiam_secure_zero(form, strlen(form));
    free(form);
    free(url);
    axiam_uma_config_dispose(&cfg);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (resp.status < 200 || resp.status >= 300) {
        kind = map_oauth2_error(&resp, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    const cJSON *token = root ? cJSON_GetObjectItemCaseSensitive(root, "access_token") : NULL;
    const cJSON *type = root ? cJSON_GetObjectItemCaseSensitive(root, "token_type") : NULL;
    const cJSON *expires = root ? cJSON_GetObjectItemCaseSensitive(root, "expires_in") : NULL;
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        cJSON_Delete(root);
        axiam_http_response_dispose(&resp);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "uma ticket exchange: malformed TokenResponse (missing access_token)");
        return AXIAM_ERR_NETWORK;
    }
    out->access_token = axiam_sensitive_new(token->valuestring);
    out->token_type = axiam_strdup0(cJSON_IsString(type) ? type->valuestring : "Bearer");
    out->expires_in = cJSON_IsNumber(expires) ? (long)expires->valuedouble : 0;
    /* §20.2 rule 5: any refresh_token the server sent is ignored — there is no
     * member for it, and synthesising one would let an RPT outlive its ticket. */
    cJSON_Delete(root);
    axiam_http_response_dispose(&resp);

    if (!out->access_token || !out->token_type) {
        axiam_uma_rpt_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* §20.3 the challenge helpers                                        */
/* ------------------------------------------------------------------ */

/* Copy `len` bytes of `s`, stripping surrounding whitespace and one layer of
 * double quotes. Returns malloc'd, or NULL. */
static char *trim_quoted(const char *s, size_t len) {
    while (len > 0 && (*s == ' ' || *s == '\t')) { s++; len--; }
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) len--;
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') { s++; len -= 2; }
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

int axiam_uma_parse_challenge(const char *header, axiam_uma_challenge_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!header) return 0;

    while (*header == ' ' || *header == '\t') header++;
    if (strncmp(header, "UMA", 3) != 0) return 0;
    const char *rest = header + 3;
    /* "UMA" alone is a valid, if useless, challenge; anything else must be
     * separated by whitespace so `UMAX realm="…"` is not read as UMA. */
    if (*rest != '\0' && *rest != ' ' && *rest != '\t') return 0;

    const char *cursor = rest;
    while (*cursor) {
        const char *comma = strchr(cursor, ',');
        size_t part_len = comma ? (size_t)(comma - cursor) : strlen(cursor);
        const char *equals = memchr(cursor, '=', part_len);
        if (equals) {
            char *key = trim_quoted(cursor, (size_t)(equals - cursor));
            char *value = trim_quoted(equals + 1, part_len - (size_t)(equals - cursor) - 1);
            if (key && value) {
                if (strcmp(key, "realm") == 0) {
                    free(out->realm);
                    out->realm = value;
                    value = NULL;
                } else if (strcmp(key, "as_uri") == 0) {
                    free(out->as_uri);
                    out->as_uri = value;
                    value = NULL;
                } else if (strcmp(key, "ticket") == 0) {
                    axiam_sensitive_free(out->ticket);
                    out->ticket = axiam_sensitive_new(value);
                }
                /* Unknown parameters are ignored rather than rejected: UMA 2.0
                 * permits a server to add its own, and refusing the whole
                 * challenge over one would lose the ticket with it. */
            }
            free(key);
            free(value);
        }
        if (!comma) break;
        cursor = comma + 1;
    }
    return 1;
}

char *axiam_uma_challenge_header(const char *realm, const char *as_uri,
                                 const axiam_sensitive_t *ticket) {
    const char *raw = pat_str(ticket);
    if (!realm || !as_uri || !raw) return NULL;
    size_t n = strlen(realm) + strlen(as_uri) + strlen(raw) + 48;
    char *out = malloc(n);
    if (!out) return NULL;
    snprintf(out, n, "UMA realm=\"%s\", as_uri=\"%s\", ticket=\"%s\"", realm, as_uri, raw);
    return out;
}
