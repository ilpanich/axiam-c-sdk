/*
 * AXIAM C SDK — RFC 7592 client configuration (CONTRACT.md §28.12, contract 1.53).
 *
 * See include/axiam/registration.h for the four rules. Two things are worth repeating
 * where the code lives:
 *
 *  - Rule 1 is checked before ANYTHING that could touch the wire, and its refusal
 *    names no part of the URI: the URI is caller input, and an error message is the
 *    string most often logged.
 *  - Every request goes out through axiam_client_send_bare(), the one path in this SDK
 *    that sends exactly the headers it is given and withholds the cookie jar. The
 *    session path (axiam_client_send_raw) would attach the CSRF token, the tenant
 *    header and a device bearer, which is the SDK's session — rule 3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/registration.h"
#include "cJSON.h"
#include "oidc_internal.h"

/* The members an update never sends (§28.12.2 rule 4). The first four the server
 * refuses with `400 invalid_request` when present; `client_secret` it never accepts
 * back. */
static const char *const SERVER_STATED_MEMBERS[] = {
    "registration_access_token",
    "registration_client_uri",
    "client_secret_expires_at",
    "client_id_issued_at",
    "client_secret",
};

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

void axiam_client_registration_free(axiam_client_registration_t *reg) {
    if (!reg) return;
    free(reg->client_id);
    free(reg->client_name);
    for (size_t i = 0; i < reg->redirect_uris_count; i++) free(reg->redirect_uris[i]);
    free(reg->redirect_uris);
    for (size_t i = 0; i < reg->grant_types_count; i++) free(reg->grant_types[i]);
    free(reg->grant_types);
    for (size_t i = 0; i < reg->response_types_count; i++) free(reg->response_types[i]);
    free(reg->response_types);
    free(reg->token_endpoint_auth_method);
    free(reg->scope);
    free(reg->registration_client_uri);
    free(reg->jwks);
    free(reg->jwks_uri);
    axiam_sensitive_free(reg->client_secret);
    axiam_sensitive_free(reg->registration_access_token);
    free(reg->extra);
    free(reg);
}

/*
 * Take `key` out of `root` when it is a string, and return a copy of it; leave a member
 * of any other type (null excepted) in `root`, so it ends up in `extra` rather than
 * being lost — a replacement must not drop what the server holds. `*failed` is set on
 * an allocation failure.
 */
static char *take_string(cJSON *root, const char *key, int *failed) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item) return NULL;
    if (cJSON_IsNull(item)) {
        cJSON_DeleteItemFromObjectCaseSensitive(root, key);
        return NULL;
    }
    if (!cJSON_IsString(item)) return NULL;
    char *copy = axiam_strdup0(item->valuestring);
    if (!copy) *failed = 1;
    cJSON_DeleteItemFromObjectCaseSensitive(root, key);
    return copy;
}

static axiam_sensitive_t *take_sensitive(cJSON *root, const char *key, int *failed) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item) return NULL;
    axiam_sensitive_t *value = NULL;
    if (cJSON_IsString(item)) {
        value = axiam_sensitive_new(item->valuestring);
        if (!value) *failed = 1;
    }
    /* Removed whatever its type: a secret in `extra` would be a secret rendered by
     * whoever prints the extra members, and it is never sent back anyway. */
    cJSON_DeleteItemFromObjectCaseSensitive(root, key);
    return value;
}

static void take_long(cJSON *root, const char *key, long *out, int *has) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item) return;
    if (cJSON_IsNull(item)) {
        cJSON_DeleteItemFromObjectCaseSensitive(root, key);
        return;
    }
    if (!cJSON_IsNumber(item)) return;
    *out = (long)item->valuedouble;
    *has = 1;
    cJSON_DeleteItemFromObjectCaseSensitive(root, key);
}

static char **take_list(cJSON *root, const char *key, size_t *count, int *failed) {
    *count = 0;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item) return NULL;
    if (!cJSON_IsArray(item)) {
        if (cJSON_IsNull(item)) cJSON_DeleteItemFromObjectCaseSensitive(root, key);
        return NULL;
    }
    int n = cJSON_GetArraySize(item);
    char **out = NULL;
    if (n > 0) {
        out = calloc((size_t)n, sizeof(char *));
        if (!out) {
            *failed = 1;
        } else {
            for (const cJSON *e = item->child; e; e = e->next) {
                if (!cJSON_IsString(e)) continue;
                char *copy = axiam_strdup0(e->valuestring);
                if (!copy) { *failed = 1; break; }
                out[(*count)++] = copy;
            }
        }
    }
    cJSON_DeleteItemFromObjectCaseSensitive(root, key);
    return out;
}

axiam_client_registration_t *axiam_client_registration_parse(const char *json,
                                                             axiam_error_t *err) {
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "client registration response is not a JSON object");
        return NULL;
    }
    axiam_client_registration_t *reg = calloc(1, sizeof(*reg));
    if (!reg) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    int failed = 0;
    reg->client_id = take_string(root, "client_id", &failed);
    take_long(root, "client_id_issued_at", &reg->client_id_issued_at,
              &reg->has_client_id_issued_at);
    reg->client_name = take_string(root, "client_name", &failed);
    reg->redirect_uris = take_list(root, "redirect_uris", &reg->redirect_uris_count, &failed);
    reg->grant_types = take_list(root, "grant_types", &reg->grant_types_count, &failed);
    reg->response_types = take_list(root, "response_types", &reg->response_types_count, &failed);
    reg->token_endpoint_auth_method = take_string(root, "token_endpoint_auth_method", &failed);
    reg->scope = take_string(root, "scope", &failed);
    reg->registration_client_uri = take_string(root, "registration_client_uri", &failed);
    take_long(root, "client_secret_expires_at", &reg->client_secret_expires_at,
              &reg->has_client_secret_expires_at);
    reg->jwks_uri = take_string(root, "jwks_uri", &failed);
    reg->client_secret = take_sensitive(root, "client_secret", &failed);
    reg->registration_access_token = take_sensitive(root, "registration_access_token", &failed);
    {
        cJSON *jwks = cJSON_DetachItemFromObjectCaseSensitive(root, "jwks");
        if (jwks && !cJSON_IsNull(jwks)) {
            reg->jwks = cJSON_PrintUnformatted(jwks);
            if (!reg->jwks) failed = 1;
        }
        cJSON_Delete(jwks);
    }
    if (root->child) {
        reg->extra = cJSON_PrintUnformatted(root);
        if (!reg->extra) failed = 1;
    }
    cJSON_Delete(root);

    if (failed) {
        axiam_client_registration_free(reg);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    if (!reg->client_id) {
        axiam_client_registration_free(reg);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "client registration response carries no client_id");
        return NULL;
    }
    return reg;
}

/* ------------------------------------------------------------------ */
/* The update body (§28.12.2 rule 4)                                  */
/* ------------------------------------------------------------------ */

static int put_list(cJSON *body, const char *key, char *const *items, size_t count) {
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return 0;
    for (size_t i = 0; i < count; i++) {
        cJSON *s = cJSON_CreateString(items[i] ? items[i] : "");
        if (!s) { cJSON_Delete(arr); return 0; }
        cJSON_AddItemToArray(arr, s);
    }
    cJSON_DeleteItemFromObjectCaseSensitive(body, key);
    if (!cJSON_AddItemToObject(body, key, arr)) { cJSON_Delete(arr); return 0; }
    return 1;
}

static int put_string(cJSON *body, const char *key, const char *value) {
    if (!value) return 1;
    cJSON *s = cJSON_CreateString(value);
    if (!s) return 0;
    cJSON_DeleteItemFromObjectCaseSensitive(body, key);
    if (!cJSON_AddItemToObject(body, key, s)) { cJSON_Delete(s); return 0; }
    return 1;
}

/* The RFC 7592 §2.2 replacement body, or NULL on an allocation failure / a metadata
 * value with no client_id / an `extra` that is not a JSON object. */
static char *update_body(const axiam_client_registration_t *m) {
    cJSON *body = m->extra ? cJSON_Parse(m->extra) : cJSON_CreateObject();
    if (!cJSON_IsObject(body)) {
        cJSON_Delete(body);
        return NULL;
    }
    for (size_t i = 0; i < sizeof(SERVER_STATED_MEMBERS) / sizeof(SERVER_STATED_MEMBERS[0]); i++)
        cJSON_DeleteItemFromObjectCaseSensitive(body, SERVER_STATED_MEMBERS[i]);

    int ok = put_string(body, "client_id", m->client_id) &&
             put_string(body, "client_name", m->client_name) &&
             put_list(body, "redirect_uris", m->redirect_uris, m->redirect_uris_count) &&
             put_list(body, "grant_types", m->grant_types, m->grant_types_count) &&
             put_list(body, "response_types", m->response_types, m->response_types_count) &&
             put_string(body, "token_endpoint_auth_method", m->token_endpoint_auth_method) &&
             put_string(body, "scope", m->scope) &&
             put_string(body, "jwks_uri", m->jwks_uri);
    if (ok && m->jwks) {
        cJSON *jwks = cJSON_Parse(m->jwks);
        if (jwks) {
            cJSON_DeleteItemFromObjectCaseSensitive(body, "jwks");
            if (!cJSON_AddItemToObject(body, "jwks", jwks)) {
                cJSON_Delete(jwks);
                ok = 0;
            }
        } else {
            ok = 0;
        }
    }
    char *json = ok ? cJSON_PrintUnformatted(body) : NULL;
    cJSON_Delete(body);
    return json;
}

/* ------------------------------------------------------------------ */
/* Rule 1: the URI, only at the configured AXIAM                      */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t check_registration_uri(axiam_client_t *c, const char *uri,
                                                 const char *operation, axiam_error_t *err) {
    axiam_url_origin_t base, target;
    const char *why = NULL;
    if (axiam_url_origin(c->cfg->base_url, &base) != 0) {
        why = "the client's base URL is not an absolute URL (CONTRACT.md \xc2\xa7" "28.12.2 rule 1)";
    } else if (!uri || axiam_url_origin(uri, &target) != 0) {
        why = "not an absolute URL (CONTRACT.md \xc2\xa7" "28.12.2 rule 1)";
    } else if (strcmp(target.scheme, "https") != 0 && strcmp(target.scheme, "http") != 0) {
        why = "must be an https URL (CONTRACT.md \xc2\xa7" "28.12.2 rule 1)";
    } else if (target.has_userinfo || strcmp(target.scheme, base.scheme) != 0 ||
               strcmp(target.host, base.host) != 0 || target.port != base.port) {
        why = "not at the configured AXIAM origin: scheme, host and port must match the "
              "client's base URL (CONTRACT.md \xc2\xa7" "28.12.2 rule 1)";
    } else if (strcmp(target.scheme, "http") == 0 && !axiam_host_is_loopback(base.host)) {
        why = "must be https unless the base URL is http on a loopback host "
              "(CONTRACT.md \xc2\xa7" "28.12.2 rule 1)";
    }
    if (!why) return AXIAM_OK;
    axiam_local_refusal(err, operation, "registration_client_uri", why);
    return AXIAM_ERR_NETWORK;
}

/* ------------------------------------------------------------------ */
/* The wire                                                           */
/* ------------------------------------------------------------------ */

/* `Authorization: Bearer <token>` plus `Accept` (and `Content-Type` with a body), and
 * nothing else: no session, no tenant header (rule 3). NULL on OOM. */
static axiam_kv_t *bearer_headers(const axiam_sensitive_t *token, int has_body) {
    const char *raw = axiam_sensitive_reveal(token);
    size_t n = strlen("Bearer ") + strlen(raw) + 1;
    char *value = malloc(n);
    if (!value) return NULL;
    snprintf(value, n, "Bearer %s", raw);
    axiam_kv_t *h = axiam_kv_append(NULL, "Authorization", value);
    axiam_secure_zero(value, n);
    free(value);
    if (!h) return NULL;
    h = axiam_kv_append(h, "Accept", "application/json");
    if (has_body) h = axiam_kv_append(h, "Content-Type", "application/json");
    return h;
}

/* One request; `retryable` selects §16 for the read. */
static int registration_send(axiam_client_t *c, const char *method, const char *uri,
                             const axiam_sensitive_t *token, const char *body, int retryable,
                             axiam_http_response_t *resp) {
    int budget = (retryable && c->retry_enabled) ? AXIAM_RETRY_MAX_ATTEMPTS : 1;
    int rc = -1;
    for (int attempt = 1; attempt <= budget; attempt++) {
        axiam_kv_t *headers = bearer_headers(token, body != NULL);
        if (!headers) {
            memset(resp, 0, sizeof(*resp));
            return -1;
        }
        rc = axiam_client_send_bare(c, method, uri, headers, body, resp);
        if (attempt == budget) break;
        /* §28.12.2 rule 5 lets the read follow §16, whose table retries a transport
         * failure, 408, 429 and 5xx -- and nothing else. A bodiless 400 maps to
         * NetworkError under §2, but it is still the server's decided answer. */
        if (!axiam_retry_should_retry(rc != 0, resp->status)) break;
        long retry_after = axiam_retry_after_ms(axiam_kv_get(resp->headers, "Retry-After"));
        long delay = axiam_retry_delay_ms(attempt, retry_after, c->jitter_fn(c->jitter_ctx));
        axiam_http_response_dispose(resp);
        c->sleep_fn(c->sleep_ctx, delay);
    }
    return rc;
}

/* Shared argument and rule 1 checks. */
static axiam_error_kind_t registration_preflight(axiam_client_t *c, const char *uri,
                                                 const axiam_sensitive_t *token,
                                                 const char *operation, axiam_error_t *err) {
    if (oidc_client_unusable(c, err)) return AXIAM_ERR_NETWORK;
    axiam_error_kind_t refused = check_registration_uri(c, uri, operation, err);
    if (refused != AXIAM_OK) return refused;
    const char *raw = axiam_sensitive_reveal(token);
    if (!raw || !raw[0]) {
        axiam_local_refusal(err, operation, "registration_access_token",
                            "a registration access token is required (CONTRACT.md \xc2\xa7"
                            "28.12.2 rule 2)");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* Turn a response into a registration (2xx) or the §28.12.3 error. */
static axiam_error_kind_t finish(int rc, axiam_http_response_t *resp, const char *operation,
                                 axiam_client_registration_t **out, axiam_error_t *err) {
    axiam_error_kind_t kind;
    if (rc != 0 || resp->status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp->transport_err,
                        resp->transport_msg ? resp->transport_msg : "network failure");
    } else if (resp->status < 200 || resp->status >= 300) {
        /* §28.12.3: an `error` body is an OAuthProtocolError at ANY status, a 401
         * included -- and that 401 never reaches §9 (rule 3): nothing here calls the
         * refresh guard. Otherwise §2 by status. */
        kind = oidc_map_grant_error(resp, operation, err);
    } else if (!out) {
        kind = AXIAM_OK;
        axiam_error_reset(err);
    } else {
        *out = axiam_client_registration_parse(resp->body, err);
        kind = *out ? AXIAM_OK : AXIAM_ERR_NETWORK;
        if (kind == AXIAM_OK) axiam_error_reset(err);
    }
    axiam_http_response_dispose(resp);
    return kind;
}

axiam_error_kind_t axiam_read_client_registration(axiam_client_t *c,
                                                  const char *registration_client_uri,
                                                  const axiam_sensitive_t *registration_access_token,
                                                  axiam_client_registration_t **out,
                                                  axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) *out = NULL;
    axiam_error_kind_t kind = registration_preflight(
        c, registration_client_uri, registration_access_token, "read_client_registration", err);
    if (kind != AXIAM_OK) return kind;

    axiam_http_response_t resp;
    int rc = registration_send(c, "GET", registration_client_uri, registration_access_token,
                               NULL, 1, &resp);
    return finish(rc, &resp, "read_client_registration", out, err);
}

axiam_error_kind_t axiam_update_client_registration(axiam_client_t *c,
                                                    const char *registration_client_uri,
                                                    const axiam_sensitive_t *registration_access_token,
                                                    const axiam_client_registration_t *metadata,
                                                    axiam_client_registration_t **out,
                                                    axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) *out = NULL;
    axiam_error_kind_t kind = registration_preflight(
        c, registration_client_uri, registration_access_token, "update_client_registration",
        err);
    if (kind != AXIAM_OK) return kind;
    if (!metadata || !metadata->client_id || !metadata->client_id[0]) {
        axiam_local_refusal(err, "update_client_registration", "client_id",
                            "the metadata must carry the registration's client_id "
                            "(CONTRACT.md \xc2\xa7" "28.12.2 rule 4)");
        return AXIAM_ERR_NETWORK;
    }
    char *body = update_body(metadata);
    if (!body) {
        axiam_local_refusal(err, "update_client_registration", "extra",
                            "the metadata could not be serialized: `extra` must be a JSON "
                            "object and `jwks` JSON");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    /* NEVER retried (rule 5): see the header. */
    int rc = registration_send(c, "PUT", registration_client_uri, registration_access_token,
                               body, 0, &resp);
    free(body);
    return finish(rc, &resp, "update_client_registration", out, err);
}

axiam_error_kind_t axiam_delete_client_registration(axiam_client_t *c,
                                                    const char *registration_client_uri,
                                                    const axiam_sensitive_t *registration_access_token,
                                                    axiam_error_t *err) {
    axiam_error_reset(err);
    axiam_error_kind_t kind = registration_preflight(
        c, registration_client_uri, registration_access_token, "delete_client_registration",
        err);
    if (kind != AXIAM_OK) return kind;

    axiam_http_response_t resp;
    /* NEVER retried (rule 5): a retry after a lost 204 reads 401. */
    int rc = registration_send(c, "DELETE", registration_client_uri, registration_access_token,
                               NULL, 0, &resp);
    return finish(rc, &resp, "delete_client_registration", NULL, err);
}
