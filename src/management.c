/*
 * CONTRACT.md §27 management API — the hand-written core every generated operation
 * funnels through. See include/axiam/management.h for the §27.3 flat-symbol rationale.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/management.h"
#include "internal.h"
#include "management_internal.h"

/* ---------------------------------------------------------------- */
/* Rule 7 classification                                            */
/* ---------------------------------------------------------------- */

axiam_mgmt_error_class_t axiam_mgmt_error_class(const axiam_error_t *err) {
    if (!err || err->kind == AXIAM_OK) return AXIAM_MGMT_ERR_NONE;
    switch (err->transport_cause) {
        case 404: return AXIAM_MGMT_ERR_NOT_FOUND;
        case 409: return AXIAM_MGMT_ERR_CONFLICT;
        case 400:
        case 422: return AXIAM_MGMT_ERR_VALIDATION;
        default:  return AXIAM_MGMT_ERR_NONE;
    }
}

void axiam_mgmt_classify(axiam_error_t *err, long status, const char *operation,
                         const char *body) {
    (void) body;
    axiam_error_kind_t kind;
    const char *what;

    /* Rule 7's parent column. This deliberately diverges from
     * axiam_error_kind_from_http_status() on 404 and 422 — see management.h. */
    switch (status) {
        case 404: kind = AXIAM_ERR_AUTHZ;   what = "not found"; break;
        case 409: kind = AXIAM_ERR_AUTHZ;   what = "conflict"; break;
        case 400: kind = AXIAM_ERR_NETWORK; what = "invalid request"; break;
        case 422: kind = AXIAM_ERR_NETWORK; what = "invalid request"; break;
        default:
            kind = axiam_error_kind_from_http_status(status);
            what = "request failed";
            break;
    }

    char msg[256];
    snprintf(msg, sizeof msg, "%s: %s (HTTP %ld)",
             operation ? operation : "management", what, status);
    axiam_error_set(err, kind, status, msg);
}

/* ---------------------------------------------------------------- */
/* Paging                                                           */
/* ---------------------------------------------------------------- */

axiam_mgmt_page_req_t axiam_mgmt_page_next(axiam_mgmt_page_req_t req) {
    long limit = req.limit < 1 ? AXIAM_MGMT_DEFAULT_LIMIT : req.limit;
    long offset = req.offset < 0 ? 0 : req.offset;
    axiam_mgmt_page_req_t next;
    next.offset = offset + limit;
    next.limit = limit;
    return next;
}

void axiam_mgmt_page_query(const axiam_mgmt_page_req_t *page, char *offset_buf, char *limit_buf) {
    long offset = 0, limit = AXIAM_MGMT_DEFAULT_LIMIT;
    if (page) {
        offset = page->offset < 0 ? 0 : page->offset;
        limit = page->limit < 1 ? AXIAM_MGMT_DEFAULT_LIMIT : page->limit;
    }
    snprintf(offset_buf, 24, "%ld", offset);
    snprintf(limit_buf, 24, "%ld", limit);
}

long axiam_mgmt_page_total(const cJSON *envelope, long item_count) {
    if (envelope) {
        const cJSON *t = cJSON_GetObjectItemCaseSensitive(envelope, "total");
        if (!cJSON_IsNumber(t)) t = cJSON_GetObjectItemCaseSensitive(envelope, "total_count");
        /* §27.4 rule 4: `total` is the SERVER's count across every page. Falling back to
         * the item count when the server sent none is the only honest default -- but the
         * two are never conflated when the server DID say. */
        if (cJSON_IsNumber(t)) return (long) t->valuedouble;
    }
    return item_count;
}

const cJSON *axiam_mgmt_page_items(const cJSON *envelope) {
    if (!envelope) return NULL;
    const cJSON *items = cJSON_GetObjectItemCaseSensitive(envelope, "items");
    if (!cJSON_IsArray(items)) items = cJSON_GetObjectItemCaseSensitive(envelope, "data");
    return cJSON_IsArray(items) ? items : NULL;
}

/* ---------------------------------------------------------------- */
/* Scope resolution (rule 3)                                        */
/* ---------------------------------------------------------------- */

static const char *first_nonempty(const char *a, const char *b, const char *c) {
    if (a && *a) return a;
    if (b && *b) return b;
    if (c && *c) return c;
    return NULL;
}

const char *axiam_mgmt_resolved_org_id(axiam_client_t *c, const axiam_mgmt_call_scope_t *scope) {
    const axiam_client_config_t *cfg = axiam_client_config_of(c);
    return first_nonempty(scope ? scope->org_id : NULL,
                          cfg ? cfg->org_id : NULL,
                          c ? c->resolved_org_id : NULL);
}

const char *axiam_mgmt_resolved_tenant_id(axiam_client_t *c, const axiam_mgmt_call_scope_t *scope) {
    const axiam_client_config_t *cfg = axiam_client_config_of(c);
    return first_nonempty(scope ? scope->tenant_id : NULL,
                          cfg ? cfg->tenant_id : NULL,
                          c ? c->resolved_tenant_id : NULL);
}

/* ---------------------------------------------------------------- */
/* Path building                                                    */
/* ---------------------------------------------------------------- */

char *axiam_mgmt_path(const char *template_, const char *const *names,
                      const char *const *values, size_t count) {
    if (!template_) return NULL;

    char *path = axiam_strdup0(template_);
    if (!path) return NULL;

    for (size_t i = 0; i < count; i++) {
        if (!values[i] || !*values[i]) {
            /* A missing implicit scope id. Refusing here is what stops the request from
             * going out with an empty path segment, which the server answers as a 404
             * the caller cannot diagnose. */
            free(path);
            return NULL;
        }

        char placeholder[64];
        snprintf(placeholder, sizeof placeholder, "{%s}", names[i]);

        const char *at = strstr(path, placeholder);
        if (!at) continue;

        char *encoded = axiam_url_encode(values[i]);
        if (!encoded) { free(path); return NULL; }

        size_t head = (size_t) (at - path);
        size_t ph_len = strlen(placeholder);
        size_t tail = strlen(path) - head - ph_len;
        size_t enc_len = strlen(encoded);

        char *next = (char *) malloc(head + enc_len + tail + 1);
        if (!next) { free(encoded); free(path); return NULL; }

        memcpy(next, path, head);
        memcpy(next + head, encoded, enc_len);
        memcpy(next + head + enc_len, at + ph_len, tail);
        next[head + enc_len + tail] = '\0';

        free(encoded);
        free(path);
        path = next;
    }

    return path;
}

char *axiam_mgmt_query(char *path, const char *const *names,
                       const char *const *values, size_t count) {
    if (!path) return NULL;

    size_t need = strlen(path) + 1;
    for (size_t i = 0; i < count; i++) {
        if (!values[i]) continue;
        need += strlen(names[i]) + strlen(values[i]) * 3 + 2;
    }

    char *out = (char *) malloc(need);
    if (!out) { free(path); return NULL; }

    size_t used = (size_t) snprintf(out, need, "%s", path);
    int first = 1;
    for (size_t i = 0; i < count; i++) {
        if (!values[i]) continue;   /* an unset optional query parameter is OMITTED */
        char *encoded = axiam_url_encode(values[i]);
        if (!encoded) { free(out); free(path); return NULL; }
        used += (size_t) snprintf(out + used, need - used, "%c%s=%s",
                                  first ? '?' : '&', names[i], encoded);
        free(encoded);
        first = 0;
    }

    free(path);
    return out;
}

/* ---------------------------------------------------------------- */
/* JSON helpers                                                     */
/* ---------------------------------------------------------------- */

char *axiam_mgmt_str(const cJSON *obj, const char *key) {
    if (!obj) return NULL;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(v) ? axiam_strdup0(v->valuestring) : NULL;
}

char *axiam_mgmt_render(cJSON *body) {
    if (!body) return NULL;
    char *json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    return json;
}

/* ---------------------------------------------------------------- */
/* The one wire path (§27.8)                                        */
/* ---------------------------------------------------------------- */

axiam_error_kind_t axiam_mgmt_send(axiam_client_t *c,
                                   const char *operation,
                                   const char *method,
                                   const char *path_template,
                                   const char *path,
                                   const char *body_json,
                                   cJSON **out_json,
                                   axiam_error_t *err) {
    if (out_json) *out_json = NULL;

    if (!c || !method || !path) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(c)) return axiam_client_shut_error(err);

    /* Rule 1: no session, no wire call. Checked before the request is built rather than
     * left to the server's 401 -- it costs the caller nothing, cannot be counted against
     * a rate limit, and the message names the operation. */
    if (!axiam_client_has_session(c)) {
        char msg[256];
        snprintf(msg, sizeof msg,
                 "%s: no active session -- management operations require an "
                 "authenticated caller (CONTRACT.md 27.4 rule 1)",
                 operation ? operation : "management");
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return AXIAM_ERR_AUTH;
    }

    /* Rule 8: a GET is the only method the §16 policy may replay. Everything else may
     * already have been applied server-side, and no client can tell from a transport
     * failure. A rejected body is never retried either, whatever the method. */
    int retryable = strcmp(method, "GET") == 0;
    int attempts = retryable ? 3 : 1;

    axiam_error_kind_t kind = AXIAM_ERR_NETWORK;

    for (int attempt = 1; attempt <= attempts; attempt++) {
        /* Rule 11: the TEMPLATE, never the substituted path. A metrics label carrying a
         * user id is an unbounded-cardinality series and, on this surface, a slow
         * identifier leak into whatever consumes the telemetry. */
        double started = axiam_now_ms();
        axiam_telemetry_request_start(&c->telemetry, operation, method,
                                      path_template, attempt);

        axiam_http_response_t resp;
        int rc = axiam_client_send_raw(c, method, path, body_json, &resp);
        long status = (rc == 0) ? resp.status : 0;

        axiam_telemetry_request_end(&c->telemetry, operation, method,
                                    path_template, attempt, status,
                                    axiam_now_ms() - started,
                                    (status >= 200 && status < 300)
                                        ? AXIAM_TELEMETRY_SUCCESS
                                        : AXIAM_TELEMETRY_FAILURE);

        if (rc != 0 || status == 0) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                            resp.transport_msg ? resp.transport_msg : "network failure");
            kind = AXIAM_ERR_NETWORK;
            axiam_http_response_dispose(&resp);
            if (attempt < attempts) continue;
            return kind;
        }

        if (status >= 200 && status < 300) {
            if (out_json && resp.body && *resp.body) {
                *out_json = cJSON_Parse(resp.body);
                if (!*out_json) {
                    axiam_error_set(err, AXIAM_ERR_NETWORK, status,
                                    "expected a JSON object or array in the response body");
                    axiam_http_response_dispose(&resp);
                    return AXIAM_ERR_NETWORK;
                }
            }
            axiam_http_response_dispose(&resp);
            axiam_error_reset(err);
            return AXIAM_OK;
        }

        axiam_mgmt_classify(err, status, operation, resp.body);
        kind = err ? err->kind : AXIAM_ERR_NETWORK;
        axiam_http_response_dispose(&resp);

        /* A 4xx is a decisive answer, not a transport failure: re-sending it just spends
         * the caller's rate limit to be told the same thing again. Only a 5xx or a
         * transport failure is worth another attempt, and only on a GET. */
        if (attempt < attempts && status >= 500) continue;
        return kind;
    }

    return kind;
}
