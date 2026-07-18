#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "internal.h"

/* ------------------------------------------------------------------ */
/* Construction                                                       */
/* ------------------------------------------------------------------ */

axiam_client_t *axiam_client_new(const axiam_client_config_t *cfg, axiam_error_t *err) {
    if (axiam_client_config_validate(cfg, err) != AXIAM_OK) return NULL;

    axiam_client_t *c = calloc(1, sizeof(*c));
    if (!c) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    c->cfg = axiam_client_config_clone(cfg);
    if (!c->cfg) {
        free(c);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    pthread_mutex_init(&c->state_mtx, NULL);
    pthread_mutex_init(&c->refresh_mtx, NULL);
    pthread_cond_init(&c->refresh_cond, NULL);
    pthread_mutex_init(&c->jwks_mtx, NULL);
    c->refresh_result = AXIAM_OK;

    if (cfg->transport) {
        c->transport = cfg->transport;
        c->transport_ctx = cfg->transport_ctx;
    } else {
        c->curl_ctx = axiam_curl_ctx_new(c->cfg);
        if (!c->curl_ctx) {
            axiam_client_free(c);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "failed to init HTTP transport");
            return NULL;
        }
        c->transport = axiam_curl_transport;
        c->transport_ctx = c->curl_ctx;
    }
    return c;
}

static void jwks_free(struct axiam_jwk *j) {
    while (j) {
        struct axiam_jwk *n = j->next;
        free(j->kid);
        free(j);
        j = n;
    }
}

void axiam_client_free(axiam_client_t *client) {
    if (!client) return;
    if (client->curl_ctx) axiam_curl_ctx_free(client->curl_ctx);
    axiam_client_config_free(client->cfg);
    free(client->csrf_token);
    jwks_free(client->jwks);
    pthread_mutex_destroy(&client->state_mtx);
    pthread_mutex_destroy(&client->refresh_mtx);
    pthread_cond_destroy(&client->refresh_cond);
    pthread_mutex_destroy(&client->jwks_mtx);
    free(client);
}

unsigned long axiam_client_refresh_count(const axiam_client_t *client) {
    return client ? client->refresh_count : 0;
}

/* ------------------------------------------------------------------ */
/* Request plumbing                                                   */
/* ------------------------------------------------------------------ */

static char *build_url(const axiam_client_t *c, const char *path) {
    const char *base = c->cfg->base_url;
    size_t blen = strlen(base);
    while (blen > 0 && base[blen - 1] == '/') blen--;
    size_t n = blen + strlen(path) + 1;
    char *url = malloc(n);
    if (!url) return NULL;
    memcpy(url, base, blen);
    strcpy(url + blen, path);
    return url;
}

static const char *tenant_header_value(const axiam_client_t *c) {
    if (c->cfg->tenant_id && c->cfg->tenant_id[0]) return c->cfg->tenant_id;
    return c->cfg->tenant_slug;
}

static axiam_kv_t *build_headers(axiam_client_t *c, int state_changing, int has_body) {
    axiam_kv_t *h = NULL;
    /* §5: X-Tenant-ID on every request. */
    h = axiam_kv_append(h, "X-Tenant-ID", tenant_header_value(c));
    if (has_body) h = axiam_kv_append(h, "Content-Type", "application/json");
    h = axiam_kv_append(h, "Accept", "application/json");
    /* §3: echo captured CSRF token on state-changing methods. */
    if (state_changing) {
        pthread_mutex_lock(&c->state_mtx);
        if (c->csrf_token) h = axiam_kv_append(h, "X-CSRF-Token", c->csrf_token);
        pthread_mutex_unlock(&c->state_mtx);
    }
    return h;
}

static void capture_csrf(axiam_client_t *c, const axiam_http_response_t *resp) {
    const char *tok = axiam_kv_get(resp->headers, "X-CSRF-Token");
    if (!tok) return;
    pthread_mutex_lock(&c->state_mtx);
    free(c->csrf_token);
    c->csrf_token = axiam_strdup0(tok);
    pthread_mutex_unlock(&c->state_mtx);
}

/* Perform one transport round-trip for a path. state_changing controls CSRF. */
static int transport_once(axiam_client_t *c, const char *method, const char *path,
                          const char *body, int state_changing,
                          axiam_http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
    char *url = build_url(c, path);
    if (!url) return -1;
    axiam_kv_t *headers = build_headers(c, state_changing, body != NULL);

    axiam_http_request_t req = {0};
    req.method = method;
    req.url = url;
    req.headers = headers;
    req.body = body;
    req.body_len = body ? strlen(body) : 0;

    int rc = c->transport(c->transport_ctx, &req, resp);
    capture_csrf(c, resp);

    axiam_kv_free(headers);
    free(url);
    return rc;
}

axiam_error_kind_t axiam_client_raw_get(axiam_client_t *c, const char *path,
                                        char **out_body, axiam_error_t *err) {
    if (out_body) *out_body = NULL;
    if (!c || !path) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    axiam_http_response_t resp;
    int rc = transport_once(c, "GET", path, NULL, 0, &resp);
    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        if (out_body) *out_body = axiam_strdup0(resp.body ? resp.body : "");
    } else {
        kind = axiam_error_kind_from_http_status(resp.status);
        axiam_error_set(err, kind, resp.status, "request failed");
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/* ------------------------------------------------------------------ */
/* Single-flight refresh (§9)                                         */
/* ------------------------------------------------------------------ */

/* The actual refresh transport call (leader only). */
static axiam_error_kind_t perform_refresh(axiam_client_t *c, axiam_error_t *err) {
    char *body = axiam_build_refresh_body(c->cfg);
    if (!body) {
        /* Cannot build a refresh (need tenant_id + org_id UUIDs). */
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "cannot refresh: tenant_id and org_id required");
        return AXIAM_ERR_AUTH;
    }
    axiam_http_response_t resp;
    int rc = transport_once(c, "POST", "/api/v1/auth/refresh", body, 1, &resp);
    free(body);
    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "refresh transport failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
    } else {
        /* §9.3: a 401 on refresh means re-authenticate; no retry loop. */
        kind = axiam_error_kind_from_http_status(resp.status);
        if (kind == AXIAM_OK) kind = AXIAM_ERR_AUTH;
        pthread_mutex_lock(&c->state_mtx);
        c->authenticated = 0;
        pthread_mutex_unlock(&c->state_mtx);
        axiam_error_set(err, kind, resp.status, "token refresh failed");
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/* Coalesce concurrent refreshes: exactly one leader performs the refresh; all
 * other callers block and share its result (§9). */
static axiam_error_kind_t single_flight_refresh(axiam_client_t *c, axiam_error_t *err) {
    pthread_mutex_lock(&c->refresh_mtx);
    if (c->refresh_in_flight) {
        while (c->refresh_in_flight)
            pthread_cond_wait(&c->refresh_cond, &c->refresh_mtx);
        axiam_error_kind_t r = c->refresh_result;
        pthread_mutex_unlock(&c->refresh_mtx);
        if (r != AXIAM_OK)
            axiam_error_set(err, r, 0, "token refresh failed");
        return r;
    }
    c->refresh_in_flight = 1;
    pthread_mutex_unlock(&c->refresh_mtx);

    axiam_error_kind_t r = perform_refresh(c, err);

    pthread_mutex_lock(&c->refresh_mtx);
    c->refresh_in_flight = 0;
    c->refresh_result = r;
    c->refresh_count++;
    pthread_cond_broadcast(&c->refresh_cond);
    pthread_mutex_unlock(&c->refresh_mtx);
    return r;
}

/* ------------------------------------------------------------------ */
/* Response parsing helpers                                           */
/* ------------------------------------------------------------------ */

static char *json_dup_str(const cJSON *obj, const char *key) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(it) && it->valuestring) return axiam_strdup0(it->valuestring);
    return NULL;
}

static long json_get_long(const cJSON *obj, const char *key) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(it)) return (long)it->valuedouble;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Auth operations                                                    */
/* ------------------------------------------------------------------ */

void axiam_login_result_dispose(axiam_login_result_t *r) {
    if (!r) return;
    free(r->challenge_token);
    free(r->setup_token);
    free(r->session_id);
    free(r->user_id);
    free(r->username);
    free(r->email);
    free(r->tenant_id);
    memset(r, 0, sizeof(*r));
}

static axiam_error_kind_t parse_login_like(axiam_client_t *c, axiam_http_response_t *resp,
                                           axiam_login_result_t *out, axiam_error_t *err) {
    long status = resp->status;
    cJSON *root = resp->body ? cJSON_Parse(resp->body) : NULL;

    axiam_error_kind_t kind = AXIAM_OK;
    if (status == 202) {
        /* MFA required — checked before the generic 2xx success branch. */
        if (out) {
            out->mfa_required = 1;
            out->challenge_token = root ? json_dup_str(root, "challenge_token") : NULL;
        }
    } else if (status >= 200 && status < 300) {
        if (out && root) {
            out->authenticated = 1;
            out->session_id = json_dup_str(root, "session_id");
            out->expires_in = json_get_long(root, "expires_in");
            const cJSON *user = cJSON_GetObjectItemCaseSensitive(root, "user");
            if (user) {
                out->user_id = json_dup_str(user, "id");
                out->username = json_dup_str(user, "username");
                out->email = json_dup_str(user, "email");
                out->tenant_id = json_dup_str(user, "tenant_id");
            }
        }
        pthread_mutex_lock(&c->state_mtx);
        c->authenticated = 1;
        pthread_mutex_unlock(&c->state_mtx);
    } else if (status == 403 && root &&
               cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(root, "mfa_setup_required"))) {
        /* MFA enrollment required — not an authorization denial. */
        if (out) {
            out->mfa_setup_required = 1;
            out->setup_token = json_dup_str(root, "setup_token");
        }
    } else {
        kind = axiam_error_kind_from_http_status(status);
        if (kind == AXIAM_OK) kind = AXIAM_ERR_AUTH;
        axiam_error_set(err, kind, status, "authentication failed");
    }
    if (root) cJSON_Delete(root);
    return kind;
}

axiam_error_kind_t axiam_login(axiam_client_t *client, const char *username_or_email,
                               const char *password, axiam_login_result_t *out,
                               axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !username_or_email || !password) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    char *body = axiam_build_login_body(username_or_email, password, client->cfg);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", "/api/v1/auth/login", body, 1, &resp);
    free(body);
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    axiam_error_kind_t kind = parse_login_like(client, &resp, out, err);
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_verify_mfa(axiam_client_t *client, const char *challenge_token,
                                    const char *totp_code, axiam_login_result_t *out,
                                    axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !challenge_token || !totp_code) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    char *body = axiam_build_mfa_body(challenge_token, totp_code);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", "/api/v1/auth/mfa/verify", body, 1, &resp);
    free(body);
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    axiam_error_kind_t kind = parse_login_like(client, &resp, out, err);
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_refresh(axiam_client_t *client, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    return single_flight_refresh(client, err);
}

axiam_error_kind_t axiam_logout(axiam_client_t *client, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", "/api/v1/auth/logout", NULL, 1, &resp);
    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        pthread_mutex_lock(&client->state_mtx);
        client->authenticated = 0;
        pthread_mutex_unlock(&client->state_mtx);
    } else {
        kind = axiam_error_kind_from_http_status(resp.status);
        axiam_error_set(err, kind, resp.status, "logout failed");
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/* ------------------------------------------------------------------ */
/* Authorization operations                                           */
/* ------------------------------------------------------------------ */

void axiam_check_result_dispose(axiam_check_result_t *r) {
    if (!r) return;
    free(r->reason);
    r->reason = NULL;
    r->allowed = 0;
}

static void parse_check_result(const cJSON *obj, axiam_check_result_t *out) {
    if (!out) return;
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(obj, "allowed");
    out->allowed = cJSON_IsTrue(allowed) ? 1 : 0;
    out->reason = json_dup_str(obj, "reason");
}

/* Shared POST-with-single-flight-refresh path for authz checks. */
static axiam_error_kind_t authz_post(axiam_client_t *client, const char *path,
                                     const char *body, char **out_body,
                                     axiam_error_t *err) {
    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", path, body, 1, &resp);
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }

    /* §9: on 401 with an active session, refresh once then retry once. */
    if (resp.status == 401) {
        int authed;
        pthread_mutex_lock(&client->state_mtx);
        authed = client->authenticated;
        pthread_mutex_unlock(&client->state_mtx);
        if (authed) {
            axiam_http_response_dispose(&resp);
            axiam_error_kind_t rk = single_flight_refresh(client, err);
            if (rk != AXIAM_OK) return rk; /* no retry loop */
            rc = transport_once(client, "POST", path, body, 1, &resp);
            if (rc != 0 || resp.status == 0) {
                axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                                resp.transport_msg ? resp.transport_msg : "network failure");
                axiam_http_response_dispose(&resp);
                return AXIAM_ERR_NETWORK;
            }
        }
    }

    axiam_error_kind_t kind;
    if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        if (out_body) *out_body = axiam_strdup0(resp.body ? resp.body : "");
    } else {
        kind = axiam_error_kind_from_http_status(resp.status);
        axiam_error_set(err, kind, resp.status, "authorization check failed");
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_check_access(axiam_client_t *client, const char *action,
                                      const char *resource_id, const char *scope,
                                      const char *subject_id, axiam_check_result_t *out,
                                      axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !action || !resource_id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    char *body = axiam_build_check_body(action, resource_id, scope, subject_id);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    char *resp_body = NULL;
    axiam_error_kind_t kind = authz_post(client, "/api/v1/authz/check", body, &resp_body, err);
    free(body);
    if (kind == AXIAM_OK && resp_body) {
        cJSON *root = cJSON_Parse(resp_body);
        if (root) { parse_check_result(root, out); cJSON_Delete(root); }
    }
    free(resp_body);
    return kind;
}

axiam_error_kind_t axiam_can(axiam_client_t *client, const char *action,
                             const char *resource_id, const char *scope,
                             axiam_check_result_t *out, axiam_error_t *err) {
    /* §1: `can` is an alias for check_access (browser/UI gating). */
    return axiam_check_access(client, action, resource_id, scope, NULL, out, err);
}

axiam_error_kind_t axiam_batch_check(axiam_client_t *client, const axiam_check_input_t *checks,
                                     size_t n, axiam_check_result_t *out_results,
                                     size_t *out_count, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_count) *out_count = 0;
    if (!client || (!checks && n > 0) || !out_results) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    char *body = axiam_build_batch_body(checks, n);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    char *resp_body = NULL;
    axiam_error_kind_t kind = authz_post(client, "/api/v1/authz/check/batch", body, &resp_body, err);
    free(body);
    if (kind == AXIAM_OK && resp_body) {
        cJSON *root = cJSON_Parse(resp_body);
        if (root) {
            const cJSON *results = cJSON_GetObjectItemCaseSensitive(root, "results");
            if (cJSON_IsArray(results)) {
                size_t i = 0;
                const cJSON *item = NULL;
                cJSON_ArrayForEach(item, results) {
                    if (i >= n) break; /* results are ordered, same length as input */
                    parse_check_result(item, &out_results[i]);
                    i++;
                }
                if (out_count) *out_count = i;
            }
            cJSON_Delete(root);
        }
    }
    free(resp_body);
    return kind;
}
