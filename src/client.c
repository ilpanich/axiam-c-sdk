#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "internal.h"

/* §19.1 path templates. Constants, never a URL with ids substituted in — a
 * metric label carrying a UUID is a cardinality bomb. */
#define PATH_AUTHZ_CHECK "/api/v1/authz/check"
#define PATH_AUTHZ_BATCH "/api/v1/authz/check/batch"

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

    /* §16 */
    c->retry_enabled = c->cfg->retry_enabled;
    c->rand_seed = (unsigned int)(time(NULL) ^ (unsigned long)(uintptr_t)c);
    c->jitter_fn = axiam_default_jitter;
    c->jitter_ctx = &c->rand_seed;
    c->sleep_fn = axiam_default_sleep;
    c->sleep_ctx = NULL;

    /* §17: clamps internally; the config keeps the unclamped request so the
     * event below can name it. */
    axiam_memo_init(&c->memo, c->cfg->decision_memo_ttl_ms);

    /* §19 */
    c->telemetry.fn = c->cfg->telemetry_hook;
    c->telemetry.ctx = c->cfg->telemetry_ctx;

    /* §19.2 rule 6: a setting we lowered is reported, not swallowed. An
     * operator who set a 60-second memo TTL believes their staleness bound is
     * 60 seconds; it is five, and without this nothing anywhere says so.
     * Nothing is emitted when the request was already inside the limit — an
     * event that fires when nothing happened trains its reader to ignore it.
     * The memo TTL is the only clamped setting here: §16.1's table is not
     * configurable in this SDK, only switchable. */
    if (c->cfg->decision_memo_ttl_ms > 0 &&
        c->cfg->decision_memo_ttl_ms != axiam_memo_effective_ttl_ms(&c->memo)) {
        char requested[32];
        char effective[32];
        snprintf(requested, sizeof(requested), "%ldms", c->cfg->decision_memo_ttl_ms);
        snprintf(effective, sizeof(effective), "%ldms",
                 axiam_memo_effective_ttl_ms(&c->memo));
        axiam_telemetry_config_clamped(&c->telemetry, "decision_memo_ttl_ms",
                                       requested, effective, "\xc2\xa7""17.1 rule 2");
    }

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

void axiam_client_close(axiam_client_t *client) {
    if (!client) return;

    /* §18.1 rule 2: idempotent. The flag is checked and set under the same
     * lock, so two threads racing on close cannot both reach the release
     * below — cleanup runs from error paths, and an error path that
     * double-frees hides the original failure. */
    pthread_mutex_lock(&client->state_mtx);
    if (client->closed) {
        pthread_mutex_unlock(&client->state_mtx);
        return;
    }
    client->closed = 1;
    /* §18.1 rule 3: the cookie jar and the CSRF token go with the handles.
     * §18.1 rule 6: the CSRF token is scrubbed rather than merely freed. */
    if (client->csrf_token) {
        axiam_secure_zero(client->csrf_token, strlen(client->csrf_token));
        free(client->csrf_token);
        client->csrf_token = NULL;
    }
    pthread_mutex_unlock(&client->state_mtx);

    /* NO REQUEST IS ISSUED HERE (§18.1 rule 5). The server-side session
     * deliberately outlives the client object — that is what lets a process
     * restart and resume — so a close() that logged out would silently end
     * every user's session on each deploy. */
    if (client->curl_ctx) {
        axiam_curl_ctx_free(client->curl_ctx);
        client->curl_ctx = NULL;
    }
    /* The transport pointer goes too: a call that slipped past the closed
     * check must fail on the flag, never dereference a freed ctx. */
    client->transport = NULL;
    client->transport_ctx = NULL;

    pthread_mutex_lock(&client->jwks_mtx);
    jwks_free(client->jwks);
    client->jwks = NULL;
    client->jwks_valid = 0;
    pthread_mutex_unlock(&client->jwks_mtx);

    axiam_memo_clear(&client->memo);
}

void axiam_client_free(axiam_client_t *client) {
    if (!client) return;
    /* §18.1 rule 1 names axiam_client_free as this SDK's canonical shutdown, so
     * free alone must still be complete: close first when the caller did not. */
    axiam_client_close(client);
    axiam_client_config_free(client->cfg);
    free(client->csrf_token);
    free(client->resolved_tenant_id);
    free(client->resolved_org_id);
    axiam_uma_config_dispose(&client->uma_config);
    axiam_memo_destroy(&client->memo);
    pthread_mutex_destroy(&client->state_mtx);
    pthread_mutex_destroy(&client->refresh_mtx);
    pthread_cond_destroy(&client->refresh_cond);
    pthread_mutex_destroy(&client->jwks_mtx);
    free(client);
}

/* §18.1 rule 4: use after close is an error, not undefined. Every entry point
 * runs this first, so a call on a closed client names its cause rather than
 * reconnecting or reading freed memory. */
static int client_is_closed(axiam_client_t *c) {
    if (!c) return 0;
    pthread_mutex_lock(&c->state_mtx);
    int closed = c->closed;
    pthread_mutex_unlock(&c->state_mtx);
    return closed;
}

static axiam_error_kind_t closed_error(axiam_error_t *err) {
    axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                    "client is closed (CONTRACT.md \xc2\xa7""18.1 rule 4)");
    return AXIAM_ERR_NETWORK;
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
    if (client_is_closed(c)) return closed_error(err);
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
    /* Prefer the UUIDs resolved from the access-token claims (D-14); fall back
     * to any UUID-form construction options. A slug is never valid here. */
    pthread_mutex_lock(&c->state_mtx);
    const char *tid = c->resolved_tenant_id ? c->resolved_tenant_id : c->cfg->tenant_id;
    const char *oid = c->resolved_org_id ? c->resolved_org_id : c->cfg->org_id;
    char *body = axiam_build_refresh_body(tid, oid);
    pthread_mutex_unlock(&c->state_mtx);
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
    double started = axiam_telemetry_installed(&c->telemetry) ? axiam_now_ms() : 0.0;

    pthread_mutex_lock(&c->refresh_mtx);
    if (c->refresh_in_flight) {
        while (c->refresh_in_flight)
            pthread_cond_wait(&c->refresh_cond, &c->refresh_mtx);
        axiam_error_kind_t r = c->refresh_result;
        pthread_mutex_unlock(&c->refresh_mtx);
        /* §19.1 refresh: the caller waited on somebody else's refresh. The
         * distinction is the whole value of the event — a follower's latency
         * is the leader's, and without the role they are indistinguishable. */
        axiam_telemetry_refresh(&c->telemetry, AXIAM_REFRESH_FOLLOWER,
                                axiam_telemetry_installed(&c->telemetry)
                                    ? axiam_now_ms() - started
                                    : 0.0);
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

    /* §17.1 rule 9: a refresh is a credential change. */
    axiam_memo_clear(&c->memo);
    axiam_telemetry_refresh(&c->telemetry, AXIAM_REFRESH_LEADER,
                            axiam_telemetry_installed(&c->telemetry)
                                ? axiam_now_ms() - started
                                : 0.0);
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

/* Lift a string claim into a Sensitive handle (§7) and scrub the plaintext
 * copy left inside the parsed document. Returns NULL when absent. */
static axiam_sensitive_t *json_dup_sensitive(cJSON *obj, const char *key) {
    cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(it) || !it->valuestring) return NULL;
    axiam_sensitive_t *s = axiam_sensitive_new(it->valuestring);
    axiam_secure_zero(it->valuestring, strlen(it->valuestring));
    return s;
}

/* Scrub a request body that carried credentials before releasing it (§7). */
static void free_scrubbed(char *body) {
    if (!body) return;
    axiam_secure_zero(body, strlen(body));
    free(body);
}

static long json_get_long(const cJSON *obj, const char *key) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(it)) return (long)it->valuedouble;
    return 0;
}

/* Decode a string claim out of a compact JWT WITHOUT verifying its signature.
 * Used only to recover the tenant_id/org_id the client must echo in the refresh
 * body (the server re-derives and re-validates the authoritative org_id, so this
 * carries no trust weight). Returns a malloc'd value or NULL. */
static char *jwt_claim_dup(const char *jwt, const char *claim) {
    if (!jwt) return NULL;
    const char *dot1 = strchr(jwt, '.');
    if (!dot1) return NULL;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return NULL;
    size_t payload_len = (size_t)(dot2 - (dot1 + 1));
    size_t out_len = 0;
    unsigned char *raw = axiam_b64url_decode(dot1 + 1, payload_len, &out_len);
    if (!raw) return NULL;
    char *json = malloc(out_len + 1);
    if (!json) { free(raw); return NULL; }
    memcpy(json, raw, out_len);
    json[out_len] = '\0';
    free(raw);
    cJSON *root = cJSON_Parse(json);
    free(json);
    if (!root) return NULL;
    char *val = json_dup_str(root, claim);
    cJSON_Delete(root);
    return val;
}

/* Recover the axiam_access cookie's value from the response's Set-Cookie
 * headers (a login sets several cookies). Returns a borrowed pointer into the
 * header list, or NULL. */
static const char *access_cookie_from_headers(const axiam_kv_t *headers) {
    for (const axiam_kv_t *kv = headers; kv; kv = kv->next) {
        if (axiam_str_ieq(kv->key, "Set-Cookie") && kv->value &&
            strncmp(kv->value, "axiam_access=", 13) == 0) {
            return kv->value + 13;
        }
    }
    return NULL;
}

/* After a successful login/verify_mfa, resolve tenant_id/org_id from the
 * access-token claims so refresh() can supply the required UUIDs even when the
 * client was constructed with slugs (D-14). Best-effort; leaves prior values
 * on any decode failure. */
static void resolve_ids_from_login(axiam_client_t *c, const axiam_http_response_t *resp) {
    const char *access = access_cookie_from_headers(resp->headers);
    if (!access) return;
    /* The cookie value may carry attributes ("axiam_access=JWT; Path=/; ..."):
     * copy just the token up to the first ';'. */
    size_t tok_len = strcspn(access, ";");
    char *jwt = malloc(tok_len + 1);
    if (!jwt) return;
    memcpy(jwt, access, tok_len);
    jwt[tok_len] = '\0';

    char *tid = jwt_claim_dup(jwt, "tenant_id");
    char *oid = jwt_claim_dup(jwt, "org_id");
    free(jwt);

    pthread_mutex_lock(&c->state_mtx);
    if (tid) { free(c->resolved_tenant_id); c->resolved_tenant_id = tid; }
    if (oid) { free(c->resolved_org_id); c->resolved_org_id = oid; }
    pthread_mutex_unlock(&c->state_mtx);
}

/* ------------------------------------------------------------------ */
/* Auth operations                                                    */
/* ------------------------------------------------------------------ */

void axiam_login_result_dispose(axiam_login_result_t *r) {
    if (!r) return;
    /* §7: the MFA challenge/setup tokens are secrets — zeroized on release. */
    axiam_sensitive_free(r->challenge_token);
    axiam_sensitive_free(r->setup_token);
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
            out->challenge_token = root ? json_dup_sensitive(root, "challenge_token") : NULL;
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
        /* D-14: the login body carries tenant_id/org_slug but not org_id —
         * recover both UUIDs from the access-token cookie for refresh(). */
        resolve_ids_from_login(c, resp);
    } else if (status == 403 && root &&
               cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(root, "mfa_setup_required"))) {
        /* MFA enrollment required — not an authorization denial. */
        if (out) {
            out->mfa_setup_required = 1;
            out->setup_token = json_dup_sensitive(root, "setup_token");
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
    if (client_is_closed(client)) return closed_error(err);
    /* §17.1 rule 9: cleared on the CALLER'S INTENT to change credentials, not
     * on the server's answer. Entries are keyed by subject rather than session,
     * so a login that failed still means this caller is done with the principal
     * whose decisions are cached. */
    axiam_memo_clear(&client->memo);
    char *body = axiam_build_login_body(username_or_email, password, client->cfg);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", "/api/v1/auth/login", body, 1, &resp);
    free_scrubbed(body); /* §7: the body carried the password. */
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
    if (client_is_closed(client)) return closed_error(err);
    axiam_memo_clear(&client->memo); /* §17.1 rule 9 */
    char *body = axiam_build_mfa_body(challenge_token, totp_code);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    axiam_http_response_t resp;
    int rc = transport_once(client, "POST", "/api/v1/auth/mfa/verify", body, 1, &resp);
    free_scrubbed(body); /* §7: the body carried the challenge token. */
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

axiam_error_kind_t axiam_verify_mfa_sensitive(axiam_client_t *client,
                                              const axiam_sensitive_t *challenge_token,
                                              const char *totp_code,
                                              axiam_login_result_t *out,
                                              axiam_error_t *err) {
    if (!challenge_token) {
        axiam_error_reset(err);
        if (out) memset(out, 0, sizeof(*out));
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    /* The raw value is read through the module-private accessor and never
     * leaves this call (§7). */
    return axiam_verify_mfa(client, (const char *)axiam_sensitive_bytes(challenge_token),
                            totp_code, out, err);
}

axiam_error_kind_t axiam_refresh(axiam_client_t *client, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (client_is_closed(client)) return closed_error(err);
    return single_flight_refresh(client, err);
}

axiam_error_kind_t axiam_logout(axiam_client_t *client, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (client_is_closed(client)) return closed_error(err);
    axiam_memo_clear(&client->memo); /* §17.1 rule 9, before the wire */
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
    free(r->reason_code);
    r->reason_code = NULL;
    r->allowed = 0;
}

static void parse_check_result(const cJSON *obj, axiam_check_result_t *out) {
    if (!out) return;
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(obj, "allowed");
    out->allowed = cJSON_IsTrue(allowed) ? 1 : 0;
    out->reason = json_dup_str(obj, "reason");
    /* §11 rule 9. Copied verbatim, with no validation against the three known
       codes: an unrecognised code must reach the caller, and a server that
       omits the field entirely must read as absent rather than as an error
       (json_dup_str yields NULL for both missing and non-string). */
    out->reason_code = json_dup_str(obj, "reason_code");
}

/*
 * One eligible operation, with the §16 budget and the §19 pairs around it.
 *
 * §16.2: eligibility is "changes no server state", NOT "is a GET". The
 * authorization check is a POST with a body and is the single most important
 * operation in that section — an SDK that gated retry on the HTTP verb would
 * retry nothing that matters. This function is therefore called ONLY from the
 * authz paths; login, verify_mfa, logout and refresh reach transport_once
 * directly and make exactly one attempt.
 *
 * One request_start/request_end pair PER ATTEMPT (§19.2 rule 5), with a retry
 * event between consecutive pairs: a caller must be able to count real wire
 * calls from the events, which one pair per logical operation would hide.
 */
static int transport_retrying(axiam_client_t *c, const char *op, const char *path,
                              const char *body, axiam_http_response_t *resp,
                              int first_attempt, int max_attempts, int *last_attempt) {
    int rc = -1;
    int attempt = first_attempt;

    for (; attempt < first_attempt + max_attempts; attempt++) {
        axiam_telemetry_request_start(&c->telemetry, op, "POST", path, attempt);
        double started = axiam_telemetry_installed(&c->telemetry) ? axiam_now_ms() : 0.0;

        rc = transport_once(c, "POST", path, body, 1, resp);

        int transport_failed = (rc != 0);
        long status = resp->status;
        axiam_telemetry_request_end(
            &c->telemetry, op, "POST", path, attempt, status,
            axiam_telemetry_installed(&c->telemetry) ? axiam_now_ms() - started : 0.0,
            (!transport_failed && status >= 200 && status < 300) ? AXIAM_TELEMETRY_SUCCESS
                                                                 : AXIAM_TELEMETRY_FAILURE);

        if (attempt == first_attempt + max_attempts - 1) break;
        if (!axiam_retry_should_retry(transport_failed, status)) break;

        long retry_after = axiam_retry_after_ms(axiam_kv_get(resp->headers, "Retry-After"));
        long delay = axiam_retry_delay_ms(attempt - first_attempt + 1, retry_after,
                                          c->jitter_fn(c->jitter_ctx));

        /* §16.5: a retried-then-succeeded operation is otherwise invisible —
         * the caller sees a slow success and no signal that the server is
         * failing. The reason carries a status or a transport message, never a
         * token. */
        char reason[96];
        if (transport_failed || status == 0) {
            snprintf(reason, sizeof(reason), "transport failure");
        } else {
            snprintf(reason, sizeof(reason), "HTTP %ld", status);
        }
        axiam_telemetry_retry(&c->telemetry, op, attempt, delay, reason);

        axiam_http_response_dispose(resp);
        c->sleep_fn(c->sleep_ctx, delay);
    }
    if (last_attempt) *last_attempt = attempt;
    return rc;
}

/* Shared POST-with-single-flight-refresh path for authz checks. */
static axiam_error_kind_t authz_post(axiam_client_t *client, const char *path,
                                     const char *body, const char *op,
                                     char **out_body, axiam_error_t *err) {
    axiam_http_response_t resp;
    int budget = client->retry_enabled ? AXIAM_RETRY_MAX_ATTEMPTS : 1;
    int spent = 1;
    int rc = transport_retrying(client, op, path, body, &resp, 1, budget, &spent);
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }

    /* §9: on 401 with an active session, refresh once then retry once.
     * §16.2: the two mechanisms compose in one direction only. The §16 budget
     * is NOT reset by a §9 refresh occurring mid-operation — one §9 refresh,
     * one §16 budget, per logical call — so the post-refresh attempt below is
     * exactly one attempt, numbered after the ones already spent. */
    if (resp.status == 401) {
        int authed;
        pthread_mutex_lock(&client->state_mtx);
        authed = client->authenticated;
        pthread_mutex_unlock(&client->state_mtx);
        if (authed) {
            axiam_http_response_dispose(&resp);
            axiam_error_kind_t rk = single_flight_refresh(client, err);
            if (rk != AXIAM_OK) return rk; /* no retry loop */
            rc = transport_retrying(client, op, path, body, &resp, spent + 1, 1, NULL);
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
    if (client_is_closed(client)) return closed_error(err);

    /* §17: consulted before the wire, written only after a decision the server
     * actually returned. */
    char *key = NULL;
    if (axiam_memo_enabled(&client->memo) && out) {
        key = axiam_memo_key(subject_id, resource_id, action, scope);
        if (key && axiam_memo_get(&client->memo, key, out)) {
            free(key);
            return AXIAM_OK;
        }
    }

    char *body = axiam_build_check_body(action, resource_id, scope, subject_id);
    if (!body) {
        free(key);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    char *resp_body = NULL;
    axiam_error_kind_t kind =
        authz_post(client, PATH_AUTHZ_CHECK, body, "check_access", &resp_body, err);
    free(body);
    if (kind == AXIAM_OK && resp_body) {
        cJSON *root = cJSON_Parse(resp_body);
        if (root) { parse_check_result(root, out); cJSON_Delete(root); }
        /* §17.1 rule 7: only a decision the server actually returned. A
         * NetworkError, a 503 or an exhausted §16 budget is never an entry —
         * memoizing a transport failure as a deny would turn a blip into a
         * TTL-long outage, and memoizing it as an allow is unthinkable.
         * Rule 4: allows and denies are stored identically, because asymmetric
         * caching changes the timing of the two outcomes and so leaks which one
         * occurred to anyone who can observe latency. */
        if (key) axiam_memo_put(&client->memo, key, out);
    }
    free(key);
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
    if (client_is_closed(client)) return closed_error(err);
    char *body = axiam_build_batch_body(checks, n);
    if (!body) { axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory"); return AXIAM_ERR_NETWORK; }

    char *resp_body = NULL;
    /* Deliberately NOT memoized: the memo key is per-check, so a batch would
     * have to be split into n entries with n keys — which is the right design,
     * but it changes what a partial cache hit means (some rows from the wire,
     * some from the memo, one composite result). §17 says nothing about batch,
     * so this SDK does the conservative thing rather than inventing semantics. */
    axiam_error_kind_t kind =
        authz_post(client, PATH_AUTHZ_BATCH, body, "batch_check", &resp_body, err);
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
