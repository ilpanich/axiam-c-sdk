/*
 * AXIAM C SDK — the nine §12 relying-party operations, plus the discovery cache
 * and PKCE construction they share.
 *
 * See include/axiam/oidc.h for the design notes and for why contract 1.11
 * un-deferred this section here. Three things are worth repeating where the
 * code lives:
 *
 *  - axiam_oidc_begin() touches NO network and does not acquire the transport
 *    (§12.6). It allocates a URL and a verifier the caller frees.
 *  - The five tenant-scoped operations refuse a slug CLIENT-SIDE, with no wire
 *    call (§12.3 rule 4). Sending a slug where the server wants a UUID would
 *    fail anyway; refusing here is about not making the caller read a server
 *    error to learn something the SDK already knew.
 *  - Nothing here adopts a token. Every operation returns one; the client's own
 *    credential is untouched.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "cJSON.h"
#include "oidc_internal.h"

#define PATH_OIDC_DISCOVERY "/.well-known/openid-configuration"
#define PATH_SSO_START      "/api/v1/auth/federation/oidc/start"
#define PATH_SSO_COMPLETE   "/api/v1/auth/federation/oidc/callback"
#define PATH_SSO_PROVIDERS  "/api/v1/auth/federation/providers"
#define PATH_SSO_OAUTH2_START    "/api/v1/auth/federation/oauth2/start"
#define PATH_SSO_OAUTH2_CALLBACK "/api/v1/auth/federation/oauth2/callback"
#define PATH_SSO_HANDOFF         "/api/v1/auth/federation/handoff"

#define FORM_CONTENT_TYPE "application/x-www-form-urlencoded"

/* ------------------------------------------------------------------ */
/* Form bodies                                                        */
/* ------------------------------------------------------------------ */

void oidc_form_init(oidc_form_t *f) {
    memset(f, 0, sizeof(*f));
    f->cap = 512;
    f->buf = malloc(f->cap);
    if (!f->buf) { f->failed = 1; return; }
    f->buf[0] = '\0';
}

static int form_reserve(oidc_form_t *f, size_t extra) {
    if (f->failed) return 0;
    if (f->len + extra + 1 <= f->cap) return 1;
    size_t cap = f->cap;
    while (cap < f->len + extra + 1) cap *= 2;
    char *grown = realloc(f->buf, cap);
    if (!grown) { f->failed = 1; return 0; }
    f->buf = grown;
    f->cap = cap;
    return 1;
}

/* Percent-encode into the buffer, RFC 3986 unreserved set only. */
static void form_append_encoded(oidc_form_t *f, const char *s) {
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char ch = (unsigned char)s[i];
        int unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                         ch == '_' || ch == '~';
        if (!form_reserve(f, 3)) return;
        if (unreserved) {
            f->buf[f->len++] = (char)ch;
        } else {
            f->buf[f->len++] = '%';
            f->buf[f->len++] = hex[ch >> 4];
            f->buf[f->len++] = hex[ch & 0xF];
        }
        f->buf[f->len] = '\0';
    }
}

void oidc_form_add(oidc_form_t *f, const char *key, const char *value) {
    /* §12.1: "MUST omit (rather than send empty/null) any optional field the
     * caller did not supply". Every optional field in this file routes through
     * here, so the rule is enforced in one place rather than at each call. */
    if (!value || !value[0]) return;
    if (f->failed) return;
    if (f->len > 0) {
        if (!form_reserve(f, 1)) return;
        f->buf[f->len++] = '&';
        f->buf[f->len] = '\0';
    }
    form_append_encoded(f, key);
    if (!form_reserve(f, 1)) return;
    f->buf[f->len++] = '=';
    f->buf[f->len] = '\0';
    form_append_encoded(f, value);
}

void oidc_form_dispose(oidc_form_t *f) {
    if (!f || !f->buf) return;
    /* A form body routinely carries a client secret, a refresh token or an
     * authorization code. Scrub before release rather than leaving them in a
     * freed heap block (§7). */
    axiam_secure_zero(f->buf, f->cap);
    free(f->buf);
    memset(f, 0, sizeof(*f));
}

/* ------------------------------------------------------------------ */
/* Guards and small helpers                                           */
/* ------------------------------------------------------------------ */

int oidc_client_unusable(axiam_client_t *c, axiam_error_t *err) {
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

int oidc_is_uuid(const char *s) {
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

const char *oidc_require_tenant_uuid(axiam_client_t *c, const char *explicit_id,
                                     const char *operation, axiam_error_t *err) {
    const char *tenant = (explicit_id && explicit_id[0]) ? explicit_id : c->cfg->tenant_id;
    if (oidc_is_uuid(tenant)) return tenant;
    /*
     * §12.3 rule 4 and §12.1 note 2's "a slug-only client cannot call five of
     * the nine operations". The header and the query parameter legitimately
     * disagree in FORM — X-Tenant-ID carries whatever the client was built
     * with, which may be a slug, while `?tenant_id=` requires a UUID — but a
     * slug is never a valid substitute in the query parameter, and sending one
     * is what this refuses. The remedy is in the message because an operator
     * hitting this needs to know it is a construction choice, not an outage.
     */
    char msg[224];
    snprintf(msg, sizeof(msg),
             "%s requires a tenant_id UUID for the /oauth2 query parameter; this "
             "client has only a tenant slug and a slug is never a substitute "
             "(§12.3 rule 4). Construct the client with tenant_id, or pass one "
             "per call.",
             operation);
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
    return NULL;
}

const char *oidc_require_client_id(axiam_client_t *c, const char *operation,
                                   axiam_error_t *err) {
    const char *id = c->cfg->oidc_client_id;
    if (id && id[0]) return id;
    char msg[192];
    snprintf(msg, sizeof(msg),
             "%s requires an OIDC client_id; set it with "
             "axiam_client_config_set_oidc_client_id() (§12.1: it is "
             "configuration, not a per-call argument)",
             operation);
    /* §12.1: fail fast with NO wire call. A missing client registration is a
     * deployment mistake, not an authentication outcome. */
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
    return NULL;
}

const char *oidc_require_client_secret(axiam_client_t *c, const char *operation,
                                       axiam_error_t *err) {
    const char *secret = axiam_sensitive_reveal(c->cfg->oidc_client_secret);
    if (secret && secret[0]) return secret;
    char msg[192];
    snprintf(msg, sizeof(msg),
             "%s is a confidential-client operation and requires an OIDC "
             "client_secret; a public client cannot call it (§12.1 rule 4)",
             operation);
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
    return NULL;
}

char *oidc_endpoint_with_tenant(const char *endpoint, const char *tenant_uuid) {
    if (!endpoint || !tenant_uuid) return NULL;
    size_t n = strlen(endpoint) + strlen(tenant_uuid) + 16;
    char *url = malloc(n);
    if (!url) return NULL;
    /* §12.1 note 2: tenant_id is a QUERY parameter and never a body field —
     * TokenRequest, IntrospectRequest and RevokeRequest have no such property. */
    snprintf(url, n, "%s%ctenant_id=%s", endpoint,
             strchr(endpoint, '?') ? '&' : '?', tenant_uuid);
    return url;
}

/* ------------------------------------------------------------------ */
/* Transport                                                          */
/* ------------------------------------------------------------------ */

/* One round trip against an absolute URL. §5 rule 2 is unconditional, so
 * X-Tenant-ID goes out here even on the /oauth2/ paths where the server reads
 * the tenant only from the query parameter and the header is inert. */
static int oidc_transport_once(axiam_client_t *c, const char *method, const char *url,
                               const char *content_type, const char *body,
                               axiam_http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
    axiam_kv_t *headers = NULL;
    headers = axiam_kv_append(headers, "X-Tenant-ID",
                              c->cfg->tenant_id && c->cfg->tenant_id[0]
                                  ? c->cfg->tenant_id : c->cfg->tenant_slug);
    headers = axiam_kv_append(headers, "Accept", "application/json");
    if (content_type) headers = axiam_kv_append(headers, "Content-Type", content_type);
    /* §12.1 note 8: the /oauth2 paths are unauthenticated, so no axiam_csrf cookie exists
     * yet on a first call. §3 step 3 already governs this — omit the header
     * rather than inventing a value — so none is added. */

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

int oidc_post(axiam_client_t *c, const char *url, const char *content_type,
              const char *body, int retryable, axiam_http_response_t *resp) {
    int budget = (retryable && c->retry_enabled) ? AXIAM_RETRY_MAX_ATTEMPTS : 1;

    /*
     * A local §16 loop rather than client.c's, because these endpoints come out
     * of the discovery document as ABSOLUTE urls and client.c's helper joins a
     * path onto the base URL. Same primitives, same table — §16.1's values are
     * in retry.c and neither loop can raise them.
     */
    int rc = -1;
    for (int attempt = 1; attempt <= budget; attempt++) {
        rc = oidc_transport_once(c, "POST", url, content_type, body, resp);
        if (attempt == budget) break;
        if (!axiam_retry_should_retry(rc != 0, resp->status)) break;

        long retry_after = axiam_retry_after_ms(axiam_kv_get(resp->headers, "Retry-After"));
        long delay = axiam_retry_delay_ms(attempt, retry_after, c->jitter_fn(c->jitter_ctx));
        axiam_http_response_dispose(resp);
        c->sleep_fn(c->sleep_ctx, delay);
    }
    return rc;
}

/*
 * One GET, no §16 retry loop.
 *
 * `sso_providers` is the only §12 operation that is a GET, and it is not
 * retried: the two answers it can give are a `200` (an empty list included —
 * §12.1 note 9) and an error the caller is meant to see, and a retried listing
 * would spend the login rate-limit budget that bounds slug guessing.
 */
static int oidc_get(axiam_client_t *c, const char *url, axiam_http_response_t *resp) {
    return oidc_transport_once(c, "GET", url, NULL, NULL, resp);
}

axiam_error_kind_t oidc_map_grant_error(const axiam_http_response_t *resp,
                                        const char *context, axiam_error_t *err) {
    cJSON *root = resp->body ? cJSON_Parse(resp->body) : NULL;
    const cJSON *code = root ? cJSON_GetObjectItemCaseSensitive(root, "error") : NULL;
    const cJSON *desc = root ? cJSON_GetObjectItemCaseSensitive(root, "error_description") : NULL;

    if (cJSON_IsString(code) && code->valuestring && code->valuestring[0]) {
        /*
         * §12.3 rule 3: an OAuth2ErrorResponse surfaces as an authentication
         * failure carrying `error` and `error_description`, with the message
         * "<error>: <error_description>". A 400 from /oauth2/token must NOT
         * become the generic §2 400 row — that mapping would erase exactly the
         * field §14.2 rule 5 and §15.3 tell callers to dispatch on.
         *
         * `error_description` is server free text. It is copied into the
         * message because the contract specifies that message shape, and the
         * message is a fixed-size buffer that never receives a token, a secret
         * or a verifier from this SDK — §2's construction rules hold.
         */
        char msg[256];
        if (cJSON_IsString(desc) && desc->valuestring && desc->valuestring[0]) {
            snprintf(msg, sizeof(msg), "%s: %s", code->valuestring, desc->valuestring);
        } else {
            snprintf(msg, sizeof(msg), "%s (%s)", code->valuestring, context);
        }
        axiam_error_set(err, AXIAM_ERR_AUTH, resp->status, msg);
        if (err) snprintf(err->oauth_error, sizeof(err->oauth_error), "%s", code->valuestring);
        cJSON_Delete(root);
        return AXIAM_ERR_AUTH;
    }

    cJSON_Delete(root);
    /* Not an OAuth2ErrorResponse — a proxy's HTML 502, say. The ordinary §2
     * status mapping applies rather than an auth error with no code. */
    axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp->status);
    axiam_error_set(err, kind, resp->status, context);
    return kind;
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_discover                                                */
/* ------------------------------------------------------------------ */

static char **json_strings(const cJSON *root, const char *name, size_t *out_count) {
    *out_count = 0;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsArray(v)) return NULL;
    int n = cJSON_GetArraySize(v);
    if (n <= 0) return NULL;
    char **items = calloc((size_t)n, sizeof(char *));
    if (!items) return NULL;
    for (int i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(v, i);
        if (cJSON_IsString(e) && e->valuestring) items[(*out_count)++] = axiam_strdup0(e->valuestring);
    }
    return items;
}

static char *json_opt(const cJSON *root, const char *name) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0]) return NULL;
    return axiam_strdup0(v->valuestring);
}

static axiam_error_kind_t parse_discovery(const char *json, axiam_oidc_config_t *out,
                                          axiam_error_t *err) {
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "oidc discovery: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    out->issuer = json_opt(root, "issuer");
    out->authorization_endpoint = json_opt(root, "authorization_endpoint");
    out->token_endpoint = json_opt(root, "token_endpoint");
    out->jwks_uri = json_opt(root, "jwks_uri");
    out->userinfo_endpoint = json_opt(root, "userinfo_endpoint");
    out->introspection_endpoint = json_opt(root, "introspection_endpoint");
    out->revocation_endpoint = json_opt(root, "revocation_endpoint");
    out->end_session_endpoint = json_opt(root, "end_session_endpoint");
    out->device_authorization_endpoint = json_opt(root, "device_authorization_endpoint");
    /* §26.1: optional, so an absent value is a fact about the server rather
     * than a malformed document. */
    out->pushed_authorization_request_endpoint =
        json_opt(root, "pushed_authorization_request_endpoint");
    out->scopes_supported = json_strings(root, "scopes_supported", &out->scopes_supported_count);
    out->response_types_supported =
        json_strings(root, "response_types_supported", &out->response_types_supported_count);
    out->id_token_signing_alg_values_supported =
        json_strings(root, "id_token_signing_alg_values_supported",
                     &out->id_token_signing_alg_values_supported_count);
    cJSON_Delete(root);

    /* The four §12 cannot work without. The optional endpoints stay NULL and
     * the operations that need them say so by name — a server without an
     * `end_session_endpoint` should fail at axiam_logout_url(), not at
     * discovery, which every other operation depends on. */
    if (!out->issuer || !out->authorization_endpoint || !out->token_endpoint || !out->jwks_uri) {
        axiam_oidc_config_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "oidc discovery: missing issuer / authorization_endpoint / "
                        "token_endpoint / jwks_uri");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

static long oidc_discovery_ttl(const axiam_client_t *c) {
    long ttl = c->cfg->oidc_discovery_ttl_s;
    return ttl < AXIAM_OIDC_DISCOVERY_TTL_FLOOR_S ? AXIAM_OIDC_DISCOVERY_TTL_FLOOR_S : ttl;
}

axiam_error_kind_t axiam_oidc_discover(axiam_client_t *client, axiam_oidc_config_t *out,
                                       axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    /*
     * §12.3 rule 6's single-flight, in its simplest correct form: the lock is
     * held across the FETCH, not just around the cache read. A second caller
     * arriving mid-fetch blocks here and then finds the cache warm, so a burst
     * of N concurrent callers produces exactly one wire call — which is the
     * observable §9 rule 2 asks for. A more elaborate leader/follower
     * arrangement would buy nothing: there is one document and every waiter
     * wants the same one.
     */
    pthread_mutex_lock(&client->oidc_config_mtx);
    int fresh = client->oidc_config_valid &&
                (time(NULL) - client->oidc_config_fetched_at) < oidc_discovery_ttl(client);
    if (fresh) {
        axiam_error_kind_t copied = oidc_config_copy(&client->oidc_config, out);
        pthread_mutex_unlock(&client->oidc_config_mtx);
        if (copied != AXIAM_OK) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
        return AXIAM_OK;
    }

    char *body = NULL;
    /* §16.2 lists the discovery fetch as eligible — it is a pure read. It goes
     * through axiam_client_raw_get, which is the same path the JWKS fetch uses. */
    axiam_error_kind_t kind = axiam_client_raw_get(client, PATH_OIDC_DISCOVERY, &body, err);
    if (kind != AXIAM_OK) {
        pthread_mutex_unlock(&client->oidc_config_mtx);
        return kind;
    }
    kind = parse_discovery(body, out, err);
    free(body);
    if (kind != AXIAM_OK) {
        pthread_mutex_unlock(&client->oidc_config_mtx);
        return kind;
    }

    axiam_oidc_config_dispose(&client->oidc_config);
    if (oidc_config_copy(out, &client->oidc_config) == AXIAM_OK) {
        client->oidc_config_fetched_at = time(NULL);
        client->oidc_config_valid = 1;
    } else {
        /* A cache that could not be populated is simply not populated; the
         * caller's copy is already built and the call succeeds. */
        client->oidc_config_valid = 0;
    }
    pthread_mutex_unlock(&client->oidc_config_mtx);
    return AXIAM_OK;
}

void axiam_oidc_client_dispose(axiam_client_t *c) {
    if (!c) return;
    pthread_mutex_lock(&c->oidc_config_mtx);
    axiam_oidc_config_dispose(&c->oidc_config);
    c->oidc_config_valid = 0;
    pthread_mutex_unlock(&c->oidc_config_mtx);
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_begin — PKCE, state, nonce                              */
/* ------------------------------------------------------------------ */

/* base64url without padding (RFC 4648 §5). */
static char *b64url_encode(const unsigned char *data, size_t len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *out = malloc(((len + 2) / 3) * 4 + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = (unsigned)data[i] << 16;
        size_t have = 1;
        if (i + 1 < len) { v |= (unsigned)data[i + 1] << 8; have = 2; }
        if (i + 2 < len) { v |= (unsigned)data[i + 2]; have = 3; }
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        if (have > 1) out[o++] = alphabet[(v >> 6) & 0x3F];
        if (have > 2) out[o++] = alphabet[v & 0x3F];
    }
    out[o] = '\0';
    return out;
}

/* 32 CSPRNG bytes, base64url without padding — 43 characters, which is both
 * §12.1's RECOMMENDED code_verifier construction and comfortably over the
 * 16-byte floor for `state` and `nonce`. */
static char *random_b64url(void) {
    unsigned char raw[32];
    if (RAND_bytes(raw, (int)sizeof(raw)) != 1) return NULL;
    char *s = b64url_encode(raw, sizeof(raw));
    axiam_secure_zero(raw, sizeof(raw));
    return s;
}

/* §12.1 rule 3: code_challenge = BASE64URL(SHA256(ASCII(verifier))). */
char *oidc_s256_challenge(const char *verifier) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, verifier, strlen(verifier)) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != SHA256_DIGEST_LENGTH) return NULL;
    return b64url_encode(digest, len);
}

/* Percent-encode a query-parameter value into a growing buffer. */
static void url_add_param(oidc_form_t *q, const char *key, const char *value) {
    oidc_form_add(q, key, value);
}

axiam_error_kind_t axiam_oidc_begin(axiam_client_t *client,
                                    const axiam_oidc_config_t *config,
                                    const char *redirect_uri, const char *scope,
                                    axiam_authorization_request_t *out,
                                    axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (!client || !config || !config->authorization_endpoint || !redirect_uri ||
        !redirect_uri[0]) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "oidc_begin requires a discovery document and a redirect_uri");
        return AXIAM_ERR_NETWORK;
    }
    /* NO closed-client check and NO transport acquisition here: §12.6 makes
     * oidc_begin synchronous and network-free in this SDK specifically, so it
     * must keep working on a client whose transport has been released. */
    const char *client_id = oidc_require_client_id(client, "oidc_begin", err);
    if (!client_id) return AXIAM_ERR_AUTH;

    char *state = random_b64url();
    char *nonce = random_b64url();
    char *verifier = random_b64url();
    char *challenge = verifier ? oidc_s256_challenge(verifier) : NULL;
    if (!state || !nonce || !verifier || !challenge) {
        free(state);
        free(nonce);
        if (verifier) axiam_secure_zero(verifier, strlen(verifier));
        free(verifier);
        free(challenge);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "oidc_begin: could not draw cryptographic randomness");
        return AXIAM_ERR_NETWORK;
    }

    /* §12.1 rule 4: the scope MUST contain `openid`; the helper adds it when
     * the caller omits it. Whole-token matching, so a caller asking for
     * "openid_extra" does not accidentally satisfy the rule. */
    char *scopes = NULL;
    {
        const char *requested = (scope && scope[0]) ? scope : "";
        int has_openid = 0;
        for (const char *p = requested; *p;) {
            const char *sp = strchr(p, ' ');
            size_t n = sp ? (size_t)(sp - p) : strlen(p);
            if (n == 6 && strncmp(p, "openid", 6) == 0) { has_openid = 1; break; }
            p = sp ? sp + 1 : p + n;
        }
        size_t need = strlen(requested) + 8;
        scopes = malloc(need);
        if (scopes) {
            if (has_openid) snprintf(scopes, need, "%s", requested);
            else if (requested[0]) snprintf(scopes, need, "openid %s", requested);
            else snprintf(scopes, need, "openid");
        }
    }

    /* §12.1 rule 5: exactly these eight parameters, and no others of the SDK's
     * own. The endpoint comes from the discovery document, never hardcoded. */
    oidc_form_t q;
    oidc_form_init(&q);
    url_add_param(&q, "response_type", "code");
    url_add_param(&q, "client_id", client_id);
    url_add_param(&q, "redirect_uri", redirect_uri);
    url_add_param(&q, "scope", scopes);
    url_add_param(&q, "state", state);
    url_add_param(&q, "nonce", nonce);
    url_add_param(&q, "code_challenge", challenge);
    url_add_param(&q, "code_challenge_method", "S256");

    char *url = NULL;
    if (scopes && !q.failed) {
        size_t n = strlen(config->authorization_endpoint) + q.len + 2;
        url = malloc(n);
        if (url) {
            snprintf(url, n, "%s%c%s", config->authorization_endpoint,
                     strchr(config->authorization_endpoint, '?') ? '&' : '?', q.buf);
        }
    }
    oidc_form_dispose(&q);
    free(scopes);
    free(challenge);

    out->url = url;
    out->state = state;
    out->nonce = nonce;
    out->code_verifier = axiam_sensitive_new(verifier);
    /* The plain copy dies here: from now on the verifier lives only behind the
     * Sensitive handle (§12.5 — secret for its whole lifetime). */
    axiam_secure_zero(verifier, strlen(verifier));
    free(verifier);

    if (!out->url || !out->code_verifier) {
        axiam_authorization_request_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* The token-endpoint grants                                          */
/* ------------------------------------------------------------------ */

/* See oidc_internal.h for why `retryable` is a parameter. */
axiam_error_kind_t oidc_token_grant(axiam_client_t *c, oidc_form_t *form,
                                    const axiam_oidc_config_t *config,
                                    const char *tenant_uuid, int retryable,
                                    const char *context, char **out_body,
                                    axiam_error_t *err) {
    *out_body = NULL;
    if (form->failed) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    char *url = oidc_endpoint_with_tenant(config->token_endpoint, tenant_uuid);
    if (!url) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = oidc_post(c, url, FORM_CONTENT_TYPE, form->buf, retryable, &resp);
    free(url);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        *out_body = axiam_strdup0(resp.body ? resp.body : "");
        if (!*out_body) {
            kind = AXIAM_ERR_NETWORK;
            axiam_error_set(err, kind, 0, "out of memory");
        }
    } else {
        kind = oidc_map_grant_error(&resp, context, err);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/* Add `client_id` plus, when the client is confidential, `client_secret`
 * (client_secret_post — §12.1 rule 3 forbids HTTP Basic on the /oauth2 paths). A
 * public client sends no secret field at all. */
static void form_add_client_auth(axiam_client_t *c, oidc_form_t *form, const char *client_id) {
    oidc_form_add(form, "client_id", client_id);
    oidc_form_add(form, "client_secret", axiam_sensitive_reveal(c->cfg->oidc_client_secret));
}

axiam_error_kind_t axiam_oidc_exchange(axiam_client_t *client,
                                       const axiam_oidc_exchange_params_t *params,
                                       axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !params) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    if (!params->code || !params->code[0] || !params->redirect_uri ||
        !params->redirect_uri[0] || !axiam_sensitive_reveal(params->code_verifier)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "oidc_exchange requires code, code_verifier and the same "
                        "redirect_uri the authorization request carried");
        return AXIAM_ERR_AUTH;
    }
    if (!params->nonce || !params->nonce[0]) {
        /* §12.4 rule 6 is MANDATORY for this operation: the helper always
         * requests `openid`, so the server always issues a nonce, and a caller
         * with nothing to compare against has lost replay protection without
         * noticing. Refusing here is louder than silently skipping the check. */
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "oidc_exchange requires the nonce oidc_begin produced "
                        "(§12.4 rule 6 is mandatory here)");
        return AXIAM_ERR_AUTH;
    }

    const char *client_id = oidc_require_client_id(client, "oidc_exchange", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, params->tenant_id, "oidc_exchange", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;

    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", "authorization_code");
    oidc_form_add(&form, "code", params->code);
    oidc_form_add(&form, "code_verifier", axiam_sensitive_reveal(params->code_verifier));
    oidc_form_add(&form, "redirect_uri", params->redirect_uri);
    form_add_client_auth(client, &form, client_id);

    char *body = NULL;
    /* NOT retryable (§16.2): the authorization code is consumed by the attempt. */
    kind = oidc_token_grant(client, &form, &config, tenant, 0, "oidc exchange failed",
                            &body, err);
    oidc_form_dispose(&form);
    if (kind == AXIAM_OK) {
        kind = oidc_parse_token_set(client, body, &config, params->nonce, out, err);
    }
    free(body);
    axiam_oidc_config_dispose(&config);
    return kind;
}

axiam_error_kind_t axiam_login_client_credentials(axiam_client_t *client, const char *scope,
                                                  const char *tenant_id,
                                                  axiam_oidc_token_set_t *out,
                                                  axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *client_id = oidc_require_client_id(client, "login_client_credentials", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *secret = oidc_require_client_secret(client, "login_client_credentials", err);
    if (!secret) return AXIAM_ERR_AUTH;
    const char *tenant =
        oidc_require_tenant_uuid(client, tenant_id, "login_client_credentials", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;

    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", "client_credentials");
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "client_secret", secret);
    /* Optional — and omitted rather than sent empty. A SERVICE ACCOUNT registers
     * no scopes at all, so asking for one answers `invalid_scope` (§12.1); its
     * authorization comes from its assigned roles. */
    oidc_form_add(&form, "scope", scope);

    char *body = NULL;
    kind = oidc_token_grant(client, &form, &config, tenant, 0,
                            "client credentials login failed", &body, err);
    oidc_form_dispose(&form);
    if (kind == AXIAM_OK) {
        /* §12.4 rule 6 is skipped: this grant requests no `openid` scope and
         * had no authorization request to carry a nonce. Rules 1-5 and 7 still
         * apply to any id_token that arrives anyway. */
        kind = oidc_parse_token_set(client, body, &config, NULL, out, err);
    }
    free(body);
    axiam_oidc_config_dispose(&config);
    return kind;
}

/* ------------------------------------------------------------------ */
/* §12.1 introspect / revoke                                          */
/* ------------------------------------------------------------------ */

/* Both are `POST` + form + `?tenant_id=`, both confidential-only, and both map
 * a 401 straight to an auth error WITHOUT entering the §9 refresh guard
 * (§12.3 rule 3: a wrong client secret is not a session expiry, and refreshing
 * cannot help). The single shared body keeps that property from drifting. */
static axiam_error_kind_t oidc_token_admin_call(
    axiam_client_t *client, const char *fallback_path, const axiam_sensitive_t *token,
    const char *token_type_hint, const char *tenant_id, const char *operation,
    int retryable, char **out_body, axiam_error_t *err) {
    *out_body = NULL;
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    const char *raw = axiam_sensitive_reveal(token);
    if (!raw || !raw[0]) {
        char msg[128];
        snprintf(msg, sizeof(msg), "%s requires a token", operation);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return AXIAM_ERR_AUTH;
    }
    const char *client_id = oidc_require_client_id(client, operation, err);
    if (!client_id) return AXIAM_ERR_AUTH;
    const char *secret = oidc_require_client_secret(client, operation, err);
    if (!secret) return AXIAM_ERR_AUTH;
    const char *tenant = oidc_require_tenant_uuid(client, tenant_id, operation, err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;

    /* The document advertises both endpoints; the fallback exists only for a
     * deployment whose discovery omits one, and is joined onto the CLIENT'S BASE
     * URL rather than onto the issuer — §12.7.2 rule 1 makes the same point
     * about `end_session_endpoint`, and the reasoning is identical here: the
     * issuer may legitimately be some other origin behind a proxy. */
    const char *endpoint = (strcmp(operation, "introspect") == 0)
                               ? config.introspection_endpoint
                               : config.revocation_endpoint;
    char *joined = NULL;
    if (!endpoint || !endpoint[0]) {
        size_t blen = strlen(client->cfg->base_url);
        while (blen > 0 && client->cfg->base_url[blen - 1] == '/') blen--;
        joined = malloc(blen + strlen(fallback_path) + 1);
        if (joined) {
            memcpy(joined, client->cfg->base_url, blen);
            strcpy(joined + blen, fallback_path);
        }
        endpoint = joined;
    }
    char *url = endpoint ? oidc_endpoint_with_tenant(endpoint, tenant) : NULL;
    free(joined);
    if (!url) {
        axiam_oidc_config_dispose(&config);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "token", raw);
    oidc_form_add(&form, "token_type_hint", token_type_hint);
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "client_secret", secret);

    /* Zero-initialised for the same reason as in src/oidc_device.c: a poisoned
     * form skips the POST, after which the transport-error arm below still
     * reads and disposes resp. An indeterminate one is a wild free. */
    axiam_http_response_t resp = {0};
    /* §16.2 lists introspection as eligible — it is a read ABOUT a token and
     * mints nothing. Revocation is a mutation and its caller passes 0. */
    int rc = form.failed ? -1
                         : oidc_post(client, url, FORM_CONTENT_TYPE, form.buf, retryable, &resp);
    oidc_form_dispose(&form);
    free(url);
    axiam_oidc_config_dispose(&config);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (resp.status >= 200 && resp.status < 300) {
        *out_body = axiam_strdup0(resp.body ? resp.body : "");
        axiam_http_response_dispose(&resp);
        return *out_body ? AXIAM_OK : AXIAM_ERR_NETWORK;
    }
    char context[96];
    snprintf(context, sizeof(context), "%s failed", operation);
    kind = oidc_map_grant_error(&resp, context, err);
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_introspect(axiam_client_t *client, const axiam_sensitive_t *token,
                                    const char *token_type_hint, const char *tenant_id,
                                    axiam_introspection_result_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));

    char *body = NULL;
    axiam_error_kind_t kind =
        oidc_token_admin_call(client, "/oauth2/introspect", token, token_type_hint,
                              tenant_id, "introspect", 1, &body, err);
    if (kind != AXIAM_OK) return kind;

    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "introspect: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    const cJSON *active = cJSON_GetObjectItemCaseSensitive(root, "active");
    /* `active` is the only guaranteed field: an inactive token answers
     * {"active":false} and nothing else, which is the point of RFC 7662. */
    out->active = cJSON_IsTrue(active) ? 1 : 0;
    out->scope = json_opt(root, "scope");
    out->client_id = json_opt(root, "client_id");
    out->username = json_opt(root, "username");
    out->token_type = json_opt(root, "token_type");
    out->subject = json_opt(root, "sub");
    out->audience = json_opt(root, "aud");
    out->issuer = json_opt(root, "iss");
    out->jwt_id = json_opt(root, "jti");
    const cJSON *exp = cJSON_GetObjectItemCaseSensitive(root, "exp");
    const cJSON *iat = cJSON_GetObjectItemCaseSensitive(root, "iat");
    out->expires_at = cJSON_IsNumber(exp) ? (long long)exp->valuedouble : 0;
    out->issued_at = cJSON_IsNumber(iat) ? (long long)iat->valuedouble : 0;
    cJSON_Delete(root);
    return AXIAM_OK;
}

axiam_error_kind_t axiam_revoke(axiam_client_t *client, const axiam_sensitive_t *token,
                                const char *token_type_hint, const char *tenant_id,
                                axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }

    char *body = NULL;
    /* retryable=0: revocation is a mutation, and §16.2 names `oidc_revoke`
     * explicitly among the ineligible operations. */
    axiam_error_kind_t kind =
        oidc_token_admin_call(client, "/oauth2/revoke", token, token_type_hint, tenant_id,
                              "revoke", 0, &body, err);
    /*
     * §12.1 rule 5: any 2xx is success, INCLUDING for a token the server has
     * never issued — RFC 7009 answers 200 for unknown, expired and
     * already-revoked tokens, and that idempotence is the point of the
     * endpoint. A 5xx is still a failure: returning void does not turn a server
     * error into a success (the correction contract 1.5 made to 1.4).
     */
    free(body);
    return kind;
}

/* ------------------------------------------------------------------ */
/* §12.1 sso_start / sso_complete                                     */
/* ------------------------------------------------------------------ */

/* A JSON POST against a path on the client's base URL. The federation pair is
 * the only §12 traffic that is JSON rather than form-encoded, and the only §12
 * traffic that accepts SLUG forms — it carries context in the body per §5.1
 * rather than in a `?tenant_id=` query parameter. */
static axiam_error_kind_t oidc_json_post(axiam_client_t *c, const char *path,
                                         const char *json, const char *context,
                                         char **out_body, axiam_error_t *err) {
    *out_body = NULL;
    size_t blen = strlen(c->cfg->base_url);
    while (blen > 0 && c->cfg->base_url[blen - 1] == '/') blen--;
    char *url = malloc(blen + strlen(path) + 1);
    if (!url) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    memcpy(url, c->cfg->base_url, blen);
    strcpy(url + blen, path);

    axiam_http_response_t resp;
    int rc = oidc_post(c, url, "application/json", json, 0, &resp);
    free(url);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = AXIAM_ERR_NETWORK;
        axiam_error_set(err, kind, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
    } else if (resp.status >= 200 && resp.status < 300) {
        kind = AXIAM_OK;
        *out_body = axiam_strdup0(resp.body ? resp.body : "");
    } else {
        kind = axiam_error_kind_from_http_status(resp.status);
        axiam_error_set(err, kind, resp.status, context);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_sso_start(axiam_client_t *client, const char *federation_config_id,
                                   const char *redirect_uri, axiam_sso_start_result_t *out,
                                   axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !federation_config_id || !redirect_uri) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "federation_config_id", federation_config_id);
    cJSON_AddStringToObject(root, "redirect_uri", redirect_uri);
    /* §5.1: one tenant form and one org form, whichever this client carries.
     * Slugs are valid here — see the note above oidc_json_post. */
    if (client->cfg->tenant_id && client->cfg->tenant_id[0])
        cJSON_AddStringToObject(root, "tenant_id", client->cfg->tenant_id);
    else if (client->cfg->tenant_slug && client->cfg->tenant_slug[0])
        cJSON_AddStringToObject(root, "tenant_slug", client->cfg->tenant_slug);
    if (client->cfg->org_id && client->cfg->org_id[0])
        cJSON_AddStringToObject(root, "org_id", client->cfg->org_id);
    else if (client->cfg->org_slug && client->cfg->org_slug[0])
        cJSON_AddStringToObject(root, "org_slug", client->cfg->org_slug);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    char *body = NULL;
    axiam_error_kind_t kind =
        oidc_json_post(client, PATH_SSO_START, json, "sso start failed", &body, err);
    free(json);
    if (kind != AXIAM_OK) return kind;

    cJSON *resp = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!resp) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "sso start: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    out->authorize_url = json_opt(resp, "authorize_url");
    out->state = json_opt(resp, "state");
    const cJSON *ttl = cJSON_GetObjectItemCaseSensitive(resp, "expires_in_secs");
    out->expires_in_secs = cJSON_IsNumber(ttl) ? (long)ttl->valuedouble : 0;
    cJSON_Delete(resp);
    /* §12.1 note 7: there is no nonce here and the SDK must not synthesise one —
     * the federation nonce never leaves the server. `state` is round-tripped
     * unmodified into sso_complete. */
    if (!out->authorize_url || !out->state) {
        axiam_sso_start_result_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "sso start: malformed OidcStartResponse");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

axiam_error_kind_t axiam_sso_complete(axiam_client_t *client, const char *code,
                                      const char *state, axiam_sso_complete_result_t *out,
                                      axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !code || !state) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "code", code);
    cJSON_AddStringToObject(root, "state", state);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    char *body = NULL;
    axiam_error_kind_t kind =
        oidc_json_post(client, PATH_SSO_COMPLETE, json, "sso complete failed", &body, err);
    free(json);
    if (kind != AXIAM_OK) return kind;

    cJSON *resp = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!resp) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "sso complete: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    out->user_id = json_opt(resp, "user_id");
    out->session_id = json_opt(resp, "session_id");
    out->redirect_uri = json_opt(resp, "redirect_uri");
    const cJSON *ttl = cJSON_GetObjectItemCaseSensitive(resp, "expires_in");
    out->expires_in = cJSON_IsNumber(ttl) ? (long)ttl->valuedouble : 0;
    cJSON_Delete(resp);
    /* §12.1 note 6: no token material comes back — the session is a Set-Cookie
     * the §4 cookie jar keeps. A transport without cookie support loses it
     * silently, which is why §4 is a requirement rather than a suggestion. */
    if (!out->user_id || !out->session_id) {
        axiam_sso_complete_result_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "sso complete: malformed SsoLoginSuccessResponse");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* §12.1 login providers (contract 1.37; rule 12a added at 1.38)       */
/* ------------------------------------------------------------------ */

/*
 * The two session-establishing completions share everything but their path and
 * their request body, so they share this. §12.1 note 6 applies to both: the
 * response carries NO token material — the session is the Set-Cookie the §4
 * cookie jar keeps, and a transport substituted without cookie support loses it
 * silently.
 */
static axiam_error_kind_t federation_complete(axiam_client_t *client, const char *path,
                                              cJSON *root, const char *context,
                                              axiam_sso_complete_result_t *out,
                                              axiam_error_t *err) {
    char *json = root ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    if (!json) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    char *body = NULL;
    axiam_error_kind_t kind = oidc_json_post(client, path, json, context, &body, err);
    free(json);
    /* §12.1 note 12: a 401 here is TERMINAL — the handoff code is spent either
     * way — and rule 12a's 400 is a configuration error. Neither is retried, and
     * oidc_json_post is called with retry disabled so neither can be. */
    if (kind != AXIAM_OK) return kind;

    cJSON *resp = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!resp) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    out->user_id = json_opt(resp, "user_id");
    out->session_id = json_opt(resp, "session_id");
    out->redirect_uri = json_opt(resp, "redirect_uri");
    const cJSON *ttl = cJSON_GetObjectItemCaseSensitive(resp, "expires_in");
    out->expires_in = cJSON_IsNumber(ttl) ? (long)ttl->valuedouble : 0;
    cJSON_Delete(resp);
    if (!out->user_id || !out->session_id) {
        axiam_sso_complete_result_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "malformed SsoLoginSuccessResponse");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* Appends `name=<url-encoded value>` to *url, growing it. Returns 0 on success. */
static int query_append(char **url, size_t *len, size_t *cap, const char *name,
                        const char *value) {
    char *encoded = axiam_url_encode(value);
    if (!encoded) return -1;
    size_t need = *len + strlen(name) + strlen(encoded) + 2 + 1;
    if (need > *cap) {
        size_t next_cap = need * 2;
        char *grown = (char *)realloc(*url, next_cap);
        if (!grown) { free(encoded); return -1; }
        *url = grown;
        *cap = next_cap;
    }
    int written = snprintf(*url + *len, *cap - *len, "%c%s=%s",
                           strchr(*url, '?') ? '&' : '?', name, encoded);
    free(encoded);
    if (written < 0) return -1;
    *len += (size_t)written;
    return 0;
}

axiam_error_kind_t axiam_sso_providers(axiam_client_t *client, const char *org_id,
                                       const char *org_slug, const char *tenant_id,
                                       const char *tenant_slug,
                                       axiam_federation_provider_list_t *out,
                                       axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    /*
     * §12.1 note 9: NOTHING here is required, and nothing is refused
     * client-side. A request naming no workspace at all is still a request and
     * still answers 200 with an empty list — a client-side 400 would restore
     * exactly the two-valued organization-slug oracle the empty list removes.
     */
    const char *eff_org_id = org_id ? org_id : client->cfg->org_id;
    const char *eff_org_slug = org_slug ? org_slug : client->cfg->org_slug;
    const char *eff_tenant_id = tenant_id ? tenant_id : client->cfg->tenant_id;
    const char *eff_tenant_slug = tenant_slug ? tenant_slug : client->cfg->tenant_slug;

    size_t blen = strlen(client->cfg->base_url);
    while (blen > 0 && client->cfg->base_url[blen - 1] == '/') blen--;
    size_t cap = blen + sizeof(PATH_SSO_PROVIDERS) + 64;
    char *url = (char *)malloc(cap);
    if (!url) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    memcpy(url, client->cfg->base_url, blen);
    strcpy(url + blen, PATH_SSO_PROVIDERS);
    size_t len = strlen(url);

    /* §5.1: the UUID form replaces the matching slug form, as everywhere else. */
    int failed = 0;
    if (eff_org_id && eff_org_id[0])
        failed |= query_append(&url, &len, &cap, "org_id", eff_org_id);
    else if (eff_org_slug && eff_org_slug[0])
        failed |= query_append(&url, &len, &cap, "org_slug", eff_org_slug);
    if (!failed) {
        if (eff_tenant_id && eff_tenant_id[0])
            failed |= query_append(&url, &len, &cap, "tenant_id", eff_tenant_id);
        else if (eff_tenant_slug && eff_tenant_slug[0])
            failed |= query_append(&url, &len, &cap, "tenant_slug", eff_tenant_slug);
    }
    if (failed) {
        free(url);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = oidc_get(client, url, &resp);
    free(url);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (resp.status < 200 || resp.status >= 300) {
        axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp.status);
        axiam_error_set(err, kind, resp.status, "sso providers failed");
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    axiam_http_response_dispose(&resp);
    const cJSON *items = root ? cJSON_GetObjectItemCaseSensitive(root, "providers") : NULL;
    if (!root || !cJSON_IsArray(items)) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "sso providers: malformed PublicFederationProvidersResponse");
        return AXIAM_ERR_NETWORK;
    }

    int n = cJSON_GetArraySize(items);
    if (n <= 0) {
        /* The empty list is the success (note 9), not a case to signal. */
        cJSON_Delete(root);
        return AXIAM_OK;
    }

    axiam_federation_provider_t *arr =
        (axiam_federation_provider_t *)calloc((size_t)n, sizeof(*arr));
    if (!arr) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    size_t kept = 0;
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(items, i);
        if (!cJSON_IsObject(entry)) continue;
        axiam_federation_provider_t *p = &arr[kept];
        p->id = json_opt(entry, "id");
        p->provider_kind = json_opt(entry, "provider_kind");
        p->display_name = json_opt(entry, "display_name");
        /* The wire string, never an enum: a protocol the server adds later must
         * not fail the parse of the whole list (note 10). */
        p->protocol = json_opt(entry, "protocol");
        p->button_icon = json_opt(entry, "button_icon"); /* absent for most */
        const cJSON *mark = cJSON_GetObjectItemCaseSensitive(entry, "has_bundled_mark");
        p->has_bundled_mark = cJSON_IsTrue(mark) ? 1 : 0;
        const cJSON *inh = cJSON_GetObjectItemCaseSensitive(entry, "inherited");
        p->inherited = cJSON_IsTrue(inh) ? 1 : 0;
        if (!p->id || !p->protocol) {
            /* A member with no id or no protocol cannot start a login. Drop it
             * rather than failing the whole listing: the buttons that ARE usable
             * must still render. */
            free(p->id); free(p->provider_kind); free(p->display_name);
            free(p->protocol); free(p->button_icon);
            memset(p, 0, sizeof(*p));
            continue;
        }
        kept++;
    }
    cJSON_Delete(root);

    if (kept == 0) { free(arr); arr = NULL; }
    out->items = arr;
    out->count = kept;
    return AXIAM_OK;
}

axiam_error_kind_t axiam_sso_start_oauth2(axiam_client_t *client,
                                          const char *federation_config_id,
                                          const char *redirect_uri,
                                          axiam_sso_start_result_t *out,
                                          axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !federation_config_id || !redirect_uri) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "federation_config_id", federation_config_id);
    cJSON_AddStringToObject(root, "redirect_uri", redirect_uri);
    /* §5.1, identical to axiam_sso_start(). And NO PKCE field anywhere: the
     * verifier is generated and held server-side (§12.1 note 11), so there is
     * nothing for this SDK to compute and nothing it may send. */
    if (client->cfg->tenant_id && client->cfg->tenant_id[0])
        cJSON_AddStringToObject(root, "tenant_id", client->cfg->tenant_id);
    else if (client->cfg->tenant_slug && client->cfg->tenant_slug[0])
        cJSON_AddStringToObject(root, "tenant_slug", client->cfg->tenant_slug);
    if (client->cfg->org_id && client->cfg->org_id[0])
        cJSON_AddStringToObject(root, "org_id", client->cfg->org_id);
    else if (client->cfg->org_slug && client->cfg->org_slug[0])
        cJSON_AddStringToObject(root, "org_slug", client->cfg->org_slug);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    char *body = NULL;
    axiam_error_kind_t kind = oidc_json_post(client, PATH_SSO_OAUTH2_START, json,
                                             "sso start oauth2 failed", &body, err);
    free(json);
    /* Rule 12a: a 400 means the deployment does not accept this redirect_uri's
     * origin. §2 puts that on the AXIAM_ERR_NETWORK row — the configuration
     * error — as distinct from the AXIAM_ERR_AUTH a 401 gets, and it is not
     * retried. */
    if (kind != AXIAM_OK) return kind;

    cJSON *resp = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!resp) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "sso start oauth2: malformed response body");
        return AXIAM_ERR_NETWORK;
    }
    out->authorize_url = json_opt(resp, "authorize_url");
    out->state = json_opt(resp, "state");
    const cJSON *ttl = cJSON_GetObjectItemCaseSensitive(resp, "expires_in_secs");
    out->expires_in_secs = cJSON_IsNumber(ttl) ? (long)ttl->valuedouble : 0;
    cJSON_Delete(resp);
    if (!out->authorize_url || !out->state) {
        axiam_sso_start_result_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "sso start oauth2: malformed OAuth2StartResponse");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

axiam_error_kind_t axiam_sso_complete_oauth2(axiam_client_t *client, const char *code,
                                             const char *state,
                                             axiam_sso_complete_result_t *out,
                                             axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !code || !state) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    cJSON *root = cJSON_CreateObject();
    if (root) {
        cJSON_AddStringToObject(root, "state", state);
        cJSON_AddStringToObject(root, "code", code);
    }
    return federation_complete(client, PATH_SSO_OAUTH2_CALLBACK, root,
                               "sso complete oauth2 failed", out, err);
}

axiam_error_kind_t axiam_sso_complete_handoff(axiam_client_t *client, const char *code,
                                              axiam_sso_complete_result_t *out,
                                              axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !code) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    /* The code is the whole request: no state, no workspace. */
    cJSON *root = cJSON_CreateObject();
    if (root) cJSON_AddStringToObject(root, "code", code);
    return federation_complete(client, PATH_SSO_HANDOFF, root,
                               "sso complete handoff failed", out, err);
}
