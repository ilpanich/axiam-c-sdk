#include <curl/curl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "internal.h"

typedef struct {
    CURL *curl;
    pthread_mutex_t mtx;
    char *ca_pem;                 /* copy for CURLOPT_CAINFO_BLOB */
    char *cert_pem;               /* copy for CURLOPT_SSLCERT_BLOB */
    unsigned char *key_pem;       /* copy for CURLOPT_SSLKEY_BLOB (§7 material) */
    size_t key_len;
    long timeout_ms;
    long connect_timeout_ms;
} curl_ctx_t;

typedef struct {
    char *buf;
    size_t len;
} growbuf_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    growbuf_t *g = userdata;
    size_t add = size * nmemb;
    char *nb = realloc(g->buf, g->len + add + 1);
    if (!nb) return 0;
    g->buf = nb;
    memcpy(g->buf + g->len, ptr, add);
    g->len += add;
    g->buf[g->len] = '\0';
    return add;
}

/* Capture a named response header's trimmed value into resp->headers under
 * `store_as`. Set-Cookie is captured too (as a linked-list append, since a
 * login sets several cookies) so the access-token JWT can be recovered for
 * org_id/tenant_id resolution (D-14). */
static void capture_header(axiam_http_response_t *resp, const char *buffer, size_t total,
                           const char *match, const char *store_as) {
    size_t klen = strlen(match);
    if (total <= klen || strncasecmp(buffer, match, klen) != 0) return;
    const char *v = buffer + klen;
    size_t vlen = total - klen;
    while (vlen && (*v == ' ' || *v == '\t')) { v++; vlen--; }
    while (vlen && (v[vlen - 1] == '\r' || v[vlen - 1] == '\n' ||
                    v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) vlen--;
    char *val = malloc(vlen + 1);
    if (val) {
        memcpy(val, v, vlen);
        val[vlen] = '\0';
        resp->headers = axiam_kv_append(resp->headers, store_as, val);
        free(val);
    }
}

/* Capture the X-CSRF-Token (§3) and Set-Cookie (§4/D-14) response headers. */
static size_t header_cb(char *buffer, size_t size, size_t nitems, void *userdata) {
    axiam_http_response_t *resp = userdata;
    size_t total = size * nitems;
    capture_header(resp, buffer, total, "X-CSRF-Token:", "X-CSRF-Token");
    capture_header(resp, buffer, total, "Set-Cookie:", "Set-Cookie");
    return total;
}

void *axiam_curl_ctx_new(const axiam_client_config_t *cfg) {
    curl_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->curl = curl_easy_init();
    if (!ctx->curl) { free(ctx); return NULL; }
    pthread_mutex_init(&ctx->mtx, NULL);
    if (cfg) {
        ctx->ca_pem = axiam_strdup0(cfg->custom_ca_pem);
        ctx->cert_pem = axiam_strdup0(cfg->client_cert_pem);
        if (cfg->client_key) {
            size_t n = axiam_sensitive_len(cfg->client_key);
            ctx->key_pem = malloc(n + 1);
            if (ctx->key_pem) {
                memcpy(ctx->key_pem, axiam_sensitive_bytes(cfg->client_key), n);
                ctx->key_pem[n] = '\0';
                ctx->key_len = n;
            }
        }
        ctx->timeout_ms = cfg->timeout_ms;
        ctx->connect_timeout_ms = cfg->connect_timeout_ms;
    }
    /* §4: enable the per-handle in-memory cookie engine. */
    curl_easy_setopt(ctx->curl, CURLOPT_COOKIEFILE, "");
    return ctx;
}

void axiam_curl_ctx_free(void *vctx) {
    curl_ctx_t *ctx = vctx;
    if (!ctx) return;
    if (ctx->curl) curl_easy_cleanup(ctx->curl);
    pthread_mutex_destroy(&ctx->mtx);
    free(ctx->ca_pem);
    free(ctx->cert_pem);
    if (ctx->key_pem) {
        memset(ctx->key_pem, 0, ctx->key_len); /* scrub key material (§7) */
        free(ctx->key_pem);
    }
    free(ctx);
}

int axiam_curl_transport(void *vctx, const axiam_http_request_t *req,
                         axiam_http_response_t *resp) {
    curl_ctx_t *ctx = vctx;
    if (!ctx || !ctx->curl || !req || !resp) return 1;

    pthread_mutex_lock(&ctx->mtx);

    CURL *c = ctx->curl;
    curl_easy_reset(c);
    /* Re-enable cookie engine after reset; in-memory cookies are preserved. */
    curl_easy_setopt(c, CURLOPT_COOKIEFILE, "");

    growbuf_t body = {0};
    curl_easy_setopt(c, CURLOPT_URL, req->url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, resp);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "axiam-c-sdk/" AXIAM_VERSION);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);

    /* §6 TLS policy: strict verification, ALWAYS ON. Never 0. */
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    if (ctx->timeout_ms > 0)
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, ctx->timeout_ms);
    if (ctx->connect_timeout_ms > 0)
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, ctx->connect_timeout_ms);

    /* §6: custom CA added to the verification chain (in-memory blob). */
    if (ctx->ca_pem) {
        struct curl_blob blob;
        blob.data = ctx->ca_pem;
        blob.len = strlen(ctx->ca_pem);
        blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(c, CURLOPT_CAINFO_BLOB, &blob);
    }
    /* §6.1: client identity certificate for mTLS (in-memory blobs, no temp files). */
    if (ctx->cert_pem && ctx->key_pem) {
        struct curl_blob cert_blob;
        cert_blob.data = ctx->cert_pem;
        cert_blob.len = strlen(ctx->cert_pem);
        cert_blob.flags = CURL_BLOB_COPY;
        struct curl_blob key_blob;
        key_blob.data = ctx->key_pem;
        key_blob.len = ctx->key_len;
        key_blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(c, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(c, CURLOPT_SSLCERT_BLOB, &cert_blob);
        curl_easy_setopt(c, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(c, CURLOPT_SSLKEY_BLOB, &key_blob);
    }

    /* Method + body. */
    if (req->method && strcasecmp(req->method, "GET") == 0) {
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    } else if (req->method && strcasecmp(req->method, "POST") == 0) {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, req->body ? req->body : "");
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE,
                         (long)(req->body ? req->body_len : 0));
    } else {
        curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, req->method ? req->method : "GET");
        if (req->body) {
            curl_easy_setopt(c, CURLOPT_POSTFIELDS, req->body);
            curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
        }
    }

    struct curl_slist *hdrs = NULL;
    for (const axiam_kv_t *kv = req->headers; kv; kv = kv->next) {
        size_t n = strlen(kv->key) + 2 + strlen(kv->value) + 1;
        char *line = malloc(n);
        if (!line) continue;
        snprintf(line, n, "%s: %s", kv->key, kv->value);
        struct curl_slist *nh = curl_slist_append(hdrs, line);
        free(line);
        if (nh) hdrs = nh;
    }
    if (hdrs) curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(c);

    int ret = 0;
    if (rc != CURLE_OK) {
        resp->status = 0;
        resp->transport_err = (int)rc;
        resp->transport_msg = axiam_strdup0(curl_easy_strerror(rc));
        free(body.buf);
        ret = 1;
    } else {
        long status = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
        resp->status = status;
        resp->body = body.buf; /* may be NULL if empty */
        ret = 0;
    }

    if (hdrs) curl_slist_free_all(hdrs);
    pthread_mutex_unlock(&ctx->mtx);
    return ret;
}
