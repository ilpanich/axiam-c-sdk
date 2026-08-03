/* Shared helpers for the AXIAM C SDK tests. */
#ifndef AXIAM_TEST_UTIL_H
#define AXIAM_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "axiam/axiam.h"

/* The tenant UUID the guard/JWKS test clients are configured with. Strict
 * verification (SEC-071) binds a token's `tenant_id` claim to it. */
#define AXIAM_TEST_TENANT_ID "11111111-1111-1111-1111-111111111111"

/**
 * Build a JWT claims payload that PASSES strict verification: a live `exp`
 * and the configured tenant. `extra` is appended verbatim inside the object
 * (e.g. ",\"roles\":[\"admin\"]") and may be NULL. Returns buf.
 */
static inline const char *test_claims(char *buf, size_t n, const char *sub,
                                      const char *extra) {
    snprintf(buf, n, "{\"sub\":\"%s\",\"tenant_id\":\"%s\",\"exp\":%lld%s}",
             sub, AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 900,
             extra ? extra : "");
    return buf;
}

/**
 * As test_claims(), but WITHOUT a `sub` claim: only the members strict
 * verification requires, plus whatever `members` appends verbatim.
 */
static inline const char *test_claims_no_sub(char *buf, size_t n,
                                             const char *members) {
    snprintf(buf, n, "{\"tenant_id\":\"%s\",\"exp\":%lld%s}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) + 900,
             members ? members : "");
    return buf;
}

/* A recorder shared by tests: captures the last request the transport saw. */
typedef struct test_recorder {
    char method[8];
    char url[1024];
    char tenant[256];
    char csrf_sent[512];
    char content_type[128];
    char body[4096];
    int  request_count;
} test_recorder_t;

static inline void recorder_capture(test_recorder_t *rec, const axiam_http_request_t *req) {
    if (!rec) return;
    rec->request_count++;
    snprintf(rec->method, sizeof(rec->method), "%s", req->method ? req->method : "");
    snprintf(rec->url, sizeof(rec->url), "%s", req->url ? req->url : "");
    const char *t = axiam_kv_get(req->headers, "X-Tenant-ID");
    snprintf(rec->tenant, sizeof(rec->tenant), "%s", t ? t : "");
    const char *csrf = axiam_kv_get(req->headers, "X-CSRF-Token");
    snprintf(rec->csrf_sent, sizeof(rec->csrf_sent), "%s", csrf ? csrf : "");
    const char *ct = axiam_kv_get(req->headers, "Content-Type");
    snprintf(rec->content_type, sizeof(rec->content_type), "%s", ct ? ct : "");
    snprintf(rec->body, sizeof(rec->body), "%s", req->body ? req->body : "");
}

/* Populate an HTTP response with a JSON body and optional CSRF header. */
static inline void resp_fill(axiam_http_response_t *resp, long status,
                             const char *body, const char *csrf) {
    memset(resp, 0, sizeof(*resp));
    resp->status = status;
    if (body) resp->body = strdup(body);
    if (csrf) resp->headers = axiam_kv_append(resp->headers, "X-CSRF-Token", csrf);
}

#endif /* AXIAM_TEST_UTIL_H */
