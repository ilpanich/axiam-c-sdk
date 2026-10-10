/*
 * AXIAM C SDK — HTTP transport seam (testability).
 *
 * The client performs all HTTP through a function pointer. The default
 * implementation is libcurl (see axiam_client_config_use_default_transport,
 * applied automatically). Tests override it with an in-memory fake that
 * returns canned status/headers/body, exercising the entire logic layer
 * (request building, JSON, error mapping, CSRF, tenant header, single-flight)
 * without a live server.
 */
#ifndef AXIAM_TRANSPORT_H
#define AXIAM_TRANSPORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A single request/response header (linked list). */
typedef struct axiam_kv {
    char *key;
    char *value;
    struct axiam_kv *next;
} axiam_kv_t;

/** Append a copy of key/value to a header list. Returns new head. */
axiam_kv_t *axiam_kv_append(axiam_kv_t *head, const char *key, const char *value);

/** Case-insensitive lookup of a header value, or NULL. */
const char *axiam_kv_get(const axiam_kv_t *head, const char *key);

/** Free an entire header list. */
void axiam_kv_free(axiam_kv_t *head);

/** Outgoing HTTP request handed to a transport implementation. */
typedef struct axiam_http_request {
    const char *method;      /**< "GET", "POST", ... */
    const char *url;         /**< Fully-qualified URL. */
    const axiam_kv_t *headers; /**< Request headers (owned by caller). */
    const char *body;        /**< Request body (may be NULL). */
    size_t body_len;         /**< Length of body; 0 when body is NULL. */
    /**
     * Nonzero when the SDK itself may send this request again after a transport failure
     * (CONTRACT.md §16: a management `GET`, an authorization check, a retried token-endpoint
     * request). Zero -- the value an unset field has -- means the request is a write that is
     * never sent twice, and a transport MUST NOT send it twice behind the SDK's back either
     * (§34.2 P11): the bundled libcurl transport puts such a request on a fresh connection
     * (`CURLOPT_FRESH_CONNECT`) that is not reused afterwards (`CURLOPT_FORBID_REUSE`), so
     * libcurl has no dead pooled connection to re-send it over. Appended last, so a
     * transport compiled against the older struct is unaffected.
     */
    int replayable;
} axiam_http_request_t;

/** Response produced by a transport implementation. All owned/heap fields. */
typedef struct axiam_http_response {
    long status;             /**< HTTP status, or 0 when no HTTP response (transport failure). */
    char *body;              /**< Response body (owned, may be NULL). */
    axiam_kv_t *headers;     /**< Response headers (owned). */
    int transport_err;       /**< Nonzero on network/TLS failure (e.g. CURLcode). */
    char *transport_msg;     /**< Owned transport error string (may be NULL). */
} axiam_http_response_t;

/** Free the heap-owned members of a response (not the struct itself). */
void axiam_http_response_dispose(axiam_http_response_t *resp);

/**
 * Transport function. Returns 0 on a completed HTTP exchange (inspect
 * resp->status) or nonzero when the request could not be delivered (a
 * transport failure — resp->transport_err/transport_msg describe it).
 *
 * @param ctx  Opaque per-transport context (set alongside the fn).
 */
typedef int (*axiam_transport_fn)(void *ctx,
                                  const axiam_http_request_t *req,
                                  axiam_http_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_TRANSPORT_H */
