/*
 * AXIAM C SDK — Error taxonomy (CONTRACT.md §2).
 *
 * Exactly three error kinds are exposed (plus AXIAM_OK). HTTP/transport
 * failures are mapped onto these kinds. Error messages NEVER contain raw
 * token material.
 */
#ifndef AXIAM_ERROR_H
#define AXIAM_ERROR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Error kind (CONTRACT.md §2). */
typedef enum axiam_error_kind {
    AXIAM_OK = 0,          /**< Success. */
    AXIAM_ERR_AUTH,        /**< Authentication failure (401, MFA, expired session). */
    AXIAM_ERR_AUTHZ,       /**< Authorization failure (403 / 409). */
    AXIAM_ERR_NETWORK      /**< Transport-level failure (timeout, TLS, DNS, 4xx-misc, 5xx). */
} axiam_error_kind_t;

/**
 * Error detail carrier. Callers may pass a pointer to a stack-allocated
 * struct to any operation; it is filled on failure. The message buffer is
 * fixed-size and is guaranteed never to contain a raw token (CONTRACT.md §2,
 * §7).
 */
typedef struct axiam_error {
    axiam_error_kind_t kind;     /**< The error kind. */
    char message[256];           /**< Human-readable, redacted message. */
    long transport_cause;        /**< Numeric transport cause: HTTP status, or CURLcode << (negated). */
} axiam_error_t;

/** Map an HTTP status code to an error kind (CONTRACT.md §2 table). */
axiam_error_kind_t axiam_error_kind_from_http_status(long status);

/** Reset an error struct to AXIAM_OK / empty. Safe to pass NULL. */
void axiam_error_reset(axiam_error_t *err);

/** Fill an error struct (safe if err is NULL). msg is copied and truncated. */
void axiam_error_set(axiam_error_t *err, axiam_error_kind_t kind, long cause, const char *msg);

/** Human-readable name of a kind (for diagnostics — contains no token). */
const char *axiam_error_kind_str(axiam_error_kind_t kind);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_ERROR_H */
