#include <stdio.h>
#include <string.h>

#include "axiam/error.h"

axiam_error_kind_t axiam_error_kind_from_http_status(long status) {
    if (status >= 200 && status < 300) return AXIAM_OK;
    switch (status) {
        case 401: return AXIAM_ERR_AUTH;
        case 403: return AXIAM_ERR_AUTHZ;
        case 409: return AXIAM_ERR_AUTHZ;
        case 400: return AXIAM_ERR_NETWORK; /* malformed request */
        case 408: return AXIAM_ERR_NETWORK; /* timeout */
        case 429: return AXIAM_ERR_NETWORK; /* rate limited */
        default: break;
    }
    if (status >= 500 && status < 600) return AXIAM_ERR_NETWORK;
    /* Any other unexpected status is treated as a transport-level anomaly. */
    return AXIAM_ERR_NETWORK;
}

void axiam_error_reset(axiam_error_t *err) {
    if (!err) return;
    err->kind = AXIAM_OK;
    err->message[0] = '\0';
    err->transport_cause = 0;
}

void axiam_error_set(axiam_error_t *err, axiam_error_kind_t kind, long cause,
                     const char *msg) {
    if (!err) return;
    err->kind = kind;
    err->transport_cause = cause;
    if (msg) {
        /* Copy + guarantee NUL-termination; message must never carry a token. */
        strncpy(err->message, msg, sizeof(err->message) - 1);
        err->message[sizeof(err->message) - 1] = '\0';
    } else {
        err->message[0] = '\0';
    }
}

const char *axiam_error_kind_str(axiam_error_kind_t kind) {
    switch (kind) {
        case AXIAM_OK: return "ok";
        case AXIAM_ERR_AUTH: return "auth";
        case AXIAM_ERR_AUTHZ: return "authz";
        case AXIAM_ERR_NETWORK: return "network";
        default: return "unknown";
    }
}
