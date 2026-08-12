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
    /**
     * The `error` field of an OAuth2ErrorResponse — e.g. "invalid_grant",
     * "access_denied" — or "" when the failure was not an OAuth2 protocol
     * error. Currently filled only by the §20 UMA ticket grant.
     *
     * Read THIS rather than the HTTP status: CONTRACT.md §20.4 puts
     * `access_denied` on a 403 where RFC 8628's is a 400, and requires an SDK
     * to dispatch on the field so the mapping stays correct if either moves.
     * The contract models it as an `OAuthProtocolError` sub-type of the
     * authentication error; C has no subtyping, so the kind stays
     * AXIAM_ERR_AUTH and the code lands here — the §2 taxonomy keeps its three
     * kinds rather than gaining a fourth.
     */
    char oauth_error[64];
    /**
     * The CONTRACT.md §12.3 rule 3 ID-token validation reason code — one of
     * AXIAM_OIDC_REASON_* (see axiam/oidc.h) — or "" when the failure was not
     * an ID-token validation failure.
     *
     * DELIBERATELY A SECOND FIELD rather than a reuse of `oauth_error`. The two
     * carry different closed vocabularies from different clauses, and one of
     * each pair is nearly a homograph of the other: §14.2's terminal
     * `expired_token` (the device grant ran out) against §12.4 rule 5's
     * `token_expired` (this ID token is stale). A caller dispatching on a
     * single field would eventually confuse them; two fields make the question
     * "which vocabulary am I asking about?" unavoidable.
     */
    char id_token_reason[32];
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
