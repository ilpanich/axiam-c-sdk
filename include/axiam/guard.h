/*
 * AXIAM C SDK — Framework-agnostic route guard (§10) and declarative
 * authorization helpers (§11).
 *
 * These compose strictly on top of the §10 authentication path: the guard
 * verifies the request's session token via JWKS (§ JWKS), then performs the
 * §11 authorization check for the *authenticated caller* (subject propagation,
 * §11.2). No decision caching (§11.6). Network failure fails CLOSED (503).
 *
 * The macros AXIAM_REQUIRE_ACCESS / AXIAM_REQUIRE_AUTH / AXIAM_REQUIRE_ROLE are
 * C's analog of the annotations other SDKs expose (§11).
 */
#ifndef AXIAM_GUARD_H
#define AXIAM_GUARD_H

#include "axiam/client.h"
#include "axiam/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Guard outcome — the numeric values are the HTTP status a framework adapter
 * should return (§11.2 error mapping).
 */
typedef enum axiam_guard_status {
    AXIAM_GUARD_ALLOW = 200,        /**< Authenticated and authorized. */
    AXIAM_GUARD_UNAUTHENTICATED = 401, /**< No/invalid session (authentication_failed). */
    AXIAM_GUARD_DENIED = 403,       /**< Authenticated but denied (authorization_denied). */
    AXIAM_GUARD_BAD_REQUEST = 400,  /**< Unresolvable resource id (invalid_request). */
    AXIAM_GUARD_UNAVAILABLE = 503   /**< Authz endpoint unreachable — fail closed (authz_unavailable). */
} axiam_guard_status_t;

/**
 * Incoming request headers for the guard. A framework adapter populates this
 * from the real request. The guard reads:
 *   - "Authorization: Bearer <jwt>"  or
 *   - "Cookie: axiam_access=<jwt>"   (session cookie)
 * to obtain the caller's identity token.
 */
typedef axiam_kv_t axiam_headers_t;

/**
 * §11 require_access. Verifies the caller's token (JWKS), then checks
 * (action, resource_id[, scope]) for that caller as subject. Returns an
 * axiam_guard_status_t. scope may be NULL.
 */
axiam_guard_status_t axiam_require_access(axiam_client_t *client,
                                          const axiam_headers_t *headers,
                                          const char *action,
                                          const char *resource_id,
                                          const char *scope);

/**
 * §11 require_auth. Returns AXIAM_GUARD_ALLOW when the request carries a valid
 * (JWKS-verified) session token, else AXIAM_GUARD_UNAUTHENTICATED /
 * AXIAM_GUARD_UNAVAILABLE.
 */
axiam_guard_status_t axiam_require_auth(axiam_client_t *client,
                                        const axiam_headers_t *headers);

/**
 * §11 require_role (local). Verifies the token and checks that its `roles`
 * claim contains at least one of the given roles. No server round-trip.
 * Returns AXIAM_GUARD_ALLOW / AXIAM_GUARD_DENIED / AXIAM_GUARD_UNAUTHENTICATED.
 */
axiam_guard_status_t axiam_require_role(axiam_client_t *client,
                                        const axiam_headers_t *headers,
                                        const char *const *roles,
                                        size_t n_roles);

/* --- §11 convenience macros (C analog of annotations). --- */

/** Evaluate to the guard status for (action, resource, scope). */
#define AXIAM_REQUIRE_ACCESS(client, headers, action, resource, scope) \
    axiam_require_access((client), (headers), (action), (resource), (scope))

/** Evaluate to the guard status for an authenticated-only endpoint. */
#define AXIAM_REQUIRE_AUTH(client, headers) \
    axiam_require_auth((client), (headers))

/** Evaluate to the guard status for a local role check over a role array. */
#define AXIAM_REQUIRE_ROLE(client, headers, roles, n) \
    axiam_require_role((client), (headers), (roles), (n))

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_GUARD_H */
