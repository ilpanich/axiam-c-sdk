/*
 * AXIAM C SDK — Framework-agnostic route guard (§10) and declarative
 * authorization helpers (§11).
 *
 * These compose strictly on top of the §10 authentication path: the guard
 * verifies the request's session token via JWKS (§ JWKS), then performs the
 * §11 authorization check for the *authenticated caller* (subject propagation,
 * §11.2). No decision caching (§11.6). Network failure fails CLOSED (503).
 *
 * Token verification is always AXIAM_JWT_VERIFY_STRICT (see jwks.h): signature
 * with `alg` pinned to EdDSA before key lookup, AND lifetime (`exp` required,
 * and `nbf` when present) AND the tenant binding AND the configured `iss` /
 * `aud` expectations. An expired token, one minted for a different tenant of
 * the same organization, or one from an unexpected issuer/audience is refused
 * with AXIAM_GUARD_UNAUTHENTICATED and never reaches the authorization check.
 *
 * The macros AXIAM_REQUIRE_ACCESS / AXIAM_REQUIRE_AUTH / AXIAM_REQUIRE_ROLE are
 * C's analog of the annotations other SDKs expose (§11).
 */
#ifndef AXIAM_GUARD_H
#define AXIAM_GUARD_H

#include "axiam/client.h"
#include "axiam/transport.h"
#include "axiam/uma.h"

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
 * §11 require_auth. Returns AXIAM_GUARD_ALLOW when the request carries a
 * session token that passes strict verification (signature + `exp`/`nbf` +
 * tenant binding), else AXIAM_GUARD_UNAUTHENTICATED / AXIAM_GUARD_UNAVAILABLE.
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

/**
 * A configured `WWW-Authenticate: UMA` challenge emitter (§20.3, emit half).
 * All members borrowed: the caller owns them and they must outlive the call.
 *
 * Pass one to axiam_require_access_uma() and a denial stops being a bare 403:
 * the guard mints a fresh permission ticket for the pair the caller lacked and
 * hands back the formatted header, so a UMA-aware client knows where to go for
 * authority instead of only being told "no".
 *
 * OPT-IN, AND DELIBERATELY SO. Emitting a challenge means minting a credential
 * — a wire call to the Protection API, and a live ticket, produced on a path
 * the caller did not explicitly request. A guard that did that on every denial
 * by default would turn each unauthorized request into a Protection API call,
 * which is a denial-of-service amplifier pointed at your own authorization
 * server. So axiam_require_access() keeps its existing behaviour untouched and
 * this is a separate entry point.
 *
 * FAILURE IS NOT ESCALATION. If minting fails — the PAT expired, the Protection
 * API is down, the resource declares none of the requested scopes — the denial
 * still surfaces as AXIAM_GUARD_DENIED with no challenge. A caller who was
 * going to be refused is refused either way; letting a Protection API outage
 * turn a deny into a 503 would hand the outage a second consequence, and
 * letting it turn into an allow would be a security bug.
 */
typedef struct axiam_uma_challenger {
    /** The protection realm to name in the header. Required. */
    const char *realm;
    /**
     * The authorization server to send the caller to — normally this
     * deployment's issuer, read from axiam_uma_discover() rather than
     * concatenated by hand. Required.
     */
    const char *as_uri;
    /**
     * A Protection API Token: a *client-credentials* token carrying the
     * `uma_protection` scope (§20.2 rule 1). A user token cannot stand in — a
     * minted ticket is bound to the client_id that minted it. Required.
     */
    const axiam_sensitive_t *pat;
} axiam_uma_challenger_t;

/**
 * §11 require_access, with §20.3 challenge emission on a denial.
 *
 * Identical to axiam_require_access() in every outcome; additionally, when the
 * result is AXIAM_GUARD_DENIED and `challenger` is non-NULL, mints one ticket
 * for (resource_id, action) and writes the formatted `WWW-Authenticate` value
 * to *out_challenge as a malloc'd string the caller frees.
 *
 * The requested UMA scope is the AXIAM *action*: asking for anything else would
 * offer the caller authority other than the one they were denied, and would
 * step outside the grants the engine just evaluated — deny rules included.
 *
 * The ticket is a live credential for its 60 seconds (§20.6): send the string
 * as a header, and do not log it.
 *
 * @param challenger    May be NULL, in which case this behaves exactly as
 *                      axiam_require_access() and mints nothing.
 * @param out_challenge May be NULL. Set to a malloc'd header value only on a
 *                      denial with a challenger and a successful mint;
 *                      otherwise set to NULL. Free with free().
 */
axiam_guard_status_t axiam_require_access_uma(axiam_client_t *client,
                                              const axiam_headers_t *headers,
                                              const char *action,
                                              const char *resource_id,
                                              const char *scope,
                                              const axiam_uma_challenger_t *challenger,
                                              char **out_challenge);

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
