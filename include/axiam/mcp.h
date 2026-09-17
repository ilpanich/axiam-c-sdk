/*
 * AXIAM C SDK — MCP resource-server helpers (CONTRACT.md §28, contract 1.48).
 *
 * The resource-server half of the Model Context Protocol authorization
 * handshake (RFC 9728 protected-resource metadata + the RFC 6750
 * `WWW-Authenticate` challenge). AXIAM is the authorization server and
 * implements none of this; §28 is the MCP server's side, and this SDK
 * implements the middle row of §28.0's table and nothing else.
 *
 * NO OPERATION HERE PERFORMS NETWORK I/O (§28.0). All three functions are
 * pure local computation, like axiam_oidc_begin() (§12.1) and
 * axiam_uma_parse_challenge() (§20.5): §16 retry and §9 single-flight refresh
 * do not apply, and nothing here touches an axiam_client_t's session.
 *
 * NOTHING HERE IS A SOURCE OF TRUTH ABOUT A TOKEN (§28's own opening rule).
 * The document is a claim this resource server publishes about itself; the
 * challenge is a hint handed to a caller that has already failed. Whether a
 * request is authorized stays axiam_require_auth() / axiam_require_access()'s
 * decision, unchanged and unreachable from here.
 *
 * OWNERSHIP CONTRACT (§28.7's C row: "each return an owned string, freed
 * with the SDK's existing string-free function"). This SDK's existing
 * string-free function for a malloc'd string is plain free() — see, for
 * example, axiam_uma_challenge_header() and axiam_reactor_routing_key().
 * Every function below follows the same contract:
 *
 *   - On SUCCESS: returns a malloc'd, NUL-terminated string. The caller owns
 *     it and releases it with free().
 *   - On FAILURE (validation refusal, or out-of-memory): returns NULL. When
 *     `err` is non-NULL, it is filled with the reason — kind AXIAM_ERR_NETWORK
 *     for a client-side refusal that made no wire call, the same kind this
 *     SDK already uses for every other configuration mistake caught before a
 *     request is built (see axiam_client_config_validate(), or
 *     oidc_client_unusable() in oidc.c). §28.6 pins "§28's refusals are
 *     ValidationError; no new type" — this SDK has no ValidationError type to
 *     begin with, so AXIAM_ERR_NETWORK is not a new kind either; it is the
 *     one this SDK already uses for exactly this situation.
 *   - Nothing is ever partially written: a refused call returns NULL and
 *     touches nothing else. There is no route, no document and no challenge
 *     to roll back, because §28's operations build a value and never a side
 *     effect (§28.3's route registration is the framework surface's job —
 *     see the CivetWeb walkthrough in README.md — not this header's).
 *
 * VALIDATION REFUSES; IT NEVER REPAIRS (§28.2). Nothing here normalises,
 * trims, lowercases or re-encodes a value to make it pass. A value that needs
 * adjusting is a configuration mistake an operator fixes in one line, and a
 * helper that quietly fixed it would publish a document — or emit a
 * challenge — describing a resource server that does not exist.
 *
 * WHY THREE METADATA FUNCTIONS, NOT TWO. CONTRACT.md §28.7's C row names only
 * `axiam_protected_resource_metadata_json` and `_path`; §28.1 separately
 * states an SDK "MUST expose both" `metadata_path` and `metadata_url`,
 * because a surface that makes the integrator write the URL twice (scheme +
 * authority, hand-concatenated from the `resource` they already typed once)
 * is the surface on which the two disagree. This SDK ships
 * `axiam_protected_resource_metadata_url` as well, for that MUST — see the
 * PR description for this addition, recorded as a divergence from §28.7's
 * literal C row rather than from §28.1's own requirement.
 *
 * NO `serve_protected_resource_metadata` HERE (§28.3, §28.7): C has no
 * router. README.md's CivetWeb walkthrough shows the adapter — a
 * `mg_request_handler` that calls axiam_protected_resource_metadata_json()
 * and axiam_protected_resource_metadata_path() and answers unauthenticated —
 * and axiam_mcp_check_resource_metadata() below is what stands in for
 * `serve_`'s optional guard cross-check (§28.5 rule 3), since there is no
 * `serve_` call to hang that argument on in this SDK.
 */
#ifndef AXIAM_MCP_H
#define AXIAM_MCP_H

#include <stddef.h>

#include "axiam/config.h"
#include "axiam/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** RFC 9728 §3.1's well-known prefix (§28.3). */
#define AXIAM_MCP_METADATA_PATH_PREFIX "/.well-known/oauth-protected-resource"

/**
 * @name RFC 6750 §3.1's error vocabulary
 *
 * The complete set axiam_bearer_challenge() accepts for
 * axiam_bearer_challenge_options_t::error. Nothing else — not even a
 * well-formed-looking OAuth error code such as "invalid_grant", which has no
 * meaning in a challenge (§28.4).
 * @{
 */
#define AXIAM_BEARER_ERROR_INVALID_REQUEST      "invalid_request"
#define AXIAM_BEARER_ERROR_INVALID_TOKEN        "invalid_token"
#define AXIAM_BEARER_ERROR_INSUFFICIENT_SCOPE   "insufficient_scope"
/** @} */

/**
 * Arguments to axiam_protected_resource_metadata_json() / `_path` / `_url`
 * (§28.1's `protected_resource_metadata`, canonical order). Every member is
 * BORROWED: the caller owns the strings/arrays and they need only outlive the
 * call.
 *
 * `scopes_supported` and `bearer_methods_supported` are NOT the same kind of
 * "empty": passing `scopes_supported = NULL, scopes_supported_count = 0`
 * means "this resource server understands no scopes" and is accepted — the
 * document then OMITS `scopes_supported` (§28.2 rule 5). Passing
 * `bearer_methods_supported = NULL` (regardless of the count field) means
 * "not specified", and defaults to `{"header"}`; passing a NON-NULL pointer
 * with `bearer_methods_supported_count == 0` is an EXPLICIT empty list, which
 * is refused, because ["header"] is the only accepted value in this contract
 * version (§28.2 rule 6) and an empty list is not it.
 */
typedef struct axiam_protected_resource_metadata_options {
    /**
     * The resource identifier this server publishes for itself (§28.2 rule
     * 1): absolute, `https://` (or `http://` on 127.0.0.1 / [::1] /
     * localhost only, §28.2 rule 2), no query, no fragment. A trailing slash
     * is significant and is preserved. Required.
     */
    const char *resource;
    /**
     * Issuer identifiers of the authorization servers guarding this resource
     * (§28.2 rules 3-4). At least one entry; each an absolute URI with no
     * query and no fragment; no duplicates. Required.
     */
    const char *const *authorization_servers;
    size_t authorization_server_count;
    /**
     * Scope tokens this resource server understands (§28.2 rule 5), in the
     * order they should appear — this SDK never sorts. Each one or more
     * RFC 6749 Appendix A NQCHAR characters; no duplicates. May be
     * `{NULL, 0}` (or `{ptr, 0}`): both omit `scopes_supported` from the
     * document.
     */
    const char *const *scopes_supported;
    size_t scopes_supported_count;
    /**
     * §28.2 rule 6. NULL defaults to `{"header"}`, the only accepted value in
     * this contract version. A non-NULL pointer is validated as given — see
     * this struct's own doc comment for why an explicit empty list is a
     * refusal rather than the default.
     */
    const char *const *bearer_methods_supported;
    size_t bearer_methods_supported_count;
    /**
     * Optional human-readable documentation page (§28.2 rule 7): an absolute
     * URL under the same scheme rule as `resource`, but MAY carry a query and
     * a fragment. NULL omits the member; this SDK never emits a JSON `null`.
     */
    const char *resource_documentation;
} axiam_protected_resource_metadata_options_t;

/**
 * `protected_resource_metadata` (§28.1) — the RFC 9728 §2 document itself,
 * as compact JSON with the member order §28.2 fixes.
 *
 * @return A malloc'd, NUL-terminated JSON string on success; free with
 * free(). NULL on a §28.2 validation refusal or out-of-memory, with `err`
 * (when non-NULL) describing which rule and field failed. §28.2: validation
 * happens here, before any document is produced, and never repairs a value
 * to make it pass.
 */
char *axiam_protected_resource_metadata_json(
    const axiam_protected_resource_metadata_options_t *options,
    axiam_error_t *err);

/**
 * `protected_resource_metadata` (§28.1) — just `metadata_path`: the absolute
 * path this document is served at, derived from `resource` per §28.3's
 * table and never chosen.
 *
 * Applies the WHOLE of §28.2's validation before deriving the path, exactly
 * as axiam_protected_resource_metadata_json() does — not a lighter check —
 * so a caller cannot obtain a path for a `resource` that could not otherwise
 * be published, and a route is never registered for a configuration this
 * SDK would refuse to serve as a document.
 *
 * @return A malloc'd, NUL-terminated string on success; free with free().
 * NULL on the same refusals as the `_json` form.
 */
char *axiam_protected_resource_metadata_path(
    const axiam_protected_resource_metadata_options_t *options,
    axiam_error_t *err);

/**
 * `protected_resource_metadata` (§28.1) — just `metadata_url`:
 * `metadata_path` resolved against `resource`'s own scheme and authority.
 *
 * NOT NAMED IN CONTRACT.md §28.7's C ROW — see this header's file comment.
 * §28.1 requires an SDK to expose both `metadata_path` and `metadata_url` so
 * that an integrator feeds axiam_client_config_set_resource_metadata_url()
 * from the value this SDK derived rather than retyping scheme + authority +
 * path by hand; this function is that second piece for C.
 *
 * @return A malloc'd, NUL-terminated string on success; free with free().
 * NULL on the same refusals as the `_json` form.
 */
char *axiam_protected_resource_metadata_url(
    const axiam_protected_resource_metadata_options_t *options,
    axiam_error_t *err);

/**
 * Arguments to axiam_bearer_challenge() (§28.1's `bearer_challenge`,
 * canonical order). Every member is BORROWED.
 */
typedef struct axiam_bearer_challenge_options {
    /**
     * The metadata document's URL — the one parameter always present.
     * Absolute, same scheme rule as `resource` (§28.2 rule 2), MAY carry a
     * query and a fragment, but no `"`, no `\`, no space and no control
     * character (§28.4). Required.
     */
    const char *resource_metadata_url;
    /**
     * One of AXIAM_BEARER_ERROR_INVALID_REQUEST / `_INVALID_TOKEN` /
     * `_INSUFFICIENT_SCOPE`, or NULL when the request carried no
     * authentication information at all (§28.4's first test vector — RFC
     * 6750 §3 says not to name an error in that case).
     */
    const char *error;
    /**
     * A human-readable description, for an application building its OWN
     * challenge for its own 400 (§28.4). NULL to omit.
     *
     * axiam_require_auth_mcp() / axiam_require_access_mcp() never set this:
     * expired, wrong tenant, wrong audience, bad signature, an unsatisfiable
     * `cnf`, a revoked `sid` are all `invalid_token`, indistinguishably —
     * every distinction a 401 draws for an unauthenticated stranger is an
     * oracle (§28.4, §28.8).
     */
    const char *error_description;
    /** The scope the route asked for, verbatim — space-joined tokens. NULL to omit. */
    const char *scope;
} axiam_bearer_challenge_options_t;

/**
 * `bearer_challenge` (§28.1, §28.4) — build the VALUE of a
 * `WWW-Authenticate` header. Never the whole header line, never a map: the
 * caller sets the header itself (or, on a CivetWeb handler, calls
 * `mg_send_http_error`/writes the header directly — see README.md).
 *
 * Parameters appear in this fixed order: `error`, `error_description`,
 * `scope`, `resource_metadata`, separated by exactly ", " (one comma, one
 * space). `resource_metadata` is always present; the other three are
 * omitted when not given. Every value is quoted; NONE is ever escaped —
 * RFC 6750 §3 restricts each parameter's character set to exclude `"` and
 * `\`, so a value needing an escape does not belong in a challenge, and this
 * function refuses it rather than escaping, truncating or stripping it.
 *
 * @return A malloc'd, NUL-terminated string on success; free with free().
 * NULL on a §28.4 validation refusal or out-of-memory, with `err` (when
 * non-NULL) describing which parameter and rule failed.
 */
char *axiam_bearer_challenge(const axiam_bearer_challenge_options_t *options,
                             axiam_error_t *err);

/**
 * §28.5 rule 3's cross-check, for a config and a document built on the same
 * process — the closest C equivalent of what other languages' optional
 * `guard` argument to `serve_protected_resource_metadata` does, since this
 * SDK has no `serve_` function to hang that argument on (§28.3, §28.7).
 *
 * Refuses (AXIAM_ERR_NETWORK) unless BOTH hold:
 *   - `cfg`'s `resource_metadata_url` equals `options`' derived `metadata_url`;
 *   - `cfg`'s `expected_audience` equals `options->resource`.
 *
 * Both comparisons are exact string equality (RFC 3986 §6.2.1): no
 * normalisation, no case folding, no trailing-slash tolerance. Note these are
 * two DIFFERENT strings — `resource` and `metadata_url` are never compared
 * against each other.
 *
 * Returns AXIAM_OK with nothing to check when `cfg`'s `resource_metadata_url`
 * is unset (§28 is off for this config) — call this only when you have
 * already decided to turn §28 on; it is not itself the switch.
 *
 * Where the guard is configured in a different process from the one serving
 * the document, nothing can be checked and nothing is: configure both from
 * one constant, which is what axiam_protected_resource_metadata_url() is for.
 */
axiam_error_kind_t axiam_mcp_check_resource_metadata(
    const axiam_client_config_t *cfg,
    const axiam_protected_resource_metadata_options_t *options,
    axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_MCP_H */
