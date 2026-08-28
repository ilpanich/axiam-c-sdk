/**
 * @file management.h
 * @brief CONTRACT.md §27 management API — shared core.
 *
 * The §27 surface is 147 administrative operations across 24 namespaces. Nine of the
 * eleven AXIAM SDKs expose them as NAMESPACE HANDLES (`client.management().users()
 * .list()`, §27.2). C is one of the two that take §27.3's **flat-symbol accommodation**
 * instead, and not as a shortcut: §27.2's shape needs a value that carries both a
 * receiver and a method table, and C has no such thing that would not amount to
 * hand-rolling a vtable for 24 structs to spell one dot differently.
 *
 * So the namespace lives in the NAME: `axiam_<namespace>_<operation>()`, which is the
 * exact shape §27.3's per-language table gives C — its row reads
 * `axiam_service_accounts_rotate_secret(client, id, &out)`. The grouping §27.2 asks for
 * is preserved — `axiam_users_*` is the users namespace, and a completion list sorted
 * alphabetically groups exactly the way handles would — while the call stays an ordinary
 * C function with no lifetime questions attached to it.
 *
 * The MODEL types below keep an `axiam_mgmt_` prefix. §27.3 spells out the operation
 * accessor and says nothing about type names, and there the prefix earns its keep by
 * separating 145 generated types from the SDK's own.
 *
 * This header carries the pieces every operation shares: paging, scope, the §27.4 rule 7
 * error classification, and the free functions for the two generic result shapes. The
 * models and the 147 operations are generated — see `axiam/management_models.h` and
 * `axiam/management_ops.h`.
 */

#ifndef AXIAM_MANAGEMENT_H
#define AXIAM_MANAGEMENT_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The §27.4 rule 7 classification of a management failure.
 *
 * C has no subtyping, so rule 7's "sub-type inside the §2 taxonomy" becomes a SECOND
 * FIELD rather than a fourth kind — the same accommodation `axiam_error_t::oauth_error`
 * already makes for the §12 `OAuthProtocolError`. `axiam_error_t::kind` keeps the parent
 * rule 7 names, and this says which sub-type it would have been:
 *
 * | status     | kind                 | class                              |
 * |------------|----------------------|------------------------------------|
 * | `404`      | `AXIAM_ERR_AUTHZ`    | `AXIAM_MGMT_ERR_NOT_FOUND`         |
 * | `409`      | `AXIAM_ERR_AUTHZ`    | `AXIAM_MGMT_ERR_CONFLICT`          |
 * | `400`,`422`| `AXIAM_ERR_NETWORK`  | `AXIAM_MGMT_ERR_VALIDATION`        |
 *
 * `404` under `AXIAM_ERR_AUTHZ` is the counter-intuitive row and the important one. AXIAM
 * is multi-tenant, and the server answers `404` for an object belonging to another tenant
 * *precisely so* a caller cannot tell "does not exist" from "exists, not yours".
 * Classifying it as an authorization outcome keeps the SDK from re-drawing a line the
 * server deliberately refused to draw. Note this differs from
 * `axiam_error_kind_from_http_status()`, which maps a bare `404` to
 * `AXIAM_ERR_NETWORK`: that mapping is right for the rest of the SDK and is left alone.
 */
typedef enum axiam_mgmt_error_class {
    AXIAM_MGMT_ERR_NONE = 0,   /**< Not a rule 7 status (or not a failure at all). */
    AXIAM_MGMT_ERR_NOT_FOUND,  /**< `404` — absent, or belonging to another tenant. */
    AXIAM_MGMT_ERR_CONFLICT,   /**< `409` — already exists, or the state forbids the write. */
    AXIAM_MGMT_ERR_VALIDATION  /**< `400`/`422` — the server rejected the request body. */
} axiam_mgmt_error_class_t;

/**
 * The rule 7 class of the failure `err` describes.
 *
 * A function rather than a struct field, so `axiam_error_t` keeps the layout every
 * existing caller compiled against — adding a member to a struct callers allocate on the
 * stack is an ABI break, and §27 is not worth one. The class is derived from
 * `err->transport_cause`, which already carries the HTTP status.
 *
 * Returns `AXIAM_MGMT_ERR_NONE` for `NULL`, for success, and for any status rule 7 does
 * not name.
 */
axiam_mgmt_error_class_t axiam_mgmt_error_class(const axiam_error_t *err);

/**
 * One page's worth of `?offset=`/`?limit=`/`?search=` (CONTRACT.md §27.4 rule 4).
 *
 * Pass `NULL` wherever an operation takes one to get the first page at the default size,
 * unfiltered.
 *
 * `search` lives here rather than as a separate argument on each of the twenty paginated
 * operations, which is what §27.4 rule 4 asks for and what makes
 * `axiam_mgmt_page_next()` carry it. A walk that filtered its first request and dropped
 * the term on the second would return the matches followed by the unfiltered tail, which
 * reads as a server bug from the caller's side.
 *
 * `search` is **borrowed, never owned**: nothing here or in any page result copies it or
 * frees it. It must outlive every request derived from it — in the ordinary walk that
 * means a string literal or a buffer declared outside the loop, since the page result
 * carries the same pointer through `axiam_mgmt_page_next(page->request)`.
 */
typedef struct axiam_mgmt_page_req {
    long offset; /**< How many items to skip. Negative is clamped to 0. */
    long limit;  /**< How many to ask for. Below 1 is clamped to 1. */
    /**
     * A free-text filter applied by the SERVER, before `offset`/`limit`, or `NULL` for
     * none.
     *
     * Matched case-insensitively against the identifying fields of whatever is being
     * listed — a name or username, plus the record id, so a UUID out of a log line can be
     * pasted in as-is. The page's `total` then counts MATCHES, not rows.
     *
     * `NULL` sends no `search` parameter, and an empty or all-whitespace term is treated
     * identically: a search box that fires on every keystroke sends one the moment it is
     * cleared, and "rows containing the empty string" is a different question from "all
     * rows". The term is trimmed but never truncated — the server caps its length, and a
     * client-side truncation the server would not have made is a silently different query.
     *
     * Borrowed. See the struct's own note.
     */
    const char *search;
} axiam_mgmt_page_req_t;

/** The server's default page size when a call names no limit. */
#define AXIAM_MGMT_DEFAULT_LIMIT 50L

/**
 * The page after `req` — same size and same `search` term, advanced by exactly `limit`.
 *
 * Advancing by the requested limit rather than by the number of items actually returned
 * is deliberate: §27.4 rule 4 stops auto-paging on an EMPTY page, not a short one, and
 * advancing by a short count would re-request rows the caller has already seen.
 *
 * The `search` pointer is copied as a pointer, not as a string. See
 * `axiam_mgmt_page_req_t`.
 */
axiam_mgmt_page_req_t axiam_mgmt_page_next(axiam_mgmt_page_req_t req);

/**
 * The `search` term as it goes on the wire, or `NULL` when there is nothing to send
 * (CONTRACT.md §27.4 rule 4).
 *
 * Skips leading whitespace and answers `NULL` for a term that is empty or all
 * whitespace — the same normalisation the server applies, and the reason absent and blank
 * are the same request. The returned pointer is into `term` itself; TRAILING whitespace is
 * left for the server to trim, because trimming it here would mean allocating a copy this
 * SDK would then have to own.
 *
 * Exposed because it is the one piece of `search` handling a caller can observe going
 * wrong, and because the suite asserts on it directly.
 */
const char *axiam_mgmt_page_search(const char *term);

/**
 * Per-call override of the `{org_id}`/`{tenant_id}` a route substitutes
 * (CONTRACT.md §27.4 rule 3).
 *
 * Every operation whose path carries an implicit identifier takes one of these, and
 * passing `NULL` — which is what almost every call does — uses the client's own. This is
 * the flat-symbol analogue of the handle-based SDKs' `->in_org()` / `->for_tenant()`, and
 * it inherits that design's most important property for free: there is no shared object
 * to re-scope, so one call's override cannot leak into the next.
 *
 * A field left `NULL` falls back to the client; the two are independent.
 *
 * Named `call_scope` rather than `scope` because `Scope` is also a SCHEMA in the AXIAM
 * spec (a sub-resource permission scope, §27's `axiam_mgmt_scope_t`). The generated model
 * keeps the spec's name — renaming it would make C the one SDK whose type does not match
 * the contract — so this hand-written one takes the qualifier.
 */
typedef struct axiam_mgmt_call_scope {
    const char *org_id;    /**< Overrides `{org_id}`, or `NULL` for the client's. */
    const char *tenant_id; /**< Overrides `{tenant_id}`, or `NULL` for the client's. */
} axiam_mgmt_call_scope_t;

/**
 * The organization UUID §27 routes substitute for `{org_id}`.
 *
 * Resolution order: the scope override, then the client's configured `org_id`, then the
 * one resolved from the access-token claims at login (D-14). Returns `NULL` when none is
 * available — the caller then reports rather than sending an empty path segment, since
 * `/api/v1/organizations//tenants` is not a 404 anybody can act on.
 *
 * The returned pointer is owned by the client and stays valid until it is freed.
 */
const char *axiam_mgmt_resolved_org_id(axiam_client_t *c, const axiam_mgmt_call_scope_t *scope);

/**
 * The tenant UUID §27 routes substitute for `{tenant_id}`. Resolution order as
 * {@link axiam_mgmt_resolved_org_id}.
 *
 * This is the UUID, never the tenant SLUG §5's `X-Tenant-ID` header takes. The two are
 * not interchangeable in a path segment, and the SDK holds both.
 */
const char *axiam_mgmt_resolved_tenant_id(axiam_client_t *c, const axiam_mgmt_call_scope_t *scope);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_MANAGEMENT_H */
