/*
 * Internal seam between the hand-written §27 core (management.c) and the generated
 * operations (management_ops.c). Not installed; not part of the public ABI.
 */

#ifndef AXIAM_MANAGEMENT_INTERNAL_H
#define AXIAM_MANAGEMENT_INTERNAL_H

#include "axiam/management.h"
#include "cJSON.h"

/*
 * One management request, through the same transport every other REST call uses
 * (CONTRACT.md §27.8).
 *
 * All 147 generated operations funnel through this one function, which is what makes
 * §27.8 structural rather than a convention: §3 CSRF, the §4 cookie jar, the §5 tenant
 * header and §6 TLS apply because axiam_client_send_raw() applies them, and no generated
 * operation is in a position to skip any of it.
 *
 * What this adds on top:
 *   - rule 1  — no session, no wire call. Checked before the request is built.
 *   - rule 7  — the status classification, via axiam_mgmt_classify().
 *   - rule 8  — only GET is retried, and never a rejected body.
 *   - rule 10 — nothing is cached.
 *   - rule 11 — telemetry carries the path TEMPLATE, never the substituted path.
 *
 * `path_template` is the `{placeholder}` form and is what telemetry sees; `path` is the
 * substituted one and is what goes on the wire. Passing the same string for both would
 * compile and quietly put identifiers into metrics labels, so they are separate
 * parameters rather than one with a flag.
 *
 * On AXIAM_OK, *out_json is the parsed body (caller frees with cJSON_Delete) or NULL for
 * a no-content response. On failure *out_json is NULL and `err` is filled.
 */
axiam_error_kind_t axiam_mgmt_send(axiam_client_t *c,
                                   const char *operation,
                                   const char *method,
                                   const char *path_template,
                                   const char *path,
                                   const char *body_json,
                                   cJSON **out_json,
                                   axiam_error_t *err);

/*
 * Build a request path from a template by substituting {name} placeholders.
 *
 * `names`/`values` are parallel arrays of `count` entries. Each value is URL-encoded:
 * an identifier is caller-supplied, and a raw '/' or '?' in one would silently retarget
 * the request at a different route.
 *
 * Returns a malloc'd string the caller frees, or NULL on allocation failure or when any
 * value is NULL/empty (which is how a missing implicit scope id surfaces — see
 * axiam_mgmt_resolved_org_id).
 */
char *axiam_mgmt_path(const char *template_, const char *const *names,
                      const char *const *values, size_t count);

/* Append `?offset=&limit=` (and any extra query pairs) to a path built above.
 * Takes ownership of `path` and returns a new string, freeing the old one. */
char *axiam_mgmt_query(char *path, const char *const *names,
                       const char *const *values, size_t count);

/* Render a page request as its two query values; both buffers must be >= 24 bytes. */
void axiam_mgmt_page_query(const axiam_mgmt_page_req_t *page, char *offset_buf, char *limit_buf);

/* Fill `err` for a management failure, applying the rule 7 parent mapping. */
void axiam_mgmt_classify(axiam_error_t *err, long status, const char *operation,
                         const char *body);

/* Read the server's total out of a page envelope; falls back to the item count. */
long axiam_mgmt_page_total(const cJSON *envelope, long item_count);

/* The `items`/`data` array of a page envelope, or NULL when neither is present. */
const cJSON *axiam_mgmt_page_items(const cJSON *envelope);

/* Serialize a cJSON body to a malloc'd string and delete the cJSON. NULL-safe. */
char *axiam_mgmt_render(cJSON *body);

#endif /* AXIAM_MANAGEMENT_INTERNAL_H */
