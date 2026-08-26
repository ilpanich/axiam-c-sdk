/*
 * Shared rig for the CONTRACT.md §27 management tests.
 *
 * The fake transport sits at the BOTTOM of the real client, exactly like every other
 * test in this suite -- not in place of it. That matters for §27.8: a test that stubbed
 * axiam_mgmt_send() would pass just as happily if the generated operations had quietly
 * opened their own connection, which is the one thing §27.8 forbids.
 */

#ifndef AXIAM_MANAGEMENT_TEST_UTIL_H
#define AXIAM_MANAGEMENT_TEST_UTIL_H

#include "axiam/axiam.h"

/** Reset the rig between cases. */
void mgmt_reset(void);

/** Queue the status and body the next management request will receive. */
void mgmt_mount(long status, const char *body);

/** Queue a second response, for the cases that make two requests. */
void mgmt_mount_next(long status, const char *body);

/**
 * A client with an established session.
 *
 * The session comes from a real login through the same fake transport, so §27.4 rule 1's
 * "no session, no wire call" check sees a genuine authenticated client rather than a
 * flag poked into place.
 */
axiam_client_t *mgmt_signed_in_client(void);

/** A client that has NOT logged in -- for the rule 1 cases. */
axiam_client_t *mgmt_anonymous_client(void);

/**
 * A signed-in client configured with a tenant SLUG and no org or tenant UUID.
 *
 * For the routes that substitute an implicit `{org_id}`/`{tenant_id}`: with neither
 * configured nor resolved, the operation must refuse rather than send an empty path
 * segment.
 */
axiam_client_t *mgmt_unscoped_client(void);

/** The method of the last management request that reached the transport. */
const char *mgmt_last_method(void);

/** The PATH (no scheme, host or query) of the last management request. */
const char *mgmt_last_path(void);

/** The full URL of the last management request, query string included. */
const char *mgmt_last_url(void);

/** The body of the last management request, or "" when it sent none. */
const char *mgmt_last_body(void);

/** How many requests have reached the transport, the login included. */
int mgmt_request_count(void);

/** How many cases the generated conformance file declares (§27.9). */
int mgmt_case_count(void);

#endif /* AXIAM_MANAGEMENT_TEST_UTIL_H */
