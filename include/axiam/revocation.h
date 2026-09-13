/**
 * @file revocation.h
 * @brief CONTRACT.md §10.4 — the optional session-revocation feed (contract
 *        1.44, AXIAM threats T-39 and T-143).
 *
 * §10.2 records the gap this narrows: local verification proves a token was
 * issued and has not expired, never that the session behind it still exists. A
 * logout or a role removal therefore does not reach a token already in a
 * caller's hands until it expires — up to fifteen minutes. The documented
 * answer has been "route the decision through gRPC introspection instead",
 * which is correct and costs a round trip PER REQUEST.
 *
 * A deployment may publish `GET /oauth2/revocations`: the hashed ids of the
 * sessions revoked within the last access-token lifetime. Enable the poller and
 * axiam_jwt_verify() rejects a revoked session within ONE POLL INTERVAL
 * instead, for one cacheable fetch per interval.
 *
 * It is **not a control**, and every property follows from that:
 *
 * - Off unless you call axiam_client_enable_revocation_feed().
 * - Never fetched on the request path once warm.
 * - It **never fails closed**: an unreachable feed, a non-200, a body that does
 *   not parse, or an `alg` this build does not know all behave exactly as no
 *   feed at all — and specifically not as an empty list, which would assert
 *   that nothing has been revoked and is a guard silently honouring no
 *   revocations while appearing to honour them.
 * - Every §10.1 rule runs first and still decides; the feed can only ever turn
 *   an accept into a reject.
 * - A token with no `sid` — a client-credentials token, an RPT, a token
 *   exchange — is never matched against it, and there is no fallback to `jti`.
 */
#ifndef AXIAM_REVOCATION_H
#define AXIAM_REVOCATION_H

#include <stddef.h>

#include "axiam/client.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The published feed's path, appended to the client's base URL. */
#define AXIAM_REVOCATION_FEED_PATH "/oauth2/revocations"

/**
 * The shortest interval a caller may configure (§10.4 rule 2). A smaller value
 * is clamped up to it, never refused: a caller who asked for something faster
 * gets the fastest thing on offer.
 */
#define AXIAM_REVOCATION_MIN_POLL_SECS 15

/** The interval §10.4 recommends. */
#define AXIAM_REVOCATION_DEFAULT_POLL_SECS 30

/**
 * The largest number of entries kept in the cache (§10.4 rule 2). The server
 * bounds the document by its own revocation rate over one token lifetime, so
 * this is defence against a server that stops doing so. Overflow drops the
 * WHOLE set rather than truncating it: a truncated set is a guard that admits
 * some revoked sessions and reports none.
 */
#define AXIAM_REVOCATION_MAX_ENTRIES 100000u

/** Buffer size for one feed entry: 43 base64url characters plus the NUL. */
#define AXIAM_REVOCATION_ENTRY_CAP 44u

/**
 * Turn the feed on for @p client, polling every @p poll_interval_secs seconds
 * (clamped up to ::AXIAM_REVOCATION_MIN_POLL_SECS). Pass
 * ::AXIAM_REVOCATION_DEFAULT_POLL_SECS for the recommended interval.
 *
 * A deployment that does not publish the feed is not an error here — that is
 * discovered on the first poll, and behaves as no feed at all from then on.
 *
 * @return 0 on success, -1 when @p client is NULL.
 */
int axiam_client_enable_revocation_feed(axiam_client_t *client, int poll_interval_secs);

/**
 * The feed entry for @p sid, as the server computes it: base64url without
 * padding over the SHA-256 of the claim's EXACT string.
 *
 * Never a parsed-and-re-rendered UUID — the answer would then depend on this
 * SDK's UUID handling rather than on the feed.
 *
 * @param out     receives 43 characters plus a NUL.
 * @param out_cap must be at least ::AXIAM_REVOCATION_ENTRY_CAP.
 * @return 0 on success, -1 on a NULL argument or an undersized buffer.
 */
int axiam_revocation_entry_for(const char *sid, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_REVOCATION_H */
