/*
 * The optional session-revocation feed poller (CONTRACT.md §10.4, contract
 * 1.44 — AXIAM threats T-39 and T-143).
 *
 * # What this narrows, and what it is not
 *
 * An AXIAM access token is self-contained and valid for up to fifteen minutes,
 * and axiam_jwt_verify() verifies it locally. A logout, a role removal or an
 * account disable therefore does not reach a token already in a caller's hands
 * until it expires — §10.2 records that, and the documented answer has been
 * "route the decision through gRPC introspection instead", which is correct and
 * costs a round trip PER REQUEST.
 *
 * A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded
 * SHA-256 of every session id revoked within the last access-token lifetime. A
 * guard that polls it rejects a revoked session within ONE POLL INTERVAL
 * instead of one token lifetime, for one cacheable fetch per interval.
 *
 * It is NOT a control, and every rule below follows from that:
 *
 *   - Default off. Nothing polls unless the caller enables it.
 *   - Never fail closed. An unreachable feed, a non-200, a body that does not
 *     parse, an `alg` this build does not know — every one of them behaves
 *     exactly as no feed at all. Not as an empty list: an empty list asserts
 *     that nothing has been revoked, which is a guard that silently honours no
 *     revocations while appearing to honour them.
 *   - It only ever rejects. Every §10.1 rule runs first and still decides.
 *   - A token with no `sid` is never matched. There is no session behind a
 *     client-credentials token, an RPT or a token exchange, and hashing `jti`
 *     instead would match nothing while looking like it worked.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>

#include "cJSON.h"
#include "internal.h"

#include "axiam/revocation.h"

/*
 * The only digest the feed publishes, and the only one this poller accepts.
 *
 * A document naming anything else is treated as unusable — exactly as an
 * unreachable feed is — rather than as a list of entries that happen not to
 * match. Silently matching nothing is how a guard ends up reporting that it
 * honours revocations while honouring none.
 */
#define REVOCATION_ALG "SHA-256"

/* base64url without padding (RFC 4648 §5), into a caller-supplied buffer.
 * A 32-byte digest encodes to exactly 43 characters plus the NUL, which is
 * AXIAM_REVOCATION_ENTRY_CAP. */
static void b64url_43(const unsigned char digest[32], char out[44]) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < 32; i += 3) {
        unsigned v = (unsigned)digest[i] << 16;
        size_t have = 1;
        if (i + 1 < 32) { v |= (unsigned)digest[i + 1] << 8; have = 2; }
        if (i + 2 < 32) { v |= (unsigned)digest[i + 2]; have = 3; }
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        if (have > 1) out[o++] = alphabet[(v >> 6) & 0x3F];
        if (have > 2) out[o++] = alphabet[v & 0x3F];
    }
    out[o] = '\0';
}

int axiam_revocation_entry_for(const char *sid, char *out, size_t out_cap) {
    if (!sid || !out || out_cap < AXIAM_REVOCATION_ENTRY_CAP) return -1;
    unsigned char digest[32];
    /* Over the claim's EXACT string — never a parsed-and-re-rendered UUID, or
     * the answer would depend on this SDK's UUID handling rather than on the
     * feed. */
    SHA256((const unsigned char *)sid, strlen(sid), digest);
    char encoded[44];
    b64url_43(digest, encoded);
    memcpy(out, encoded, sizeof(encoded));
    return 0;
}

int axiam_client_enable_revocation_feed(axiam_client_t *client, int poll_interval_secs) {
    if (!client) return -1;
    if (poll_interval_secs < AXIAM_REVOCATION_MIN_POLL_SECS) {
        /* Clamped, not refused: a caller who asked for something faster gets
         * the fastest thing on offer. The floor exists because the feed is one
         * deployment-wide document and a fleet of guards polling it at a
         * hundred milliseconds is a load source, not a security improvement. */
        poll_interval_secs = AXIAM_REVOCATION_MIN_POLL_SECS;
    }
    pthread_mutex_lock(&client->revocation_mtx);
    client->revocation_on = 1;
    client->revocation_poll_secs = poll_interval_secs;
    pthread_mutex_unlock(&client->revocation_mtx);
    return 0;
}

/* Replace the cached set. Caller holds revocation_mtx. */
static void adopt_entries(axiam_client_t *c, char **entries, size_t count) {
    for (size_t i = 0; i < c->revocation_count; i++) free(c->revocation_entries[i]);
    free(c->revocation_entries);
    c->revocation_entries = entries;
    c->revocation_count = count;
}

/*
 * Parse one document. Returns 1 and adopts the set on success; 0 for every kind
 * of failure, which the caller treats identically — see the file header on why
 * "unusable" must not collapse into "empty". Caller holds revocation_mtx.
 */
static int parse_feed(axiam_client_t *c, const char *body) {
    cJSON *root = cJSON_Parse(body);
    if (!root) return 0;
    int ok = 0;
    char **entries = NULL;
    size_t count = 0;

    const cJSON *alg = cJSON_GetObjectItemCaseSensitive(root, "alg");
    if (!cJSON_IsString(alg) || !alg->valuestring || strcmp(alg->valuestring, REVOCATION_ALG) != 0)
        goto done;

    const cJSON *revoked = cJSON_GetObjectItemCaseSensitive(root, "revoked");
    if (!cJSON_IsArray(revoked)) goto done;

    int size = cJSON_GetArraySize(revoked);
    /* Overflow drops the WHOLE set rather than truncating it: a truncated set
     * is a guard that admits some revoked sessions and reports none, which is
     * worse than one that admits all of them and says the feed is unusable. */
    if (size < 0 || (size_t)size > AXIAM_REVOCATION_MAX_ENTRIES) goto done;

    if (size > 0) {
        entries = calloc((size_t)size, sizeof(*entries));
        if (!entries) goto done;
    }
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, revoked) {
        if (!cJSON_IsString(entry) || !entry->valuestring) continue;
        char *copy = axiam_strdup0(entry->valuestring);
        if (!copy) {
            /* An allocation failure mid-parse is the same answer as a bad
             * document: keep what we had, report unusable. */
            for (size_t i = 0; i < count; i++) free(entries[i]);
            free(entries);
            entries = NULL;
            count = 0;
            goto done;
        }
        entries[count++] = copy;
    }
    adopt_entries(c, entries, count);
    entries = NULL;
    ok = 1;

done:
    for (size_t i = 0; entries && i < count; i++) free(entries[i]);
    free(entries);
    cJSON_Delete(root);
    return ok;
}

/*
 * Refetch if the poll interval has elapsed since the last ATTEMPT.
 *
 * Attempt, not success: a feed that is down must not be retried on every
 * request, which would put the request path back on the network — the cost
 * §10.4 exists to avoid.
 */
static void refresh_if_stale(axiam_client_t *c) {
    time_t now = time(NULL);
    pthread_mutex_lock(&c->revocation_mtx);
    int due = c->revocation_last_attempt == 0 ||
              (now - c->revocation_last_attempt) >= c->revocation_poll_secs;
    if (due) c->revocation_last_attempt = now;
    pthread_mutex_unlock(&c->revocation_mtx);
    if (!due) return;

    char *body = NULL;
    int fetched;
    if (c->revocation_fetch_fn) {
        fetched = c->revocation_fetch_fn(c->revocation_fetch_ctx, &body) == 0;
    } else {
        /* The error is deliberately discarded: §10.4 rule 3 says every way the
         * feed can fail behaves as no feed at all, so there is nothing here to
         * report to a caller who never asked the feed a question. */
        axiam_error_t err;
        fetched = axiam_client_raw_get(c, AXIAM_REVOCATION_FEED_PATH, &body, &err) == AXIAM_OK;
    }
    if (fetched && body) {
        pthread_mutex_lock(&c->revocation_mtx);
        /* parse_feed leaves the previous set untouched when it returns 0. */
        (void)parse_feed(c, body);
        pthread_mutex_unlock(&c->revocation_mtx);
    }
    free(body);
}

int axiam_revocation_is_revoked(axiam_client_t *c, const char *sid) {
    if (!c || !sid || !sid[0]) return 0;
    pthread_mutex_lock(&c->revocation_mtx);
    int on = c->revocation_on;
    pthread_mutex_unlock(&c->revocation_mtx);
    if (!on) return 0;

    refresh_if_stale(c);

    char want[AXIAM_REVOCATION_ENTRY_CAP];
    if (axiam_revocation_entry_for(sid, want, sizeof(want)) != 0) return 0;

    int found = 0;
    pthread_mutex_lock(&c->revocation_mtx);
    /* NULL means "never successfully fetched" and is deliberately distinct from
     * a fetched-but-empty document; both answer "not revoked", but only the
     * second is an assertion about the deployment. */
    for (size_t i = 0; !found && i < c->revocation_count; i++) {
        if (c->revocation_entries[i] && strcmp(c->revocation_entries[i], want) == 0) found = 1;
    }
    pthread_mutex_unlock(&c->revocation_mtx);
    return found;
}

void axiam_revocation_dispose(axiam_client_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->revocation_count; i++) free(c->revocation_entries[i]);
    free(c->revocation_entries);
    c->revocation_entries = NULL;
    c->revocation_count = 0;
}
