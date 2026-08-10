/*
 * AXIAM C SDK — client-side decision memo (CONTRACT.md §17).
 *
 * DISABLED BY DEFAULT. §11.2 rule 6's ban on caching allow/deny decisions is
 * still the default behaviour; this is the single opt-in exception that section
 * carves out, and a caller has to switch it on having read the cost.
 *
 * WHAT IT COSTS
 *
 * The staleness bound is the TTL, IN BOTH DIRECTIONS. A grant revoked on the
 * server can still read as allowed for up to the TTL, and a grant just added
 * can still read as denied for up to the TTL. That second direction is the one
 * that surprises people: READ-YOUR-OWN-WRITES IS NOT GUARANTEED. An admin UI
 * that grants a role and immediately re-checks is the case that breaks, and it
 * breaks silently.
 *
 * This mirrors the server's own bound rather than inventing a second staleness
 * story — AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS (default 5s) makes the same
 * trade server-side. One deliberate difference: the server's setting is an
 * unclamped integer, so an operator can configure a multi-hour staleness
 * window. AXIAM_MEMO_MAX_TTL_MS clamps this one at 5s, because the client has
 * no reason to repeat that.
 *
 * Guarded by its own mutex: a C client is routinely shared across threads, and
 * a cache that corrupted under concurrency would be a worse bug than the one it
 * is optimising away.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* U+001F (unit separator) cannot appear in an action, a UUID or a scope, so no
 * combination of caller-supplied values can forge a collision. U+0000 marks an
 * absent optional, which is why an absent scope can never collide with a
 * present one — a memo that let them collide would answer a narrower question
 * with a broader answer. Both are single bytes, so the key stays a plain C
 * string despite carrying a NUL-valued marker: the marker is written as the
 * printable-free byte 0x00 only in the ABSENT sentinel below, which is a
 * one-character string "\x01"-style stand-in chosen to keep strcmp usable. */
#define MEMO_SEP "\x1F"
/* 0x01 rather than 0x00: a literal NUL would terminate the key string and make
 * every absent-component key compare equal from that point on, which is the
 * exact collision rule 3 forbids. 0x01 is equally impossible in a UUID, an
 * action or a scope, and it survives strcmp. */
#define MEMO_ABSENT "\x01"

void axiam_memo_init(axiam_memo_t *m, long requested_ttl_ms) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
    pthread_mutex_init(&m->mtx, NULL);
    if (requested_ttl_ms <= 0) {
        m->ttl_ms = 0; /* disabled — not "cache for zero milliseconds" */
    } else if (requested_ttl_ms > AXIAM_MEMO_MAX_TTL_MS) {
        m->ttl_ms = AXIAM_MEMO_MAX_TTL_MS; /* §17.1 rule 2: clamp, never reject */
    } else {
        m->ttl_ms = requested_ttl_ms;
    }
}

int axiam_memo_enabled(const axiam_memo_t *m) {
    return m && m->ttl_ms > 0 ? 1 : 0;
}

long axiam_memo_effective_ttl_ms(const axiam_memo_t *m) {
    return m ? m->ttl_ms : 0;
}

char *axiam_memo_key(const char *subject_id, const char *resource_id,
                     const char *action, const char *scope) {
    const char *s = (subject_id && subject_id[0]) ? subject_id : MEMO_ABSENT;
    const char *r = resource_id ? resource_id : "";
    const char *a = action ? action : "";
    const char *c = (scope && scope[0]) ? scope : MEMO_ABSENT;

    size_t n = strlen(s) + strlen(r) + strlen(a) + strlen(c) + 4;
    char *key = malloc(n);
    if (!key) return NULL;
    snprintf(key, n, "%s" MEMO_SEP "%s" MEMO_SEP "%s" MEMO_SEP "%s", s, r, a, c);
    return key;
}

static void entry_free(struct axiam_memo_entry *e) {
    if (!e) return;
    free(e->key);
    free(e->reason);
    free(e->reason_code);
    free(e);
}

/* Unlink the oldest entry. Caller holds the lock. */
static void evict_oldest(axiam_memo_t *m) {
    struct axiam_memo_entry *old = m->head;
    if (!old) return;
    m->head = old->next;
    if (!m->head) m->tail = NULL;
    m->count--;
    entry_free(old);
}

/* Unlink `key` if present. Caller holds the lock. */
static void unlink_key(axiam_memo_t *m, const char *key) {
    struct axiam_memo_entry *prev = NULL;
    struct axiam_memo_entry *cur = m->head;
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            if (prev) {
                prev->next = cur->next;
            } else {
                m->head = cur->next;
            }
            if (m->tail == cur) m->tail = prev;
            m->count--;
            entry_free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

int axiam_memo_get(axiam_memo_t *m, const char *key, axiam_check_result_t *out) {
    if (!axiam_memo_enabled(m) || !key || !out) return 0;

    pthread_mutex_lock(&m->mtx);
    struct axiam_memo_entry *cur = m->head;
    while (cur && strcmp(cur->key, key) != 0) cur = cur->next;
    if (!cur) {
        pthread_mutex_unlock(&m->mtx);
        return 0;
    }
    if (axiam_now_ms() - cur->stored_at_ms >= (double)m->ttl_ms) {
        unlink_key(m, key);
        pthread_mutex_unlock(&m->mtx);
        return 0;
    }
    /* Returned WHOLE, including reason_code: §17.1 rule 5 forbids returning
     * `allowed` while dropping the code, which would make the field
     * intermittently absent — worse than never having had it. */
    out->allowed = cur->allowed;
    out->reason = axiam_strdup0(cur->reason);
    out->reason_code = axiam_strdup0(cur->reason_code);
    pthread_mutex_unlock(&m->mtx);
    return 1;
}

void axiam_memo_put(axiam_memo_t *m, const char *key, const axiam_check_result_t *r) {
    /* Callers must only reach here on success. §17.1 rule 7 forbids
     * negative-caching a failure: memoizing a transport error as a deny would
     * turn a blip into a TTL-long outage, and memoizing it as an allow is
     * unthinkable. */
    if (!axiam_memo_enabled(m) || !key || !r) return;

    struct axiam_memo_entry *e = calloc(1, sizeof(*e));
    if (!e) return; /* the memo is an optimisation; dropping is always correct */
    e->key = axiam_strdup0(key);
    if (!e->key) {
        entry_free(e);
        return;
    }
    e->allowed = r->allowed;
    e->reason = axiam_strdup0(r->reason);
    e->reason_code = axiam_strdup0(r->reason_code);
    e->stored_at_ms = axiam_now_ms();

    pthread_mutex_lock(&m->mtx);
    /* Re-inserting at the tail is what makes the eviction below FIFO: entries
     * expire on age, so the oldest is the one that was going to expire first
     * anyway. */
    unlink_key(m, key);
    if (m->tail) {
        m->tail->next = e;
    } else {
        m->head = e;
    }
    m->tail = e;
    m->count++;
    while (m->count > AXIAM_MEMO_MAX_ENTRIES) evict_oldest(m);
    pthread_mutex_unlock(&m->mtx);
}

void axiam_memo_clear(axiam_memo_t *m) {
    /* §17.1 rule 9. Called on login, verify_mfa, refresh and logout. Entries
     * are keyed by subject, not by session, so a re-authentication as a
     * DIFFERENT principal would otherwise read the previous principal's
     * decisions. */
    if (!m) return;
    pthread_mutex_lock(&m->mtx);
    struct axiam_memo_entry *cur = m->head;
    while (cur) {
        struct axiam_memo_entry *next = cur->next;
        entry_free(cur);
        cur = next;
    }
    m->head = NULL;
    m->tail = NULL;
    m->count = 0;
    pthread_mutex_unlock(&m->mtx);
}

size_t axiam_memo_count(axiam_memo_t *m) {
    if (!m) return 0;
    pthread_mutex_lock(&m->mtx);
    size_t n = m->count;
    pthread_mutex_unlock(&m->mtx);
    return n;
}

void axiam_memo_destroy(axiam_memo_t *m) {
    if (!m) return;
    axiam_memo_clear(m);
    pthread_mutex_destroy(&m->mtx);
}
