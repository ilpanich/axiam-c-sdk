/*
 * AXIAM C SDK — bounded read-only retry (CONTRACT.md §16).
 *
 * The policy is machinery, not surface: the only public knob is the disable
 * switch (axiam_client_config_set_retry_enabled). §16.1 permits lowering the
 * budget or turning it off, never raising it — a caller who can raise the cap
 * turns one client into the herd the backoff exists to prevent.
 *
 * Everything here is a pure function of (attempt, header, fraction) so §16.7's
 * "injected clock and injected PRNG — never by sleeping" is achievable: a test
 * that really waits 200 ms is a test nobody runs.
 */

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"

long axiam_retry_backoff_ms(int attempt) {
    if (attempt < 1) attempt = 1;
    /* min(cap, base * 2^(attempt-1)). Shift on a long, guarded so a large
     * attempt cannot shift past the width — the cap makes the result identical
     * either way, but UB does not become correct just because it is unreachable
     * today. */
    long backoff = AXIAM_RETRY_BASE_DELAY_MS;
    for (int i = 1; i < attempt && backoff < AXIAM_RETRY_MAX_DELAY_MS; i++) {
        backoff *= 2;
    }
    return backoff > AXIAM_RETRY_MAX_DELAY_MS ? AXIAM_RETRY_MAX_DELAY_MS : backoff;
}

long axiam_retry_delay_ms(int attempt, long retry_after_ms, double fraction) {
    if (fraction < 0.0) fraction = 0.0;
    if (fraction > 1.0) fraction = 1.0;

    /* FULL jitter: uniform over [0, backoff]. Not "backoff ± 10%" — partial
     * jitter keeps every client's retries clustered around the same instant,
     * which is the failure mode retries cause rather than fix. */
    long jittered = (long)((double)axiam_retry_backoff_ms(attempt) * fraction);

    /* Retry-After is a FLOOR, never a ceiling (§16.1). The server is telling
     * you when it will be ready, so retrying sooner is not permitted; and
     * because it only ever lengthens, a `Retry-After: 0` cannot defeat the
     * backoff. Replacing the backoff with the hint — which is what a
     * `retry_after ?: backoff` idiom does — is the bug this wording names. */
    if (retry_after_ms > jittered) return retry_after_ms;
    return jittered;
}

int axiam_retry_should_retry(int transport_failed, long status) {
    /* Connection refused / DNS / TLS / read timeout: no response arrived, so
     * the request may never have been seen. */
    if (transport_failed || status == 0) return 1;
    /* 429 is exactly where Retry-After usually arrives. */
    if (status == 408 || status == 429) return 1;
    if (status >= 500 && status <= 599) return 1;
    /* Everything else is decisive: 401 belongs to §9's refresh path, 403 is the
     * server having decided, and every other 4xx would produce an identical
     * rejection on a second attempt. */
    return 0;
}

/* RFC 7231 allows either delta-seconds or an HTTP-date. Both appear in the
 * wild, so both are parsed; anything else yields -1 (absent) rather than 0,
 * because an unparseable hint must not become a zero-length floor. */
long axiam_retry_after_ms(const char *header_value) {
    if (!header_value) return -1;

    const char *p = header_value;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) return -1;

    if (isdigit((unsigned char)*p)) {
        char *end = NULL;
        errno = 0;
        long secs = strtol(p, &end, 10);
        if (errno != 0 || end == p || secs < 0) return -1;
        while (end && *end && isspace((unsigned char)*end)) end++;
        if (end && *end) return -1; /* trailing junk: not a delta-seconds */
        /* Clamped at an hour so a hostile or broken header cannot park a
         * thread for a day. The §16.1 cap governs the backoff, not the floor,
         * so without this the floor would be unbounded. */
        if (secs > 3600) secs = 3600;
        return secs * 1000L;
    }

    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    /* IMF-fixdate, the only form a server is required to send. */
    if (!strptime(p, "%a, %d %b %Y %H:%M:%S", &tm_val)) return -1;
    time_t when = timegm(&tm_val);
    if (when == (time_t)-1) return -1;
    double delta = difftime(when, time(NULL));
    if (delta <= 0) return -1; /* a date already past is not a wait */
    if (delta > 3600) delta = 3600;
    return (long)(delta * 1000.0);
}

double axiam_default_jitter(void *ctx) {
    unsigned int *seed = ctx;
    /* rand_r rather than rand: the SDK must not perturb a caller's global RNG
     * state. §16.1 says the source need not be cryptographic — the jitter is a
     * load-spreading device, not a secret. */
    return (double)rand_r(seed) / (double)RAND_MAX;
}

void axiam_default_sleep(void *ctx, long ms) {
    (void)ctx;
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    /* Resumed on EINTR: a signal must not shorten a backoff into a retry the
     * server asked us not to make yet. */
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}
