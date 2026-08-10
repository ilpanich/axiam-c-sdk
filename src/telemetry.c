/*
 * AXIAM C SDK — telemetry dispatch (CONTRACT.md §19).
 *
 * Thin by design. Every helper builds a stack event, fills only the fields its
 * kind carries, and calls the hook — no allocation, no queue, no thread. §19.2
 * rule 4 makes buffering the caller's job so they can pick the policy; a queue
 * added here would take that choice away from every caller to defend against
 * the one who blocks.
 */

#include <string.h>
#include <time.h>

#include "internal.h"

int axiam_telemetry_installed(const axiam_telemetry_t *t) {
    return t && t->fn ? 1 : 0;
}

void axiam_telemetry_emit(const axiam_telemetry_t *t, const axiam_telemetry_event_t *ev) {
    if (!axiam_telemetry_installed(t) || !ev) return;
    /* The return value is deliberately not inspected and the hook is given no
     * way to influence control flow: §19.2 rule 2 says telemetry is not
     * permitted to fail an authorization check. C cannot catch a hook that
     * aborts, but it can refuse to let one decide anything. */
    t->fn(t->ctx, ev);
}

double axiam_now_ms(void) {
    struct timespec ts;
    /* MONOTONIC: a duration measured against the wall clock goes negative when
     * NTP steps the machine, and a negative latency in a metrics backend is
     * indistinguishable from a bug in the caller's dashboard. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0.0;
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

void axiam_telemetry_request_start(const axiam_telemetry_t *t, const char *op,
                                   const char *method, const char *path, int attempt) {
    if (!axiam_telemetry_installed(t)) return;
    axiam_telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = AXIAM_TELEMETRY_REQUEST_START;
    ev.operation = op;
    ev.method = method;
    ev.path_template = path;
    ev.attempt = attempt;
    axiam_telemetry_emit(t, &ev);
}

void axiam_telemetry_request_end(const axiam_telemetry_t *t, const char *op,
                                 const char *method, const char *path, int attempt,
                                 long status, double duration_ms,
                                 axiam_telemetry_outcome_t outcome) {
    if (!axiam_telemetry_installed(t)) return;
    axiam_telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = AXIAM_TELEMETRY_REQUEST_END;
    ev.operation = op;
    ev.method = method;
    ev.path_template = path;
    ev.attempt = attempt;
    ev.status = status;
    ev.duration_ms = duration_ms;
    ev.outcome = outcome;
    axiam_telemetry_emit(t, &ev);
}

void axiam_telemetry_retry(const axiam_telemetry_t *t, const char *op, int attempt,
                           long delay_ms, const char *reason) {
    if (!axiam_telemetry_installed(t)) return;
    axiam_telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = AXIAM_TELEMETRY_RETRY;
    ev.operation = op;
    ev.attempt = attempt;
    ev.delay_ms = delay_ms;
    ev.reason = reason;
    axiam_telemetry_emit(t, &ev);
}

void axiam_telemetry_refresh(const axiam_telemetry_t *t, axiam_refresh_role_t role,
                             double duration_ms) {
    if (!axiam_telemetry_installed(t)) return;
    axiam_telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = AXIAM_TELEMETRY_REFRESH;
    ev.refresh_role = role;
    ev.duration_ms = duration_ms;
    axiam_telemetry_emit(t, &ev);
}

void axiam_telemetry_config_clamped(const axiam_telemetry_t *t, const char *setting,
                                    const char *requested, const char *effective,
                                    const char *contract_reference) {
    if (!axiam_telemetry_installed(t)) return;
    axiam_telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = AXIAM_TELEMETRY_CONFIG_CLAMPED;
    ev.setting = setting;
    ev.requested = requested;
    ev.effective = effective;
    ev.contract_reference = contract_reference;
    axiam_telemetry_emit(t, &ev);
}
