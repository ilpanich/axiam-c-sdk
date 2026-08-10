/*
 * Telemetry hooks (CONTRACT.md §19): wiring metrics to an AXIAM client
 * WITHOUT this library depending on any metrics package.
 *
 * The sink below aggregates in-process so the example builds with no extra
 * dependencies; the comment at the bottom shows the exact mapping onto
 * OpenTelemetry / Prometheus, which is a drop-in replacement for the body.
 * Uses ONLY public headers.
 *
 * Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:   AXIAM_BASE_URL=https://iam.example.com AXIAM_TENANT=acme ./telemetry_hook
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"

typedef struct {
    long attempts;      /* request_end events — one per WIRE call */
    long failures;
    double total_ms;
    long retries;
    long refreshes;
} metrics_t;

static void sink(void *ctx, const axiam_telemetry_event_t *ev) {
    metrics_t *m = ctx;
    switch (ev->kind) {
    case AXIAM_TELEMETRY_REQUEST_END:
        /* One pair per ATTEMPT, not per logical call (§19.2 rule 5), so
         * counting these gives the real number of wire calls — including the
         * ones a retry made on your behalf. */
        m->attempts++;
        m->total_ms += ev->duration_ms;
        if (ev->outcome == AXIAM_TELEMETRY_FAILURE) m->failures++;
        break;

    case AXIAM_TELEMETRY_RETRY:
        /* §16.5 — the reason this event exists. A retried-then-succeeded
         * operation is otherwise invisible: the caller sees a slow success and
         * no signal that the server is failing. Alert on THIS rate, not on the
         * error rate, or a degrading server looks healthy right up until the
         * retries stop being enough. */
        m->retries++;
        break;

    case AXIAM_TELEMETRY_REFRESH:
        m->refreshes++;
        break;

    case AXIAM_TELEMETRY_CONFIG_CLAMPED:
        /* §19.2 rule 6 — fired at most once per clamped setting, at
         * construction. Worth logging loudly rather than counting: it means a
         * value in your configuration is not the value in force, and the gap
         * is silent everywhere else. */
        fprintf(stderr, "WARN: %s=%s was clamped to %s (%s)\n",
                ev->setting, ev->requested, ev->effective, ev->contract_reference);
        break;

    case AXIAM_TELEMETRY_REQUEST_START:
    default:
        break;
    }
}

int main(void) {
    const char *base = getenv("AXIAM_BASE_URL");
    const char *tenant = getenv("AXIAM_TENANT");
    if (!base || !tenant) {
        fprintf(stderr, "set AXIAM_BASE_URL and AXIAM_TENANT\n");
        return 2;
    }

    metrics_t metrics;
    memset(&metrics, 0, sizeof(metrics));

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, tenant);
    axiam_client_config_set_telemetry_hook(cfg, sink, &metrics);
    /* Deliberately above the §17.1 rule 2 ceiling, so the run demonstrates the
     * config_clamped warning above rather than leaving it theoretical. */
    axiam_client_config_set_decision_memo_ttl(cfg, 60000);

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "client construction failed: %s\n", err.message);
        return 1;
    }

    axiam_check_result_t result;
    axiam_error_kind_t kind =
        axiam_check_access(client, "read", "doc-1", NULL, NULL, &result, &err);
    if (kind == AXIAM_OK) {
        printf("allowed=%d reason_code=%s\n", result.allowed,
               result.reason_code ? result.reason_code : "(absent)");
    } else {
        printf("check failed: %s\n", err.message);
    }
    axiam_check_result_dispose(&result);

    printf("--- telemetry ---\n");
    printf("  wire attempts : %ld (%ld failed)\n", metrics.attempts, metrics.failures);
    printf("  mean latency  : %.1f ms\n",
           metrics.attempts ? metrics.total_ms / (double)metrics.attempts : 0.0);
    printf("  retries       : %ld\n", metrics.retries);
    printf("  refreshes     : %ld\n", metrics.refreshes);

    /* §18: releases the transport and the cookie jar without issuing a request.
     * It does NOT log out — the server-side session outlives this process. */
    axiam_client_close(client);
    axiam_client_free(client);
    return 0;
}

/*
 * Mapping onto a real backend — replace sink()'s body, nothing else:
 *
 *   REQUEST_END    → histogram "axiam.request.duration"
 *                    labels: operation, path_template, status, outcome, attempt
 *   RETRY          → counter   "axiam.request.retries"   labels: operation
 *   REFRESH        → counter   "axiam.token.refresh"     labels: role
 *   CONFIG_CLAMPED → a log line at WARN, not a metric: it fires once at
 *                    construction and its whole value is being READ.
 *
 * Label with `path_template`, never with the request URL: a metric label
 * carrying a UUID is a cardinality bomb. The hook runs on the calling thread,
 * so it must not block — every mature metrics library already buffers, which is
 * why §19.2 rule 4 leaves that choice to you rather than making it here.
 */
