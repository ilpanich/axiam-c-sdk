/*
 * D5 conformance — CONTRACT.md §16, §17, §18, §19.
 *
 * The wire-count assertions here are normative as of contract 1.8.1, not
 * stylistic. The TypeScript SDK shipped a retry helper that was exported,
 * unit-tested and green while no production path called it; the C# SDK had
 * three retry settings that were defaulted, documented and asserted in tests
 * and read by nothing. Both suites passed. Neither SDK retried anything.
 *
 * §16.7 is the response: conformance MUST be asserted through the public
 * check_access surface by counting requests ON THE WIRE. Every §16 case below
 * therefore drives a real client against a counting transport rather than
 * calling axiam_retry_* in isolation — the pure-function cases exist only where
 * §16.7 explicitly requires an injected PRNG (a test that really waits 200 ms
 * is a test nobody runs).
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

#define MAX_EVENTS 64

typedef struct {
    int request_count;
    /* A scripted status sequence; the last entry repeats once exhausted. */
    long statuses[8];
    int n_statuses;
    const char *body;
    const char *retry_after; /* optional Retry-After on every response */

    /* §19 sink */
    axiam_telemetry_event_t events[MAX_EVENTS];
    char event_strings[MAX_EVENTS][8][128]; /* owned copies of borrowed fields */
    int n_events;

    /* observed §16 sleeps, so a delay can be asserted without taking it */
    long sleeps[8];
    int n_sleeps;
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    (void)req;
    int idx = st->request_count < st->n_statuses ? st->request_count
                                                 : (st->n_statuses - 1);
    long status = st->n_statuses > 0 ? st->statuses[idx] : 200;
    st->request_count++;

    if (status == 0) {
        /* A transport failure: no HTTP response arrived at all. */
        memset(resp, 0, sizeof(*resp));
        resp->transport_err = 7;
        resp->transport_msg = strdup("connection refused");
        return -1;
    }
    resp_fill(resp, status, st->body ? st->body : "{\"allowed\":true,\"reason_code\":\"allowed\"}",
              NULL);
    if (st->retry_after) {
        resp->headers = axiam_kv_append(resp->headers, "Retry-After", st->retry_after);
    }
    return 0;
}

/*
 * Copies EVERY borrowed string, without exception.
 *
 * §19's event fields are valid only for the duration of the call, and this
 * harness is where that rule earns its keep: `reason` points into
 * transport_retrying's stack frame and `effective` into axiam_client_new's, so
 * an earlier version of this sink that copied only four of the eight fields
 * read freed stack later — caught by the ASan gate, not by any assertion.
 * Copying selectively is the mistake; the rule is copy or discard.
 */
static void record_hook(void *ctx, const axiam_telemetry_event_t *ev) {
    fake_state_t *st = ctx;
    if (st->n_events >= MAX_EVENTS) return;
    int i = st->n_events++;
    st->events[i] = *ev;

#define COPY(slot, field)                                                      \
    do {                                                                       \
        if (ev->field) {                                                       \
            snprintf(st->event_strings[i][slot], 128, "%s", ev->field);         \
            st->events[i].field = st->event_strings[i][slot];                  \
        }                                                                      \
    } while (0)
    COPY(0, operation);
    COPY(1, method);
    COPY(2, path_template);
    COPY(3, reason);
    COPY(4, setting);
    COPY(5, requested);
    COPY(6, effective);
    COPY(7, contract_reference);
#undef COPY
}

static void record_sleep(void *ctx, long ms) {
    fake_state_t *st = ctx;
    if (st->n_sleeps < 8) st->sleeps[st->n_sleeps++] = ms;
}

/* Jitter pinned to its maximum, so the observed delay is the full backoff and
 * the sequence is deterministic. */
static double jitter_max(void *ctx) { (void)ctx; return 1.0; }
static double jitter_min(void *ctx) { (void)ctx; return 0.0; }

typedef struct {
    int retry_enabled;
    long memo_ttl_ms;
    int with_hook;
} client_opts_t;

static axiam_client_t *make_client(client_opts_t o) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_client_config_set_retry_enabled(cfg, o.retry_enabled);
    if (o.memo_ttl_ms) axiam_client_config_set_decision_memo_ttl(cfg, o.memo_ttl_ms);
    if (o.with_hook) axiam_client_config_set_telemetry_hook(cfg, record_hook, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (c) {
        /* §16.7: an injected PRNG and an injected sleep. Never a real wait. */
        c->jitter_fn = jitter_max;
        c->jitter_ctx = NULL;
        c->sleep_fn = record_sleep;
        c->sleep_ctx = &g;
    }
    return c;
}

static axiam_client_t *default_client(void) {
    client_opts_t o = {1, 0, 0};
    return make_client(o);
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    g.statuses[0] = 200;
    g.n_statuses = 1;
}
void tearDown(void) {}

static int count_events(axiam_telemetry_kind_t kind) {
    int n = 0;
    for (int i = 0; i < g.n_events; i++)
        if (g.events[i].kind == kind) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/* §16 — the policy, asserted through the public surface               */
/* ------------------------------------------------------------------ */

static void test_persistent_503_makes_exactly_three_attempts(void) {
    g.statuses[0] = 503;
    g.n_statuses = 1;
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err));
    /* Not 2, not 4. The cap is the whole point of a bounded policy. */
    TEST_ASSERT_EQUAL_INT(3, g.request_count);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_transient_failure_is_retried_and_the_success_returned(void) {
    g.statuses[0] = 503;
    g.statuses[1] = 200;
    g.n_statuses = 2;
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(1, r.allowed);
    TEST_ASSERT_EQUAL_INT(2, g.request_count);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_transport_failure_is_retried(void) {
    g.statuses[0] = 0; /* connection refused, no HTTP response at all */
    g.n_statuses = 1;
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(3, g.request_count);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_decisive_statuses_make_exactly_one_attempt(void) {
    const long decisive[] = {403, 401, 400, 404, 409};
    for (size_t i = 0; i < sizeof(decisive) / sizeof(decisive[0]); i++) {
        setUp();
        g.statuses[0] = decisive[i];
        g.n_statuses = 1;
        axiam_client_t *c = default_client();
        axiam_check_result_t r;
        axiam_error_t err;
        axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
        /* 401 reaches exactly one attempt here because no session is active —
         * §9 owns the refresh path, and §16 must not turn a decisive answer
         * into three identical rejections. */
        TEST_ASSERT_EQUAL_INT(1, g.request_count);
        axiam_check_result_dispose(&r);
        axiam_client_free(c);
    }
}

static void test_retry_disabled_makes_exactly_one_attempt(void) {
    g.statuses[0] = 503;
    g.n_statuses = 1;
    client_opts_t o = {0, 0, 0};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    TEST_ASSERT_EQUAL_INT(1, g.request_count);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_a_non_idempotent_operation_is_never_retried(void) {
    /* §16.2 and §16.7's named trap: this is the assertion that catches a retry
     * wired at the TRANSPORT layer instead of the operation layer. login is
     * ineligible because it changes state and because its credential is
     * single-use — a silent replay turns a recoverable blip into a hard
     * rejection the caller cannot interpret. */
    g.statuses[0] = 503;
    g.n_statuses = 1;
    axiam_client_t *c = default_client();
    axiam_login_result_t lr;
    axiam_error_t err;
    axiam_login(c, "u@example.com", "pw", &lr, &err);
    TEST_ASSERT_EQUAL_INT(1, g.request_count);
    axiam_login_result_dispose(&lr);
    axiam_client_free(c);
}

static void test_the_delay_sequence_with_jitter_pinned_to_max(void) {
    /* §16.1: min(cap, base * 2^(attempt-1)) → 200 ms then 400 ms, both under
     * the 5 s cap. Observed through the injected sleep, never taken. */
    g.statuses[0] = 503;
    g.n_statuses = 1;
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    TEST_ASSERT_EQUAL_INT(2, g.n_sleeps);
    TEST_ASSERT_EQUAL_INT(200, g.sleeps[0]);
    TEST_ASSERT_EQUAL_INT(400, g.sleeps[1]);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_jitter_pinned_to_zero_waits_zero_on_the_wire(void) {
    /* §16.7 requires this at both ends of the range, and asserting it through
     * the client rather than the pure function is what proves the injected PRNG
     * is the one the retry loop actually consults. */
    g.statuses[0] = 503;
    g.n_statuses = 1;
    axiam_client_t *c = default_client();
    c->jitter_fn = jitter_min;
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    TEST_ASSERT_EQUAL_INT(3, g.request_count); /* still three attempts */
    TEST_ASSERT_EQUAL_INT(2, g.n_sleeps);
    TEST_ASSERT_EQUAL_INT(0, g.sleeps[0]);
    TEST_ASSERT_EQUAL_INT(0, g.sleeps[1]);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_full_jitter_spans_zero_to_the_backoff(void) {
    /* The range is [0, backoff], NOT backoff ± something. Partial jitter keeps
     * every client's retries clustered around the same instant, which is the
     * failure mode retries cause rather than fix. */
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_delay_ms(1, -1, 0.0));
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_delay_ms(1, -1, 1.0));
    TEST_ASSERT_EQUAL_INT(100, axiam_retry_delay_ms(1, -1, 0.5));
    /* A fraction outside the unit interval is clamped rather than trusted. */
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_delay_ms(1, -1, -3.0));
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_delay_ms(1, -1, 9.0));
}

static void test_backoff_doubles_from_the_base_and_stops_at_the_cap(void) {
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_backoff_ms(1));
    TEST_ASSERT_EQUAL_INT(400, axiam_retry_backoff_ms(2));
    TEST_ASSERT_EQUAL_INT(800, axiam_retry_backoff_ms(3));
    TEST_ASSERT_EQUAL_INT(5000, axiam_retry_backoff_ms(20));
    /* An attempt below 1 is treated as the first, not as a shift by -1. */
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_backoff_ms(0));
}

static void test_retry_after_is_a_floor_never_a_ceiling(void) {
    /* Longer than the backoff: the server wins. */
    TEST_ASSERT_EQUAL_INT(3000, axiam_retry_delay_ms(1, 3000, 1.0));
    /* Shorter than the backoff: it does NOT shorten the wait. `Retry-After: 0`
     * replacing the backoff is the shipped bug §16.1's wording describes. */
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_delay_ms(1, 0, 1.0));
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_delay_ms(1, 50, 1.0));
    /* Absent (-1) leaves the jittered backoff alone. */
    TEST_ASSERT_EQUAL_INT(200, axiam_retry_delay_ms(1, -1, 1.0));
}

static void test_retry_after_header_parsing(void) {
    TEST_ASSERT_EQUAL_INT(2000, axiam_retry_after_ms("2"));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_after_ms("0"));
    TEST_ASSERT_EQUAL_INT(2000, axiam_retry_after_ms("  2  "));
    /* An unparseable hint is ABSENT (-1), not a zero-length floor. */
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms(NULL));
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms(""));
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms("soon"));
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms("2x"));
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms("-5"));
    /* A date already in the past is not a wait. */
    TEST_ASSERT_EQUAL_INT(-1, axiam_retry_after_ms("Wed, 21 Oct 2015 07:28:00 GMT"));
    /* Bounded, so a hostile header cannot park a thread for a day. */
    TEST_ASSERT_EQUAL_INT(3600000, axiam_retry_after_ms("999999"));
}

static void test_retry_after_accepts_an_http_date(void) {
    /* RFC 7231 allows either form and both appear in the wild, so an SDK that
     * parsed only delta-seconds would silently drop the hint from every server
     * that sends a date — and dropping it means retrying sooner than the server
     * asked, which §16.1 forbids. */
    time_t future = time(NULL) + 120;
    struct tm gm;
    gmtime_r(&future, &gm);
    char header[64];
    strftime(header, sizeof(header), "%a, %d %b %Y %H:%M:%S GMT", &gm);

    long ms = axiam_retry_after_ms(header);
    /* ~120 s, with a second of slack for the clock ticking between the two
     * calls. Asserted as a range rather than a value for exactly that reason. */
    TEST_ASSERT_TRUE(ms > 118000 && ms <= 120000);
}

static void test_retry_after_header_reaches_the_wait(void) {
    g.statuses[0] = 429; /* exactly where Retry-After usually arrives */
    g.n_statuses = 1;
    g.retry_after = "2";
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    TEST_ASSERT_EQUAL_INT(3, g.request_count);
    TEST_ASSERT_EQUAL_INT(2, g.n_sleeps);
    TEST_ASSERT_EQUAL_INT(2000, g.sleeps[0]); /* floors the 200 ms backoff */
    TEST_ASSERT_EQUAL_INT(2000, g.sleeps[1]); /* and the 400 ms one */
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_which_failures_retry(void) {
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(1, 0));
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(0, 0));
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(0, 408));
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(0, 429));
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(0, 500));
    TEST_ASSERT_EQUAL_INT(1, axiam_retry_should_retry(0, 599));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 200));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 401));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 403));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 400));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 404));
    TEST_ASSERT_EQUAL_INT(0, axiam_retry_should_retry(0, 409));
}

/* ------------------------------------------------------------------ */
/* §17 — client-side decision memo                                     */
/* ------------------------------------------------------------------ */

static void test_the_memo_is_off_by_default(void) {
    /* With the default configuration EVERY repeat check reaches the wire.
     * §11.2 rule 6's ban is still the default behaviour. */
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    for (int i = 0; i < 3; i++) {
        axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
        axiam_check_result_dispose(&r);
    }
    TEST_ASSERT_EQUAL_INT(3, g.request_count);
    axiam_client_free(c);
}

static void test_a_repeat_inside_the_ttl_makes_no_second_wire_call(void) {
    client_opts_t o = {1, 5000, 0};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t first, second;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_check_access(c, "read", "r-1", NULL, NULL, &first, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_check_access(c, "read", "r-1", NULL, NULL, &second, &err));
    TEST_ASSERT_EQUAL_INT(1, g.request_count);
    TEST_ASSERT_EQUAL_INT(first.allowed, second.allowed);
    /* §17.1 rule 5: the reason_code comes back with the decision. A memo that
     * returned `allowed` while dropping the code would make the field
     * intermittently absent — worse than never having had it. */
    TEST_ASSERT_EQUAL_STRING("allowed", second.reason_code);
    axiam_check_result_dispose(&first);
    axiam_check_result_dispose(&second);
    axiam_client_free(c);
}

static void test_denies_are_memoized_exactly_like_allows(void) {
    /* §17.1 rule 4. Asymmetric caching changes the TIMING of the two outcomes
     * and so leaks which one occurred to anyone who can observe latency. */
    g.body = "{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}";
    client_opts_t o = {1, 5000, 0};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    TEST_ASSERT_EQUAL_INT(1, g.request_count);
    TEST_ASSERT_EQUAL_INT(0, r.allowed);
    TEST_ASSERT_EQUAL_STRING("denied_by_rule", r.reason_code);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_a_failure_is_never_memoized(void) {
    /* §17.1 rule 7. Memoizing a transport error as a deny would turn a blip
     * into a TTL-long outage; memoizing it as an allow is unthinkable. */
    g.statuses[0] = 503;
    g.n_statuses = 1;
    client_opts_t o = {0, 5000, 0}; /* retry off, so the count is the call count */
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    TEST_ASSERT_EQUAL_INT(2, g.request_count);
    axiam_client_free(c);
}

static void test_every_key_component_is_distinguished(void) {
    char *keys[6];
    keys[0] = axiam_memo_key(NULL, "r1", "read", NULL);
    keys[1] = axiam_memo_key("s1", "r1", "read", NULL);
    keys[2] = axiam_memo_key(NULL, "r2", "read", NULL);
    keys[3] = axiam_memo_key(NULL, "r1", "write", NULL);
    keys[4] = axiam_memo_key(NULL, "r1", "read", "sc");
    keys[5] = axiam_memo_key(NULL, "r1", "read", NULL);

    for (int i = 0; i < 5; i++)
        for (int j = i + 1; j < 5; j++)
            TEST_ASSERT_NOT_EQUAL(0, strcmp(keys[i], keys[j]));
    /* Same inputs, same key — otherwise nothing would ever hit. */
    TEST_ASSERT_EQUAL_STRING(keys[0], keys[5]);
    /* An absent scope must never collide with a present empty one: a memo that
     * let them collide would answer a narrower question with a broader
     * answer. */
    char *absent = axiam_memo_key(NULL, "r1", "read", NULL);
    char *empty = axiam_memo_key(NULL, "r1", "read", "");
    TEST_ASSERT_EQUAL_STRING(absent, empty); /* "" is absent, by construction */
    free(absent);
    free(empty);
    for (int i = 0; i < 6; i++) free(keys[i]);
}

static void test_differing_components_miss_rather_than_collide(void) {
    client_opts_t o = {1, 5000, 0};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-1", "scope-a", NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "write", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-2", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-1", NULL, "subj", &r, &err);
    axiam_check_result_dispose(&r);
    TEST_ASSERT_EQUAL_INT(5, g.request_count);
    axiam_client_free(c);
}

static void test_a_ttl_above_the_ceiling_is_clamped_not_rejected(void) {
    axiam_memo_t m;
    axiam_memo_init(&m, 3600000);
    TEST_ASSERT_EQUAL_INT(AXIAM_MEMO_MAX_TTL_MS, axiam_memo_effective_ttl_ms(&m));
    axiam_memo_destroy(&m);

    axiam_memo_init(&m, 2000);
    TEST_ASSERT_EQUAL_INT(2000, axiam_memo_effective_ttl_ms(&m));
    axiam_memo_destroy(&m);

    axiam_memo_init(&m, 0);
    TEST_ASSERT_EQUAL_INT(0, axiam_memo_enabled(&m));
    axiam_memo_destroy(&m);

    /* A negative TTL DISABLES rather than wrapping to a huge unsigned wait. */
    axiam_memo_init(&m, -5000);
    TEST_ASSERT_EQUAL_INT(0, axiam_memo_enabled(&m));
    axiam_memo_destroy(&m);
}

static void test_the_memo_evicts_rather_than_growing_without_bound(void) {
    /* §17.1 rule 8. An unbounded per-client cache keyed by (subject, resource,
     * action, scope) is a memory leak in any service that checks many
     * resources. */
    axiam_memo_t m;
    axiam_memo_init(&m, 5000);
    axiam_check_result_t decision = {1, NULL, NULL};
    char key[64];
    for (int i = 0; i < AXIAM_MEMO_MAX_ENTRIES + 100; i++) {
        snprintf(key, sizeof(key), "k-%d", i);
        axiam_memo_put(&m, key, &decision);
    }
    TEST_ASSERT_EQUAL_INT(AXIAM_MEMO_MAX_ENTRIES, (int)axiam_memo_count(&m));
    axiam_memo_destroy(&m);
}

static void test_the_memo_is_cleared_on_a_credential_change(void) {
    /* §17.1 rule 9. Entries are keyed by subject, not by session, so a
     * re-authentication as a DIFFERENT principal would otherwise read the
     * previous principal's decisions. */
    client_opts_t o = {1, 5000, 0};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    TEST_ASSERT_EQUAL_INT(1, g.request_count);

    axiam_logout(c, &err);
    int after_logout = g.request_count;

    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    TEST_ASSERT_EQUAL_INT(after_logout + 1, g.request_count);
    axiam_client_free(c);
}

static void test_an_entry_expires_at_the_ttl(void) {
    axiam_memo_t m;
    axiam_memo_init(&m, 1); /* 1 ms, so the boundary is reachable without a wait */
    axiam_check_result_t stored = {1, NULL, NULL};
    axiam_memo_put(&m, "k", &stored);

    axiam_check_result_t got;
    memset(&got, 0, sizeof(got));
    /* Busy-wait past 1 ms rather than sleeping: the point is that the entry
     * goes away on age, and 1 ms of spin is cheaper than a scheduler round. */
    double until = axiam_now_ms() + 2.0;
    while (axiam_now_ms() < until) { }
    TEST_ASSERT_EQUAL_INT(0, axiam_memo_get(&m, "k", &got));
    axiam_memo_destroy(&m);
}

/* ------------------------------------------------------------------ */
/* §18 — deterministic shutdown                                        */
/* ------------------------------------------------------------------ */

static void test_close_is_idempotent(void) {
    axiam_client_t *c = default_client();
    axiam_client_close(c);
    axiam_client_close(c);
    axiam_client_close(c);
    axiam_client_free(c); /* and free after close must not double-release */
    axiam_client_close(NULL);
    axiam_client_free(NULL);
}

static void test_close_issues_no_network_request(void) {
    /* §18.1 rule 5. The server-side session deliberately outlives the client
     * object — that is what lets a process restart and resume — so a close()
     * that logged out would silently end every user's session on each deploy.
     * Asserted against the wire, because a logout wired into close succeeds
     * silently and would pass any return-value assertion. */
    axiam_client_t *c = default_client();
    axiam_client_close(c);
    TEST_ASSERT_EQUAL_INT(0, g.request_count);
    axiam_client_free(c);
}

static void test_use_after_close_is_an_error_not_undefined(void) {
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);
    int before = g.request_count;

    axiam_client_close(c);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err));
    /* §18.1 rule 4: the message must NAME the cause, not merely be non-empty. */
    TEST_ASSERT_NOT_NULL(strstr(err.message, "closed"));
    axiam_check_result_dispose(&r);

    axiam_login_result_t lr;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login(c, "u", "p", &lr, &err));
    axiam_login_result_dispose(&lr);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_logout(c, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_refresh(c, &err));

    axiam_check_input_t in = {"read", "r-1", NULL, NULL};
    axiam_check_result_t out[1];
    size_t n = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_batch_check(c, &in, 1, out, &n, &err));

    /* Not one request reached the wire after close. */
    TEST_ASSERT_EQUAL_INT(before, g.request_count);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §19 — telemetry                                                     */
/* ------------------------------------------------------------------ */

static void test_one_request_pair_per_attempt_with_a_retry_between(void) {
    g.statuses[0] = 503;
    g.statuses[1] = 200;
    g.n_statuses = 2;
    client_opts_t o = {1, 0, 1};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);

    /* Emitting both pairs as attempt 1 would make a retried call
     * indistinguishable from a single slow one. */
    TEST_ASSERT_EQUAL_INT(5, g.n_events);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_REQUEST_START, g.events[0].kind);
    TEST_ASSERT_EQUAL_INT(1, g.events[0].attempt);
    TEST_ASSERT_EQUAL_STRING("check_access", g.events[0].operation);
    /* The path TEMPLATE, never a substituted URL — a metric label carrying a
     * UUID is a cardinality bomb. */
    TEST_ASSERT_EQUAL_STRING("/api/v1/authz/check", g.events[0].path_template);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_REQUEST_END, g.events[1].kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_FAILURE, g.events[1].outcome);
    TEST_ASSERT_EQUAL_INT(503, g.events[1].status);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_RETRY, g.events[2].kind);
    TEST_ASSERT_EQUAL_INT(1, g.events[2].attempt);
    TEST_ASSERT_EQUAL_INT(200, g.events[2].delay_ms);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_REQUEST_START, g.events[3].kind);
    TEST_ASSERT_EQUAL_INT(2, g.events[3].attempt);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_REQUEST_END, g.events[4].kind);
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_SUCCESS, g.events[4].outcome);
    axiam_client_free(c);
}

static void test_a_refresh_emits_its_event_with_a_role(void) {
    /* §19.1 refresh. The role is the whole value of the event: a follower's
     * latency is the leader's, so without it the two are indistinguishable and
     * a §9 coalescing problem looks like a slow server. */
    g.statuses[0] = 200; /* login */
    g.n_statuses = 1;
    client_opts_t o = {1, 0, 1};
    axiam_client_t *c = make_client(o);
    axiam_error_t err;

    axiam_refresh(c, &err);

    int n = 0;
    for (int i = 0; i < g.n_events; i++) {
        if (g.events[i].kind != AXIAM_TELEMETRY_REFRESH) continue;
        n++;
        /* Single-threaded: this caller performed the refresh itself. */
        TEST_ASSERT_EQUAL_INT(AXIAM_REFRESH_LEADER, g.events[i].refresh_role);
    }
    TEST_ASSERT_EQUAL_INT(1, n);
    axiam_client_free(c);
}

static void test_a_failing_call_still_emits_request_end(void) {
    g.statuses[0] = 0; /* transport failure: no response at all */
    g.n_statuses = 1;
    client_opts_t o = {0, 0, 1};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);

    TEST_ASSERT_EQUAL_INT(1, count_events(AXIAM_TELEMETRY_REQUEST_END));
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_FAILURE, g.events[1].outcome);
    /* Status 0 means the call never got a response, which is a different fact
     * from a 500 and must stay distinguishable in a metrics backend. */
    TEST_ASSERT_EQUAL_INT(0, g.events[1].status);
    axiam_client_free(c);
}

static void test_no_hook_installed_behaves_identically(void) {
    /* §19.2 rule 1, and §19.4's "a client with no hook installed behaves
     * identically to one before this section existed". */
    g.statuses[0] = 503;
    g.statuses[1] = 200;
    g.n_statuses = 2;
    axiam_client_t *c = default_client();
    axiam_check_result_t r;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err));
    TEST_ASSERT_EQUAL_INT(2, g.request_count);
    TEST_ASSERT_EQUAL_INT(0, g.n_events);
    axiam_check_result_dispose(&r);
    axiam_client_free(c);
}

static void test_no_event_payload_carries_a_token(void) {
    /* §19.2 rule 3. This surface exists to be shipped to a metrics backend,
     * which is the last place a bearer token should land. */
    g.statuses[0] = 503;
    g.n_statuses = 1;
    g.body = "{\"access_token\":\"eyJhbGciOiJFZERTQSJ9.secret.sig\"}";
    client_opts_t o = {1, 0, 1};
    axiam_client_t *c = make_client(o);
    axiam_check_result_t r;
    axiam_error_t err;
    axiam_check_access(c, "read", "r-1", NULL, NULL, &r, &err);
    axiam_check_result_dispose(&r);

    TEST_ASSERT_TRUE(g.n_events > 0);
    for (int i = 0; i < g.n_events; i++) {
        const char *fields[] = {g.events[i].operation, g.events[i].method,
                                g.events[i].path_template, g.events[i].reason,
                                g.events[i].setting,     g.events[i].requested,
                                g.events[i].effective,   g.events[i].contract_reference};
        for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++) {
            if (!fields[f]) continue;
            TEST_ASSERT_NULL(strstr(fields[f], "eyJ"));
            TEST_ASSERT_NULL(strstr(fields[f], "secret"));
        }
    }
    axiam_client_free(c);
}

static void test_a_clamped_setting_is_reported_not_swallowed(void) {
    /* §19.2 rule 6. An operator who set a 60-second memo TTL believes their
     * staleness bound is 60 seconds. It is five. Clamping is right; doing it
     * silently leaves their revocation reasoning wrong by a factor of twelve
     * with nothing anywhere to say so. */
    client_opts_t o = {1, 60000, 1};
    axiam_client_t *c = make_client(o);
    TEST_ASSERT_EQUAL_INT(1, count_events(AXIAM_TELEMETRY_CONFIG_CLAMPED));
    TEST_ASSERT_EQUAL_INT(AXIAM_TELEMETRY_CONFIG_CLAMPED, g.events[0].kind);
    TEST_ASSERT_EQUAL_STRING("decision_memo_ttl_ms", g.events[0].setting);
    TEST_ASSERT_EQUAL_STRING("60000ms", g.events[0].requested);
    axiam_client_free(c);
}

static void test_a_value_inside_its_limit_reports_nothing(void) {
    /* An event that fires when nothing happened trains its reader to ignore
     * it, which costs exactly the case above. */
    client_opts_t in_range = {1, 2000, 1};
    axiam_client_t *c = make_client(in_range);
    TEST_ASSERT_EQUAL_INT(0, count_events(AXIAM_TELEMETRY_CONFIG_CLAMPED));
    axiam_client_free(c);

    setUp();
    client_opts_t boundary = {1, AXIAM_MEMO_MAX_TTL_MS, 1};
    c = make_client(boundary);
    TEST_ASSERT_EQUAL_INT(0, count_events(AXIAM_TELEMETRY_CONFIG_CLAMPED));
    axiam_client_free(c);

    setUp();
    client_opts_t disabled = {1, 0, 1};
    c = make_client(disabled);
    TEST_ASSERT_EQUAL_INT(0, count_events(AXIAM_TELEMETRY_CONFIG_CLAMPED));
    axiam_client_free(c);
}

static void test_an_uninstalled_dispatcher_is_inert(void) {
    axiam_telemetry_t t = {NULL, NULL};
    TEST_ASSERT_EQUAL_INT(0, axiam_telemetry_installed(&t));
    TEST_ASSERT_EQUAL_INT(0, axiam_telemetry_installed(NULL));
    /* None of these may fault, and none may reach a hook that is not there. */
    axiam_telemetry_emit(&t, NULL);
    axiam_telemetry_request_start(&t, "op", "POST", "/p", 1);
    axiam_telemetry_request_end(&t, "op", "POST", "/p", 1, 200, 1.0, AXIAM_TELEMETRY_SUCCESS);
    axiam_telemetry_retry(&t, "op", 1, 200, "HTTP 503");
    axiam_telemetry_refresh(&t, AXIAM_REFRESH_LEADER, 1.0);
    axiam_telemetry_config_clamped(&t, "s", "r", "e", "ref");
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_persistent_503_makes_exactly_three_attempts);
    RUN_TEST(test_transient_failure_is_retried_and_the_success_returned);
    RUN_TEST(test_transport_failure_is_retried);
    RUN_TEST(test_decisive_statuses_make_exactly_one_attempt);
    RUN_TEST(test_retry_disabled_makes_exactly_one_attempt);
    RUN_TEST(test_a_non_idempotent_operation_is_never_retried);
    RUN_TEST(test_the_delay_sequence_with_jitter_pinned_to_max);
    RUN_TEST(test_jitter_pinned_to_zero_waits_zero_on_the_wire);
    RUN_TEST(test_full_jitter_spans_zero_to_the_backoff);
    RUN_TEST(test_backoff_doubles_from_the_base_and_stops_at_the_cap);
    RUN_TEST(test_retry_after_is_a_floor_never_a_ceiling);
    RUN_TEST(test_retry_after_header_parsing);
    RUN_TEST(test_retry_after_accepts_an_http_date);
    RUN_TEST(test_retry_after_header_reaches_the_wait);
    RUN_TEST(test_which_failures_retry);

    RUN_TEST(test_the_memo_is_off_by_default);
    RUN_TEST(test_a_repeat_inside_the_ttl_makes_no_second_wire_call);
    RUN_TEST(test_denies_are_memoized_exactly_like_allows);
    RUN_TEST(test_a_failure_is_never_memoized);
    RUN_TEST(test_every_key_component_is_distinguished);
    RUN_TEST(test_differing_components_miss_rather_than_collide);
    RUN_TEST(test_a_ttl_above_the_ceiling_is_clamped_not_rejected);
    RUN_TEST(test_the_memo_evicts_rather_than_growing_without_bound);
    RUN_TEST(test_the_memo_is_cleared_on_a_credential_change);
    RUN_TEST(test_an_entry_expires_at_the_ttl);

    RUN_TEST(test_close_is_idempotent);
    RUN_TEST(test_close_issues_no_network_request);
    RUN_TEST(test_use_after_close_is_an_error_not_undefined);

    RUN_TEST(test_one_request_pair_per_attempt_with_a_retry_between);
    RUN_TEST(test_a_refresh_emits_its_event_with_a_role);
    RUN_TEST(test_a_failing_call_still_emits_request_end);
    RUN_TEST(test_no_hook_installed_behaves_identically);
    RUN_TEST(test_no_event_payload_carries_a_token);
    RUN_TEST(test_a_clamped_setting_is_reported_not_swallowed);
    RUN_TEST(test_a_value_inside_its_limit_reports_nothing);
    RUN_TEST(test_an_uninstalled_dispatcher_is_inert);

    return UNITY_END();
}
