/* CONTRACT.md §12.4 rule 2 "Stale-if-error, bounded" (contract 1.69; D-10) -- the conformance
 * test, with an injected clock and a counting mock server.
 *
 * Fill the cache at t0, make every later fetch fail: held kid accepted at t0+TTL+1, an unknown
 * kid refused at t0+TTL+250 while the held kid is still accepted, the held kid refused at
 * t0+TTL+301; then one successful fetch accepts it again. Repeated with `200 {"keys":[]}`.
 * Plus: TTL from Cache-Control max-age (clamped to 300), the configured TTL clamp and its
 * config_clamped event, and the 304 conditional re-confirmation.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define TTL 300

typedef enum { M_OK, M_FAIL, M_EMPTY, M_500, M_GARBAGE, M_304, M_ALT, M_203, M_206 } mode_t_;

typedef struct {
    const char *jwks_body;
    mode_t_ mode;
    int jwks_calls;
    const char *cache_control;
    const char *etag;
    const char *alt_body;
    const char *cache_control_304;
    const char *cache_control2;
    char last_if_none_match[64];
} fake_state_t;

static fake_state_t g;
static time_t g_now;
static int clamp_events;
static char clamp_setting[64], clamp_req[32], clamp_eff[32];

static time_t fake_clock(void *ctx) { (void)ctx; return g_now; }

static int fake_transport(void *ctx, const axiam_http_request_t *req, axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (!strstr(req->url, "/oauth2/jwks")) { resp_fill(resp, 404, NULL, NULL); return 0; }
    st->jwks_calls++;
    const char *inm = axiam_kv_get(req->headers, "If-None-Match");
    snprintf(st->last_if_none_match, sizeof(st->last_if_none_match), "%s", inm ? inm : "");
    switch (st->mode) {
    case M_FAIL:
        memset(resp, 0, sizeof(*resp));
        resp->transport_err = 7;
        return -1;
    case M_500: resp_fill(resp, 500, "oops", NULL); return 0;
    case M_EMPTY: resp_fill(resp, 200, "{\"keys\":[]}", NULL); break;
    case M_GARBAGE: resp_fill(resp, 200, "<html>not jwks</html>", NULL); break;
    case M_304:
        resp_fill(resp, 304, NULL, NULL);
        if (st->cache_control_304)
            resp->headers = axiam_kv_append(resp->headers, "Cache-Control", st->cache_control_304);
        break;
    case M_ALT: resp_fill(resp, 200, st->alt_body, NULL); break;
    case M_203: resp_fill(resp, 203, st->jwks_body, NULL); break;
    case M_206: resp_fill(resp, 206, st->jwks_body, NULL); break;
    default: resp_fill(resp, 200, st->jwks_body, NULL); break;
    }
    if (st->cache_control && st->mode != M_304) resp->headers = axiam_kv_append(resp->headers, "Cache-Control", st->cache_control);
    if (st->cache_control2) resp->headers = axiam_kv_append(resp->headers, "Cache-Control", st->cache_control2);
    if (st->etag) resp->headers = axiam_kv_append(resp->headers, "ETag", st->etag);
    return 0;
}

static void hook(void *ctx, const axiam_telemetry_event_t *ev) {
    (void)ctx;
    if (ev->kind != AXIAM_TELEMETRY_CONFIG_CLAMPED) return;
    clamp_events++;
    snprintf(clamp_setting, sizeof(clamp_setting), "%s", ev->setting);
    snprintf(clamp_req, sizeof(clamp_req), "%s", ev->requested);
    snprintf(clamp_eff, sizeof(clamp_eff), "%s", ev->effective);
}

static axiam_client_t *make_client(long cfg_ttl) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_client_config_set_telemetry_hook(cfg, hook, NULL);

    if (cfg_ttl) axiam_client_config_set_jwks_cache_ttl(cfg, cfg_ttl);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    c->clock_fn = fake_clock;
    return c;
}

static char *held_tok, *held_jwks, *unk_tok, *unk_jwks;

void setUp(void) {
    memset(&g, 0, sizeof(g));
    clamp_events = 0;
    g_now = 1900000000;
    char p[256];
    jwt_make("held", test_claims(p, sizeof(p), "u", NULL), &held_tok, &held_jwks);
    jwt_make("unknown", test_claims(p, sizeof(p), "u", NULL), &unk_tok, &unk_jwks);
    g.jwks_body = held_jwks;
}
void tearDown(void) { free(held_tok); free(held_jwks); free(unk_tok); free(unk_jwks); }

static axiam_error_kind_t verify(axiam_client_t *c, const char *tok) {
    axiam_error_t err;
    return axiam_jwt_verify(c, tok, NULL, &err);
}

static void conformance(mode_t_ failing_mode) {
    axiam_client_t *c = make_client(0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* fill at t0 */
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);
    time_t t0 = g_now;

    g.mode = failing_mode;
    g_now = t0 + TTL - 1;                                   /* within TTL: no fetch */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);

    g_now = t0 + TTL + 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* held kid accepted */
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);                 /* one failed refresh attempted */

    g_now = t0 + TTL + 250;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, unk_tok));    /* unknown kid refused */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* held kid still accepted */

    g_now = t0 + TTL + 300;                                 /* exactly the bound: still held */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));

    g_now = t0 + TTL + 301;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));   /* past the bound: refused */

    int before = g.jwks_calls;
    g.mode = M_OK;
    g_now = t0 + TTL + 301 + 61;                            /* past the window */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* accepted after one fetch */
    TEST_ASSERT_EQUAL_INT(before + 1, g.jwks_calls);
    axiam_client_free(c);
}

static void test_stale_bound_transport_error(void) { conformance(M_FAIL); }
static void test_stale_bound_status_500(void) { conformance(M_500); }
static void test_stale_bound_non_jwks_body(void) { conformance(M_GARBAGE); }
/* Only a 200 (or a 304 to a conditional request) is a successful fetch. */
static void test_stale_bound_status_203(void) { conformance(M_203); }
static void test_stale_bound_status_206(void) { conformance(M_206); }

static void test_empty_key_set_never_replaces_held_keys(void) {
    axiam_client_t *c = make_client(0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    time_t t0 = g_now;
    g.mode = M_EMPTY;
    g_now = t0 + TTL + 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    /* the empty answer did not move the anchor either */
    g_now = t0 + TTL + 301;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));
    axiam_client_free(c);
}

/* A failed refresh costs one fetch per window, not one per token. */
static void test_failed_refresh_counts_toward_window(void) {
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    g.mode = M_FAIL;
    g_now += TTL + 1;
    int base = g.jwks_calls;
    for (int i = 0; i < 20; i++) TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_INT(base + 1, g.jwks_calls);
    axiam_client_free(c);
}

/* An unknown-kid refresh that fails never opens or extends the stale window. */
static void test_unknown_kid_failed_refresh_does_not_extend_window(void) {
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    time_t t0 = g_now;
    g.mode = M_FAIL;
    g_now = t0 + TTL - 10;                                  /* fresh, unknown kid -> refetch fails */
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, unk_tok));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    g_now = t0 + TTL + 301;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));
    axiam_client_free(c);
}

static void test_cache_control_max_age_shortens_ttl_and_is_clamped(void) {
    g.cache_control = "public, max-age=60";
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    time_t t0 = g_now;
    g_now = t0 + 61;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);                 /* 60 s honoured */
    axiam_client_free(c);

    memset(&g, 0, sizeof(g)); g.jwks_body = held_jwks;
    g.cache_control = "max-age=86400";
    c = make_client(0);
    g_now = 1900000000;
    verify(c, held_tok);
    g_now += TTL - 1;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);
    g_now += 2;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);                 /* clamped to 300 s */
    TEST_ASSERT_EQUAL_INT(0, clamp_events);                 /* advertised: no event */
    axiam_client_free(c);
}

/* A 304 to a conditional request re-confirms the held set and moves the anchor. */
static void test_304_moves_anchor(void) {
    g.etag = "\"v1\"";
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    time_t t0 = g_now;
    g.mode = M_304;
    g_now = t0 + TTL + 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_STRING("\"v1\"", g.last_if_none_match);
    g.mode = M_FAIL;
    g_now = t0 + TTL + 1 + TTL + 250;                       /* beyond t0+TTL+300, inside anchor2+TTL+300 */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    axiam_client_free(c);
}


static void test_configured_ttl_clamped_with_event(void) {
    axiam_client_t *c = make_client(900);
    TEST_ASSERT_EQUAL_INT(1, clamp_events);
    TEST_ASSERT_EQUAL_STRING("jwks_cache_ttl_s", clamp_setting);
    TEST_ASSERT_EQUAL_STRING("900s", clamp_req);
    TEST_ASSERT_EQUAL_STRING("300s", clamp_eff);
    axiam_client_free(c);
    clamp_events = 0;
    c = make_client(120);
    TEST_ASSERT_EQUAL_INT(0, clamp_events);
    verify(c, held_tok);
    g_now += 121;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    axiam_client_free(c);
}

static void bad_doc_keeps_held(const char *doc) {
    axiam_client_t *c = make_client(0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    time_t t0 = g_now;
    g.mode = M_ALT; g.alt_body = doc;
    g_now = t0 + TTL + 1;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    g_now = t0 + TTL + 301;                                /* anchor did not move */
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));
    axiam_client_free(c);
}
static void test_keys_with_empty_object_is_not_a_jwks(void) { bad_doc_keeps_held("{\"keys\":[{}]}"); }
static void test_keys_with_number_is_not_a_jwks(void) { bad_doc_keeps_held("{\"keys\":[0]}"); }
static void test_keys_with_null_is_not_a_jwks(void) { bad_doc_keeps_held("{\"keys\":[null]}"); }

/* PIN: the contract counts "a JWKS document holding at least one key" as success, so a set of
 * valid JWKs with no Ed25519 key (RSA-only) replaces the held set. */
static void test_rsa_only_set_is_a_successful_fetch_pin(void) {
    axiam_client_t *c = make_client(0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    time_t t0 = g_now;
    g.mode = M_ALT;
    g.alt_body = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"r\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}";
    g_now = t0 + TTL + 1;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));   /* replaced: held kid gone */
    axiam_client_free(c);
}

static void test_cold_cache_failing_endpoint_one_fetch_per_window(void) {
    axiam_client_t *c = make_client(0);
    g.mode = M_FAIL;
    for (int i = 0; i < 20; i++) TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);
    g_now += 61;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    g.mode = M_OK;
    g_now += 61;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* recovers after the window */
    axiam_client_free(c);
}

static void test_clock_moved_backwards_makes_refresh_due(void) {
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    g_now -= 1000;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    axiam_client_free(c);
}

static void test_304_rereads_max_age(void) {
    g.etag = "\"v1\"";
    g.cache_control = "max-age=300";
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    time_t t0 = g_now;
    g.mode = M_304; g.cache_control_304 = "max-age=60";
    g_now = t0 + TTL + 1;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    g_now += 61;                                            /* new TTL 60 honoured */
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(3, g.jwks_calls);
    axiam_client_free(c);
}

static void test_unusable_etag_is_never_echoed(void) {
    char longtag[400];
    memset(longtag, 'a', sizeof(longtag) - 1); longtag[0] = '"'; longtag[sizeof(longtag) - 1] = 0;
    g.etag = longtag;
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    g_now += TTL + 1;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_STRING("", g.last_if_none_match);
    axiam_client_free(c);
    memset(&g, 0, sizeof(g)); g.jwks_body = held_jwks;
    g.etag = "\"a\x01" "b\"";
    c = make_client(0);
    g_now = 1900000000;
    verify(c, held_tok);
    g_now += TTL + 1;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_STRING("", g.last_if_none_match);
    axiam_client_free(c);
}

/* Owner note: a configured TTL wins over an advertised max-age (both clamped to 300). */
static void test_configured_ttl_wins_over_advertised_max_age(void) {
    g.cache_control = "max-age=30";
    axiam_client_t *c = make_client(200);
    verify(c, held_tok);
    g_now += 100;                       /* past the advertised 30 s, inside the configured 200 s */
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(1, g.jwks_calls);
    g_now += 101;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    axiam_client_free(c);
}

static void test_negative_age_failed_refresh_refuses_held_keys(void) {
    axiam_client_t *c = make_client(0);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));
    g.mode = M_FAIL;
    g_now -= 5000;                                          /* clock stepped back */
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, verify(c, held_tok));   /* not trusted while now < anchor */
    g.mode = M_OK;
    g_now += 61;                                            /* past the window */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, verify(c, held_tok));   /* a successful refresh re-anchors */
    axiam_client_free(c);
}

static void test_duplicate_cache_control_headers_find_later_max_age(void) {
    g.cache_control = "public";
    g.cache_control2 = "max-age=60";
    axiam_client_t *c = make_client(0);
    verify(c, held_tok);
    g_now += 61;
    verify(c, held_tok);
    TEST_ASSERT_EQUAL_INT(2, g.jwks_calls);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_stale_bound_transport_error);
    RUN_TEST(test_stale_bound_status_500);
    RUN_TEST(test_stale_bound_non_jwks_body);
    RUN_TEST(test_stale_bound_status_203);
    RUN_TEST(test_stale_bound_status_206);
    RUN_TEST(test_negative_age_failed_refresh_refuses_held_keys);
    RUN_TEST(test_duplicate_cache_control_headers_find_later_max_age);
    RUN_TEST(test_empty_key_set_never_replaces_held_keys);
    RUN_TEST(test_failed_refresh_counts_toward_window);
    RUN_TEST(test_unknown_kid_failed_refresh_does_not_extend_window);
    RUN_TEST(test_cache_control_max_age_shortens_ttl_and_is_clamped);
    RUN_TEST(test_304_moves_anchor);

    RUN_TEST(test_configured_ttl_clamped_with_event);
    RUN_TEST(test_keys_with_empty_object_is_not_a_jwks);
    RUN_TEST(test_keys_with_number_is_not_a_jwks);
    RUN_TEST(test_keys_with_null_is_not_a_jwks);
    RUN_TEST(test_rsa_only_set_is_a_successful_fetch_pin);
    RUN_TEST(test_cold_cache_failing_endpoint_one_fetch_per_window);
    RUN_TEST(test_clock_moved_backwards_makes_refresh_due);
    RUN_TEST(test_304_rereads_max_age);
    RUN_TEST(test_unusable_etag_is_never_echoed);
    RUN_TEST(test_configured_ttl_wins_over_advertised_max_age);
    return UNITY_END();
}
