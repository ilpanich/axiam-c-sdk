/*
 * CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
 * AXIAM threats T-39 and T-143).
 *
 * Two things are under test and they are separable: what the poller does with a
 * document, and what enabling it changes about a verification. The second is
 * the shorter half and the one that matters — the feed may only ever turn an
 * accept into a reject, and only for a token that names a session.
 *
 * Every negative is paired with its I4 twin: a client left as it was before
 * 1.44, a token with no session behind it, a feed that cannot be read. A guard
 * that started denying requests because an advisory document went missing would
 * be a worse failure than the fifteen-minute window §10.2 records, and those
 * twins are what rule it out.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define REVOKED_SID "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
#define LIVE_SID "11111111-2222-3333-4444-555555555555"

typedef struct {
    const char *jwks_body;
    const char *feed_body;
    long feed_status;
    int feed_calls;
} fake_state_t;

static fake_state_t g;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, AXIAM_REVOCATION_FEED_PATH)) {
        st->feed_calls++;
        if (st->feed_status == 0) {
            /* A transport failure: no HTTP response arrived at all. */
            memset(resp, 0, sizeof(*resp));
            resp->transport_err = 7;
            resp->transport_msg = strdup("connection refused");
            return -1;
        }
        resp_fill(resp, st->feed_status, st->feed_body ? st->feed_body : "", NULL);
        return 0;
    }
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    g.feed_status = 200;
}
void tearDown(void) {}

/* A token carrying `sid`, plus the matching JWKS. Both are heap; the caller
 * frees them. */
static void a_token_with_sid(const char *sid, char **out_token, char **out_jwks) {
    char payload[320];
    char extra[128];
    snprintf(extra, sizeof(extra), ",\"sid\":\"%s\"", sid);
    TEST_ASSERT_EQUAL_INT(
        0, jwt_make("k1", test_claims(payload, sizeof(payload), "user-1", extra), out_token,
                    out_jwks));
}

/* The feed document listing exactly the entries for `sid` (NULL for none). */
static const char *feed_listing(char *buf, size_t n, const char *sid) {
    if (!sid) {
        snprintf(buf, n, "{\"alg\":\"SHA-256\",\"revoked\":[]}");
        return buf;
    }
    char entry[AXIAM_REVOCATION_ENTRY_CAP];
    TEST_ASSERT_EQUAL_INT(0, axiam_revocation_entry_for(sid, entry, sizeof(entry)));
    snprintf(buf, n, "{\"alg\":\"SHA-256\",\"revoked\":[\"%s\"]}", entry);
    return buf;
}

/* ------------------------------------------------------------------ */
/* The entry format                                                    */
/* ------------------------------------------------------------------ */

/*
 * The server computes this entry in axiam_core::revocation_feed and every SDK
 * recomputes it from a `sid` claim. A pinned vector is the only thing keeping
 * twelve implementations of one wire format in agreement; a round trip through
 * this file's own hash would agree with itself while agreeing with nobody.
 */
static void test_the_entry_matches_the_pinned_vector(void) {
    char entry[AXIAM_REVOCATION_ENTRY_CAP];
    TEST_ASSERT_EQUAL_INT(0, axiam_revocation_entry_for(REVOKED_SID, entry, sizeof(entry)));
    TEST_ASSERT_EQUAL_STRING("i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ", entry);
}

/*
 * Hashed over the claim's EXACT string. An implementation that parsed the sid
 * as a UUID and re-rendered it would agree on canonical input and disagree the
 * moment a server issued anything else.
 */
static void test_the_entry_hashes_the_string_not_a_parsed_uuid(void) {
    char lower[AXIAM_REVOCATION_ENTRY_CAP];
    char upper[AXIAM_REVOCATION_ENTRY_CAP];
    axiam_revocation_entry_for(REVOKED_SID, lower, sizeof(lower));
    axiam_revocation_entry_for("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B", upper, sizeof(upper));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(lower, upper));
}

static void test_an_undersized_buffer_is_refused_rather_than_truncated(void) {
    char small[8];
    TEST_ASSERT_EQUAL_INT(-1, axiam_revocation_entry_for(REVOKED_SID, small, sizeof(small)));
    TEST_ASSERT_EQUAL_INT(-1, axiam_revocation_entry_for(NULL, small, sizeof(small)));
}

/* ------------------------------------------------------------------ */
/* What enabling the feed changes about a verification                 */
/* ------------------------------------------------------------------ */

static void test_a_revoked_session_is_rejected(void) {
    char *token = NULL, *jwks = NULL, feed[256];
    a_token_with_sid(REVOKED_SID, &token, &jwks);
    g.jwks_body = jwks;
    g.feed_body = feed_listing(feed, sizeof(feed), REVOKED_SID);
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    /* Its own report: "the session is gone" is not "this credential was never
     * valid", and a guard that conflated them would tell a logged-out user
     * their token had expired. */
    TEST_ASSERT_NOT_NULL(strstr(err.message, "revoked"));
    TEST_ASSERT_NULL(strstr(err.message, "exp"));

    axiam_client_free(c);
    free(token);
    free(jwks);
}

static void test_a_session_the_feed_does_not_list_is_admitted(void) {
    char *token = NULL, *jwks = NULL, feed[256];
    a_token_with_sid(LIVE_SID, &token, &jwks);
    g.jwks_body = jwks;
    g.feed_body = feed_listing(feed, sizeof(feed), REVOKED_SID);
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));

    axiam_client_free(c);
    free(token);
    free(jwks);
}

/*
 * §10.4 rule 3 — every way the feed can be unusable behaves exactly as no feed
 * at all. The failure this forecloses is the opposite: a guard that starts
 * denying every request because a document it treats as advisory became
 * unreachable.
 */
static void test_an_unusable_feed_denies_nothing(void) {
    char listing[256];
    feed_listing(listing, sizeof(listing), REVOKED_SID);
    char wrong_alg[256];
    {
        char entry[AXIAM_REVOCATION_ENTRY_CAP];
        axiam_revocation_entry_for(REVOKED_SID, entry, sizeof(entry));
        snprintf(wrong_alg, sizeof(wrong_alg), "{\"alg\":\"SHA-512\",\"revoked\":[\"%s\"]}", entry);
    }

    struct { const char *name; long status; const char *body; } cases[] = {
        {"a 404 — the deployment does not publish the feed", 404, listing},
        {"a 500 — the feed is broken", 500, listing},
        {"a transport failure — the host is unreachable", 0, listing},
        {"a body that is not JSON", 200, "not json"},
        {"a document that is not an object", 200, "[]"},
        {"an alg this build does not know", 200, wrong_alg},
        {"a revoked member that is not an array", 200, "{\"alg\":\"SHA-256\",\"revoked\":\"x\"}"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        setUp();
        char *token = NULL, *jwks = NULL;
        a_token_with_sid(REVOKED_SID, &token, &jwks);
        g.jwks_body = jwks;
        g.feed_status = cases[i].status;
        g.feed_body = cases[i].body;
        axiam_client_t *c = make_client();
        axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
        axiam_error_t err;
        axiam_error_reset(&err);

        TEST_ASSERT_EQUAL_MESSAGE(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err),
                                  cases[i].name);
        axiam_client_free(c);
        free(token);
        free(jwks);
    }
}

/*
 * A blip must not un-revoke a session the guard already knows about: the
 * previous set stays in place across a failed refresh. Asserted through
 * axiam_revocation_is_revoked because the poll interval makes a second
 * verification in the same second answer from the cache without refetching.
 */
static void test_a_failed_poll_keeps_the_previous_set(void) {
    char feed[256];
    g.feed_body = feed_listing(feed, sizeof(feed), REVOKED_SID);
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);

    TEST_ASSERT_EQUAL_INT(1, axiam_revocation_is_revoked(c, REVOKED_SID));

    /* Force the next check to refetch, and make that fetch fail. */
    g.feed_status = 500;
    c->revocation_last_attempt = 0;
    TEST_ASSERT_EQUAL_INT(1, axiam_revocation_is_revoked(c, REVOKED_SID));
    TEST_ASSERT_EQUAL_INT(2, g.feed_calls);

    axiam_client_free(c);
}

/*
 * The request path never waits on a fetch it does not need: inside one
 * interval, repeated checks answer from the cache. And a feed that is DOWN is
 * not retried on every request either — the interval is measured from the last
 * ATTEMPT, which is the cost §10.4 exists to avoid.
 */
static void test_repeated_checks_inside_one_interval_do_not_refetch(void) {
    char feed[256];
    g.feed_body = feed_listing(feed, sizeof(feed), REVOKED_SID);
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);

    for (int i = 0; i < 5; i++) axiam_revocation_is_revoked(c, LIVE_SID);
    TEST_ASSERT_EQUAL_INT(1, g.feed_calls);

    axiam_client_free(c);
}

static void test_a_down_feed_is_not_retried_on_every_request(void) {
    g.feed_status = 500;
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);

    for (int i = 0; i < 5; i++) axiam_revocation_is_revoked(c, LIVE_SID);
    TEST_ASSERT_EQUAL_INT(1, g.feed_calls);

    axiam_client_free(c);
}

/*
 * The floor is applied by clamping, not by refusing: a caller who asks for
 * something faster gets the fastest thing on offer.
 */
static void test_a_shorter_interval_is_clamped_rather_than_refused(void) {
    axiam_client_t *c = make_client();

    TEST_ASSERT_EQUAL_INT(0, axiam_client_enable_revocation_feed(c, 1));
    TEST_ASSERT_EQUAL_INT(AXIAM_REVOCATION_MIN_POLL_SECS, c->revocation_poll_secs);

    TEST_ASSERT_EQUAL_INT(0, axiam_client_enable_revocation_feed(c, 120));
    TEST_ASSERT_EQUAL_INT(120, c->revocation_poll_secs);

    TEST_ASSERT_EQUAL_INT(-1, axiam_client_enable_revocation_feed(NULL, 30));
    axiam_client_free(c);
}

/*
 * An over-sized document drops the WHOLE set rather than truncating it. A
 * truncated set is a guard that admits some revoked sessions and reports none,
 * which is worse than one that admits all of them and says so.
 */
static void test_an_oversized_document_drops_everything_rather_than_truncating(void) {
    /* Built at AXIAM_REVOCATION_MAX_ENTRIES + 1, with the entry under test
     * first, so a truncating implementation would still honour it. */
    size_t cap = 64u * (AXIAM_REVOCATION_MAX_ENTRIES + 2u);
    char *body = malloc(cap);
    TEST_ASSERT_NOT_NULL(body);
    char entry[AXIAM_REVOCATION_ENTRY_CAP];
    axiam_revocation_entry_for(REVOKED_SID, entry, sizeof(entry));
    size_t o = (size_t)snprintf(body, cap, "{\"alg\":\"SHA-256\",\"revoked\":[\"%s\"", entry);
    for (unsigned i = 0; i <= AXIAM_REVOCATION_MAX_ENTRIES; i++) {
        o += (size_t)snprintf(body + o, cap - o, ",\"e%u\"", i);
    }
    snprintf(body + o, cap - o, "]}");

    g.feed_body = body;
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);

    TEST_ASSERT_EQUAL_INT(0, axiam_revocation_is_revoked(c, REVOKED_SID));

    axiam_client_free(c);
    free(body);
}

/* ------------------------------------------------------------------ */
/* I4 — configured as today, behaves as today                          */
/* ------------------------------------------------------------------ */

/*
 * The default. A client left as it was before contract 1.44 accepts exactly
 * what it accepted then, including a token whose session a feed WOULD have
 * listed — the §10.2 posture this narrows rather than replaces. And it never
 * polls: a deployment that publishes no feed sees no traffic for one.
 */
static void test_the_feed_is_off_by_default(void) {
    char *token = NULL, *jwks = NULL, feed[256];
    a_token_with_sid(REVOKED_SID, &token, &jwks);
    g.jwks_body = jwks;
    g.feed_body = feed_listing(feed, sizeof(feed), REVOKED_SID);
    axiam_client_t *c = make_client();
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_EQUAL_INT(0, g.feed_calls);

    axiam_client_free(c);
    free(token);
    free(jwks);
}

/*
 * A token with no session behind it is never matched against the feed, even
 * when the document happens to list the hash of the empty string. Hashing `jti`
 * instead would match nothing while looking like it worked.
 */
static void test_a_token_with_no_session_is_never_matched(void) {
    char *token = NULL, *jwks = NULL, payload[256], feed[256];
    TEST_ASSERT_EQUAL_INT(
        0, jwt_make("k1", test_claims(payload, sizeof(payload), "user-1", NULL), &token, &jwks));
    g.jwks_body = jwks;
    g.feed_body = feed_listing(feed, sizeof(feed), "");
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));
    /* Not even a fetch: a sid-less token asks the feed no question at all. */
    TEST_ASSERT_EQUAL_INT(0, g.feed_calls);

    axiam_client_free(c);
    free(token);
    free(jwks);
}

/*
 * The feed can only ever turn an accept into a reject: a token that fails
 * §10.1 still fails for its own reason, so a feed listing nothing can never
 * rescue an expired token.
 */
static void test_the_feed_never_turns_a_reject_into_an_accept(void) {
    char *token = NULL, *jwks = NULL, payload[320], feed[256];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"user-1\",\"tenant_id\":\"%s\",\"exp\":%lld,\"sid\":\"%s\"}",
             AXIAM_TEST_TENANT_ID, (long long)time(NULL) - 900, LIVE_SID);
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", payload, &token, &jwks));
    g.jwks_body = jwks;
    g.feed_body = feed_listing(feed, sizeof(feed), NULL);
    axiam_client_t *c = make_client();
    axiam_client_enable_revocation_feed(c, AXIAM_REVOCATION_DEFAULT_POLL_SECS);
    axiam_error_t err;
    axiam_error_reset(&err);

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, axiam_jwt_verify(c, token, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "exp"));

    axiam_client_free(c);
    free(token);
    free(jwks);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_entry_matches_the_pinned_vector);
    RUN_TEST(test_the_entry_hashes_the_string_not_a_parsed_uuid);
    RUN_TEST(test_an_undersized_buffer_is_refused_rather_than_truncated);
    RUN_TEST(test_a_revoked_session_is_rejected);
    RUN_TEST(test_a_session_the_feed_does_not_list_is_admitted);
    RUN_TEST(test_an_unusable_feed_denies_nothing);
    RUN_TEST(test_a_failed_poll_keeps_the_previous_set);
    RUN_TEST(test_repeated_checks_inside_one_interval_do_not_refetch);
    RUN_TEST(test_a_down_feed_is_not_retried_on_every_request);
    RUN_TEST(test_a_shorter_interval_is_clamped_rather_than_refused);
    RUN_TEST(test_an_oversized_document_drops_everything_rather_than_truncating);
    RUN_TEST(test_the_feed_is_off_by_default);
    RUN_TEST(test_a_token_with_no_session_is_never_matched);
    RUN_TEST(test_the_feed_never_turns_a_reject_into_an_accept);
    return UNITY_END();
}
