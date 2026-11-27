/*
 * CONTRACT.md §12.1 / §9 rule 2 — `oidc_refresh` is single-flighted.
 *
 * §12.1 says `oidc_refresh` "MUST be governed by a §9-conformant single-flight
 * guard — including §9 rule 2's observable requirement (one wire call per
 * burst, that one outcome shared with every concurrent caller) and §9's test
 * requirement in its own right". That observable is a COUNT, so this test
 * counts.
 *
 * Why it matters here even though the caller supplies the token: AXIAM rotates
 * refresh tokens. Two threads redeeming the same one concurrently produce one
 * winner and one `invalid_grant` — for a token that was perfectly good a
 * millisecond earlier, and which the loser cannot distinguish from a genuinely
 * revoked session. The second test is the other half of the guard's design:
 * DIFFERENT tokens must not contend, because coalescing them would hand one
 * caller another's tokens.
 */

#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define N_THREADS 8
#define SF_ISSUER    "https://issuer.test"
#define SF_CLIENT_ID "rp-client"

#define SF_DISCOVERY                                                     \
    "{\"issuer\":\"https://issuer.test\","                               \
    "\"authorization_endpoint\":\"https://api.test/oauth2/authorize\","  \
    "\"token_endpoint\":\"https://api.test/oauth2/token\","              \
    "\"jwks_uri\":\"https://api.test/oauth2/jwks\"}"

typedef struct {
    pthread_mutex_t mtx;
    int token_calls;
    int discovery_calls;
    int other_calls; /* anything that is neither discovery, JWKS nor the token endpoint */
    /* When set, the token endpoint refuses — the flight then has to share a
     * FAILURE with every waiter, which is the other half of §9 rule 2. */
    int refuse;
    /*
     * The coalescing window, made deterministic.
     *
     * The barrier below already guarantees all N workers are RUNNING before any
     * of them calls. What it cannot guarantee is that they have reached the
     * GUARD before the leader's flight finishes — and a fixed usleep() is a bet
     * that they do. Under valgrind, or on a runner with fewer cores than
     * threads, that bet loses: the leader returns first, a follower opens a
     * second flight, and token_calls is 2 for a reason that has nothing to do
     * with the guard being wrong.
     *
     * So the leader also waits for `gate_expect` workers to have ENTERED the
     * operation, which each signals by bumping `gate_arrived` on its way in. If
     * the guard works, followers park and never reach the transport; if it were
     * broken they would arrive here too, and token_calls would say so. A late
     * arrival finds the count already satisfied, so nothing deadlocks, and the
     * single-threaded tests leave gate_expect at 0 and are unaffected.
     */
    int gate_expect;
    int gate_arrived;
    /* The `tenant_id` query value of each token-endpoint request, in arrival order. */
    char tenants_seen[8][40];
    char token_body[4096];
    char jwks_body[2048];
} sf_state_t;

static sf_state_t g;
static pthread_barrier_t g_barrier;
static axiam_client_t *g_client;

static int sf_transport(void *ctx, const axiam_http_request_t *req,
                        axiam_http_response_t *resp) {
    sf_state_t *st = ctx;
    if (strstr(req->url, "openid-configuration")) {
        pthread_mutex_lock(&st->mtx);
        st->discovery_calls++;
        pthread_mutex_unlock(&st->mtx);
        resp_fill(resp, 200, SF_DISCOVERY, NULL);
        return 0;
    }
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, st->jwks_body, NULL);
        return 0;
    }
    if (strstr(req->url, "/oauth2/token")) {
        pthread_mutex_lock(&st->mtx);
        if (st->token_calls < 8) {
            const char *q = strstr(req->url, "tenant_id=");
            if (q) snprintf(st->tenants_seen[st->token_calls], 40, "%.36s", q + 10);
        }
        st->token_calls++;
        int refuse = st->refuse;
        int expect = st->gate_expect;
        pthread_mutex_unlock(&st->mtx);
        if (expect > 0) {
            /* Bounded at ~10s, so a genuine regression fails the assertion
             * rather than hanging the suite until the job times out. */
            for (int waited = 0; waited < 10000; waited++) {
                pthread_mutex_lock(&st->mtx);
                int arrived = st->gate_arrived;
                pthread_mutex_unlock(&st->mtx);
                if (arrived >= expect) break;
                usleep(1000);
            }
        }
        /* Slack on top of the gate, for a worker that has entered the operation
         * but not yet parked on the guard. */
        usleep(60 * 1000);
        if (refuse) {
            resp_fill(resp, 400, "{\"error\":\"invalid_grant\"}", NULL);
            return 0;
        }
        resp_fill(resp, 200, st->token_body, NULL);
        return 0;
    }
    pthread_mutex_lock(&st->mtx);
    st->other_calls++;
    pthread_mutex_unlock(&st->mtx);
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

/* Build the success body, including a VALID ID token so the shared outcome
 * carries validated claims. That matters: the leader's result is deep-copied to
 * every waiter, and a copy that dropped `id_claims` would hand a follower a
 * token set the SDK had verified but could no longer describe. */
static void sf_prepare_tokens(void) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" SF_ISSUER "\",\"aud\":\"" SF_CLIENT_ID "\",\"sub\":\"user-1\","
             "\"exp\":%lld,\"iat\":%lld,\"email\":\"a@b.test\",\"roles\":[\"admin\"]}",
             now + 900, now - 5);
    char *token = NULL;
    char *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("sf-kid", payload, &token, &jwks));
    snprintf(g.token_body, sizeof(g.token_body),
             "{\"access_token\":\"rotated-access\",\"token_type\":\"Bearer\","
             "\"expires_in\":900,\"refresh_token\":\"rotated-refresh\",\"id_token\":\"%s\"}",
             token);
    snprintf(g.jwks_body, sizeof(g.jwks_body), "%s", jwks);
    free(token);
    free(jwks);
}

static axiam_client_t *make_client_for_tenant(const char *tenant_id) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://api.test");
    axiam_client_config_set_tenant_id(cfg, tenant_id);
    axiam_client_config_set_oidc_client_id(cfg, "rp-client");
    axiam_client_config_set_oidc_client_secret(cfg, "rp-secret");
    axiam_client_config_set_transport(cfg, sf_transport, &g);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static axiam_client_t *make_client(void) { return make_client_for_tenant(AXIAM_TEST_TENANT_ID); }

void setUp(void) {
    memset(&g, 0, sizeof(g));
    pthread_mutex_init(&g.mtx, NULL);
}
void tearDown(void) { pthread_mutex_destroy(&g.mtx); }

/* Signal that this worker has entered the operation under test — see
 * sf_state_t::gate_expect. */
static void sf_gate_arrive(void) {
    pthread_mutex_lock(&g.mtx);
    g.gate_arrived++;
    pthread_mutex_unlock(&g.mtx);
}

/* Every worker presents the SAME refresh token. */
static void *same_token_worker(void *arg) {
    (void)arg;
    axiam_sensitive_t *token = axiam_sensitive_new("the-one-refresh-token");
    pthread_barrier_wait(&g_barrier);
    sf_gate_arrive();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_error_kind_t k = axiam_oidc_refresh(g_client, token, NULL, NULL, &set, &err);
    /* Every participant must get the full outcome, not a hollowed-out copy:
     * the rotated access token, the rotated refresh token, and the validated
     * ID-token claims that came with them. */
    int ok = (k == AXIAM_OK) && set.access_token && set.refresh_token && set.id_claims &&
             strcmp(axiam_sensitive_reveal(set.access_token), "rotated-access") == 0 &&
             strcmp(axiam_sensitive_reveal(set.refresh_token), "rotated-refresh") == 0 &&
             set.id_claims->subject && strcmp(set.id_claims->subject, "user-1") == 0 &&
             set.id_claims->roles_count == 1;
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    return (void *)(intptr_t)(ok ? 0 : 1);
}

/* Every worker presents the same token against a server that refuses it. */
static void *failing_worker(void *arg) {
    (void)arg;
    axiam_sensitive_t *token = axiam_sensitive_new("the-spent-refresh-token");
    pthread_barrier_wait(&g_barrier);
    sf_gate_arrive();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_error_kind_t k = axiam_oidc_refresh(g_client, token, NULL, NULL, &set, &err);
    int ok = (k == AXIAM_ERR_AUTH) && strcmp(err.oauth_error, "invalid_grant") == 0 &&
             set.access_token == NULL;
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    return (void *)(intptr_t)(ok ? 0 : 1);
}

/* Each worker presents a DIFFERENT refresh token. */
static void *distinct_token_worker(void *arg) {
    char value[64];
    snprintf(value, sizeof(value), "refresh-token-%d", (int)(intptr_t)arg);
    axiam_sensitive_t *token = axiam_sensitive_new(value);
    pthread_barrier_wait(&g_barrier);
    sf_gate_arrive();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_error_kind_t k = axiam_oidc_refresh(g_client, token, NULL, NULL, &set, &err);
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    return (void *)(intptr_t)(k == AXIAM_OK ? 0 : 1);
}

static void run_workers(void *(*fn)(void *)) {
    pthread_mutex_lock(&g.mtx);
    g.gate_expect = N_THREADS;
    g.gate_arrived = 0;
    pthread_mutex_unlock(&g.mtx);
    pthread_barrier_init(&g_barrier, NULL, N_THREADS);
    pthread_t th[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&th[i], NULL, fn, (void *)(intptr_t)i);
    for (int i = 0; i < N_THREADS; i++) {
        void *r;
        pthread_join(th[i], &r);
        TEST_ASSERT_EQUAL_INT(0, (int)(intptr_t)r);
    }
    pthread_barrier_destroy(&g_barrier);
    pthread_mutex_lock(&g.mtx);
    g.gate_expect = 0;
    pthread_mutex_unlock(&g.mtx);
}

void test_concurrent_refreshes_of_one_token_make_exactly_one_wire_call(void) {
    sf_prepare_tokens();
    g_client = make_client();
    TEST_ASSERT_NOT_NULL(g_client);
    /* Warm the discovery cache so the assertion below is about the grant and
     * not about discovery. */
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(g_client, &cfg, &err);
    axiam_oidc_config_dispose(&cfg);

    run_workers(same_token_worker);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights); /* every slot vacated */

    /* §9 rule 2's observable: ONE wire call for the burst... */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    TEST_ASSERT_EQUAL_INT(1, g.discovery_calls);
    /* ...and every worker got that one outcome (asserted inside the worker,
     * which fails the join above if any of them saw something else). */

    axiam_client_free(g_client);
    g_client = NULL;
}

void test_a_failing_flight_shares_its_failure_with_every_waiter(void) {
    /*
     * The other half of §9 rule 2: "that ONE OUTCOME shared with every
     * concurrent caller" — outcome, not success. Eight threads redeem one
     * already-spent token; one request goes out and all eight see the same
     * `invalid_grant`, with no token set. A guard that only shared successes
     * would leave the followers to make their own requests and collect a
     * second, differently-worded refusal each.
     */
    sf_prepare_tokens();
    g.refuse = 1;
    g_client = make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(g_client, &cfg, &err);
    axiam_oidc_config_dispose(&cfg);

    run_workers(failing_worker);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights); /* every slot vacated */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);

    axiam_client_free(g_client);
    g_client = NULL;
}

/* Every worker of the burst records its own outcome here. */
static int g_outcome_ok[N_THREADS];

static void *invalid_grant_waiter(void *arg) {
    int slot = (int)(intptr_t)arg;
    axiam_sensitive_t *token = axiam_sensitive_new("the-spent-refresh-token");
    pthread_barrier_wait(&g_barrier);
    sf_gate_arrive();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    axiam_error_kind_t k = axiam_oidc_refresh(g_client, token, NULL, NULL, &set, &err);
    /* The one shared error, with its code and the server's body intact, and nothing else. */
    g_outcome_ok[slot] = (k == AXIAM_ERR_AUTH) && strcmp(err.oauth_error, "invalid_grant") == 0 &&
                         strncmp(err.message, "invalid_grant", 13) == 0 &&
                         set.access_token == NULL && set.refresh_token == NULL;
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    return NULL;
}

void test_invalid_grant_on_refresh_is_one_wire_call_one_shared_error_and_no_replay(void) {
    /*
     * CONTRACT.md §9, the contract-1.65 paragraph "A replayed refresh token ends the session".
     *
     * With the tenant setting `oauth2.refresh_reuse_response` at its default, a rotated refresh
     * token presented again is answered `400 invalid_grant` AND ends the session: the
     * legitimate successor is revoked with it. What that asks of an SDK is not new behaviour but
     * the rules it already has, confirmed here against a mocked `400 invalid_grant`:
     *
     *   - exactly ONE wire call for a burst of N >= 5 concurrent callers (N-1 followers that each
     *     made their own call would be N-1 replays, and from 1.65 each costs the user the
     *     session);
     *   - every waiter receives that ONE OAuthProtocolError;
     *   - a later call made with no new token from the caller makes no request with the spent
     *     token again — this SDK holds no refresh token of its own to present, so a call with
     *     nothing to present is refused locally.
     */
    sf_prepare_tokens();
    g.refuse = 1;
    g_client = make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(g_client, &cfg, &err);
    axiam_oidc_config_dispose(&cfg);
    TEST_ASSERT_TRUE(N_THREADS >= 5);

    pthread_mutex_lock(&g.mtx);
    g.gate_expect = N_THREADS;
    g.gate_arrived = 0;
    pthread_mutex_unlock(&g.mtx);
    memset(g_outcome_ok, 0, sizeof g_outcome_ok);
    pthread_barrier_init(&g_barrier, NULL, N_THREADS);
    pthread_t th[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&th[i], NULL, invalid_grant_waiter, (void *)(intptr_t)i);
    for (int i = 0; i < N_THREADS; i++) pthread_join(th[i], NULL);
    pthread_barrier_destroy(&g_barrier);
    pthread_mutex_lock(&g.mtx);
    g.gate_expect = 0;
    pthread_mutex_unlock(&g.mtx);

    /* ONE wire call for the burst, and every one of the N waiters got that one error. */
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    for (int i = 0; i < N_THREADS; i++) TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_outcome_ok[i], "waiter");

    /* A later call with no new token makes no request: nothing is retained to replay... */
    axiam_oidc_token_set_t set;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, NULL, NULL, NULL, &set, &err));
    axiam_sensitive_t *empty = axiam_sensitive_new("");
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, empty, NULL, NULL, &set, &err));
    axiam_sensitive_free(empty);
    /* ...and no other path (the cookie-session refresh, the SDK's own retry) re-presented it. */
    usleep(100 * 1000);
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    TEST_ASSERT_EQUAL_INT(0, g.other_calls);

    axiam_client_free(g_client);
    g_client = NULL;
}

void test_distinct_refresh_tokens_do_not_contend(void) {
    sf_prepare_tokens();
    /* The guard is keyed on the TOKEN, not on the client. Coalescing unrelated
     * tokens would be worse than not coalescing at all: one caller would be
     * handed another caller's freshly-rotated credential. */
    g_client = make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    axiam_oidc_discover(g_client, &cfg, &err);
    axiam_oidc_config_dispose(&cfg);

    run_workers(distinct_token_worker);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights); /* every slot vacated */

    TEST_ASSERT_EQUAL_INT(N_THREADS, g.token_calls);

    axiam_client_free(g_client);
    g_client = NULL;
}

void test_a_second_refresh_after_the_burst_is_a_new_flight(void) {
    /*
     * A coalesce, not a cache. The flight is unlinked before its outcome is
     * published, so a caller arriving after it completed starts a fresh one —
     * anything else would hand out a token whose refresh token has already been
     * spent, with no TTL and no invalidation.
     */
    sf_prepare_tokens();
    g_client = make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("the-one-refresh-token");
    axiam_oidc_token_set_t a, b;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, token, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, token, NULL, NULL, &b, &err));
    TEST_ASSERT_EQUAL_INT(2, g.token_calls);

    axiam_oidc_token_set_dispose(&a);
    axiam_oidc_token_set_dispose(&b);
    axiam_sensitive_free(token);
    axiam_client_free(g_client);
    g_client = NULL;
}

void test_a_shared_outcome_without_optional_members_copies_cleanly(void) {
    /* The leader's result is deep-copied to every participant, and the copy has
     * to survive a token set whose optional halves are absent: no refresh
     * token, no ID token, no claims. A copy routine that assumed they were
     * there would fail exactly where the server was most minimal. */
    snprintf(g.token_body, sizeof(g.token_body),
             "{\"access_token\":\"bare\",\"token_type\":\"Bearer\",\"expires_in\":900}");
    g_client = make_client();
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("plain-refresh-token");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, token, "openid", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("bare", axiam_sensitive_reveal(set.access_token));
    TEST_ASSERT_NULL(set.refresh_token);
    TEST_ASSERT_NULL(set.id_token);
    TEST_ASSERT_NULL(set.id_claims);
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    axiam_client_free(g_client);
    g_client = NULL;
}

/* CONTRACT §9 rule 7: the flight is keyed by the RESOLVED tenant and the token (scope is not
 * part of the key). The tenant tests run their callers concurrently: the leader's call is held
 * on the wire (the gate) until every caller has entered the operation. */
#define KEY_DEFAULT_TENANT_LC "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
#define KEY_DEFAULT_TENANT_UC "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
#define KEY_OTHER_TENANT      "22222222-2222-2222-2222-222222222222"

typedef struct {
    const char *tenant; /* NULL: omitted, so the client's default applies */
    const char *scope;
    const char *token; /* NULL: the common one */
    int ok;
} key_call_t;

static void *key_worker(void *arg) {
    key_call_t *kc = arg;
    axiam_sensitive_t *token = axiam_sensitive_new(kc->token ? kc->token : "the-one-refresh-token");
    pthread_barrier_wait(&g_barrier);
    sf_gate_arrive();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    kc->ok = axiam_oidc_refresh(g_client, token, kc->scope, kc->tenant, &set, &err) == AXIAM_OK;
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(token);
    return NULL;
}

static void run_key_calls(key_call_t *calls, int n) {
    pthread_mutex_lock(&g.mtx);
    g.gate_expect = n;
    g.gate_arrived = 0;
    pthread_mutex_unlock(&g.mtx);
    pthread_barrier_init(&g_barrier, NULL, (unsigned) n);
    pthread_t th[4];
    for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, key_worker, &calls[i]);
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
    pthread_barrier_destroy(&g_barrier);
    pthread_mutex_lock(&g.mtx);
    g.gate_expect = 0;
    pthread_mutex_unlock(&g.mtx);
    for (int i = 0; i < n; i++) TEST_ASSERT_EQUAL_INT_MESSAGE(1, calls[i].ok, "call outcome");
}

void test_the_same_token_for_a_different_tenant_is_a_separate_flight(void) {
    sf_prepare_tokens();
    g_client = make_client_for_tenant(KEY_DEFAULT_TENANT_LC);
    key_call_t calls[2] = {{KEY_DEFAULT_TENANT_LC, NULL, NULL, 0}, {KEY_OTHER_TENANT, NULL, NULL, 0}};
    run_key_calls(calls, 2);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights);
    /* Two tenants, one token: each gets its own server check (its own wire tenant_id) and its
     * own outcome (every caller's success is asserted in run_key_calls). */
    TEST_ASSERT_EQUAL_INT(2, g.token_calls);
    int saw_default = 0, saw_other = 0;
    for (int i = 0; i < 2; i++) {
        saw_default += strcmp(g.tenants_seen[i], KEY_DEFAULT_TENANT_LC) == 0;
        saw_other += strcmp(g.tenants_seen[i], KEY_OTHER_TENANT) == 0;
    }
    TEST_ASSERT_EQUAL_INT(1, saw_default);
    TEST_ASSERT_EQUAL_INT(1, saw_other);
    axiam_client_free(g_client);
    g_client = NULL;
}

void test_the_default_tenant_explicit_in_either_case_or_omitted_is_one_flight(void) {
    sf_prepare_tokens();
    g_client = make_client_for_tenant(KEY_DEFAULT_TENANT_LC);
    /* Omitted, explicit lower-case, explicit upper-case, and a different scope (not part of
     * the key): one rotating token, so exactly one wire call. */
    key_call_t calls[4] = {{NULL, NULL, NULL, 0},
                           {KEY_DEFAULT_TENANT_LC, NULL, NULL, 0},
                           {KEY_DEFAULT_TENANT_UC, NULL, NULL, 0},
                           {KEY_DEFAULT_TENANT_UC, "openid", NULL, 0}};
    run_key_calls(calls, 4);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights);
    TEST_ASSERT_EQUAL_INT(1, g.token_calls);
    /* The one wire call carries the canonical lower-case tenant, whichever spelling led. */
    TEST_ASSERT_EQUAL_STRING(KEY_DEFAULT_TENANT_LC, g.tenants_seen[0]);
    axiam_client_free(g_client);
    g_client = NULL;
}

void test_a_different_token_gets_its_own_call_while_a_second_caller_of_the_first_joins(void) {
    sf_prepare_tokens();
    g_client = make_client_for_tenant(KEY_DEFAULT_TENANT_LC);
    key_call_t calls[3] = {{NULL, NULL, "token-A", 0}, {NULL, NULL, "token-A", 0},
                           {NULL, NULL, "token-B", 0}};
    run_key_calls(calls, 3);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights);
    TEST_ASSERT_EQUAL_INT(2, g.token_calls); /* A's two callers share one call; B has its own */
    axiam_client_free(g_client);
    g_client = NULL;
}

void test_an_invalid_tenant_fails_at_once_with_no_slot_and_no_request(void) {
    sf_prepare_tokens();
    g_client = make_client_for_tenant(KEY_DEFAULT_TENANT_LC);
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("the-one-refresh-token");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                      axiam_oidc_refresh(g_client, token, NULL, "not-a-uuid", &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g.token_calls);
    TEST_ASSERT_EQUAL_INT(0, g.discovery_calls);
    TEST_ASSERT_NULL(g_client->oidc_refresh_flights);
    axiam_sensitive_free(token);
    axiam_client_free(g_client);
    g_client = NULL;
}

/* Publish and vacate are ONE step under oidc_refresh_mtx in axiam_oidc_refresh (the flight is
 * unlinked and its outcome published inside a single critical section), so no
 * publish-before-vacate window exists to hold open: the same-window "joins" case is the
 * after-vacate case, which test_a_second_refresh_after_the_burst_is_a_new_flight covers for
 * the same token and tenant. Here the earliest reachable instant after A's outcome is
 * published, a different tenant's call is a fresh wire call of its own. */
void test_a_different_tenant_right_after_a_flight_makes_its_own_wire_call(void) {
    sf_prepare_tokens();
    g_client = make_client_for_tenant(KEY_DEFAULT_TENANT_LC);
    axiam_error_t err;
    axiam_sensitive_t *token = axiam_sensitive_new("the-one-refresh-token");
    axiam_oidc_token_set_t a, b;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, token, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(g_client, token, NULL, KEY_OTHER_TENANT, &b, &err));
    TEST_ASSERT_EQUAL_INT(2, g.token_calls);
    axiam_oidc_token_set_dispose(&a);
    axiam_oidc_token_set_dispose(&b);
    axiam_sensitive_free(token);
    axiam_client_free(g_client);
    g_client = NULL;
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_concurrent_refreshes_of_one_token_make_exactly_one_wire_call);
    RUN_TEST(test_a_failing_flight_shares_its_failure_with_every_waiter);
    RUN_TEST(test_invalid_grant_on_refresh_is_one_wire_call_one_shared_error_and_no_replay);
    RUN_TEST(test_distinct_refresh_tokens_do_not_contend);
    RUN_TEST(test_a_second_refresh_after_the_burst_is_a_new_flight);
    RUN_TEST(test_a_shared_outcome_without_optional_members_copies_cleanly);
    RUN_TEST(test_the_same_token_for_a_different_tenant_is_a_separate_flight);
    RUN_TEST(test_the_default_tenant_explicit_in_either_case_or_omitted_is_one_flight);
    RUN_TEST(test_a_different_token_gets_its_own_call_while_a_second_caller_of_the_first_joins);
    RUN_TEST(test_an_invalid_tenant_fails_at_once_with_no_slot_and_no_request);
    RUN_TEST(test_a_different_tenant_right_after_a_flight_makes_its_own_wire_call);
    return UNITY_END();
}
