/* Phase D1: src/client.c mock-transport failure sweep.
 *
 * A single shared `failing_transport` (rc=1, resp->status=0, like a hard
 * connect failure) drives the network-failure branch of raw_get,
 * perform_refresh, verify_mfa and logout in one place. Plus: NULL-arg
 * guards, the slug-only axiam_refresh AUTH error (no UUIDs resolved yet),
 * single-flight follower error propagation, the post-refresh authz retry
 * failure branch, and json_get_long's non-number fallback.
 */
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

/* ---- D1: shared failing transport (rc=1 / status=0) ---- */
static int failing_transport(void *ctx, const axiam_http_request_t *req,
                             axiam_http_response_t *resp) {
    (void)ctx; (void)req;
    memset(resp, 0, sizeof(*resp));
    resp->status = 0;
    resp->transport_err = 7;
    resp->transport_msg = strdup("Couldn't connect to host");
    return 1;
}

static axiam_client_t *make_uuid_client(axiam_transport_fn fn, void *ctx) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fn, ctx);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

typedef struct { long status; } status_state_t;
static int status_transport(void *ctx, const axiam_http_request_t *req,
                            axiam_http_response_t *resp) {
    (void)req;
    status_state_t *st = ctx;
    resp_fill(resp, st->status, NULL, NULL);
    return 0;
}

void setUp(void) {}
void tearDown(void) {}

/* raw_get: transport failure -> AXIAM_ERR_NETWORK (src/client.c:155-157). */
static void test_raw_get_transport_failure(void) {
    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    char *body = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "connect"));
    axiam_client_free(c);
}

/* raw_get: non-2xx/non-network HTTP status maps through
 * axiam_error_kind_from_http_status (src/client.c:162-163). */
static void test_raw_get_error_status(void) {
    status_state_t st = { .status = 404 };
    axiam_client_t *c = make_uuid_client(status_transport, &st);
    char *body = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(body);
    axiam_client_free(c);
}

/* raw_get: NULL-arg guards (src/client.c:147-150). */
static void test_raw_get_null_guards(void) {
    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    char *body = (char *)0x1;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_raw_get(NULL, "/x", &body, &err));
    TEST_ASSERT_NULL(body);
    body = (char *)0x1;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_raw_get(c, NULL, &body, &err));
    TEST_ASSERT_NULL(body);
    axiam_client_free(c);
}

/* perform_refresh transport failure (src/client.c:193-195), reached through
 * axiam_refresh() with UUID tenant/org configured directly (no login needed). */
static void test_refresh_transport_failure(void) {
    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    axiam_error_t err;
    axiam_error_kind_t k = axiam_refresh(c, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "connect"));
    axiam_client_free(c);
}

/* Slug-only client (no UUIDs, never logged in) -> axiam_build_refresh_body
 * cannot build a body -> AXIAM_ERR_AUTH (src/client.c:184,186). */
static void test_refresh_slug_only_is_auth_error(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "globex");
    axiam_client_config_set_transport(cfg, failing_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    axiam_error_kind_t k = axiam_refresh(c, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "tenant_id and org_id"));
    axiam_client_free(c);
}

/* verify_mfa transport failure (src/client.c:424-427) + NULL guard (414-415). */
static void test_verify_mfa_transport_failure_and_null_guard(void) {
    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_verify_mfa(c, "chal", "123456", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    axiam_login_result_dispose(&res);

    k = axiam_verify_mfa(NULL, "chal", "123456", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    axiam_login_result_dispose(&res);

    axiam_client_free(c);
}

/* login NULL guard (src/client.c:388-389). */
static void test_login_null_guard(void) {
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login(NULL, "a", "b", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    axiam_login_result_dispose(&res);
}

/* refresh NULL guard (src/client.c:437-438). */
static void test_refresh_null_guard(void) {
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_refresh(NULL, &err));
}

/* logout: NULL guard (446-447), transport failure (453-455), error status (462-463). */
static void test_logout_null_guard_and_failures(void) {
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_logout(NULL, &err));

    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_logout(c, &err));
    axiam_client_free(c);
}

static void test_logout_error_status(void) {
    status_state_t st = { .status = 500 };
    axiam_client_t *c = make_uuid_client(status_transport, &st);
    axiam_error_t err;
    axiam_error_kind_t k = axiam_logout(c, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    axiam_client_free(c);
}

/* check_access / batch_check NULL / invalid-arg guards (539-540, 569-570). */
static void test_check_access_and_batch_null_guards(void) {
    axiam_client_t *c = make_uuid_client(failing_transport, NULL);
    axiam_check_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_check_access(NULL, "a", "r", NULL, NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_check_access(c, NULL, "r", NULL, NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_check_access(c, "a", NULL, NULL, NULL, &res, &err));

    axiam_check_result_t results[1];
    size_t count = 999;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_batch_check(NULL, NULL, 0, results, &count, &err));
    TEST_ASSERT_EQUAL_UINT(0, count);
    /* n > 0 but checks == NULL. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_batch_check(c, NULL, 1, results, &count, &err));
    /* out_results == NULL. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_batch_check(c, NULL, 0, NULL, &count, &err));

    axiam_client_free(c);
}

/* json_get_long: non-number "expires_in" falls back to 0 (src/client.c:251). */
typedef struct { const char *body; } body_state_t;
static int body_transport(void *ctx, const axiam_http_request_t *req, axiam_http_response_t *resp) {
    (void)req;
    body_state_t *b = ctx;
    resp_fill(resp, 200, b->body, NULL);
    return 0;
}

static void test_json_get_long_non_number_falls_back_to_zero(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");

    body_state_t bst = { .body =
        "{\"session_id\":\"s\",\"expires_in\":\"not-a-number\","
        "\"user\":{\"id\":\"u\",\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}" };
    axiam_client_config_set_transport(cfg, body_transport, &bst);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    axiam_login_result_t res;
    axiam_error_kind_t k = axiam_login(c, "a", "b", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_INT(0, (int)res.expires_in);
    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

/* ---- post-refresh authz retry failure (src/client.c:512-515) ---- */
typedef struct {
    int authz_calls;
} retry_fail_state_t;
static retry_fail_state_t g_retry;

static int retry_fail_transport(void *ctx, const axiam_http_request_t *req,
                                axiam_http_response_t *resp) {
    retry_fail_state_t *st = ctx;
    if (strstr(req->url, "/auth/login")) {
        resp_fill(resp, 200,
                  "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                  "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}", NULL);
        return 0;
    }
    if (strstr(req->url, "/auth/refresh")) {
        resp_fill(resp, 200, "{\"expires_in\":900}", NULL);
        return 0;
    }
    /* /authz/check: 401 the first time (triggers refresh+retry), then the
     * retried call fails at the transport level. */
    st->authz_calls++;
    if (st->authz_calls == 1) {
        resp_fill(resp, 401, NULL, NULL);
        return 0;
    }
    memset(resp, 0, sizeof(*resp));
    resp->status = 0;
    resp->transport_err = 7;
    resp->transport_msg = strdup("Couldn't connect to host");
    return 1;
}

static void test_authz_post_refresh_retry_transport_failure(void) {
    memset(&g_retry, 0, sizeof(g_retry));
    axiam_client_t *c = make_uuid_client(retry_fail_transport, &g_retry);

    axiam_login_result_t lr;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    axiam_check_result_t res;
    axiam_error_kind_t k = axiam_check_access(
        c, "read", "44444444-4444-4444-4444-444444444444", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_EQUAL_INT(2, g_retry.authz_calls);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

/* ---- single-flight follower error propagation (src/client.c:221) ---- */
#define N_FOLLOWERS 6

typedef struct {
    pthread_mutex_t mtx;
    int refresh_calls;
} follower_err_state_t;

static follower_err_state_t g_ferr;
static pthread_barrier_t g_ferr_barrier;
static axiam_client_t *g_ferr_client;

static int follower_err_transport(void *ctx, const axiam_http_request_t *req,
                                  axiam_http_response_t *resp) {
    (void)req;
    follower_err_state_t *st = ctx;
    pthread_mutex_lock(&st->mtx);
    st->refresh_calls++;
    pthread_mutex_unlock(&st->mtx);
    usleep(60 * 1000); /* widen the coalescing window so followers pile up */
    /* Every refresh call fails (§9.3: 401 -> AuthError, no retry). */
    resp_fill(resp, 401, NULL, NULL);
    return 0;
}

static void *follower_worker(void *arg) {
    (void)arg;
    pthread_barrier_wait(&g_ferr_barrier);
    axiam_error_t err;
    return (void *)(intptr_t)axiam_refresh(g_ferr_client, &err);
}

static void test_single_flight_follower_error_propagation(void) {
    memset(&g_ferr, 0, sizeof(g_ferr));
    pthread_mutex_init(&g_ferr.mtx, NULL);
    g_ferr_client = make_uuid_client(follower_err_transport, &g_ferr);

    pthread_barrier_init(&g_ferr_barrier, NULL, N_FOLLOWERS);
    pthread_t th[N_FOLLOWERS];
    for (int i = 0; i < N_FOLLOWERS; i++)
        pthread_create(&th[i], NULL, follower_worker, NULL);
    for (int i = 0; i < N_FOLLOWERS; i++) {
        void *r;
        pthread_join(th[i], &r);
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, (int)(intptr_t)r);
    }
    pthread_barrier_destroy(&g_ferr_barrier);

    /* Exactly one leader performed the transport call despite N concurrent
     * refreshes, and every follower observed the leader's error (§9). */
    TEST_ASSERT_EQUAL_INT(1, g_ferr.refresh_calls);

    axiam_client_free(g_ferr_client);
    g_ferr_client = NULL;
    pthread_mutex_destroy(&g_ferr.mtx);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_raw_get_transport_failure);
    RUN_TEST(test_raw_get_error_status);
    RUN_TEST(test_raw_get_null_guards);
    RUN_TEST(test_refresh_transport_failure);
    RUN_TEST(test_refresh_slug_only_is_auth_error);
    RUN_TEST(test_verify_mfa_transport_failure_and_null_guard);
    RUN_TEST(test_login_null_guard);
    RUN_TEST(test_refresh_null_guard);
    RUN_TEST(test_logout_null_guard_and_failures);
    RUN_TEST(test_logout_error_status);
    RUN_TEST(test_check_access_and_batch_null_guards);
    RUN_TEST(test_json_get_long_non_number_falls_back_to_zero);
    RUN_TEST(test_authz_post_refresh_retry_transport_failure);
    RUN_TEST(test_single_flight_follower_error_propagation);
    return UNITY_END();
}
