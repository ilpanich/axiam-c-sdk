#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

#define N_THREADS 8

typedef struct {
    pthread_mutex_t mtx;
    int refreshed;
    int refresh_calls;
} fake_state_t;

static fake_state_t g;
static pthread_barrier_t g_barrier;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    if (strstr(req->url, "/auth/login")) {
        resp_fill(resp, 200,
                  "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                  "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}", NULL);
        return 0;
    }
    if (strstr(req->url, "/auth/refresh")) {
        pthread_mutex_lock(&st->mtx);
        st->refresh_calls++;
        pthread_mutex_unlock(&st->mtx);
        usleep(60 * 1000); /* widen the coalescing window */
        pthread_mutex_lock(&st->mtx);
        st->refreshed = 1;
        pthread_mutex_unlock(&st->mtx);
        resp_fill(resp, 200, "{\"expires_in\":900}", NULL);
        return 0;
    }
    /* /authz/check */
    int refreshed;
    pthread_mutex_lock(&st->mtx);
    refreshed = st->refreshed;
    pthread_mutex_unlock(&st->mtx);
    if (refreshed) {
        resp_fill(resp, 200, "{\"allowed\":true}", NULL);
    } else {
        resp_fill(resp, 401, NULL, NULL);
    }
    return 0;
}

static axiam_client_t *g_client;

static void *worker(void *arg) {
    (void)arg;
    pthread_barrier_wait(&g_barrier);
    axiam_check_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_check_access(
        g_client, "users:get", "44444444-4444-4444-4444-444444444444",
        NULL, NULL, &res, &err);
    axiam_check_result_dispose(&res);
    return (void *)(intptr_t)k;
}

void setUp(void) {
    memset(&g, 0, sizeof(g));
    pthread_mutex_init(&g.mtx, NULL);
}
void tearDown(void) { pthread_mutex_destroy(&g.mtx); }

static void test_single_flight_exactly_one_refresh(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, &g);
    axiam_error_t err;
    g_client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(g_client);

    /* Establish a session so 401s trigger refresh. */
    axiam_login_result_t lr;
    axiam_login(g_client, "a", "b", &lr, &err);
    axiam_login_result_dispose(&lr);

    pthread_barrier_init(&g_barrier, NULL, N_THREADS);
    pthread_t th[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < N_THREADS; i++) {
        void *r;
        pthread_join(th[i], &r);
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, (int)(intptr_t)r);
    }
    pthread_barrier_destroy(&g_barrier);

    /* §9: exactly one refresh despite N concurrent 401s. */
    TEST_ASSERT_EQUAL_INT(1, g.refresh_calls);
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)axiam_client_refresh_count(g_client));

    axiam_client_free(g_client);
    g_client = NULL;
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_single_flight_exactly_one_refresh);
    return UNITY_END();
}
