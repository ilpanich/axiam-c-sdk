/* Regression test for ilpanich/axiam-c-sdk#91: the vendored cJSON kept one process-global
 * error record that every parse reset and every failed parse overwrote, so concurrent token
 * verification was a C data race. The assertions below are ordinary functional ones; the race
 * itself is reported by ThreadSanitizer (build with -fsanitize=thread, see the `sanitizers` job
 * in .github/workflows/sdk-ci-c.yml), which makes the process exit non-zero. */
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "cJSON.h"
#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

#define N_THREADS 8
#define N_ROUNDS 200

static const char *g_jwks_body;
static char *g_token;
static char *g_bad_token;
static axiam_client_t *g_client;
static pthread_barrier_t g_barrier;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void)ctx;
    if (strstr(req->url, "/oauth2/jwks")) {
        resp_fill(resp, 200, g_jwks_body, NULL);
        return 0;
    }
    resp_fill(resp, 404, NULL, NULL);
    return 0;
}

void setUp(void) {}
void tearDown(void) {}

static void *worker(void *arg) {
    intptr_t failures = 0;
    (void)arg;
    pthread_barrier_wait(&g_barrier);
    for (int i = 0; i < N_ROUNDS; i++) {
        char *claims = NULL;
        axiam_error_t err;
        if (axiam_jwt_verify(g_client, g_token, &claims, &err) != AXIAM_OK) failures++;
        free(claims);
        claims = NULL;
        if (axiam_jwt_verify(g_client, g_bad_token, &claims, &err) == AXIAM_OK) failures++;
        free(claims);
        /* A failing parse is the path that used to write the shared error record. */
        cJSON *j = cJSON_Parse("{\"a\":");
        if (j != NULL) { failures++; cJSON_Delete(j); }
        j = cJSON_ParseWithLength("{\"a\":1}", 7);
        if (j == NULL) failures++;
        cJSON_Delete(j);
    }
    return (void *)failures;
}

static void test_concurrent_parse_and_verify(void) {
    char payload[256];
    char *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", test_claims(payload, sizeof(payload), "user-1", NULL),
                                      &g_token, &jwks));
    g_jwks_body = jwks;
    g_bad_token = strdup(g_token);
    TEST_ASSERT_NOT_NULL(g_bad_token);
    /* Corrupt the last signature character so the token is a well-formed but forged JWT. */
    size_t n = strlen(g_bad_token);
    g_bad_token[n - 2] = (g_bad_token[n - 2] == 'A') ? 'B' : 'A';

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    g_client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(g_client);

    /* Warm the JWKS cache so the workers only parse and verify. */
    char *claims = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(g_client, g_token, &claims, &err));
    free(claims);

    pthread_t th[N_THREADS];
    TEST_ASSERT_EQUAL_INT(0, pthread_barrier_init(&g_barrier, NULL, N_THREADS));
    int started = 0;
    for (int i = 0; i < N_THREADS; i++) {
        if (pthread_create(&th[i], NULL, worker, NULL) != 0) break;
        started++;
    }
    if (started != N_THREADS) {
        /* The started workers are parked on the barrier, which never fills. pthread_barrier_wait is
         * not a cancellation point, so they can be neither cancelled nor joined: detach them, fail,
         * and let process exit reclaim them (never joining is what keeps this path from hanging). */
        for (int i = 0; i < started; i++) pthread_detach(th[i]);
        TEST_FAIL_MESSAGE("pthread_create failed");
    }
    intptr_t failures = 0;
    for (int i = 0; i < N_THREADS; i++) {
        void *rv;
        pthread_join(th[i], &rv);
        failures += (intptr_t)rv;
    }
    pthread_barrier_destroy(&g_barrier);
    TEST_ASSERT_EQUAL_INT(0, (int)failures);

    axiam_client_free(g_client);
    free(g_token);
    free(g_bad_token);
    free(jwks);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_concurrent_parse_and_verify);
    return UNITY_END();
}
