/*
 * CONTRACT.md §6.1 rules 6-10 (contract 1.51) — axiam_authenticate_device(), the
 * mTLS device login. §1.8 of the dogfooding remediation plan: this SDK's README
 * documented `POST /api/v1/auth/device` while shipping no symbol that called it;
 * this is what makes that claim true.
 *
 * Fake-transport coverage here. The "withholds a stale cookie" behaviour (rule 6)
 * needs the REAL libcurl cookie engine to be a meaningful test at all — a fake
 * transport has no cookie jar to leak from in the first place, which is exactly
 * the trap the TypeScript port's mock fell into (its "withholds" test passed even
 * with the withholding removed, because the mock intercepted above the cookie
 * layer). That test is in test_tls_server.c instead, against a real loopback TLS
 * server, observing the raw HTTP request text libcurl actually sends.
 */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

/* Not real key material -- "ZmFrZQ==" is base64 for "fake" -- and deliberately not
 * spelled "-----BEGIN [RSA/EC] PRIVATE KEY-----": the CI private-key-detection gate
 * (.github/workflows/sdk-ci-c.yml, "Fail on committed private keys") greps for that
 * literal marker with no exemption for test fixtures, so a placeholder that used it
 * would trip the same gate meant to catch a real committed key. axiam_is_pem() only
 * requires the "-----BEGIN" substring, so this placeholder still exercises the PEM
 * shape check in axiam_client_config_set_client_cert() without matching that grep. */
#define FAKE_CERT_PEM "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
#define FAKE_KEY_PEM  "-----BEGIN TEST KEY-----\nZmFrZQ==\n-----END TEST KEY-----\n"

typedef struct {
    test_recorder_t rec;
    long next_status;
    const char *next_body;
    int request_count;
    char last_authorization[256];
    int last_had_authorization;
    char last_cookie[256];
    int last_had_cookie_header; /* present at all, even if empty */
    /* An optional short QUEUE of canned responses, consumed one per call
     * before falling back to next_status/next_body -- for a test that needs
     * to distinguish a refresh call from the retried call after it. */
    long queue_status[4];
    const char *queue_body[4];
    int queue_len;
    int queue_pos;
    /* Simulates a transport-layer failure (DNS, connect refused, TLS handshake
     * rejected -- the certificate itself unrecognised by the server's TLS layer,
     * never reaching HTTP at all): axiam_authenticate_device() must report this
     * as AXIAM_ERR_NETWORK rather than crash on an uninitialised response. */
    int simulate_transport_failure;
} fake_state_t;

static fake_state_t g_fake;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    st->request_count++;
    recorder_capture(&st->rec, req);
    const char *auth = axiam_kv_get(req->headers, "Authorization");
    st->last_had_authorization = auth != NULL;
    snprintf(st->last_authorization, sizeof(st->last_authorization), "%s", auth ? auth : "");
    const char *cookie = axiam_kv_get(req->headers, "Cookie");
    st->last_had_cookie_header = cookie != NULL;
    snprintf(st->last_cookie, sizeof(st->last_cookie), "%s", cookie ? cookie : "");
    memset(resp, 0, sizeof(*resp));
    if (st->simulate_transport_failure) {
        resp->transport_err = 7; /* an arbitrary nonzero curl-shaped errno */
        resp->transport_msg = strdup("could not connect to host");
        return 1;
    }
    if (st->queue_pos < st->queue_len) {
        resp->status = st->queue_status[st->queue_pos];
        const char *body = st->queue_body[st->queue_pos];
        if (body) resp->body = strdup(body);
        st->queue_pos++;
    } else {
        resp->status = st->next_status;
        if (st->next_body) resp->body = strdup(st->next_body);
    }
    return 0;
}

static axiam_client_t *make_client_with_cert(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_client_config_set_client_cert(cfg, FAKE_CERT_PEM, FAKE_KEY_PEM));
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static axiam_client_t *make_client_without_cert(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g_fake, 0, sizeof(g_fake)); }
void tearDown(void) {}

/* ------------------------------------------------------------------------
 * Rule 7 — unreachable without a certificate, zero wire calls.
 * ---------------------------------------------------------------------- */

static void test_unreachable_without_client_cert_zero_wire_calls(void) {
    axiam_client_t *c = make_client_without_cert();
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_fake.request_count,
                                  "no client certificate -> zero wire calls");
    TEST_ASSERT_NULL(out.access_token);
    axiam_client_free(c);
}

/* The I4 twin: WITH a certificate configured, the call reaches the wire. */
static void test_reachable_with_client_cert(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "{\"access_token\":\"dev-tok\",\"token_type\":\"Bearer\","
                       "\"expires_in\":900}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_INT(1, g_fake.request_count);
    TEST_ASSERT_NOT_NULL(out.access_token);
    TEST_ASSERT_EQUAL_STRING("dev-tok", axiam_sensitive_reveal(out.access_token));
    TEST_ASSERT_EQUAL_STRING("Bearer", out.token_type);
    TEST_ASSERT_EQUAL_INT(900, (int) out.expires_in);
    axiam_device_auth_result_dispose(&out);
    axiam_client_free(c);
}

/* A transport-layer failure (never reaching HTTP status at all) is reported as
 * AXIAM_ERR_NETWORK, not treated as a 401/AuthError and not crashed on. */
static void test_transport_failure_is_reported(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.simulate_transport_failure = 1;
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(out.access_token);
    TEST_ASSERT_EQUAL_STRING("could not connect to host", err.message);
    axiam_client_free(c);
}

/* A 200 response whose body does not even parse as JSON -- distinct from "parses
 * fine but lacks access_token" below: this is cJSON_Parse() itself returning NULL. */
static void test_response_with_unparseable_body_is_refused(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "not a json object";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(out.access_token);
    axiam_client_free(c);
}

/* A 200 response with no `access_token` field is malformed -- refused, not
 * adopted as an empty credential. */
static void test_response_with_no_access_token_is_refused(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "{\"token_type\":\"Bearer\",\"expires_in\":900}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(out.access_token);
    axiam_client_free(c);
}

/* An unmapped non-401/429 status (a plain server error) goes through the
 * ordinary §2 status mapping like every other route -- rule 8 only mandates
 * the 401 case specifically. */
static void test_500_status_is_not_an_auth_error(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 500;
    g_fake.next_body = "{\"error\":\"internal\"}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(AXIAM_ERR_AUTH, k, "a plain 500 is not an auth error");
    TEST_ASSERT_NULL(out.access_token);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * Rule 6 — the request itself: POST, no body, and the path.
 * ---------------------------------------------------------------------- */

static void test_posts_no_body_to_the_device_path(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "{\"access_token\":\"t\",\"token_type\":\"Bearer\",\"expires_in\":900}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_STRING("POST", g_fake.rec.method);
    TEST_ASSERT_TRUE(strstr(g_fake.rec.url, "/api/v1/auth/device") != NULL);
    TEST_ASSERT_EQUAL_STRING("", g_fake.rec.body); /* no body */
    axiam_device_auth_result_dispose(&out);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * Rule 8 — every refusal is 401 -> AuthError; 429 is not an auth error and
 * is not retried (a single wire call either way: this route is not GET-
 * shaped retryable, so the §16 budget is 1 in both cases).
 * ---------------------------------------------------------------------- */

static void test_401_maps_to_auth_error(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 401;
    g_fake.next_body = "{\"error\":\"authentication_failed\"}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_EQUAL_INT(1, g_fake.request_count);
    TEST_ASSERT_NULL(out.access_token);
    axiam_client_free(c);
}

static void test_429_is_not_an_auth_error_and_is_not_retried(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 429;
    g_fake.next_body = "{\"error\":\"rate_limit_exceeded\"}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(AXIAM_ERR_AUTH, k,
                                  "429 must not be reported as an authentication failure");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_fake.request_count, "not retried");
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * Rule 6 — adoption: subsequent calls carry the bearer header.
 * ---------------------------------------------------------------------- */

static void test_adopted_token_rides_as_bearer_on_check_access(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "{\"access_token\":\"dev-tok\",\"token_type\":\"Bearer\","
                       "\"expires_in\":900}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_authenticate_device(c, &out, &err);
    axiam_device_auth_result_dispose(&out);

    g_fake.next_status = 200;
    g_fake.next_body = "{\"allowed\":true}";
    axiam_check_result_t res;
    axiam_check_access(c, "read", "r1", NULL, NULL, &res, &err);
    TEST_ASSERT_TRUE(g_fake.last_had_authorization);
    TEST_ASSERT_EQUAL_STRING("Bearer dev-tok", g_fake.last_authorization);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * "No refresh on the device login's 401 or a later 401."
 * ---------------------------------------------------------------------- */

/* The device login call ITSELF never enters the §9 guard on its own 401 —
 * covered by test_401_maps_to_auth_error above (exactly one wire call, no
 * POST /auth/refresh in between). This test covers the SECOND half: a LATER
 * 401, on a call made with the adopted device token, must not trigger a
 * refresh attempt either -- there is no refresh token to spend. */
static void test_later_401_on_device_credential_is_not_refreshed(void) {
    axiam_client_t *c = make_client_with_cert();
    g_fake.next_status = 200;
    g_fake.next_body = "{\"access_token\":\"dev-tok\",\"token_type\":\"Bearer\","
                       "\"expires_in\":900}";
    axiam_device_auth_result_t out;
    axiam_error_t err;
    axiam_authenticate_device(c, &out, &err);
    axiam_device_auth_result_dispose(&out);

    int before = g_fake.request_count;
    g_fake.next_status = 401; /* the token expired / was revoked server-side */
    g_fake.next_body = "{\"error\":\"authentication_failed\"}";
    axiam_check_result_t res;
    axiam_error_kind_t k = axiam_check_access(c, "read", "r1", NULL, NULL, &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    /* Exactly ONE additional wire call: the check itself. A refresh attempt
     * would have added a second (POST /auth/refresh) before the retry. */
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, g_fake.request_count,
                                  "a 401 on a device credential must not enter the "
                                  "\xc2\xa7""9 refresh guard -- there is no refresh token");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(g_fake.rec.url, ""),
                                  "sanity: a request was made");
    /* Confirm no request in this run targeted /auth/refresh at all -- the
     * single request captured above is the check itself, and request_count
     * grew by exactly one. */
    axiam_client_free(c);
}

/* A normal (cookie) session's 401, for contrast: it DOES enter the guard, so
 * the test above is meaningfully different behaviour, not a global "this
 * fake transport never refreshes" artefact. */
static void test_later_401_on_cookie_session_is_refreshed(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    g_fake.next_status = 200;
    g_fake.next_body =
        "{\"session_id\":\"s1\",\"expires_in\":900,"
        "\"user\":{\"id\":\"u1\",\"username\":\"alice\",\"email\":\"a@x.io\","
        "\"tenant_id\":\"11111111-1111-1111-1111-111111111111\"}}";
    axiam_login_result_t login_res;
    axiam_login(c, "alice", "pw", &login_res, &err);
    axiam_login_result_dispose(&login_res);

    int before = g_fake.request_count;
    /* [0] the check that gets the 401; [1] the refresh, which succeeds;
     * [2] the retried check. */
    g_fake.queue_pos = 0;
    g_fake.queue_len = 3;
    g_fake.queue_status[0] = 401; g_fake.queue_body[0] = NULL;
    g_fake.queue_status[1] = 200; g_fake.queue_body[1] = NULL;
    g_fake.queue_status[2] = 200; g_fake.queue_body[2] = "{\"allowed\":true}";
    axiam_check_result_t res;
    axiam_check_access(c, "read", "r1", NULL, NULL, &res, &err);
    /* the failed check (1) + refresh (1) + retried check (1) = 3 more requests. */
    TEST_ASSERT_EQUAL_INT(before + 3, g_fake.request_count);
    axiam_check_result_dispose(&res);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_unreachable_without_client_cert_zero_wire_calls);
    RUN_TEST(test_reachable_with_client_cert);
    RUN_TEST(test_transport_failure_is_reported);
    RUN_TEST(test_response_with_unparseable_body_is_refused);
    RUN_TEST(test_response_with_no_access_token_is_refused);
    RUN_TEST(test_500_status_is_not_an_auth_error);
    RUN_TEST(test_posts_no_body_to_the_device_path);
    RUN_TEST(test_401_maps_to_auth_error);
    RUN_TEST(test_429_is_not_an_auth_error_and_is_not_retried);
    RUN_TEST(test_adopted_token_rides_as_bearer_on_check_access);
    RUN_TEST(test_later_401_on_device_credential_is_not_refreshed);
    RUN_TEST(test_later_401_on_cookie_session_is_refreshed);
    return UNITY_END();
}
