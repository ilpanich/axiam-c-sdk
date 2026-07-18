/* D-14: a client configured with an org *slug* must still send a valid org_id
 * (and tenant_id) UUID on refresh, recovered from the access-token cookie the
 * login response set — the login response body never carries org_id. */
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

/* JWT whose payload is {"tenant_id":"tenant-uuid-abc","org_id":"org-uuid-xyz",...}. */
#define ACCESS_JWT \
    "eyJhbGciOiAiRWREU0EiLCAidHlwIjogIkpXVCJ9." \
    "eyJ0ZW5hbnRfaWQiOiAidGVuYW50LXV1aWQtYWJjIiwgIm9yZ19pZCI6ICJvcmctdXVpZC14eXoiLCAiZXhwIjogOTk5OTk5OTk5OX0." \
    "sig"

typedef struct {
    int refreshed;
    char refresh_body[4096];
} org_state_t;

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    org_state_t *st = ctx;
    if (strstr(req->url, "/auth/login")) {
        resp_fill(resp, 200,
                  "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                  "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"tenant-uuid-abc\"}}",
                  NULL);
        resp->headers = axiam_kv_append(resp->headers, "Set-Cookie",
                                        "axiam_access=" ACCESS_JWT "; Path=/; HttpOnly");
        return 0;
    }
    if (strstr(req->url, "/auth/refresh")) {
        snprintf(st->refresh_body, sizeof(st->refresh_body), "%s",
                 req->body ? req->body : "");
        st->refreshed = 1;
        resp_fill(resp, 200, "{\"expires_in\":900}", NULL);
        return 0;
    }
    /* /authz/check: 401 until the refresh completes, then allow. */
    resp_fill(resp, st->refreshed ? 200 : 401,
              st->refreshed ? "{\"allowed\":true}" : NULL, NULL);
    return 0;
}

void setUp(void) {}
void tearDown(void) {}

static void test_refresh_uses_org_id_from_token(void) {
    org_state_t st;
    memset(&st, 0, sizeof(st));

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");   /* SLUGS only — no UUIDs */
    axiam_client_config_set_org_slug(cfg, "globex");
    axiam_client_config_set_transport(cfg, fake_transport, &st);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    axiam_login_result_t lr;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &lr, &err));
    axiam_login_result_dispose(&lr);

    /* A check that 401s once drives exactly one refresh. */
    axiam_check_result_t res;
    axiam_error_kind_t k = axiam_check_access(
        c, "read", "44444444-4444-4444-4444-444444444444", NULL, NULL, &res, &err);
    axiam_check_result_dispose(&res);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);

    /* The refresh body carries the UUIDs decoded from the token, not the slugs. */
    TEST_ASSERT_NOT_NULL(strstr(st.refresh_body, "\"org_id\":\"org-uuid-xyz\""));
    TEST_ASSERT_NOT_NULL(strstr(st.refresh_body, "\"tenant_id\":\"tenant-uuid-abc\""));
    TEST_ASSERT_NULL(strstr(st.refresh_body, "globex"));

    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_refresh_uses_org_id_from_token);
    return UNITY_END();
}
