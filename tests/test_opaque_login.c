/* axiam_login_opaque / axiam_opaque_enrollment end to end (src/client.c,
 * CONTRACT.md §23).
 *
 * The protocol is `libaxiam_opaque_ffi`'s and the binding is covered by
 * tests/test_opaque_binding.c. What is tested here is the part the SDK owns:
 * what goes on the wire — and, more importantly, what does NOT — which failures
 * are credential failures and which are configuration facts, and that a failed
 * credential check never reaches login/finish.
 *
 * The fake transport is scriptable rather than protocol-speaking, which is a
 * real change from the SRP suite it replaces: that fake held a verifier and
 * computed B, M1 and M2 from whatever A the client sent, because a client that
 * got u or the padding wrong had to fail against it. There is no arithmetic
 * here to get wrong — §23.1 puts it all inside the shared library — so the
 * assertions that matter are about request bodies, error taxonomy and request
 * COUNTS.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"
#include "opaque_fake.h"

fake_opaque_t g_fake_opaque;

#define TEST_USER "alice"
#define WIRE_KE2 "6b6532"
#define WIRE_REGISTRATION_RESPONSE "726573703a"

/* Minted per run; nothing here depends on the value, and a literal that reads
 * like a credential is a finding for every secret scanner. */
static char g_password[32];

typedef struct {
    test_recorder_t rec;

    long login_start_status;
    long login_finish_status;
    long register_start_status;
    int mfa_required;
    int mfa_setup_required;
    int omit_ke2;
    int transport_error_on_start;
    const char *ksf; /* "argon2id" (default) or "scrypt" */

    int login_start_count;
    int login_finish_count;
    int register_start_count;

    char login_start_body[2048];
    char login_finish_body[2048];
    char register_start_body[2048];
} fake_state_t;

static fake_state_t g_fake;

static void ksf_fields(char *buf, size_t n) {
    if (g_fake.ksf && strcmp(g_fake.ksf, "scrypt") == 0) {
        snprintf(buf, n, "\"ksf\":\"scrypt\",\"log_n\":15,\"r\":8,\"p\":1");
    } else {
        snprintf(buf, n, "\"ksf\":\"%s\",\"memory_kib\":19456,\"iterations\":2,"
                         "\"parallelism\":1",
                 g_fake.ksf ? g_fake.ksf : AXIAM_OPAQUE_KSF_ARGON2ID);
    }
}

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void)ctx;
    recorder_capture(&g_fake.rec, req);
    const char *url = req->url ? req->url : "";
    char ksf[160];

    if (strstr(url, "/auth/opaque/login/start")) {
        g_fake.login_start_count++;
        snprintf(g_fake.login_start_body, sizeof(g_fake.login_start_body), "%s",
                 req->body ? req->body : "");
        if (g_fake.transport_error_on_start) {
            memset(resp, 0, sizeof(*resp));
            resp->status = 0;
            resp->transport_err = 7;
            resp->transport_msg = strdup("Couldn't connect");
            return 1;
        }
        if (g_fake.login_start_status && g_fake.login_start_status != 200) {
            resp_fill(resp, g_fake.login_start_status, "{}", NULL);
            return 0;
        }
        ksf_fields(ksf, sizeof(ksf));
        char body[512];
        if (g_fake.omit_ke2) {
            snprintf(body, sizeof(body), "{\"opaque_session\":\"handle-42\",%s}", ksf);
        } else {
            snprintf(body, sizeof(body),
                     "{\"opaque_session\":\"handle-42\",\"ke2\":\"" WIRE_KE2 "\",%s}", ksf);
        }
        resp_fill(resp, 200, body, NULL);
        return 0;
    }

    if (strstr(url, "/auth/opaque/login/finish")) {
        g_fake.login_finish_count++;
        snprintf(g_fake.login_finish_body, sizeof(g_fake.login_finish_body), "%s",
                 req->body ? req->body : "");
        if (g_fake.mfa_setup_required) {
            resp_fill(resp, 403,
                      "{\"mfa_setup_required\":true,\"setup_token\":\"setup-1\"}", NULL);
            return 0;
        }
        if (g_fake.login_finish_status && g_fake.login_finish_status != 200) {
            resp_fill(resp, g_fake.login_finish_status, "{}", NULL);
            return 0;
        }
        if (g_fake.mfa_required) {
            resp_fill(resp, 202,
                      "{\"mfa_required\":true,\"challenge_token\":\"opaque-mfa-challenge\"}",
                      NULL);
            return 0;
        }
        resp_fill(resp, 200,
                  "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
                  "\"expires_in\":900,"
                  "\"user\":{\"id\":\"u-1\",\"username\":\"" TEST_USER "\","
                  "\"email\":\"a@x.io\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}}",
                  "csrf-abc");
        return 0;
    }

    if (strstr(url, "/auth/opaque/register/start")) {
        g_fake.register_start_count++;
        snprintf(g_fake.register_start_body, sizeof(g_fake.register_start_body), "%s",
                 req->body ? req->body : "");
        if (g_fake.register_start_status && g_fake.register_start_status != 200) {
            resp_fill(resp, g_fake.register_start_status, "{}", NULL);
            return 0;
        }
        ksf_fields(ksf, sizeof(ksf));
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"opaque_session\":\"reg-handle\",\"registration_response\":\""
                 WIRE_REGISTRATION_RESPONSE "\",%s}", ksf);
        resp_fill(resp, 200, body, NULL);
        return 0;
    }

    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) {
    memset(&g_fake, 0, sizeof(g_fake));
    fake_opaque_install();
    unsigned char raw[8];
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)(rand() & 0xff);
    size_t at = (size_t)snprintf(g_password, sizeof(g_password), "correct-");
    for (size_t i = 0; i < sizeof(raw) && at + 2 < sizeof(g_password); i++, at += 2)
        snprintf(g_password + at, sizeof(g_password) - at, "%02x", raw[i]);
}

void tearDown(void) {
    axiam_opaque_native_reset_for_tests();
}

/* ------------------------------------------------------------------------
 * What crosses the wire
 * ---------------------------------------------------------------------- */

static void test_login_start_carries_ke1_and_no_password_field(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    /* The entire point of the exchange. A body that still carried a password
     * would be SRP's failure mode with extra steps. */
    TEST_ASSERT_NULL(strstr(g_fake.login_start_body, "\"password\""));
    TEST_ASSERT_NOT_NULL(strstr(g_fake.login_start_body, "\"username_or_email\":\"" TEST_USER "\""));
    TEST_ASSERT_NOT_NULL(strstr(g_fake.login_start_body,
                                "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));

    char expected[128];
    snprintf(expected, sizeof(expected), "\"ke1\":\"ke1:%s\"", g_password);
    TEST_ASSERT_NOT_NULL(strstr(g_fake.login_start_body, expected));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_register_start_names_no_account_at_all(void) {
    axiam_client_t *c = make_client();
    axiam_opaque_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_opaque_enrollment(c, g_password, &e, &err));

    TEST_ASSERT_EQUAL_STRING("reg-handle", e.opaque_session);
    TEST_ASSERT_EQUAL_INT(0, strncmp(e.registration_record, "record:", 7));

    TEST_ASSERT_NULL(strstr(g_fake.register_start_body, "\"password\""));
    /* No username either: a record binds to a credential identifier the SERVER
     * chooses, which is why a later rename cannot invalidate one — and why the
     * SRP enrolment's `identity` argument has no successor. */
    TEST_ASSERT_NULL(strstr(g_fake.register_start_body, "\"username_or_email\""));
    TEST_ASSERT_NOT_NULL(strstr(g_fake.register_start_body,
                                "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));

    char expected[128];
    snprintf(expected, sizeof(expected), "\"registration_request\":\"req:%s\"", g_password);
    TEST_ASSERT_NOT_NULL(strstr(g_fake.register_start_body, expected));

    axiam_opaque_enrollment_dispose(&e);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_login_finish_echoes_the_session_handle_the_server_issued(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_NOT_NULL(strstr(g_fake.login_finish_body, "\"opaque_session\":\"handle-42\""));
    char expected[256];
    snprintf(expected, sizeof(expected), "\"ke3\":\"ke3:%s:" WIRE_KE2 ":", g_password);
    TEST_ASSERT_NOT_NULL(strstr(g_fake.login_finish_body, expected));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_the_server_named_ksf_is_the_one_used(void) {
    /* §23.4 rule 2: never local defaults. A credential enrolled under one cost
     * keeps working after a tenant raises its policy, so a client that guessed
     * would fail against a record that is perfectly good. */
    g_fake.ksf = "scrypt";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    /* scrypt handles are tagged 0xb....; argon2id's are 0xa..... */
    TEST_ASSERT_EQUAL_UINT(0xB0000u + 15u + 8u + 1u, g_fake_opaque.last_ksf_tag);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_an_absent_cost_reaches_the_library_absent(void) {
    /* The argon2id response names no log_n/r/p at all. Reading those as 0 would
     * be §23.4 rule 5's failure; the tag proves the argon2id branch ran with
     * the three costs the server DID name. */
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_EQUAL_UINT(0xA0000u + 19456u + 2u + 1u, g_fake_opaque.last_ksf_tag);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * Results — the union axiam_login() fills, filled identically
 * ---------------------------------------------------------------------- */

static void test_a_successful_login_returns_what_login_returns(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_EQUAL_INT(1, res.authenticated);
    TEST_ASSERT_EQUAL_STRING("u-1", res.user_id);
    TEST_ASSERT_EQUAL_STRING(AXIAM_TEST_TENANT_ID, res.tenant_id);
    TEST_ASSERT_EQUAL_INT(1, g_fake.login_start_count);
    TEST_ASSERT_EQUAL_INT(1, g_fake.login_finish_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_the_mfa_required_branch_survives_the_opaque_path(void) {
    /* One result handler must serve both login paths, so the second phase has
     * to arrive here exactly as it does from axiam_login(). */
    g_fake.mfa_required = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_EQUAL_INT(1, res.mfa_required);
    TEST_ASSERT_EQUAL_INT(0, res.authenticated);
    TEST_ASSERT_NOT_NULL(res.challenge_token);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_the_mfa_setup_branch_survives_the_opaque_path_too(void) {
    /* A 403 whose body says mfa_setup_required is the login FLOW, not an
     * authorization denial. axiam_login() disambiguates on the body shape and
     * so must this, or the one result handler §23.1 promises has a hole in it. */
    g_fake.mfa_setup_required = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_EQUAL_INT(1, res.mfa_setup_required);
    TEST_ASSERT_NOT_NULL(res.setup_token);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * Failures
 * ---------------------------------------------------------------------- */

static void test_a_disabled_tenant_is_a_network_error_a_caller_can_fall_back_from(void) {
    /* A 404 is a property of the tenant, not of the credentials. As an auth
     * error it would be shown as "invalid password" and send a user to reset a
     * working one, while stopping a fallback to axiam_login(). */
    g_fake.login_start_status = 404;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_NOT_NULL(strstr(err.message, "opaque_mode is disabled"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);
    TEST_ASSERT_EQUAL_INT(0, res.authenticated);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_enrolment_reports_a_disabled_tenant_the_same_way(void) {
    g_fake.register_start_status = 404;
    axiam_client_t *c = make_client();
    axiam_opaque_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_opaque_enrollment(c, g_password, &e, &err));

    TEST_ASSERT_NOT_NULL(strstr(err.message, "opaque_mode is disabled"));
    TEST_ASSERT_NULL(e.registration_record);

    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_a_401_at_login_start_is_an_auth_error(void) {
    g_fake.login_start_status = 401;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_a_wrong_password_never_reaches_login_finish(void) {
    /* §23.4 rule 7. The envelope failing to open IS the authentication check;
     * sending anything afterwards would ask the server to decide something the
     * client has already decided. */
    g_fake_opaque.fail[FAKE_LOGIN_FINISH] = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_EQUAL_INT(1, g_fake.login_start_count);
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);
    TEST_ASSERT_EQUAL_INT(0, res.authenticated);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "invalid credentials"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_an_unsupported_ksf_is_a_configuration_error_not_a_bad_password(void) {
    g_fake.ksf = "bcrypt";
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_NOT_NULL(strstr(err.message, "bcrypt"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);
    /* The exchange was abandoned rather than spent, and login_opaque's close()
     * must have released it — otherwise a misconfigured tenant leaks once per
     * login attempt. */
    TEST_ASSERT_FALSE(fake_opaque_leaked());

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_start_response_without_ke2_is_a_malformed_response(void) {
    g_fake.omit_ke2 = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_NOT_NULL(strstr(err.message, "no `ke2`"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_a_transport_failure_on_the_start_is_a_network_error(void) {
    g_fake.transport_error_on_start = 1;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_finish_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_a_5xx_at_login_finish_is_a_network_error(void) {
    g_fake.login_finish_status = 503;
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_EQUAL_INT(1, g_fake.login_finish_count);
    TEST_ASSERT_EQUAL_INT(0, res.authenticated);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_an_absent_library_is_reported_before_any_request_is_sent(void) {
    axiam_opaque_native_set_for_tests(NULL);
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_login_opaque(c, TEST_USER, g_password, &res, &err));

    TEST_ASSERT_NOT_NULL(strstr(err.message, "libaxiam_opaque_ffi"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.login_start_count);
    TEST_ASSERT_EQUAL_INT(0, g_fake.rec.request_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_null_arguments_are_refused_without_a_request(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_opaque_enrollment_t e;
    axiam_error_t err;

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_opaque(NULL, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_opaque(c, NULL, g_password, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_opaque(c, TEST_USER, NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_opaque_enrollment(NULL, g_password, &e, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_opaque_enrollment(c, NULL, &e, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_opaque_enrollment(c, g_password, NULL, &err));
    TEST_ASSERT_EQUAL_INT(0, g_fake.rec.request_count);

    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

static void test_a_closed_client_refuses_both_operations(void) {
    /* §18: close() is terminal, and neither path may open a native exchange
     * whose release nobody is going to reach. */
    axiam_client_t *c = make_client();
    axiam_client_close(c);

    axiam_login_result_t res;
    axiam_opaque_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_login_opaque(c, TEST_USER, g_password, &res, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, axiam_opaque_enrollment(c, g_password, &e, &err));
    TEST_ASSERT_EQUAL_INT(0, g_fake.rec.request_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    TEST_ASSERT_FALSE(fake_opaque_leaked());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_login_start_carries_ke1_and_no_password_field);
    RUN_TEST(test_register_start_names_no_account_at_all);
    RUN_TEST(test_login_finish_echoes_the_session_handle_the_server_issued);
    RUN_TEST(test_the_server_named_ksf_is_the_one_used);
    RUN_TEST(test_an_absent_cost_reaches_the_library_absent);

    RUN_TEST(test_a_successful_login_returns_what_login_returns);
    RUN_TEST(test_the_mfa_required_branch_survives_the_opaque_path);
    RUN_TEST(test_the_mfa_setup_branch_survives_the_opaque_path_too);

    RUN_TEST(test_a_disabled_tenant_is_a_network_error_a_caller_can_fall_back_from);
    RUN_TEST(test_enrolment_reports_a_disabled_tenant_the_same_way);
    RUN_TEST(test_a_401_at_login_start_is_an_auth_error);
    RUN_TEST(test_a_wrong_password_never_reaches_login_finish);
    RUN_TEST(test_an_unsupported_ksf_is_a_configuration_error_not_a_bad_password);
    RUN_TEST(test_a_start_response_without_ke2_is_a_malformed_response);
    RUN_TEST(test_a_transport_failure_on_the_start_is_a_network_error);
    RUN_TEST(test_a_5xx_at_login_finish_is_a_network_error);
    RUN_TEST(test_an_absent_library_is_reported_before_any_request_is_sent);
    RUN_TEST(test_null_arguments_are_refused_without_a_request);
    RUN_TEST(test_a_closed_client_refuses_both_operations);
    return UNITY_END();
}
