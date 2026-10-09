/*
 * Allocation-failure sweep over the contract 1.53 – 1.58 additions: §28.12
 * (src/registration.c), the §29 – §32 helpers (src/management_helpers.c), the §32.7
 * receiver (src/ssf.c) and §33 CIBA (src/oidc_ciba.c).
 *
 * The technique is tests/test_alloc_failures.c's: link-time --wrap of malloc/calloc/
 * realloc (this target only), arm the Nth allocation to fail, drive the REAL call graph,
 * and require that it reports failure — or, for an allocation after the point of no
 * return, succeeds — without crashing, double-freeing or (under ASan/valgrind) leaking.
 * Every one of these functions checks each allocation, and those arms run nowhere else.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/ciba.h"
#include "axiam/management_helpers.h"
#include "axiam/registration.h"
#include "axiam/ssf.h"
#include "cJSON.h"
#include "internal.h"
#include "jwt_fixture.h"
#include "test_util.h"

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

static long g_fail_at = -1;
static long g_call_count = 0;

static int alloc_should_fail(void) {
    g_call_count++;
    if (g_fail_at > 0 && g_call_count == g_fail_at) {
        g_fail_at = -1; /* one-shot */
        return 1;
    }
    return 0;
}

void *__wrap_malloc(size_t size) {
    if (alloc_should_fail()) return NULL;
    return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size) {
    if (alloc_should_fail()) return NULL;
    return __real_calloc(nmemb, size);
}

void *__wrap_realloc(void *ptr, size_t size) {
    if (alloc_should_fail()) return NULL;
    return __real_realloc(ptr, size);
}

static void arm(long n) {
    g_fail_at = n;
    g_call_count = 0;
}

static void disarm(void) {
    g_fail_at = -1;
    g_call_count = 0;
}

/* Deep enough for the longest call graph here (a poll that verifies a SET). */
#define DEPTH 160

/* ------------------------------------------------------------------ */
/* One fake server for every route                                    */
/* ------------------------------------------------------------------ */

#define BASE "https://api.test"
#define ISSUER "https://issuer.test"

static const char *g_poll_reply;
static const char *g_jwks;
static char g_registration[512];
static char g_tokens[4096];
static char g_initiate[256];

static int fake_transport(void *ctx, const axiam_http_request_t *req, axiam_http_response_t *resp) {
    (void) ctx;
    memset(resp, 0, sizeof *resp);
    const char *url = req->url ? req->url : "";
    const char *body = "{}";
    if (strstr(url, "/.well-known/openid-configuration"))
        body = "{\"issuer\":\"" ISSUER "\",\"authorization_endpoint\":\"" BASE "/oauth2/authorize\","
               "\"token_endpoint\":\"" BASE "/oauth2/token\",\"jwks_uri\":\"" BASE "/oauth2/jwks\","
               "\"backchannel_authentication_endpoint\":\"" BASE "/oauth2/bc-authorize\","
               "\"backchannel_token_delivery_modes_supported\":[\"poll\"],"
               "\"backchannel_authentication_request_signing_alg_values_supported\":[\"EdDSA\"],"
               "\"backchannel_user_code_parameter_supported\":false}";
    else if (strstr(url, "/oauth2/jwks") || strstr(url, "/ssf-jwks"))
        body = g_jwks ? g_jwks : "{\"keys\":[]}";
    else if (strstr(url, "/oauth2/register/"))
        body = g_registration;
    else if (strstr(url, "/oauth2/bc-authorize"))
        body = g_initiate;
    else if (strstr(url, "/oauth2/token"))
        body = g_tokens;
    else if (strstr(url, "/ssf/v1/poll/"))
        body = g_poll_reply ? g_poll_reply : "{\"sets\":{}}";
    resp->status = 200;
    resp->body = strdup(body);
    return 0;
}

static void no_sleep(void *ctx, long ms) {
    (void) ctx;
    (void) ms;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, "c1");
    char secret[33];
    unsigned char raw[16];
    RAND_bytes(raw, (int) sizeof raw);
    for (int i = 0; i < 16; i++) snprintf(secret + 2 * i, 3, "%02x", raw[i]);
    axiam_client_config_set_oidc_client_secret(cfg, secret);
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    c->sleep_fn = no_sleep;
    return c;
}

void setUp(void) { disarm(); }
void tearDown(void) { disarm(); }

/* ---- §28.12 --------------------------------------------------------------------- */

static void test_registration_survives_oom(void) {
    snprintf(g_registration, sizeof g_registration,
             "{\"client_id\":\"c1\",\"client_name\":\"n\",\"redirect_uris\":[\"https://a/cb\"],"
             "\"grant_types\":[\"x\"],\"response_types\":[\"code\"],\"scope\":\"openid\","
             "\"token_endpoint_auth_method\":\"none\",\"registration_client_uri\":\"u\","
             "\"jwks\":{\"keys\":[]},\"jwks_uri\":\"https://a/j\",\"client_secret\":\"s\","
             "\"registration_access_token\":\"t\",\"x_extra\":1}");
    axiam_client_t *c = make_client();
    axiam_sensitive_t *token = axiam_sensitive_new("tok");
    for (long n = 1; n <= DEPTH; n++) {
        axiam_error_t err;
        axiam_client_registration_t *out = NULL;
        arm(n);
        axiam_client_registration_t *parsed = axiam_client_registration_parse(g_registration, &err);
        disarm();
        axiam_client_registration_free(parsed);

        arm(n);
        (void) axiam_read_client_registration(c, BASE "/oauth2/register/c1", token, &out, &err);
        disarm();
        axiam_client_registration_t *meta = out;
        out = NULL;
        if (meta) {
            arm(n);
            (void) axiam_update_client_registration(c, BASE "/oauth2/register/c1", token, meta,
                                                    &out, &err);
            disarm();
            axiam_client_registration_free(out);
            axiam_client_registration_free(meta);
        }
        arm(n);
        (void) axiam_delete_client_registration(c, BASE "/oauth2/register/c1", token, &err);
        disarm();
    }
    axiam_sensitive_free(token);
    axiam_client_free(c);
    TEST_PASS();
}

/* ---- §29 – §32 helpers ----------------------------------------------------------- */

cJSON *axiam_mgmt_saml_service_provider_build(const axiam_mgmt_saml_service_provider_t *value);
axiam_mgmt_saml_service_provider_t *axiam_mgmt_saml_service_provider_parse(const cJSON *src);
axiam_mgmt_ssf_stream_t *axiam_mgmt_ssf_stream_parse(const cJSON *src);
axiam_mgmt_scim_target_response_t *axiam_mgmt_scim_target_response_parse(const cJSON *src);
axiam_mgmt_directory_config_t *axiam_mgmt_directory_config_parse(const cJSON *src);

static void test_management_helpers_survive_oom(void) {
    cJSON *sp_src = cJSON_Parse("{\"display_name\":\"d\",\"entity_id\":\"e\",\"enabled\":true,"
                                "\"acs_urls\":[{\"url\":\"u\",\"binding\":\"http_post\",\"index\":0}]}");
    cJSON *st_src = cJSON_Parse("{\"audience\":\"a\",\"receiver_client_id\":\"r\",\"delivery_method\":\"push\","
                                "\"events_allowed\":[\"x\"]}");
    cJSON *sc_src = cJSON_Parse("{\"name\":\"n\",\"base_url\":\"b\",\"auth\":{\"type\":\"bearer\"},"
                                "\"scope\":{\"type\":\"all_users\"}}");
    cJSON *dc_src = cJSON_Parse("{\"url\":\"l\",\"bind_dn\":\"b\",\"base_dn\":\"d\",\"user_filter\":\"f\"}");
    axiam_mgmt_saml_service_provider_t *sp = axiam_mgmt_saml_service_provider_parse(sp_src);
    axiam_mgmt_ssf_stream_t *st = axiam_mgmt_ssf_stream_parse(st_src);
    axiam_mgmt_scim_target_response_t *sc = axiam_mgmt_scim_target_response_parse(sc_src);
    axiam_mgmt_directory_config_t *dc = axiam_mgmt_directory_config_parse(dc_src);
    const char *ids[] = {"g1", "g2"};
    for (long n = 1; n <= DEPTH; n++) {
        arm(n);
        axiam_mgmt_saml_service_provider_input_free(axiam_mgmt_saml_service_provider_to_input(sp));
        disarm();
        arm(n);
        axiam_mgmt_ssf_stream_input_free(axiam_mgmt_ssf_stream_to_input(st));
        disarm();
        arm(n);
        axiam_mgmt_scim_target_input_free(axiam_mgmt_scim_target_response_to_input(sc));
        disarm();
        arm(n);
        axiam_mgmt_set_directory_config_free(axiam_mgmt_directory_config_to_set(dc));
        disarm();
        arm(n);
        axiam_mgmt_parse_saml_sp_metadata_free(axiam_mgmt_parse_saml_sp_metadata_from_url("https://m"));
        disarm();
        arm(n);
        axiam_mgmt_scim_target_auth_free(axiam_mgmt_scim_target_auth_bearer());
        disarm();
        arm(n);
        axiam_mgmt_scim_target_auth_free(
            axiam_mgmt_scim_target_auth_client_credentials("https://t", "c", "s"));
        disarm();
        arm(n);
        axiam_mgmt_scim_target_scope_free(axiam_mgmt_scim_target_scope_all_users());
        disarm();
        arm(n);
        axiam_mgmt_scim_target_scope_free(axiam_mgmt_scim_target_scope_groups(ids, 2));
        disarm();
        axiam_mgmt_scim_target_auth_t unknown = {(char *) "x", (char *) "{\"type\":\"bearer\"}"};
        arm(n);
        (void) axiam_mgmt_scim_target_auth_is_known(&unknown);
        disarm();
    }
    axiam_mgmt_saml_service_provider_free(sp);
    axiam_mgmt_ssf_stream_free(st);
    axiam_mgmt_scim_target_response_free(sc);
    axiam_mgmt_directory_config_free(dc);
    cJSON_Delete(sp_src);
    cJSON_Delete(st_src);
    cJSON_Delete(sc_src);
    cJSON_Delete(dc_src);
    TEST_PASS();
}

/* ---- §32.7 ----------------------------------------------------------------------- */

static char *sign_set(EVP_PKEY *key, const char *header, const char *payload) {
    char *h = jwt_b64url_encode((const unsigned char *) header, strlen(header));
    char *p = jwt_b64url_encode((const unsigned char *) payload, strlen(payload));
    size_t n = strlen(h) + strlen(p) + 2;
    char *input = malloc(n);
    snprintf(input, n, "%s.%s", h, p);
    unsigned char sig[64];
    size_t sig_len = sizeof sig;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, key);
    EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *) input, strlen(input));
    EVP_MD_CTX_free(ctx);
    char *s = jwt_b64url_encode(sig, sig_len);
    size_t m = n + strlen(s) + 1;
    char *set = malloc(m);
    snprintf(set, m, "%s.%s", input, s);
    free(h);
    free(p);
    free(input);
    free(s);
    return set;
}

static axiam_error_kind_t token_provider(void *ctx, axiam_sensitive_t **out, axiam_error_t *err) {
    (void) ctx;
    *out = axiam_sensitive_new("bearer-for-poll");
    if (!*out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

static void test_ssf_receiver_survives_oom(void) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    unsigned char raw[32];
    size_t len = sizeof raw;
    EVP_PKEY_get_raw_public_key(key, raw, &len);
    char *x = jwt_b64url_encode(raw, len);
    char jwks[256];
    snprintf(jwks, sizeof jwks, "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k1\",\"x\":\"%s\"}]}", x);
    free(x);
    g_jwks = jwks;
    axiam_client_t *c = make_client();
    axiam_ssf_receiver_config_t cfg = {0};
    cfg.issuer = ISSUER;
    cfg.audience = "aud";
    cfg.jwks_uri = BASE "/ssf-jwks";
    cfg.access_token_provider = token_provider;
    const axiam_ssf_set_err_t errs[1] = {{"j0", "invalid_key", "d"}};
    const char *ack[1] = {"a1"};
    axiam_ssf_poll_options_t opts = {0};
    opts.max_events = 5;
    opts.has_max_events = 1;
    opts.return_immediately = 1;
    opts.has_return_immediately = 1;
    opts.ack = ack;
    opts.ack_count = 1;
    opts.set_errs = errs;
    opts.set_errs_count = 1;
    for (long n = 1; n <= DEPTH; n++) {
        char jti[40], body[512];
        snprintf(jti, sizeof jti, "jti-%ld", n);
        snprintf(body, sizeof body,
                 "{\"iss\":\"" ISSUER "\",\"aud\":\"aud\",\"iat\":1,\"jti\":\"%s\",\"txn\":\"t\","
                 "\"sub_id\":{\"format\":\"opaque\",\"id\":\"s\"},\"events\":{\"e\":{\"a\":1}}}", jti);
        char *set = sign_set(key, "{\"alg\":\"EdDSA\",\"typ\":\"secevent+jwt\",\"kid\":\"k1\"}", body);
        char reply[2048];
        snprintf(reply, sizeof reply, "{\"sets\":{\"%s\":\"%s\",\"bad\":1},\"moreAvailable\":true}", jti, set);
        g_poll_reply = reply;
        axiam_error_t err;

        arm(n);
        axiam_ssf_receiver_t *r = axiam_ssf_receiver_new(c, &cfg, &err);
        disarm();
        if (r) {
            axiam_security_event_t ev;
            axiam_ssf_reason_t why;
            arm(n);
            if (axiam_ssf_verify_set(r, set, &ev, &why, &err) == AXIAM_OK) axiam_security_event_dispose(&ev);
            disarm();
            axiam_ssf_receiver_free(r);
        }
        r = axiam_ssf_receiver_new(c, &cfg, &err);
        axiam_ssf_poll_result_t res;
        arm(n);
        if (axiam_ssf_poll(r, "stream-1", &opts, &res, &err) == AXIAM_OK) axiam_ssf_poll_result_dispose(&res);
        disarm();
        axiam_ssf_receiver_free(r);
        free(set);
    }
    g_poll_reply = NULL;
    g_jwks = NULL;
    EVP_PKEY_free(key);
    axiam_client_free(c);
    TEST_PASS();
}

/* ---- §33 ------------------------------------------------------------------------- */

static void test_ciba_survives_oom(void) {
    char claims[256];
    long long now = (long long) time(NULL);
    snprintf(claims, sizeof claims, "{\"iss\":\"" ISSUER "\",\"aud\":\"c1\",\"sub\":\"u\",\"exp\":%lld,\"iat\":%lld}",
             now + 600, now - 5);
    char *id_token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("kid-1", claims, &id_token, &jwks));
    g_jwks = jwks;
    snprintf(g_tokens, sizeof g_tokens,
             "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":60,\"id_token\":\"%s\"}", id_token);
    snprintf(g_initiate, sizeof g_initiate, "{\"auth_req_id\":\"r-1\",\"expires_in\":300,\"interval\":5}");

    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    axiam_sensitive_t *pem = axiam_sensitive_new_bytes(pem_data, (size_t) pem_len);
    BIO_free(bio);
    axiam_sensitive_t *notify = axiam_sensitive_new("notify-token");

    axiam_client_t *c = make_client();
    axiam_kv_t *ping = axiam_kv_append(NULL, "Authorization", "Bearer notify-token");
    const char *ping_body = "{\"auth_req_id\":\"r-1\"}";
    for (long n = 1; n <= DEPTH; n++) {
        axiam_error_t err;
        arm(n);
        axiam_ciba_request_signer_t *signer =
            axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, pem, "k", &err);
        disarm();
        if (!signer) signer = axiam_ciba_request_signer_new(AXIAM_CIBA_SIGNING_EDDSA, pem, "k", &err);

        axiam_ciba_initiate_params_t p = {0};
        p.scope = "openid";
        p.hint = "alice";
        p.binding_message = "bm";
        p.requested_expiry = 60;
        p.has_requested_expiry = 1;
        p.acr_values = "a";
        p.resource = "https://r";
        p.delivery = AXIAM_CIBA_DELIVERY_PING;
        p.client_notification_token = notify;
        axiam_ciba_initiate_response_t r;
        arm(n);
        if (axiam_ciba_initiate(c, &p, &r, &err) == AXIAM_OK) axiam_ciba_initiate_response_dispose(&r);
        disarm();
        p.signer = signer;
        arm(n);
        if (axiam_ciba_initiate(c, &p, &r, &err) == AXIAM_OK) axiam_ciba_initiate_response_dispose(&r);
        disarm();

        axiam_sensitive_t *id = axiam_sensitive_new("r-1");
        axiam_oidc_token_set_t set;
        arm(n);
        if (axiam_ciba_poll(c, id, NULL, NULL, &set, &err) == AXIAM_OK) axiam_oidc_token_set_dispose(&set);
        disarm();
        axiam_ciba_initiate_response_t started = {id, 600, 5, time(NULL)};
        arm(n);
        if (axiam_ciba_await(c, &started, NULL, NULL, NULL, &set, &err) == AXIAM_OK)
            axiam_oidc_token_set_dispose(&set);
        disarm();
        axiam_sensitive_free(id);

        axiam_sensitive_t *got = NULL;
        arm(n);
        (void) axiam_ciba_handle_ping(ping, ping_body, strlen(ping_body), notify, &got, &err);
        disarm();
        axiam_sensitive_free(got);
        axiam_ciba_request_signer_free(signer);
    }
    axiam_kv_free(ping);
    axiam_sensitive_free(notify);
    axiam_sensitive_free(pem);
    EVP_PKEY_free(key);
    axiam_client_free(c);
    free(id_token);
    free(jwks);
    g_jwks = NULL;
    TEST_PASS();
}

/* ---- src/util.c ------------------------------------------------------------------ */

static void test_util_additions_survive_oom(void) {
    for (long n = 1; n <= 4; n++) {
        arm(n);
        char *e = axiam_b64url_encode((const unsigned char *) "abc", 3);
        disarm();
        free(e);
    }
    axiam_url_origin_t o;
    TEST_ASSERT_EQUAL_INT(0, axiam_url_origin("https://[::1]:8443/x", &o));
    TEST_ASSERT_EQUAL_STRING("[::1]", o.host);
    TEST_ASSERT_EQUAL_INT(8443, (int) o.port);
    TEST_ASSERT_TRUE(axiam_host_is_loopback(o.host));
    TEST_ASSERT_EQUAL_INT(0, axiam_url_origin("http://h:/x", &o));
    TEST_ASSERT_EQUAL_INT(80, (int) o.port);
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https://[::1/x", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https://[::1]x/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https://h:0/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https://h:99999/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https://h:8a/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("gopher://h/", &o));
    TEST_ASSERT_EQUAL_INT(0, axiam_url_origin("gopher://h:70/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("https:///", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin("averyveryverylongscheme://h/", &o));
    TEST_ASSERT_EQUAL_INT(-1, axiam_url_origin(NULL, &o));
    TEST_ASSERT_FALSE(axiam_host_is_loopback(NULL));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_registration_survives_oom);
    RUN_TEST(test_management_helpers_survive_oom);
    RUN_TEST(test_ssf_receiver_survives_oom);
    RUN_TEST(test_ciba_survives_oom);
    RUN_TEST(test_util_additions_survive_oom);
    return UNITY_END();
}
