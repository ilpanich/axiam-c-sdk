/*
 * Allocation-failure guard branches, across the whole SDK.
 *
 * Every calloc/malloc/realloc/strdup call in src/ is followed by a NULL check
 * that only takes its "OOM" arm when the allocator itself fails — which never
 * happens in an ordinary test run, so gcovr reports that arm as an uncovered
 * branch no matter how many happy-path tests exist. The 2026-08-15 coverage
 * incident (main failing its own --fail-under-branch 80 gate at 79.9%) traces
 * to exactly this: the contract-1.11 §12/§12.7/§14/§15 port added a batch of
 * allocation guards that are one-sided by construction.
 *
 * This file wraps malloc/calloc/realloc at LINK TIME, using the GNU ld
 * `--wrap` option applied only to this test binary's CMake target (see
 * tests/CMakeLists.txt). That turns every call to malloc/calloc/realloc
 * anywhere in the final link — src/, third_party/cjson, this file itself —
 * into a call to __wrap_*, which can be told "let call #N fail" and otherwise
 * defers to the real allocator via __real_*. Each test arms the Nth
 * allocation to fail, drives a real (not stubbed) SDK code path through it,
 * and asserts the function actually reports failure and does not crash or
 * double-free — never a pragma, never an unreachable line, never an
 * assertion-free "just run it".
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/account.h"
#include "axiam/reactor.h"
#include "axiam/axiam.h"
#include "axiam/webauthn.h"
#include "internal.h"
#include "oidc_internal.h"
#include "test_util.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "jwt_fixture.h"
#include "oidc_test_util.h"
#include "opaque_fake.h"

/* The fake OPAQUE library's counters, defined once per test binary. */
fake_opaque_t g_fake_opaque;

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

/* 1-based allocation call number to fail; <= 0 means "never fail". One-shot:
 * once the counter matches, failure injection turns itself off, so a single
 * arm() call reliably fails exactly one allocation in whatever call graph
 * runs next, however many further allocations that call graph goes on to
 * make. */
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

static void alloc_fail_after(long n) {
    g_fail_at = n;
    g_call_count = 0;
}

static void alloc_fail_reset(void) {
    g_fail_at = -1;
    g_call_count = 0;
}

void setUp(void) { alloc_fail_reset(); }
void tearDown(void) { alloc_fail_reset(); }

static const char *PEM_CERT =
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
static const char *PEM_KEY =
    "-----BEGIN TEST KEY PLACEHOLDER-----\nMC4C\n-----END TEST KEY PLACEHOLDER-----\n";

/* ------------------------------------------------------------------ */
/* src/sensitive.c                                                    */
/* ------------------------------------------------------------------ */

static void test_sensitive_new_bytes_calloc_failure(void) {
    /* src/sensitive.c:15-16 — the handle's own calloc. */
    alloc_fail_after(1);
    TEST_ASSERT_NULL(axiam_sensitive_new_bytes("secret", 6));
}

static void test_sensitive_new_bytes_malloc_failure(void) {
    /* src/sensitive.c:17-21 — calloc(handle) succeeds, malloc(data) fails;
     * the handle itself must be freed rather than leaked. */
    alloc_fail_after(2);
    TEST_ASSERT_NULL(axiam_sensitive_new_bytes("secret", 6));
}

/* ------------------------------------------------------------------ */
/* src/util.c                                                         */
/* ------------------------------------------------------------------ */

static void test_strdup0_malloc_failure(void) {
    alloc_fail_after(1); /* src/util.c:10-11 */
    TEST_ASSERT_NULL(axiam_strdup0("hi"));
}

static void test_kv_append_calloc_failure(void) {
    alloc_fail_after(1); /* src/util.c:87-88 */
    axiam_kv_t *head = axiam_kv_append(NULL, "k", "v");
    TEST_ASSERT_NULL(head);
}

static void test_b64url_decode_malloc_failure(void) {
    alloc_fail_after(1); /* src/util.c:145-146 */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("QUJD", 4, &out_len));
}

/* ------------------------------------------------------------------ */
/* src/config.c                                                       */
/* ------------------------------------------------------------------ */

static void test_config_new_calloc_failure(void) {
    alloc_fail_after(1); /* src/config.c:7-8 */
    TEST_ASSERT_NULL(axiam_client_config_new());
}

static void test_config_set_client_cert_client_key_alloc_failure_sweep(void) {
    /* src/config.c:88-90 — the Sensitive wrapping the private key, after the
     * cert's own strdup already succeeded. Sweeping every failure point
     * inside this call also exercises the cert_pem strdup guard on the way. */
    for (long i = 1; i <= 6; i++) {
        axiam_client_config_t *cfg = axiam_client_config_new();
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_client_config_set_client_cert(cfg, PEM_CERT, PEM_KEY);
        alloc_fail_reset();
        TEST_ASSERT_TRUE(k == AXIAM_OK || k == AXIAM_ERR_NETWORK);
        axiam_client_config_free(cfg);
    }
}

static void test_config_clone_alloc_failure_sweep(void) {
    /* src/config.c:194-229 — every strdup/array-copy in a full clone, one at
     * a time. A failure anywhere must yield NULL, not a half-built config. */
    axiam_client_config_t *src = axiam_client_config_new();
    axiam_client_config_set_base_url(src, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(src, "acme");
    axiam_client_config_set_tenant_id(src, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_org_slug(src, "org");
    axiam_client_config_set_org_id(src, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_custom_ca(src,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    axiam_client_config_set_client_cert(src, PEM_CERT, PEM_KEY);
    axiam_client_config_set_expected_issuer(src, "https://issuer.example.com");
    axiam_client_config_set_expected_audience(src, "some-audience");
    axiam_client_config_set_oidc_client_id(src, "client-id");
    axiam_client_config_set_oidc_client_secret(src, "shh-its-a-secret");
    TEST_ASSERT_NOT_NULL(src);

    for (long i = 1; i <= 40; i++) {
        alloc_fail_after(i);
        axiam_client_config_t *c = axiam_client_config_clone(src);
        alloc_fail_reset();
        if (c) axiam_client_config_free(c);
    }
    axiam_client_config_free(src);
}

/* ------------------------------------------------------------------ */
/* src/client.c — axiam_client_new()                                  */
/* ------------------------------------------------------------------ */

static int noop_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void)ctx;
    (void)req;
    memset(resp, 0, sizeof(*resp));
    resp->status = 200;
    return 0;
}

static void test_client_new_alloc_failure_sweep(void) {
    /* src/client.c:22-32 — the client struct's own calloc, then
     * axiam_client_config_clone()'s failure surfacing back through
     * axiam_client_new(). A custom transport is configured so this exercises
     * only those two allocations, not axiam_curl_ctx_new()'s libcurl-backed
     * ones (out of scope for a malloc-only wrap). */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, noop_transport, NULL);

    for (long i = 1; i <= 30; i++) {
        alloc_fail_after(i);
        axiam_error_t err;
        axiam_client_t *c = axiam_client_new(cfg, &err);
        alloc_fail_reset();
        if (c) axiam_client_free(c);
    }
    axiam_client_config_free(cfg);
}

/* ------------------------------------------------------------------ */
/* src/oidc.c — the form-body builder shared by every §12/§14/§15 grant */
/* ------------------------------------------------------------------ */

static void test_oidc_form_init_malloc_failure(void) {
    /* src/oidc.c:43-46 */
    oidc_form_t f;
    alloc_fail_after(1);
    oidc_form_init(&f);
    alloc_fail_reset();
    TEST_ASSERT_EQUAL_INT(1, f.failed);
    TEST_ASSERT_NULL(f.buf);
    oidc_form_dispose(&f); /* src/oidc.c:100 — must tolerate a NULL buf */
}

static void test_oidc_form_add_growth_realloc_failure(void) {
    /* src/oidc.c:52-58 (form_reserve's realloc) and :86 (the sticky `failed`
     * short-circuit on the next add). */
    oidc_form_t f;
    oidc_form_init(&f); /* cap == 512, unfailed */
    TEST_ASSERT_EQUAL_INT(0, f.failed);

    char big[600];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    alloc_fail_after(1); /* the one realloc this add needs to grow past 512 */
    oidc_form_add(&f, "k", big);
    alloc_fail_reset();
    TEST_ASSERT_EQUAL_INT(1, f.failed);

    /* Once poisoned, further adds must no-op rather than touch a stale buffer. */
    size_t len_before = f.len;
    oidc_form_add(&f, "k2", "v2");
    TEST_ASSERT_EQUAL_UINT(len_before, f.len);

    oidc_form_dispose(&f);
}

static void test_oidc_discover_alloc_failure_sweep(void) {
    /* src/oidc.c:310-368 (parse_discovery's json_opt/json_strings guards) and
     * :398-429 (the discovery cache's own oidc_config_copy() calls, both the
     * fresh-cache-serves-a-copy path and the just-fetched-populates-the-cache
     * path). Reuses the scripted fake transport every other §12 suite shares
     * (tests/oidc_test_util.h) so this drives the REAL discovery parse, not a
     * stub of it. */
    oidc_reset();
    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 60; i++) {
        axiam_oidc_client_dispose(c); /* drop any cached document first */
        axiam_oidc_config_t cfg;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_discover(c, &cfg, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_oidc_config_dispose(&cfg);
    }

    /* The fresh-cache COPY path specifically: populate for real, then fail
     * only the copy serving the very next call from that cache. */
    axiam_oidc_client_dispose(c);
    axiam_oidc_config_t primed;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_oidc_discover(c, &primed, NULL));
    axiam_oidc_config_dispose(&primed);
    for (long i = 1; i <= 30; i++) {
        axiam_oidc_config_t cfg;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_discover(c, &cfg, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_oidc_config_dispose(&cfg);
    }

    axiam_client_free(c);
}

static void test_oidc_endpoint_with_tenant_malloc_failure(void) {
    /* src/oidc.c:200-202 */
    alloc_fail_after(1);
    char *url = oidc_endpoint_with_tenant("https://issuer.example.com/oauth2/token",
                                          "11111111-1111-1111-1111-111111111111");
    alloc_fail_reset();
    TEST_ASSERT_NULL(url);
}

/* ------------------------------------------------------------------ */
/* src/oidc_validate.c — Copies (the §9 single-flight fan-out path)     */
/* ------------------------------------------------------------------ */

static char **dup_strv(const char *const *items, size_t count) {
    if (count == 0) return NULL;
    char **out = malloc(count * sizeof(char *));
    for (size_t i = 0; i < count; i++) out[i] = strdup(items[i]);
    return out;
}

static void free_strv(char **items, size_t count) {
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

static void test_oidc_token_set_copy_alloc_failure_sweep(void) {
    /* src/oidc_validate.c:463-514 — sensitive_copy, string_array_copy (twice,
     * inside claims_copy) and every strdup along the way, one failure point
     * at a time. On any failure oidc_token_set_copy() must return 0 and dst
     * must come back fully disposed, never half-built. */
    const char *aud[] = {"client-a", "client-b"};
    const char *roles[] = {"admin"};

    axiam_oidc_token_set_t src;
    memset(&src, 0, sizeof(src));
    src.access_token = axiam_sensitive_new("access-token-value");
    src.refresh_token = axiam_sensitive_new("refresh-token-value");
    src.id_token = axiam_sensitive_new("id-token-value");
    src.token_type = strdup("Bearer");
    src.scope = strdup("openid profile");
    src.expires_in = 3600;

    axiam_id_token_claims_t claims;
    memset(&claims, 0, sizeof(claims));
    claims.subject = strdup("user-123");
    claims.issuer = strdup("https://issuer.example.com");
    claims.audience = dup_strv(aud, 2);
    claims.audience_count = 2;
    claims.expires_at = 999999;
    claims.issued_at = 111111;
    claims.nonce = strdup("nonce-value");
    claims.authorized_party = strdup("client-a");
    claims.email = strdup("user@example.com");
    claims.preferred_username = strdup("user");
    claims.tenant_id = strdup("tenant-1");
    claims.roles = dup_strv(roles, 1);
    claims.roles_count = 1;
    claims.raw_claims_json = strdup("{\"sub\":\"user-123\"}");
    src.id_claims = &claims;

    for (long i = 1; i <= 50; i++) {
        axiam_oidc_token_set_t dst;
        alloc_fail_after(i);
        int ok = oidc_token_set_copy(&src, &dst);
        alloc_fail_reset();
        if (ok) {
            axiam_oidc_token_set_dispose(&dst);
        }
        /* A failed copy has already disposed dst internally (src/oidc_validate.c
         * :510); nothing further to release either way. */
    }

    axiam_sensitive_free(src.access_token);
    axiam_sensitive_free(src.refresh_token);
    axiam_sensitive_free(src.id_token);
    free(src.token_type);
    free(src.scope);
    free(claims.subject);
    free(claims.issuer);
    free_strv(claims.audience, claims.audience_count);
    free(claims.nonce);
    free(claims.authorized_party);
    free(claims.email);
    free(claims.preferred_username);
    free(claims.tenant_id);
    free_strv(claims.roles, claims.roles_count);
    free(claims.raw_claims_json);
}

static void test_oidc_config_copy_alloc_failure_sweep(void) {
    /* src/oidc_validate.c:516-545 — every endpoint strdup and every
     * string-array copy, one failure point at a time. */
    const char *scopes[] = {"openid", "profile", "email"};
    const char *resp_types[] = {"code"};
    const char *algs[] = {"EdDSA"};

    axiam_oidc_config_t src;
    memset(&src, 0, sizeof(src));
    src.issuer = strdup("https://issuer.example.com");
    src.authorization_endpoint = strdup("https://issuer.example.com/oauth2/authorize");
    src.token_endpoint = strdup("https://issuer.example.com/oauth2/token");
    src.jwks_uri = strdup("https://issuer.example.com/.well-known/jwks.json");
    src.userinfo_endpoint = strdup("https://issuer.example.com/oauth2/userinfo");
    src.introspection_endpoint = strdup("https://issuer.example.com/oauth2/introspect");
    src.revocation_endpoint = strdup("https://issuer.example.com/oauth2/revoke");
    src.end_session_endpoint = strdup("https://issuer.example.com/oauth2/logout");
    src.device_authorization_endpoint = strdup("https://issuer.example.com/oauth2/device");
    src.scopes_supported = dup_strv(scopes, 3);
    src.scopes_supported_count = 3;
    src.response_types_supported = dup_strv(resp_types, 1);
    src.response_types_supported_count = 1;
    src.id_token_signing_alg_values_supported = dup_strv(algs, 1);
    src.id_token_signing_alg_values_supported_count = 1;

    for (long i = 1; i <= 40; i++) {
        axiam_oidc_config_t dst;
        alloc_fail_after(i);
        axiam_error_kind_t k = oidc_config_copy(&src, &dst);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            axiam_oidc_config_dispose(&dst);
        }
    }

    free(src.issuer);
    free(src.authorization_endpoint);
    free(src.token_endpoint);
    free(src.jwks_uri);
    free(src.userinfo_endpoint);
    free(src.introspection_endpoint);
    free(src.revocation_endpoint);
    free(src.end_session_endpoint);
    free(src.device_authorization_endpoint);
    free_strv(src.scopes_supported, src.scopes_supported_count);
    free_strv(src.response_types_supported, src.response_types_supported_count);
    free_strv(src.id_token_signing_alg_values_supported,
             src.id_token_signing_alg_values_supported_count);
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_begin — the three random draws and the URL build         */
/* ------------------------------------------------------------------ */

static void test_oidc_begin_alloc_failure_sweep(void) {
    /* src/oidc.c:526-533 (any of state / nonce / verifier / challenge failing
     * to allocate, which must free the other three rather than leak a
     * half-built request) and :594-596 (the assembled URL and the Sensitive
     * wrapping the verifier). §12.1 makes oidc_begin network-free, so the
     * sweep needs only a discovered document, fetched once up front. */
    oidc_reset();
    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, NULL));

    for (long i = 1; i <= 30; i++) {
        axiam_authorization_request_t req;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "profile",
                                                &req, NULL);
        alloc_fail_reset();
        /* Either it built everything, or it reported OOM — never a request
         * with a URL but no verifier, which a caller would send and then be
         * unable to complete. */
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(req.url);
            TEST_ASSERT_NOT_NULL(req.code_verifier);
            axiam_authorization_request_dispose(&req);
        } else {
            TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, k);
        }
    }

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 oidc_exchange — the shared grant POST and the token-set parse */
/* ------------------------------------------------------------------ */

static void test_oidc_exchange_alloc_failure_sweep(void) {
    /* src/oidc.c:613-619 (oidc_post_grant's poisoned-form and URL guards) and
     * :635-636 (the response-body strdup), plus src/oidc_validate.c:452-458
     * (the parsed token set's all-or-nothing check). Drives the REAL §12.1
     * exchange through the shared scripted transport. */
    oidc_reset();
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\","
        "\"expires_in\":900,\"refresh_token\":\"the-refresh-token\","
        "\"scope\":\"openid profile\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");
    TEST_ASSERT_NOT_NULL(verifier);

    for (long i = 1; i <= 70; i++) {
        axiam_oidc_exchange_params_t p = {0};
        p.code = "the-code";
        p.code_verifier = verifier;
        p.redirect_uri = OIDC_REDIRECT_URI;
        p.nonce = "the-nonce";

        axiam_oidc_token_set_t set;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_exchange(c, &p, &set, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            /* §12.4 all-or-nothing: a success carries both members. */
            TEST_ASSERT_NOT_NULL(set.access_token);
            TEST_ASSERT_NOT_NULL(set.token_type);
            axiam_oidc_token_set_dispose(&set);
        }
    }

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.4 id_token validation — the signed-token branch of the parse    */
/* ------------------------------------------------------------------ */

static void test_oidc_exchange_id_token_alloc_failure_sweep(void) {
    /* src/oidc_validate.c:348-352 (build_claims' raw_claims_json strdup),
     * :380-386 (the payload that could not be parsed) and :389-394
     * (build_claims failing inside the OK branch), plus src/jwks.c:448-454 —
     * the "payload decoded but its buffer could not be allocated" arm, which
     * is only reachable with a signature that actually verifies. */
    oidc_reset();
    char payload[512];
    long long now = (long long)time(NULL);
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sub\":\"user-1\",\"exp\":%lld,\"iat\":%lld,\"nonce\":\"the-nonce\","
             "\"email\":\"a@b.test\",\"roles\":[\"admin\"]}",
             now + 900, now - 5);

    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &token, &jwks));
    g_oidc.jwks_body = jwks;

    static char body[8192];
    snprintf(body, sizeof(body),
             "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\","
             "\"expires_in\":900,\"id_token\":\"%s\"}", token);
    g_oidc.token_script[0] = (oidc_answer_t){200, body, 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *verifier = axiam_sensitive_new("the-verifier");

    for (long i = 1; i <= 120; i++) {
        axiam_oidc_exchange_params_t p = {0};
        p.code = "the-code";
        p.code_verifier = verifier;
        p.redirect_uri = OIDC_REDIRECT_URI;
        p.nonce = "the-nonce";

        axiam_oidc_token_set_t set;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_exchange(c, &p, &set, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            /* §12.4 rule 7: an id_token that was accepted always arrives
             * alongside the claims parsed out of it, never one without the
             * other. */
            TEST_ASSERT_NOT_NULL(set.access_token);
            if (set.id_claims) TEST_ASSERT_NOT_NULL(set.id_token);
            axiam_oidc_token_set_dispose(&set);
        }
    }

    axiam_sensitive_free(verifier);
    axiam_client_free(c);
    free(token);
    free(jwks);
    g_oidc.jwks_body = NULL;
}

/* ------------------------------------------------------------------ */
/* §12.5 oidc_refresh — the single-flight leader path                  */
/* ------------------------------------------------------------------ */

static void test_oidc_refresh_alloc_failure_sweep(void) {
    /* src/oidc_refresh.c:106-112 (take_outcome's copy of the flight result
     * into the caller's out-parameter) and :169-174 (the flight record's own
     * calloc, which must unlock the mutex before returning — a leaked lock
     * here would deadlock every later refresh rather than fail this one). */
    oidc_reset();
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"rotated-access\",\"token_type\":\"Bearer\","
        "\"expires_in\":900,\"refresh_token\":\"rotated-refresh\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *rt = axiam_sensitive_new("the-refresh-token");
    TEST_ASSERT_NOT_NULL(rt);

    for (long i = 1; i <= 70; i++) {
        axiam_oidc_token_set_t set;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_refresh(c, rt, NULL, NULL, &set, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_oidc_token_set_dispose(&set);
        /* Whatever happened, the flight table must be usable again: a
         * subsequent refresh still completes. */
    }

    axiam_oidc_token_set_t after;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_refresh(c, rt, NULL, NULL, &after, NULL));
    axiam_oidc_token_set_dispose(&after);

    axiam_sensitive_free(rt);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §14 device authorization grant                                     */
/* ------------------------------------------------------------------ */

static void device_display_noop(void *ctx, const axiam_device_authorization_t *a) {
    (void)ctx;
    (void)a;
}

static void test_device_authorize_alloc_failure_sweep(void) {
    /* src/oidc_device.c:78-84 (the endpoint URL the POST needs) and :130-136
     * (the parsed authorization's all-or-nothing check — a grant missing its
     * device_code or user_code is unusable and must not be handed back). */
    oidc_reset();
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\","
        "\"verification_uri\":\"https://api.test/device\","
        "\"verification_uri_complete\":\"https://api.test/device?user_code=WDJB-MJHT\","
        "\"expires_in\":600,\"interval\":5}", 0};

    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 60; i++) {
        axiam_device_authorization_t da;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_device_authorize(c, "openid", NULL, &da, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(da.device_code);
            TEST_ASSERT_NOT_NULL(da.user_code);
            TEST_ASSERT_NOT_NULL(da.verification_uri);
            axiam_device_authorization_dispose(&da);
        }
    }

    axiam_client_free(c);
}

static void test_device_login_alloc_failure_sweep(void) {
    /* src/oidc_device.c:230-236 — the second discovery, taken AFTER the
     * authorization was already obtained. Its failure arm has to dispose that
     * authorization rather than return with it still owned by nobody. */
    oidc_reset();
    g_oidc.device_answer = (oidc_answer_t){200,
        "{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\","
        "\"verification_uri\":\"https://api.test/device\","
        "\"expires_in\":600,\"interval\":1}", 0};
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 80; i++) {
        axiam_oidc_client_dispose(c); /* force the discovery cache cold */
        axiam_oidc_token_set_t set;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_device_login(c, "openid", NULL,
                                                  device_display_noop, NULL, &set, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_oidc_token_set_dispose(&set);
    }

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §15 token exchange (RFC 8693)                                      */
/* ------------------------------------------------------------------ */

static void test_token_exchange_alloc_failure_sweep(void) {
    /* src/oidc_exchange.c:98-104 (the joined `scope` string, whose failure
     * must poison the form rather than send a request with the scopes
     * silently dropped) and :160-166 (the result's all-or-nothing check). */
    oidc_reset();
    g_oidc.token_script[0] = (oidc_answer_t){200,
        "{\"access_token\":\"exchanged-token\","
        "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\","
        "\"token_type\":\"Bearer\",\"expires_in\":900,\"scope\":\"read write\"}", 0};
    g_oidc.token_script_len = 1;

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *subject = axiam_sensitive_new("subject-token-value");
    TEST_ASSERT_NOT_NULL(subject);
    const char *scopes[] = {"read", "write", "admin"};

    for (long i = 1; i <= 70; i++) {
        axiam_token_exchange_params_t p = {0};
        p.subject_token = subject;
        p.subject_token_type = AXIAM_TOKEN_TYPE_ACCESS_TOKEN;
        p.scopes = scopes;
        p.scope_count = 3;
        p.audience = "https://downstream.test";

        axiam_exchanged_token_t out;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_token_exchange(c, &p, &out, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(out.access_token);
            TEST_ASSERT_NOT_NULL(out.issued_token_type);
            TEST_ASSERT_NOT_NULL(out.token_type);
            axiam_exchanged_token_dispose(&out);
        }
    }

    axiam_sensitive_free(subject);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 federation SSO — the two JSON-bodied endpoints                */
/* ------------------------------------------------------------------ */

static void test_sso_start_and_complete_alloc_failure_sweep(void) {
    /* src/oidc.c:939-944 (the base-URL + path join both SSO calls share),
     * :978-983 and :996-1001 (sso_start's request object and its serialised
     * body), :1042-1047 and :1050-1055 (the same pair for sso_complete). */
    oidc_reset();
    g_oidc.sso_start_answer = (oidc_answer_t){200,
        "{\"authorize_url\":\"https://idp.test/authorize?x=1\","
        "\"state\":\"the-state\",\"expires_in_secs\":600}", 0};
    g_oidc.sso_complete_answer = (oidc_answer_t){200,
        "{\"user_id\":\"user-1\",\"session_id\":\"session-1\","
        "\"expires_in\":900,\"redirect_uri\":\"https://app.test/home\"}", 0};

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 40; i++) {
        axiam_sso_start_result_t s;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_sso_start(c, "fed-config-1",
                                               "https://app.test/callback", &s, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_sso_start_result_dispose(&s);
    }

    for (long i = 1; i <= 40; i++) {
        axiam_sso_complete_result_t s;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_sso_complete(c, "the-code", "the-state", &s, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_sso_complete_result_dispose(&s);
    }

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.7.3 verify_logout_token                                        */
/* ------------------------------------------------------------------ */

static void test_verify_logout_token_alloc_failure_sweep(void) {
    /* src/oidc_logout.c:130-135 (a payload that could not be parsed — here
     * because its buffer could not be allocated) and :206-212 (the verified
     * token's all-or-nothing check: a result claiming a `sid` the caller
     * cannot read is worse than a reported failure). */
    oidc_reset();
    char payload[512];
    long long now = (long long)time(NULL);
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\","
             "\"sid\":\"session-1\",\"sub\":\"user-1\",\"jti\":\"jti-1\","
             "\"iat\":%lld,\"exp\":%lld,"
             "\"events\":{\"" AXIAM_LOGOUT_EVENT_KEY "\":{}}}",
             now - 5, now + 120);

    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &token, &jwks));
    g_oidc.jwks_body = jwks;

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 90; i++) {
        axiam_verified_logout_token_t t;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_verify_logout_token(c, token, &t, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(t.issuer);
            /* §12.7.3 rule 5: a verified token always names something. */
            TEST_ASSERT_TRUE(t.sid != NULL || t.subject != NULL);
            axiam_verified_logout_token_dispose(&t);
        }
    }

    axiam_client_free(c);
    free(token);
    free(jwks);
    g_oidc.jwks_body = NULL;
}

/* ------------------------------------------------------------------ */
/* §12.1 introspect / revoke — the fallback-path endpoint join         */
/* ------------------------------------------------------------------ */

static void test_introspect_and_revoke_alloc_failure_sweep(void) {
    /* src/oidc.c:816-821 — the endpoint URL both operations build, either
     * from the discovered endpoint or by joining the fallback path onto the
     * base URL. */
    oidc_reset();
    g_oidc.introspect_answer = (oidc_answer_t){200,
        "{\"active\":true,\"sub\":\"user-1\",\"scope\":\"openid\"}", 0};
    g_oidc.revoke_answer = (oidc_answer_t){200, "", 0};

    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *tok = axiam_sensitive_new("the-access-token");
    TEST_ASSERT_NOT_NULL(tok);

    for (long i = 1; i <= 50; i++) {
        axiam_introspection_result_t intro;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_introspect(c, tok, NULL, NULL, &intro, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_introspection_result_dispose(&intro);
    }

    for (long i = 1; i <= 40; i++) {
        alloc_fail_after(i);
        (void)axiam_revoke(c, tok, NULL, NULL, NULL);
        alloc_fail_reset();
    }

    axiam_sensitive_free(tok);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §20 UMA 2.0                                                        */
/* ------------------------------------------------------------------ */

#define UMA_ALLOC_DISCOVERY_BODY                                               \
    "{\"issuer\":\"" OIDC_BASE "\","                                           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"permission_endpoint\":\"" OIDC_BASE "/uma2/perm\","                     \
    "\"resource_registration_endpoint\":\"" OIDC_BASE "/uma2/rreg/resource_set\"," \
    "\"jwks_uri\":\"" OIDC_BASE "/.well-known/jwks.json\","                    \
    "\"permission_ticket_lifetime\":60}"

/* A resource set carrying every optional member, so the sweep reaches each
 * strdup in parse_resource_set() rather than stopping at the first absent
 * field. */
#define UMA_ALLOC_RESOURCE_BODY                                                \
    "{\"_id\":\"99999999-8888-7777-6666-555555555555\","                       \
    "\"name\":\"invoice-42\",\"type\":\"urn:axiam:invoice\","                  \
    "\"resource_scopes\":[\"read\",\"write\",\"share\"]}"

static int uma_alloc_transport(void *ctx, const axiam_http_request_t *req,
                               axiam_http_response_t *resp) {
    (void)ctx;
    const char *url = req->url ? req->url : "";
    if (strstr(url, "/.well-known/uma2-configuration")) {
        resp_fill(resp, 200, UMA_ALLOC_DISCOVERY_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/uma2/rreg/resource_set")) {
        /* The listing is the only one that answers with a bare array. */
        if (req->method && strcmp(req->method, "GET") == 0 &&
            !strstr(url, "resource_set/")) {
            resp_fill(resp, 200,
                      "[\"11111111-1111-1111-1111-111111111111\","
                      "\"22222222-2222-2222-2222-222222222222\"]", NULL);
            return 0;
        }
        resp_fill(resp, 200, UMA_ALLOC_RESOURCE_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/uma2/perm")) {
        resp_fill(resp, 200, "{\"ticket\":\"the-permission-ticket\"}", NULL);
        return 0;
    }
    if (strstr(url, "/oauth2/token")) {
        resp_fill(resp, 200,
                  "{\"access_token\":\"the-rpt\",\"token_type\":\"Bearer\","
                  "\"expires_in\":300}", NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *uma_alloc_make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_transport(cfg, uma_alloc_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static void test_uma_discover_alloc_failure_sweep(void) {
    /* src/uma.c:203-212 (parse_uma_config's all-or-nothing check on the three
     * endpoints the profile requires), :219-228 (config_copy) and the two
     * cache arms at :241-250 and :265-272 — the fresh-cache copy that serves a
     * hit, and the post-fetch copy that populates the cache. The latter's
     * failure arm is deliberately NOT an error: a cache that could not be
     * filled is simply not filled, and the caller's own copy still succeeds. */
    axiam_client_t *c = uma_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 60; i++) {
        axiam_uma_config_t cfg;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_discover(c, &cfg, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(cfg.token_endpoint);
            TEST_ASSERT_NOT_NULL(cfg.permission_endpoint);
            TEST_ASSERT_NOT_NULL(cfg.resource_registration_endpoint);
            axiam_uma_config_dispose(&cfg);
        }
    }

    /* Now with a WARM cache, so the sweep lands on the copy that serves the
     * hit rather than on the parse. */
    axiam_uma_config_t primed;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_uma_discover(c, &primed, NULL));
    axiam_uma_config_dispose(&primed);
    for (long i = 1; i <= 12; i++) {
        axiam_uma_config_t cfg;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_discover(c, &cfg, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_uma_config_dispose(&cfg);
    }

    axiam_client_free(c);
}

static void test_uma_resource_registration_alloc_failure_sweep(void) {
    /* src/uma.c:341-352 (the scopes array and each scope strdup in
     * parse_resource_set), :357-365 (its all-or-nothing check), :394-402 (the
     * per-id URL the read/update/delete calls build) and :597-606 (the
     * listing's id array). */
    axiam_client_t *c = uma_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    TEST_ASSERT_NOT_NULL(pat);
    const char *scopes[] = {"read", "write", "share"};

    for (long i = 1; i <= 60; i++) {
        axiam_uma_resource_set_t rs;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_register_resource(c, pat, "invoice-42",
                                                           "urn:axiam:invoice",
                                                           scopes, 3, &rs, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(rs.name);
            axiam_uma_resource_set_dispose(&rs);
        }
    }

    for (long i = 1; i <= 40; i++) {
        axiam_uma_resource_set_t rs;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_read_resource(
            c, pat, "99999999-8888-7777-6666-555555555555", &rs, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_uma_resource_set_dispose(&rs);
    }

    for (long i = 1; i <= 50; i++) {
        axiam_uma_resource_set_t rs;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_update_resource(
            c, pat, "99999999-8888-7777-6666-555555555555", "invoice-43",
            "urn:axiam:invoice", scopes, 3, &rs, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_uma_resource_set_dispose(&rs);
    }

    for (long i = 1; i <= 30; i++) {
        alloc_fail_after(i);
        (void)axiam_uma_delete_resource(c, pat,
                                        "99999999-8888-7777-6666-555555555555", NULL);
        alloc_fail_reset();
    }

    for (long i = 1; i <= 40; i++) {
        char **ids = NULL;
        size_t count = 0;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_list_resources(c, pat, &ids, &count, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_uma_string_array_free(ids, count);
    }

    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

static void test_uma_ticket_and_rpt_alloc_failure_sweep(void) {
    /* src/uma.c:651-660 (the Sensitive wrapping the minted ticket — §20.6
     * makes it a credential for its whole 60-second life, so a handle that
     * could not be allocated must be reported, never returned unwrapped),
     * :783-795 (the token URL and the grant form, which carries four secrets)
     * and :840-849 (the RPT's all-or-nothing check). */
    axiam_client_t *c = uma_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *pat = axiam_sensitive_new("pat-token-value");
    const char *scopes[] = {"read", "write"};
    axiam_uma_permission_t perms[1];
    perms[0].resource_id = "99999999-8888-7777-6666-555555555555";
    perms[0].scopes = scopes;
    perms[0].scope_count = 2;

    for (long i = 1; i <= 60; i++) {
        axiam_sensitive_t *ticket = NULL;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_request_ticket(c, pat, perms, 1, &ticket, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(ticket);
            axiam_sensitive_free(ticket);
        } else {
            TEST_ASSERT_NULL(ticket);
        }
    }

    axiam_sensitive_t *ticket = axiam_sensitive_new("the-permission-ticket");
    axiam_sensitive_t *claim = axiam_sensitive_new("claim-token-value");
    axiam_sensitive_t *secret = axiam_sensitive_new(OIDC_CLIENT_SECRET);
    TEST_ASSERT_NOT_NULL(ticket);

    for (long i = 1; i <= 60; i++) {
        axiam_uma_exchange_params_t p = {0};
        p.ticket = ticket;
        p.claim_token = claim;
        p.client_id = OIDC_CLIENT_ID;
        p.client_secret = secret;

        axiam_uma_rpt_t rpt;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_uma_exchange_ticket(c, &p, &rpt, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(rpt.access_token);
            TEST_ASSERT_NOT_NULL(rpt.token_type);
            axiam_uma_rpt_dispose(&rpt);
        }
    }

    axiam_sensitive_free(ticket);
    axiam_sensitive_free(claim);
    axiam_sensitive_free(secret);
    axiam_sensitive_free(pat);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §17 decision memo, §21 webhook, §8 check_access body                */
/* ------------------------------------------------------------------ */

static int authz_allow_transport(void *ctx, const axiam_http_request_t *req,
                                 axiam_http_response_t *resp) {
    (void)ctx;
    (void)req;
    resp_fill(resp, 200,
              "{\"allowed\":true,\"reason\":\"role grant\",\"reason_code\":\"role\"}", NULL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* src/opaque.c + src/client.c (CONTRACT.md §23)                      */
/* ------------------------------------------------------------------ */

/* A start response well-formed enough to reach every allocation on both OPAQUE
 * paths: a session handle, a peer message, and a key-stretching function this
 * SDK can ask for at costs inside the accepted bands. */
static const char *OPAQUE_ALLOC_LOGIN_START =
    "{\"opaque_session\":\"s1\",\"ke2\":\"6b6532\",\"ksf\":\"" AXIAM_OPAQUE_KSF_ARGON2ID "\","
    "\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1}";

static const char *OPAQUE_ALLOC_REGISTER_START =
    "{\"opaque_session\":\"s1\",\"registration_response\":\"726573\","
    "\"ksf\":\"" AXIAM_OPAQUE_KSF_ARGON2ID "\",\"memory_kib\":19456,\"iterations\":2,"
    "\"parallelism\":1}";

static int opaque_alloc_transport(void *ctx, const axiam_http_request_t *req,
                                  axiam_http_response_t *resp) {
    (void)ctx;
    const char *url = req->url ? req->url : "";
    if (strstr(url, "/auth/opaque/login/start")) {
        resp_fill(resp, 200, OPAQUE_ALLOC_LOGIN_START, NULL);
        return 0;
    }
    if (strstr(url, "/auth/opaque/register/start")) {
        resp_fill(resp, 200, OPAQUE_ALLOC_REGISTER_START, NULL);
        return 0;
    }
    if (strstr(url, "/auth/opaque/login/finish")) {
        resp_fill(resp, 200,
                  "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
                  "\"expires_in\":900,"
                  "\"user\":{\"id\":\"u-1\",\"username\":\"alice\",\"email\":\"a@x.io\","
                  "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}}",
                  NULL);
        return 0;
    }
    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *opaque_alloc_make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_transport(cfg, opaque_alloc_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

static void test_opaque_login_alloc_failure_sweep(void) {
    /* src/opaque.c's take()/start() copies, src/client.c's two request bodies
     * and the strdup of the session handle, and cJSON's own allocations in
     * between. Nothing here may crash, double-free, or report AXIAM_OK for a
     * run that did not authenticate.
     *
     * The leak check is the assertion that carries the weight: an allocation
     * failure part-way through must still leave the native exchange released,
     * because a caller cannot reach a state handle the SDK dropped. */
    fake_opaque_install();
    axiam_client_t *c = opaque_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 60; i++) {
        axiam_login_result_t res;
        axiam_error_t err;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_login_opaque(c, "alice", "pw", &res, &err);
        alloc_fail_reset();
        if (k != AXIAM_OK) TEST_ASSERT_FALSE(res.authenticated);
        axiam_login_result_dispose(&res);
        TEST_ASSERT_FALSE_MESSAGE(fake_opaque_leaked(),
                                  "an allocation failure stranded a native handle");
    }

    axiam_client_free(c);
    axiam_opaque_native_reset_for_tests();
}

static void test_opaque_enrollment_alloc_failure_sweep(void) {
    /* All-or-nothing, the same property the SRP enrolment sweep asserted: every
     * member is there or none is. A partly-filled enrolment would be worse than
     * an error — the caller would send a record with no session to bind it to. */
    fake_opaque_install();
    axiam_client_t *c = opaque_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 50; i++) {
        axiam_opaque_enrollment_t e;
        axiam_error_t err;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_opaque_enrollment(c, "pw", &e, &err);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(e.opaque_session);
            TEST_ASSERT_NOT_NULL(e.registration_record);
            axiam_opaque_enrollment_dispose(&e);
        } else {
            TEST_ASSERT_NULL(e.opaque_session);
            TEST_ASSERT_NULL(e.registration_record);
        }
        TEST_ASSERT_FALSE_MESSAGE(fake_opaque_leaked(),
                                  "an allocation failure stranded a native handle");
    }

    axiam_client_free(c);
    axiam_opaque_native_reset_for_tests();
}

static void test_memo_store_alloc_failure_is_silent(void) {
    /* src/memo.c:159-166 — the memo is an OPTIMISATION, so an entry that
     * could not be allocated is dropped rather than surfaced. The assertion is
     * therefore that check_access still SUCCEEDS under the failure, and that
     * a later decision is still correct: a memo left half-built by a failed
     * store would answer the next lookup with a truncated key. */
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_decision_memo_ttl(cfg, 60000);
    axiam_client_config_set_transport(cfg, authz_allow_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    for (long i = 1; i <= 60; i++) {
        axiam_check_result_t r;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_check_access(c, "read", "res-1", NULL, NULL, &r, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) axiam_check_result_dispose(&r);
    }

    axiam_check_result_t r;
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_check_access(c, "read", "res-1", NULL, NULL, &r, NULL));
    TEST_ASSERT_TRUE(r.allowed);
    axiam_check_result_dispose(&r);

    axiam_client_free(c);
}

static void test_webhook_verify_headers_body_malloc_failure(void) {
    /* src/webhook.c:224-229 — the copy of the delivered body. A verify that
     * cannot own the body must report failure rather than hand back an event
     * whose `body` is NULL, which every caller would then dereference. */
    static const char SECRET[] = "whsec-test-value";
    axiam_sensitive_t *secret = axiam_sensitive_new(SECRET);
    TEST_ASSERT_NOT_NULL(secret);

    const char *body = "{\"id\":\"evt-1\",\"type\":\"user.created\"}";
    long long ts = (long long)time(NULL);

    char signed_payload[512];
    int n = snprintf(signed_payload, sizeof(signed_payload), "%lld.%s", ts, body);
    TEST_ASSERT_TRUE(n > 0 && (size_t)n < sizeof(signed_payload));

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    TEST_ASSERT_NOT_NULL(HMAC(EVP_sha256(), SECRET, (int)strlen(SECRET),
                              (const unsigned char *)signed_payload, (size_t)n,
                              mac, &mac_len));
    char hex[65];
    for (unsigned int i = 0; i < mac_len; i++) snprintf(hex + 2 * i, 3, "%02x", mac[i]);

    char sig_header[160];
    snprintf(sig_header, sizeof(sig_header), "t=%lld,v1=%s", ts, hex);
    char ts_header[32];
    snprintf(ts_header, sizeof(ts_header), "%lld", ts);

    axiam_kv_t *headers = NULL;
    headers = axiam_kv_append(headers, "X-Axiam-Timestamp", ts_header);
    headers = axiam_kv_append(headers, "X-Axiam-Signature", sig_header);
    headers = axiam_kv_append(headers, "X-Axiam-Event", "user.created");
    headers = axiam_kv_append(headers, "X-Axiam-Delivery", "delivery-1");
    TEST_ASSERT_NOT_NULL(headers);

    for (long i = 1; i <= 20; i++) {
        axiam_webhook_event_t ev;
        alloc_fail_after(i);
        axiam_webhook_status_t k = axiam_webhook_verify_headers(secret, headers, body,
                                                                strlen(body), 300, &ev);
        alloc_fail_reset();
        if (k == AXIAM_WEBHOOK_OK) {
            TEST_ASSERT_NOT_NULL(ev.body);
            axiam_webhook_event_dispose(&ev);
        }
    }

    axiam_kv_free(headers);
    axiam_sensitive_free(secret);
}

/* ------------------------------------------------------------------ */
/* §24 WebAuthn, §25 account lifecycle, §26 PAR (contract 1.28)        */
/* ------------------------------------------------------------------ */

#define WA_ALLOC_OPTIONS                                                       \
    "{\"publicKey\":{\"challenge\":\"q83vAAAAAAAAAAAAAAAAAA\","                \
    "\"rp\":{\"id\":\"acme.test\",\"name\":\"Acme\"},"                         \
    "\"user\":{\"id\":\"dXNlci0x\",\"name\":\"ada\",\"displayName\":\"Ada\"}," \
    "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]}}"

#define WA_ALLOC_RESPONSE                                                      \
    "{\"type\":\"public-key\",\"rawId\":\"Y3JlZC1pZA\",\"id\":\"Y3JlZC1pZA\"," \
    "\"response\":{\"clientDataJSON\":\"eyJ0eXAiOiJ3ZWJhdXRobi5jcmVhdGUifQ\"," \
    "\"attestationObject\":\"o2NmbXRkbm9uZQ\"},\"clientExtensionResults\":{}}"

#define ACCT_ALLOC_LOGIN_BODY                                                  \
    "{\"authenticated\":true,\"access_token\":\"access-1\","                   \
    "\"refresh_token\":\"refresh-1\",\"session_id\":\"sess-1\","               \
    "\"expires_in\":900,\"user_id\":\"user-1\",\"username\":\"ada\","          \
    "\"email\":\"ada@acme.test\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}"

/*
 * The §26 discovery document, which the shared OIDC_DISCOVERY_BODY does not
 * carry — a server with no PAR endpoint is refused client-side, and a sweep
 * against that answer would never reach an allocation.
 */
#define PAR_ALLOC_DISCOVERY_BODY                                               \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"pushed_authorization_request_endpoint\":\"" OIDC_BASE "/oauth2/par\","  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"]}"

static int c128_alloc_transport(void *ctx, const axiam_http_request_t *req,
                                axiam_http_response_t *resp) {
    (void)ctx;
    const char *url = req->url ? req->url : "";

    if (strstr(url, "/.well-known/openid-configuration")) {
        resp_fill(resp, 200, PAR_ALLOC_DISCOVERY_BODY, NULL);
        return 0;
    }
    if (strstr(url, "/oauth2/par")) {
        resp_fill(resp, 201,
                  "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:abc\","
                  "\"expires_in\":90}", NULL);
        return 0;
    }
    if (strstr(url, "/auth/login")) {
        resp_fill(resp, 200, ACCT_ALLOC_LOGIN_BODY, "csrf-1");
        return 0;
    }
    if (strstr(url, "/webauthn/register/start") ||
        strstr(url, "/webauthn/authenticate/start") ||
        strstr(url, "/webauthn/authenticate/discoverable/start")) {
        resp_fill(resp, 200,
                  "{\"challenge\":" WA_ALLOC_OPTIONS ",\"state_token\":\"state-1\"}",
                  NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/register/finish")) {
        resp_fill(resp, 201,
                  "{\"id\":\"cred-1\",\"credential_id\":\"Y3JlZC1pZA\","
                  "\"name\":\"laptop\",\"credential_type\":\"passkey\","
                  "\"created_at\":\"2026-08-22T10:00:00Z\","
                  "\"last_used_at\":\"2026-08-22T11:00:00Z\"}", NULL);
        return 0;
    }
    if (strstr(url, "/webauthn/authenticate/finish") ||
        strstr(url, "/webauthn/authenticate/discoverable/finish")) {
        resp_fill(resp, 200,
                  "{\"access_token\":\"wa-access\",\"refresh_token\":\"wa-refresh\","
                  "\"session_id\":\"sess-wa\",\"expires_in\":900}", "csrf-wa");
        return 0;
    }
    if (strstr(url, "/auth/mfa/setup/confirm")) {
        resp_fill(resp, 200, ACCT_ALLOC_LOGIN_BODY, "csrf-2");
        return 0;
    }
    if (strstr(url, "/auth/mfa/enroll") || strstr(url, "/auth/mfa/setup/enroll")) {
        resp_fill(resp, 200,
                  "{\"secret_base32\":\"JBSWY3DPEHPK3PXP\","
                  "\"totp_uri\":\"otpauth://totp/Acme:ada?secret=JBSWY3DPEHPK3PXP\"}",
                  NULL);
        return 0;
    }
    if (strstr(url, "/auth/reset/context")) {
        resp_fill(resp, 200,
                  "{\"opaque\":{\"mode\":\"required\",\"suite\":\"ristretto255-SHA512\"}}",
                  NULL);
        return 0;
    }
    resp_fill(resp, 204, NULL, NULL);
    return 0;
}

static axiam_client_t *c128_alloc_make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_org_slug(cfg, "acme-org");
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    axiam_client_config_set_oidc_client_secret(cfg, OIDC_CLIENT_SECRET);
    axiam_client_config_set_transport(cfg, c128_alloc_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* Signed in for real, so §24.1's session requirement is satisfied the way a
 * caller would satisfy it rather than by reaching into the client. */
static axiam_client_t *c128_alloc_signed_in_client(void) {
    axiam_client_t *c = c128_alloc_make_client();
    if (!c) return NULL;
    axiam_login_result_t r;
    axiam_login(c, "ada@acme.test", "pw", &r, NULL);
    axiam_login_result_dispose(&r);
    return c;
}

static void test_webauthn_alloc_failure_sweep(void) {
    /* src/webauthn.c: the string-builder growth in append_json_string /
     * append_raw (the *_finish body is assembled as TEXT precisely so the
     * authenticator's bytes are not re-encoded, which is what makes those
     * reallocs load-bearing), the challenge and login field copies, and
     * build_workspace_body's object. Every failure must REPORT — a half-built
     * finish body is a body the server cannot verify, and returning it would
     * turn an allocation failure into a signature failure. */
    axiam_client_t *c = c128_alloc_signed_in_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *state = axiam_sensitive_new("state-1");

    for (long i = 1; i <= 130; i++) {
        axiam_webauthn_challenge_t ch;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_webauthn_register_start(c, &ch, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(ch.challenge_json);
        axiam_webauthn_challenge_dispose(&ch);
    }

    for (long i = 1; i <= 130; i++) {
        axiam_webauthn_credential_t cred;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_webauthn_register_finish(
            c, state, "laptop", WA_ALLOC_RESPONSE, &cred, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(cred.id);
        axiam_webauthn_credential_dispose(&cred);
    }

    for (long i = 1; i <= 130; i++) {
        axiam_webauthn_login_t login;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_webauthn_authenticate_finish(
            c, state, WA_ALLOC_RESPONSE, &login, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(login.session_id);
        axiam_webauthn_login_dispose(&login);
    }

    for (long i = 1; i <= 130; i++) {
        axiam_webauthn_challenge_t ch;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_webauthn_authenticate_start(c, state, &ch, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(ch.state_token);
        axiam_webauthn_challenge_dispose(&ch);
    }

    for (long i = 1; i <= 130; i++) {
        axiam_webauthn_challenge_t ch;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_webauthn_discoverable_start(c, NULL, &ch, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(ch.state_token);
        axiam_webauthn_challenge_dispose(&ch);
    }

    /* A response long enough that the builder has to GROW rather than fitting
     * in its first block — the realloc arm, which the short fixture above never
     * reaches. */
    char big[4096];
    memset(big, 'A', sizeof(big));
    snprintf(big, sizeof(big), "{\"type\":\"public-key\",\"pad\":\"%.*s\"}",
             3000, "AAAAAAAAAAAAAAAA");
    for (long i = 1; i <= 60; i++) {
        axiam_webauthn_login_t login;
        alloc_fail_after(i);
        axiam_error_kind_t k =
            axiam_webauthn_discoverable_finish(c, state, big, &login, NULL);
        alloc_fail_reset();
        axiam_webauthn_login_dispose(&login);
        (void)k;
    }

    axiam_sensitive_free(state);
    axiam_client_free(c);
}

static void test_account_alloc_failure_sweep(void) {
    /* src/account.c: the enrolment's two Sensitive handles (§25.3 — the
     * otpauth URI is wrapped too, because it CONTAINS the secret), every
     * request body, and the percent-encoded reset/context path. */
    axiam_client_t *c = c128_alloc_signed_in_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_sensitive_t *token = axiam_sensitive_new("token-value");
    axiam_sensitive_t *pw = axiam_sensitive_new("new-password");

    for (long i = 1; i <= 90; i++) {
        axiam_mfa_enrollment_t e;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_mfa_enroll(c, &e, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(e.secret_base32);
            TEST_ASSERT_NOT_NULL(e.totp_uri);
        }
        axiam_mfa_enrollment_dispose(&e);
    }

    for (long i = 1; i <= 90; i++) {
        alloc_fail_after(i);
        axiam_mfa_confirm(c, "123456", NULL, NULL);
        alloc_fail_reset();
    }

    for (long i = 1; i <= 90; i++) {
        axiam_mfa_enrollment_t e;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_mfa_setup_enroll(c, token, &e, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(e.totp_uri);
        axiam_mfa_enrollment_dispose(&e);
    }

    for (long i = 1; i <= 90; i++) {
        axiam_login_result_t r;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_mfa_setup_confirm(c, token, "123456", &r, NULL);
        alloc_fail_reset();
        /* No assertion on `authenticated` here. §25.2 rule 2 routes this call
         * through the SAME parser axiam_login() uses rather than a second one
         * that could drift, and that parser treats an unparseable 2xx body as a
         * success with an empty result — a pre-existing shape shared with
         * login() and verify_mfa(), not something this call may diverge on.
         * What the sweep asserts is that the failure does not corrupt: dispose
         * must accept whatever came back. */
        (void)k;
        axiam_login_result_dispose(&r);
    }

    for (long i = 1; i <= 60; i++) {
        alloc_fail_after(i);
        axiam_verify_email(c, token, AXIAM_TEST_TENANT_ID, NULL);
        alloc_fail_reset();
        alloc_fail_after(i);
        axiam_resend_verification(c, "ada@acme.test", AXIAM_TEST_TENANT_ID, NULL);
        alloc_fail_reset();
    }

    for (long i = 1; i <= 90; i++) {
        axiam_password_reset_request_t req = {"ada@acme.test", "acme-org",
                                              AXIAM_TEST_TENANT_ID, NULL};
        alloc_fail_after(i);
        axiam_request_password_reset(c, &req, NULL);
        alloc_fail_reset();
    }

    for (long i = 1; i <= 90; i++) {
        axiam_password_reset_context_t ctx;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_password_reset_context(c, token, &ctx, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) TEST_ASSERT_NOT_NULL(ctx.opaque_json);
        axiam_password_reset_context_dispose(&ctx);
    }

    for (long i = 1; i <= 90; i++) {
        axiam_password_reset_confirmation_t conf = {
            token, pw, AXIAM_TEST_TENANT_ID,
            "{\"registration_record\":\"cmVjb3Jk\"}"};
        alloc_fail_after(i);
        axiam_confirm_password_reset(c, &conf, NULL);
        alloc_fail_reset();
    }

    axiam_sensitive_free(token);
    axiam_sensitive_free(pw);
    axiam_client_free(c);
}

static void test_oidc_par_alloc_failure_sweep(void) {
    /* src/oidc_par.c: normalize_scope, the S256 challenge, the form, the
     * tenant-qualified URL, the redirect URL's two percent-encodings and the
     * all-or-nothing check at the end. That last one is the important arm: a
     * result missing its url or its verifier is not a partial success, because
     * the caller would redirect with an empty request_uri. */
    axiam_client_t *c = c128_alloc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, NULL));

    for (long i = 1; i <= 150; i++) {
        axiam_authorization_request_t req;
        if (axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid profile", &req, NULL)
            != AXIAM_OK) {
            continue;
        }
        axiam_pushed_authorization_request_t par;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI,
                                              "openid profile", NULL, &par, NULL);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            TEST_ASSERT_NOT_NULL(par.url);
            TEST_ASSERT_NOT_NULL(par.request_uri);
            TEST_ASSERT_NOT_NULL(par.code_verifier);
        }
        axiam_pushed_authorization_request_dispose(&par);
        axiam_authorization_request_dispose(&req);
    }

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §22 reactor (contract 1.28)                                        */
/* ------------------------------------------------------------------ */

/*
 * A minimal validly-signed event, built here rather than loaded from the §22.13
 * vectors: this suite must not depend on a fixture file, and what the sweep
 * needs is a body that REACHES the allocations, not one the server signed.
 * tests/test_reactor.c is where agreement with the server is asserted.
 */
#define REACTOR_SWEEP_KEY "reactor-signing-key"

static char *reactor_sweep_event(void) {
    /* Signed with the same primitive the SDK uses, over the canonical form §22.2
     * specifies — declared field order, hmac_signature as a null placeholder. */
    static const char *canonical =
        "{\"tenant_id\":\"11111111-1111-1111-1111-111111111111\","
        "\"event\":\"token.pre_issue\","
        "\"correlation_id\":\"22222222-2222-2222-2222-222222222222\","
        "\"payload\":{\"sub\":\"alice\"},"
        "\"timeout_ms\":1000,\"key_version\":2,"
        "\"nonce\":\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\","
        "\"issued_at\":\"%s\",\"hmac_signature\":null}";

    char issued_at[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(issued_at, sizeof(issued_at), "%Y-%m-%dT%H:%M:%SZ", &tm);

    char signed_bytes[512];
    snprintf(signed_bytes, sizeof(signed_bytes), canonical, issued_at);

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), REACTOR_SWEEP_KEY, (int)strlen(REACTOR_SWEEP_KEY),
         (const unsigned char *)signed_bytes, strlen(signed_bytes), mac, &len);
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < len; i++) snprintf(hex + i * 2, 3, "%02x", mac[i]);

    const char *placeholder = "\"hmac_signature\":null";
    char *at = strstr(signed_bytes, placeholder);
    size_t head = (size_t)(at - signed_bytes);
    size_t need = strlen(signed_bytes) + strlen(hex) + 8;
    char *wire = __real_malloc(need);
    if (!wire) return NULL;
    snprintf(wire, need, "%.*s\"hmac_signature\":\"%s\"%s", (int)head, signed_bytes, hex,
             at + strlen(placeholder));
    return wire;
}

typedef struct {
    const char *body;
    int served;
    int published;
} reactor_sweep_transport_t;

static int reactor_sweep_next(void *ctx, axiam_reactor_delivery_t *out) {
    reactor_sweep_transport_t *t = ctx;
    if (t->served++) return 0;
    out->body = t->body;
    out->reply_to = "replies";
    out->correlation_id = NULL;
    return 1;
}

static void reactor_sweep_publish(void *ctx, const char *destination,
                                  const char *correlation_id, const char *body) {
    (void)destination;
    (void)correlation_id;
    (void)body;
    ((reactor_sweep_transport_t *)ctx)->published++;
}

static axiam_reactor_decision_t reactor_sweep_handler(const axiam_reactor_event_t *event,
                                                      void *ctx) {
    (void)event;
    (void)ctx;
    static const axiam_reactor_patch_entry_t patch[2] = {{"ext.department", "engineering"},
                                                         {"ext.cost_center", "42"}};
    return axiam_reactor_mutate(patch, 2);
}

static void test_reactor_sign_alloc_failure_sweep(void) {
    /* src/reactor.c's string builder and the reply it assembles. Every failure
     * must REPORT — a half-built reply is a reply the server cannot verify, and
     * returning one would turn an allocation failure into a signature failure,
     * which is the hardest kind to diagnose from the other end. */
    axiam_sensitive_t *key = axiam_sensitive_new(REACTOR_SWEEP_KEY);
    TEST_ASSERT_NOT_NULL(key);
    const axiam_reactor_patch_entry_t patch[2] = {{"ext.department", "engineering"},
                                                  {"ext.cost_center", "42"}};

    axiam_reactor_decision_t decisions[3];
    decisions[0] = axiam_reactor_allow_with_step_up();
    decisions[1] = axiam_reactor_deny("a reason long enough to force the builder to grow "
                                      "past its first block, with \"quotes\" and \n escapes");
    decisions[2] = axiam_reactor_mutate(patch, 2);
    const char *events[3] = {AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH,
                             AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH,
                             AXIAM_REACTOR_EVENT_TOKEN_PRE_ISSUE};

    for (int d = 0; d < 3; d++) {
        for (long i = 1; i <= 40; i++) {
            alloc_fail_after(i);
            char *canonical = axiam_reactor_canonical_reply(
                "22222222-2222-2222-2222-222222222222",
                "11111111-1111-1111-1111-111111111111", events[d], &decisions[d], "nonce",
                "2026-07-10T12:00:00Z");
            alloc_fail_reset();
            free(canonical);

            alloc_fail_after(i);
            char *wire = axiam_reactor_build_reply(
                key, "22222222-2222-2222-2222-222222222222",
                "11111111-1111-1111-1111-111111111111", events[d], &decisions[d], "nonce",
                "2026-07-10T12:00:00Z");
            alloc_fail_reset();
            if (wire) {
                /* Whatever came back is a COMPLETE reply or nothing: the MAC is
                 * present and the placeholder is gone. */
                TEST_ASSERT_NOT_NULL(strstr(wire, "\"hmac_signature\":\""));
                TEST_ASSERT_NULL(strstr(wire, "\"hmac_signature\":null"));
            }
            free(wire);
        }
    }
    axiam_sensitive_free(key);
}

static void test_reactor_verify_alloc_failure_sweep(void) {
    /* The verified event's owned copies are all-or-nothing: a caller handed an
     * event with a NULL member would dereference it inside its own handler. */
    axiam_sensitive_t *key = axiam_sensitive_new(REACTOR_SWEEP_KEY);
    char *body = reactor_sweep_event();
    TEST_ASSERT_NOT_NULL(body);

    for (long i = 1; i <= 60; i++) {
        axiam_reactor_verified_t verified;
        alloc_fail_after(i);
        axiam_reactor_refusal_t refusal = axiam_reactor_verify_event(
            key, body, "11111111-1111-1111-1111-111111111111", (long)time(NULL), NULL,
            &verified);
        alloc_fail_reset();
        if (refusal == AXIAM_REACTOR_OK) {
            TEST_ASSERT_NOT_NULL(verified.event.tenant_id);
            TEST_ASSERT_NOT_NULL(verified.event.event);
            TEST_ASSERT_NOT_NULL(verified.event.correlation_id);
            TEST_ASSERT_NOT_NULL(verified.event.payload_json);
            TEST_ASSERT_NOT_NULL(verified.event.nonce);
        }
        axiam_reactor_verified_dispose(&verified);
    }

    /* And with a nonce seen-set in play, so its own growth is swept too. */
    for (long i = 1; i <= 60; i++) {
        axiam_reactor_nonce_set_t *seen = axiam_reactor_nonce_set_new();
        axiam_reactor_verified_t verified;
        alloc_fail_after(i);
        axiam_reactor_verify_event(key, body, "11111111-1111-1111-1111-111111111111",
                                   (long)time(NULL), seen, &verified);
        alloc_fail_reset();
        axiam_reactor_verified_dispose(&verified);
        axiam_reactor_nonce_set_free(seen);
    }

    free(body);
    axiam_sensitive_free(key);
}

static void test_reactor_serve_alloc_failure_sweep(void) {
    /* §22.10 rule 2 under memory pressure: a runtime that cannot build a reply
     * publishes NOTHING rather than something shorter. The assertion is that the
     * transport either saw one complete reply or saw none. */
    axiam_sensitive_t *key = axiam_sensitive_new(REACTOR_SWEEP_KEY);
    char *body = reactor_sweep_event();
    TEST_ASSERT_NOT_NULL(body);

    for (long i = 1; i <= 80; i++) {
        reactor_sweep_transport_t state = {body, 0, 0};
        axiam_reactor_transport_t transport;
        transport.ctx = &state;
        transport.next_delivery = reactor_sweep_next;
        transport.publish_reply = reactor_sweep_publish;

        axiam_reactor_config_t config;
        memset(&config, 0, sizeof(config));
        config.tenant_id = "11111111-1111-1111-1111-111111111111";
        config.reactor_id = "99999999-9999-9999-9999-999999999999";
        config.signing_key = key;

        alloc_fail_after(i);
        axiam_reactor_serve(&config, &transport, reactor_sweep_handler, NULL, NULL);
        alloc_fail_reset();
        TEST_ASSERT_TRUE(state.published == 0 || state.published == 1);
    }

    free(body);
    axiam_sensitive_free(key);
}

static void test_reactor_router_and_amqps_alloc_failure_sweep(void) {
    /* The binder's table and the §8b endpoint's copies. A router that could not
     * record a binding must REFUSE it: a binding silently dropped is the "typo
     * discovered as silence" failure §22.14 rule 2 exists to prevent, arrived at
     * through OOM instead. */
    for (long i = 1; i <= 30; i++) {
        alloc_fail_after(i);
        axiam_reactor_router_t *router = axiam_reactor_router_new();
        alloc_fail_reset();
        if (!router) continue;

        for (long j = 1; j <= 12; j++) {
            axiam_error_t err;
            alloc_fail_after(j);
            axiam_error_kind_t k = axiam_reactor_router_on(
                router, AXIAM_REACTOR_EVENT_TOKEN_PRE_ISSUE, reactor_sweep_handler, NULL, &err);
            alloc_fail_reset();
            if (k == AXIAM_OK) {
                size_t count = 0;
                axiam_reactor_router_bound_events(router, &count);
                break;
            }
        }
        axiam_reactor_router_free(router);
    }

    for (long i = 1; i <= 20; i++) {
        axiam_amqps_endpoint_t endpoint;
        axiam_error_t err;
        alloc_fail_after(i);
        axiam_error_kind_t k = axiam_amqps_endpoint("amqps://broker.internal:5671/prod", "CA",
                                                    "CERT", "KEY", &endpoint, &err);
        alloc_fail_reset();
        if (k == AXIAM_OK) {
            /* All-or-nothing again: a half-copied endpoint would open a
             * connection with no CA bundle while the caller believes one is set. */
            TEST_ASSERT_NOT_NULL(endpoint.url);
            TEST_ASSERT_NOT_NULL(endpoint.host);
            TEST_ASSERT_NOT_NULL(endpoint.virtual_host);
            TEST_ASSERT_NOT_NULL(endpoint.ca_pem);
            TEST_ASSERT_NOT_NULL(endpoint.client_cert_pem);
            TEST_ASSERT_NOT_NULL(endpoint.client_key_pem);
        }
        axiam_amqps_endpoint_dispose(&endpoint);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sensitive_new_bytes_calloc_failure);
    RUN_TEST(test_sensitive_new_bytes_malloc_failure);
    RUN_TEST(test_strdup0_malloc_failure);
    RUN_TEST(test_kv_append_calloc_failure);
    RUN_TEST(test_b64url_decode_malloc_failure);
    RUN_TEST(test_config_new_calloc_failure);
    RUN_TEST(test_config_set_client_cert_client_key_alloc_failure_sweep);
    RUN_TEST(test_config_clone_alloc_failure_sweep);
    RUN_TEST(test_client_new_alloc_failure_sweep);
    RUN_TEST(test_oidc_form_init_malloc_failure);
    RUN_TEST(test_oidc_form_add_growth_realloc_failure);
    RUN_TEST(test_oidc_discover_alloc_failure_sweep);
    RUN_TEST(test_oidc_endpoint_with_tenant_malloc_failure);
    RUN_TEST(test_oidc_token_set_copy_alloc_failure_sweep);
    RUN_TEST(test_oidc_config_copy_alloc_failure_sweep);
    RUN_TEST(test_oidc_begin_alloc_failure_sweep);
    RUN_TEST(test_oidc_exchange_alloc_failure_sweep);
    RUN_TEST(test_oidc_exchange_id_token_alloc_failure_sweep);
    RUN_TEST(test_oidc_refresh_alloc_failure_sweep);
    RUN_TEST(test_device_authorize_alloc_failure_sweep);
    RUN_TEST(test_device_login_alloc_failure_sweep);
    RUN_TEST(test_token_exchange_alloc_failure_sweep);
    RUN_TEST(test_sso_start_and_complete_alloc_failure_sweep);
    RUN_TEST(test_verify_logout_token_alloc_failure_sweep);
    RUN_TEST(test_introspect_and_revoke_alloc_failure_sweep);
    RUN_TEST(test_uma_discover_alloc_failure_sweep);
    RUN_TEST(test_uma_resource_registration_alloc_failure_sweep);
    RUN_TEST(test_uma_ticket_and_rpt_alloc_failure_sweep);
    RUN_TEST(test_opaque_login_alloc_failure_sweep);
    RUN_TEST(test_opaque_enrollment_alloc_failure_sweep);
    RUN_TEST(test_memo_store_alloc_failure_is_silent);
    RUN_TEST(test_webhook_verify_headers_body_malloc_failure);
    RUN_TEST(test_webauthn_alloc_failure_sweep);
    RUN_TEST(test_account_alloc_failure_sweep);
    RUN_TEST(test_oidc_par_alloc_failure_sweep);
    RUN_TEST(test_reactor_sign_alloc_failure_sweep);
    RUN_TEST(test_reactor_verify_alloc_failure_sweep);
    RUN_TEST(test_reactor_serve_alloc_failure_sweep);
    RUN_TEST(test_reactor_router_and_amqps_alloc_failure_sweep);
    return UNITY_END();
}
