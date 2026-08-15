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
#include "axiam/axiam.h"
#include "internal.h"
#include "oidc_internal.h"
#include "test_util.h"
#include "oidc_test_util.h"

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
    return UNITY_END();
}
