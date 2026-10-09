/*
 * CONTRACT.md §30.5, §31.5, §32.5 and §7 (contract 1.59, R-19): a write-only secret —
 * `bind_secret`, `credential`, `authorization_header` — "MUST NOT be kept after the
 * request". The rendered JSON request body that carries it is heap memory: released
 * without `axiam_secure_zero`, the secret survives in the freed block.
 *
 * This binary wraps free() and realloc() at link time (GNU ld --wrap, as
 * test_alloc_failures does for the allocators). While a secret is being watched, every
 * block the library releases — by free(), or by a realloc() that may move it — is
 * searched for the secret before it goes back to the allocator. A block that still holds
 * it is a copy the library let go unscrubbed. Each case runs a §30 / §31 / §32 write with
 * a fresh secret and asserts the count is zero.
 *
 * The secret is generated at run time; no literal. A failure names the operation, never
 * the secret.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

/* Under valgrind a released block's unwritten tail is "uninitialised", and searching it
 * would be reported as a use of uninitialised memory. The search is the point of this
 * file, so the block is marked defined first. memcheck.h ships with valgrind; without it
 * (and outside valgrind) the mark is a no-op. */
#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define MARK_DEFINED(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#endif
#endif
#ifndef MARK_DEFINED
#define MARK_DEFINED(p, n) ((void) 0)
#endif

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_helpers.h"
#include "axiam/management_ops.h"
#include "cJSON.h"
#include "internal.h"
#include "management_test_util.h"
#include "test_util.h"

/* ------------------------------------------------------------------ */
/* The release watch                                                  */
/* ------------------------------------------------------------------ */

extern void __real_free(void *ptr);
extern void *__real_realloc(void *ptr, size_t size);

static char g_watch[64];
static size_t g_watch_len; /* 0 = not watching */
static int g_unscrubbed;   /* blocks released still holding the secret */
static int g_released;     /* blocks released while watching, for a sanity floor */

static void inspect(void *ptr) {
    if (!g_watch_len || !ptr) return;
    g_released++;
    size_t n = malloc_usable_size(ptr);
    MARK_DEFINED(ptr, n);
    if (n >= g_watch_len && memmem(ptr, n, g_watch, g_watch_len)) g_unscrubbed++;
}

void __wrap_free(void *ptr) {
    inspect(ptr);
    __real_free(ptr);
}

void *__wrap_realloc(void *ptr, size_t size) {
    inspect(ptr); /* a moving realloc releases the old block as it is */
    return __real_realloc(ptr, size);
}

static void watch(const char *secret) {
    snprintf(g_watch, sizeof g_watch, "%s", secret);
    g_watch_len = strlen(g_watch);
    g_unscrubbed = 0;
    g_released = 0;
}

static int unwatch(void) {
    g_watch_len = 0;
    return g_unscrubbed;
}

static void random_secret(char *out, size_t cap) {
    unsigned char raw[24];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    size_t n = 0;
    for (size_t i = 0; i < sizeof raw && n + 2 < cap; i++, n += 2) snprintf(out + n, 3, "%02x", raw[i]);
    out[n] = '\0';
}

#define TARGET_ID "12121212-1212-4212-8212-121212121212"
#define STREAM_ID "13131313-1313-4313-8313-131313131313"
#define REFUSED "{\"error\":\"validation_error\",\"message\":\"refused\"}"

static void expect_scrubbed(const char *operation) {
    int left = unwatch();
    char msg[160];
    snprintf(msg, sizeof msg, "%s released %d block(s) still holding the secret", operation, left);
    TEST_ASSERT_TRUE_MESSAGE(g_released > 0, "the watch saw no release at all");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, left, msg);
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) { g_watch_len = 0; }

/* ---- §30: bind_secret --------------------------------------------------------------- */

static void test_directory_set_and_update_scrub_the_rendered_body(void) {
    char s[64];
    random_secret(s, sizeof s);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    axiam_mgmt_set_directory_config_t set;
    memset(&set, 0, sizeof set);
    set.enabled = 1;
    set.kind = AXIAM_MGMT_DIRECTORY_KIND_ACTIVE_DIRECTORY;
    set.url = (char *) "ldaps://dc.corp.example";
    set.bind_dn = (char *) "cn=svc,dc=corp";
    set.base_dn = (char *) "dc=corp";
    set.user_filter = (char *) "(sAMAccountName={username})";
    set.bind_secret = axiam_sensitive_new(s);
    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, &set, NULL, &err));
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), s) != NULL, "the secret was sent");
    expect_scrubbed("directory.set");
    axiam_sensitive_free(set.bind_secret);

    axiam_mgmt_update_directory_config_t upd;
    memset(&upd, 0, sizeof upd);
    upd.bind_secret = axiam_sensitive_new(s);
    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_update(c, NULL, &upd, NULL, &err));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    expect_scrubbed("directory.update");
    axiam_sensitive_free(upd.bind_secret);
    axiam_client_free(c);
}

/* ---- §31: credential ---------------------------------------------------------------- */

static void test_scim_targets_create_and_update_scrub_the_rendered_body(void) {
    char s[64];
    random_secret(s, sizeof s);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_scim_target_input_t in;
    memset(&in, 0, sizeof in);
    in.name = (char *) "Downstream";
    in.base_url = (char *) "https://idp.example/scim/v2";
    in.auth = axiam_mgmt_scim_target_auth_bearer();
    in.scope = axiam_mgmt_scim_target_scope_all_users();
    in.credential = axiam_sensitive_new(s);

    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_create(c, &in, NULL, &err));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    expect_scrubbed("scim_targets.create");

    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    expect_scrubbed("scim_targets.update");

    axiam_mgmt_scim_target_auth_free(in.auth);
    axiam_mgmt_scim_target_scope_free(in.scope);
    axiam_sensitive_free(in.credential);
    axiam_client_free(c);
}

/* ---- §32: authorization_header ------------------------------------------------------ */

static void test_ssf_create_and_update_stream_scrub_the_rendered_body(void) {
    char s[64], header[80];
    random_secret(s, sizeof s);
    snprintf(header, sizeof header, "Bearer %s", s);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    memset(&in, 0, sizeof in);
    in.receiver_client_id = (char *) "rp";
    in.audience = (char *) "https://rp.example";
    in.delivery_method = AXIAM_MGMT_SSF_DELIVERY_METHOD_PUSH;
    in.events_allowed = (char *) "[\"https://schemas.openid.net/secevent/caep/event-type/session-revoked\"]";
    in.endpoint_url = (char *) "https://rp.example/ssf/push";
    in.authorization_header = axiam_sensitive_new(header);

    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    expect_scrubbed("ssf.create_stream");

    mgmt_mount(400, REFUSED);
    watch(s);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    expect_scrubbed("ssf.update_stream");

    axiam_sensitive_free(in.authorization_header);
    axiam_client_free(c);
}

/* ---- the watch itself --------------------------------------------------------------- */

/* The instrument can see what it is meant to: a block holding the secret, freed as it
 * is, is counted — so a zero above is a measurement, not a blind spot. */
static void test_the_watch_counts_an_unscrubbed_release(void) {
    char s[64];
    random_secret(s, sizeof s);
    watch(s);
    char *copy = strdup(s);
    TEST_ASSERT_NOT_NULL(copy);
    free(copy);
    TEST_ASSERT_EQUAL_INT(1, unwatch());
    /* ... and a scrubbed one is not. */
    watch(s);
    copy = strdup(s);
    TEST_ASSERT_NOT_NULL(copy);
    axiam_secure_zero(copy, strlen(copy));
    free(copy);
    TEST_ASSERT_EQUAL_INT(0, unwatch());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_watch_counts_an_unscrubbed_release);
    RUN_TEST(test_directory_set_and_update_scrub_the_rendered_body);
    RUN_TEST(test_scim_targets_create_and_update_scrub_the_rendered_body);
    RUN_TEST(test_ssf_create_and_update_stream_scrub_the_rendered_body);
    return UNITY_END();
}
