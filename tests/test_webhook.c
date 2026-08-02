/* T-145 / CONTRACT §13 — webhook signature verification.
 *
 * The MAC is computed here in the test with OpenSSL directly from the spec
 * ("<t>.<raw_body>", HMAC-SHA256, hex lowercase) rather than copied from a
 * hardcoded hex string, so the shared cross-SDK vector pins every SDK to the
 * same bytes.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

/* --- the shared cross-SDK vector (CONTRACT §13.4) --- */
#define PIN_SECRET "whsec_test_0123456789abcdef"
#define PIN_TIMESTAMP 1785700000LL
#define PIN_BODY "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000000\"}"

void setUp(void) {}
void tearDown(void) {}

/* Compute the lowercase hex HMAC-SHA256 of "<ts>.<body>" under `secret`. */
static void sign_hex(const char *secret, long long ts, const char *body, char out[65]) {
    char signed_payload[1024];
    int n = snprintf(signed_payload, sizeof(signed_payload), "%lld.%s", ts, body);
    TEST_ASSERT_TRUE(n > 0 && (size_t)n < sizeof(signed_payload));

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    TEST_ASSERT_NOT_NULL(HMAC(EVP_sha256(), secret, (int)strlen(secret),
                              (const unsigned char *)signed_payload, (size_t)n,
                              mac, &mac_len));
    TEST_ASSERT_EQUAL_UINT(32, mac_len);
    for (unsigned int i = 0; i < mac_len; i++) snprintf(out + 2 * i, 3, "%02x", mac[i]);
    out[64] = '\0';
}

/* Build a "t=<ts>,v1=<hex>" header for (secret, ts, body). */
static void sign_header(const char *secret, long long ts, const char *body,
                        char *out, size_t out_len) {
    char hex[65];
    sign_hex(secret, ts, body, hex);
    snprintf(out, out_len, "t=%lld,v1=%s", ts, hex);
}

static axiam_sensitive_t *secret_of(const char *s) {
    axiam_sensitive_t *sec = axiam_sensitive_new(s);
    TEST_ASSERT_NOT_NULL(sec);
    return sec;
}

/* --- 1. valid signature + fresh timestamp --- */

static void test_valid_signature_is_accepted(void) {
    long long now = (long long)time(NULL);
    char header[256];
    sign_header(PIN_SECRET, now, PIN_BODY, header, sizeof(header));

    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    long long ts = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify(sec, header, PIN_BODY, strlen(PIN_BODY), 0, &ts));
    TEST_ASSERT_EQUAL_INT64(now, ts);
    axiam_sensitive_free(sec);
}

/* --- 2. the shared cross-SDK vector, verified at its own timestamp --- */

static void test_cross_sdk_pinned_vector(void) {
    char header[256];
    sign_header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, header, sizeof(header));

    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    long long ts = 0;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 300,
                                PIN_TIMESTAMP, &ts));
    TEST_ASSERT_EQUAL_INT64(PIN_TIMESTAMP, ts);

    /* Same vector, one byte of the body flipped -> rejected. */
    char tampered[256];
    snprintf(tampered, sizeof(tampered), "%s", PIN_BODY);
    tampered[10] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify_at(sec, header, tampered, strlen(tampered), 300,
                                PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* --- 3. tampered body --- */

static void test_tampered_body_is_rejected(void) {
    long long now = (long long)time(NULL);
    char header[256];
    sign_header(PIN_SECRET, now, PIN_BODY, header, sizeof(header));

    const char *tampered = "{\"event\":\"user.deleted\",\"id\":\"01JQ0000000000000000000000\"}";
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify(sec, header, tampered, strlen(tampered), 0, NULL));
    axiam_sensitive_free(sec);
}

/* --- 4. wrong secret --- */

static void test_wrong_secret_is_rejected(void) {
    long long now = (long long)time(NULL);
    char header[256];
    sign_header(PIN_SECRET, now, PIN_BODY, header, sizeof(header));

    axiam_sensitive_t *sec = secret_of("whsec_test_not_the_right_secret");
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify(sec, header, PIN_BODY, strlen(PIN_BODY), 0, NULL));
    axiam_sensitive_free(sec);
}

/* --- 5. freshness is two-sided --- */

static void test_stale_timestamp_is_rejected(void) {
    char header[256];
    sign_header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, header, sizeof(header));
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);

    /* now - t = 301 > 300 */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP + 301, NULL));
    /* exactly at the boundary is still accepted */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP + 300, NULL));
    /* a custom (tighter) tolerance is honoured */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 30,
                                PIN_TIMESTAMP + 31, NULL));
    axiam_sensitive_free(sec);
}

static void test_future_timestamp_is_rejected(void) {
    char header[256];
    sign_header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, header, sizeof(header));
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);

    /* t - now = 301 > 300: clock-skew abuse is refused like staleness. */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP - 301, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP - 300, NULL));
    axiam_sensitive_free(sec);
}

/* --- 6. malformed headers all fail closed --- */

static void test_malformed_headers_are_rejected(void) {
    char hex[65];
    sign_hex(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, hex);
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    char header[256];

    /* no v1 at all — "nothing to verify" is never success */
    snprintf(header, sizeof(header), "t=%lld", PIN_TIMESTAMP);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* only an unknown scheme present */
    snprintf(header, sizeof(header), "t=%lld,v9=%s", PIN_TIMESTAMP, hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* no t */
    snprintf(header, sizeof(header), "v1=%s", hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* duplicate t */
    snprintf(header, sizeof(header), "t=%lld,t=%lld,v1=%s", PIN_TIMESTAMP,
             PIN_TIMESTAMP, hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* non-numeric t */
    snprintf(header, sizeof(header), "t=not-a-number,v1=%s", hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* signed t (rejected: only plain decimal digits are accepted) */
    snprintf(header, sizeof(header), "t=-%lld,v1=%s", PIN_TIMESTAMP, hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* empty t */
    snprintf(header, sizeof(header), "t=,v1=%s", hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* empty header / no pairs at all */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, "", PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_at(sec, "garbage", PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* A v1 whose hex is malformed or the wrong length fails closed as a mismatch,
 * never as an accidental success. */
static void test_bad_hex_v1_is_rejected(void) {
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    char header[256];

    snprintf(header, sizeof(header), "t=%lld,v1=zz", PIN_TIMESTAMP);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* right length, non-hex characters */
    snprintf(header, sizeof(header),
             "t=%lld,v1=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
             PIN_TIMESTAMP);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* --- 7. forward compatibility: unknown keys ignored, several v1 accepted --- */

static void test_extra_keys_and_multiple_v1_candidates(void) {
    char hex[65];
    sign_hex(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, hex);
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    char header[512];

    /* a rotated-secret delivery carries several v1s; one match is enough */
    snprintf(header, sizeof(header),
             "t=%lld,v0=deadbeef,v1=%064d,v1=%s,scheme=future",
             PIN_TIMESTAMP, 0, hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* whitespace around the pairs is tolerated */
    snprintf(header, sizeof(header), " t = %lld , v1 = %s ", PIN_TIMESTAMP, hex);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));

    /* uppercase hex still decodes to the same bytes */
    char upper[65];
    for (int i = 0; i < 64; i++)
        upper[i] = (char)(hex[i] >= 'a' && hex[i] <= 'f' ? hex[i] - 32 : hex[i]);
    upper[64] = '\0';
    snprintf(header, sizeof(header), "t=%lld,v1=%s", PIN_TIMESTAMP, upper);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* --- 8. argument guards --- */

static void test_invalid_arguments(void) {
    char header[256];
    sign_header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, header, sizeof(header));
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);

    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT,
        axiam_webhook_verify_at(NULL, header, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT,
        axiam_webhook_verify_at(sec, NULL, PIN_BODY, strlen(PIN_BODY), 0,
                                PIN_TIMESTAMP, NULL));
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT,
        axiam_webhook_verify_at(sec, header, NULL, 12, 0, PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* An empty body is legitimate and must verify. */
static void test_empty_body_verifies(void) {
    char header[256];
    sign_header(PIN_SECRET, PIN_TIMESTAMP, "", header, sizeof(header));
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, NULL, 0, 0, PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* A body containing NUL bytes is signed over its full length, not to the
 * first NUL — the helper takes (pointer, length). */
static void test_binary_body_is_signed_in_full(void) {
    const char body[] = "{\"a\":\"\0b\"}";
    size_t body_len = sizeof(body) - 1;

    char signed_payload[64];
    int off = snprintf(signed_payload, sizeof(signed_payload), "%lld.", PIN_TIMESTAMP);
    memcpy(signed_payload + off, body, body_len);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), PIN_SECRET, (int)strlen(PIN_SECRET),
         (const unsigned char *)signed_payload, (size_t)off + body_len, mac, &mac_len);
    char hex[65];
    for (unsigned int i = 0; i < mac_len; i++) snprintf(hex + 2 * i, 3, "%02x", mac[i]);

    char header[256];
    snprintf(header, sizeof(header), "t=%lld,v1=%s", PIN_TIMESTAMP, hex);
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_at(sec, header, body, body_len, 0, PIN_TIMESTAMP, NULL));
    /* Truncating at the NUL must NOT verify. */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        axiam_webhook_verify_at(sec, header, body, strlen(body), 0, PIN_TIMESTAMP, NULL));
    axiam_sensitive_free(sec);
}

/* --- 9. the header-list convenience form --- */

static void test_verify_headers_extracts_event_and_delivery(void) {
    long long now = (long long)time(NULL);
    char sig[256], ts_str[32];
    sign_header(PIN_SECRET, now, PIN_BODY, sig, sizeof(sig));
    snprintf(ts_str, sizeof(ts_str), "%lld", now);

    axiam_kv_t *h = axiam_kv_append(NULL, "X-Axiam-Signature", sig);
    h = axiam_kv_append(h, "X-Axiam-Timestamp", ts_str);
    h = axiam_kv_append(h, "X-Axiam-Event", "user.created");
    h = axiam_kv_append(h, "X-Axiam-Delivery", "d3a1f0c2-0000-4000-8000-000000000001");

    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    axiam_webhook_event_t ev;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_headers(sec, h, PIN_BODY, strlen(PIN_BODY), 0, &ev));
    TEST_ASSERT_EQUAL_STRING("user.created", ev.event_type);
    TEST_ASSERT_EQUAL_STRING("d3a1f0c2-0000-4000-8000-000000000001", ev.delivery_id);
    TEST_ASSERT_EQUAL_STRING(PIN_BODY, ev.body);
    TEST_ASSERT_EQUAL_UINT(strlen(PIN_BODY), ev.body_len);
    TEST_ASSERT_EQUAL_INT64(now, ev.timestamp);
    axiam_webhook_event_dispose(&ev);
    axiam_webhook_event_dispose(&ev); /* idempotent */

    /* out_event is optional. */
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_OK,
        axiam_webhook_verify_headers(sec, h, PIN_BODY, strlen(PIN_BODY), 0, NULL));

    axiam_kv_free(h);
    axiam_sensitive_free(sec);
}

/* X-Axiam-Timestamp is redundant with t=; when it disagrees the delivery is
 * refused (only `t` is covered by the MAC). */
static void test_verify_headers_requires_timestamp_header_to_agree(void) {
    long long now = (long long)time(NULL);
    char sig[256], ts_str[32];
    sign_header(PIN_SECRET, now, PIN_BODY, sig, sizeof(sig));
    snprintf(ts_str, sizeof(ts_str), "%lld", now + 5);

    axiam_kv_t *h = axiam_kv_append(NULL, "X-Axiam-Signature", sig);
    h = axiam_kv_append(h, "X-Axiam-Timestamp", ts_str);

    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    axiam_webhook_event_t ev;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_headers(sec, h, PIN_BODY, strlen(PIN_BODY), 0, &ev));
    axiam_kv_free(h);

    /* a non-numeric timestamp header is equally refused */
    h = axiam_kv_append(NULL, "X-Axiam-Signature", sig);
    h = axiam_kv_append(h, "X-Axiam-Timestamp", "yesterday");
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_headers(sec, h, PIN_BODY, strlen(PIN_BODY), 0, NULL));
    axiam_kv_free(h);
    axiam_sensitive_free(sec);
}

static void test_verify_headers_without_signature_header(void) {
    axiam_kv_t *h = axiam_kv_append(NULL, "X-Axiam-Event", "user.created");
    axiam_sensitive_t *sec = secret_of(PIN_SECRET);
    axiam_webhook_event_t ev;
    TEST_ASSERT_EQUAL_INT(AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE,
        axiam_webhook_verify_headers(sec, h, PIN_BODY, strlen(PIN_BODY), 0, &ev));
    TEST_ASSERT_NULL(ev.event_type);
    axiam_kv_free(h);
    axiam_sensitive_free(sec);
}

/* --- 10. diagnostics never carry the expected signature --- */

static void test_status_strings_are_secret_free(void) {
    const axiam_webhook_status_t all[] = {
        AXIAM_WEBHOOK_OK, AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT,
        AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE, AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,
        AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP, AXIAM_WEBHOOK_ERR_INTERNAL};
    char hex[65];
    sign_hex(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY, hex);
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char *s = axiam_webhook_status_str(all[i]);
        TEST_ASSERT_NOT_NULL(s);
        TEST_ASSERT_TRUE(strlen(s) > 0);
        TEST_ASSERT_NULL(strstr(s, hex));
        TEST_ASSERT_NULL(strstr(s, PIN_SECRET));
    }
    TEST_ASSERT_EQUAL_STRING("unknown", axiam_webhook_status_str((axiam_webhook_status_t)999));
    axiam_webhook_event_dispose(NULL);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_valid_signature_is_accepted);
    RUN_TEST(test_cross_sdk_pinned_vector);
    RUN_TEST(test_tampered_body_is_rejected);
    RUN_TEST(test_wrong_secret_is_rejected);
    RUN_TEST(test_stale_timestamp_is_rejected);
    RUN_TEST(test_future_timestamp_is_rejected);
    RUN_TEST(test_malformed_headers_are_rejected);
    RUN_TEST(test_bad_hex_v1_is_rejected);
    RUN_TEST(test_extra_keys_and_multiple_v1_candidates);
    RUN_TEST(test_invalid_arguments);
    RUN_TEST(test_empty_body_verifies);
    RUN_TEST(test_binary_body_is_signed_in_full);
    RUN_TEST(test_verify_headers_extracts_event_and_delivery);
    RUN_TEST(test_verify_headers_requires_timestamp_header_to_agree);
    RUN_TEST(test_verify_headers_without_signature_header);
    RUN_TEST(test_status_strings_are_secret_free);
    return UNITY_END();
}
