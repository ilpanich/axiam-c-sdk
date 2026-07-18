#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"

void setUp(void) {}
void tearDown(void) {}

static void test_to_string_is_redacted(void) {
    axiam_sensitive_t *s = axiam_sensitive_new("super-secret-token-value");
    TEST_ASSERT_NOT_NULL(s);
    const char *rendered = axiam_sensitive_to_string(s);
    /* §7: NEVER the raw value. */
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", rendered);
    TEST_ASSERT_NULL(strstr(rendered, "secret"));
    axiam_sensitive_free(s);
}

static void test_len_is_metadata_only(void) {
    axiam_sensitive_t *s = axiam_sensitive_new("abcdef");
    TEST_ASSERT_EQUAL_UINT(6, (unsigned)axiam_sensitive_len(s));
    axiam_sensitive_free(s);
}

static void test_null_inputs(void) {
    TEST_ASSERT_NULL(axiam_sensitive_new(NULL));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(NULL));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)axiam_sensitive_len(NULL));
    axiam_sensitive_free(NULL); /* must not crash */
}

static void test_bytes_ctor(void) {
    const unsigned char raw[] = {0x01, 0x00, 0x02, 0x03};
    axiam_sensitive_t *s = axiam_sensitive_new_bytes(raw, sizeof(raw));
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_EQUAL_UINT(4, (unsigned)axiam_sensitive_len(s));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(s));
    axiam_sensitive_free(s);
}

static void test_version_string(void) {
    TEST_ASSERT_EQUAL_STRING("1.0.0-alpha8", axiam_version());
    TEST_ASSERT_EQUAL_STRING("1.0.0-alpha8", AXIAM_VERSION);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_version_string);
    RUN_TEST(test_to_string_is_redacted);
    RUN_TEST(test_len_is_metadata_only);
    RUN_TEST(test_null_inputs);
    RUN_TEST(test_bytes_ctor);
    return UNITY_END();
}
