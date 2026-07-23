#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"

/* Stringize the numeric version macros so we can build the expected
 * "MAJOR.MINOR.PATCH" prefix at compile time without hardcoding a literal. */
#define AXIAM_STR2(x) #x
#define AXIAM_STR(x) AXIAM_STR2(x)
#define AXIAM_VERSION_PREFIX \
    AXIAM_STR(AXIAM_VERSION_MAJOR) "." AXIAM_STR(AXIAM_VERSION_MINOR) "." AXIAM_STR(AXIAM_VERSION_PATCH)

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

/* C2 (src/sensitive.c:14): axiam_sensitive_new_bytes(NULL, ...) directly —
 * axiam_sensitive_new() itself never reaches this arm (it already returns
 * early on a NULL string before delegating). */
static void test_bytes_ctor_null_data(void) {
    TEST_ASSERT_NULL(axiam_sensitive_new_bytes(NULL, 5));
}

/* C2 (src/sensitive.c:48): axiam_sensitive_bytes(NULL) — the module-private
 * accessor's NULL-arg ternary arm, reachable only via internal.h. */
static void test_sensitive_bytes_null(void) {
    TEST_ASSERT_NULL(axiam_sensitive_bytes(NULL));
}

/* C2 (src/sensitive.c:30): axiam_sensitive_free() on a handle whose `data`
 * field is NULL — skips the scrub/free(data) arm but still frees the handle
 * itself. Constructed directly via the internal.h struct layout since the
 * public constructors never produce this shape. */
static void test_sensitive_free_with_null_data_field(void) {
    axiam_sensitive_t *s = malloc(sizeof(*s));
    TEST_ASSERT_NOT_NULL(s);
    s->data = NULL;
    s->len = 0;
    axiam_sensitive_free(s); /* must not crash */
}

static void test_version_string(void) {
    /* The accessor must return the compiled-in macro verbatim. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_VERSION, axiam_version());
    /* The version string must begin with MAJOR.MINOR.PATCH derived from the
     * numeric macros, catching drift between them and the string. The
     * pre-release suffix (e.g. "-alpha10") is intentionally not asserted so
     * routine version bumps don't break this test. */
    TEST_ASSERT_EQUAL_STRING_LEN(AXIAM_VERSION_PREFIX, axiam_version(),
                                 strlen(AXIAM_VERSION_PREFIX));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_version_string);
    RUN_TEST(test_to_string_is_redacted);
    RUN_TEST(test_len_is_metadata_only);
    RUN_TEST(test_null_inputs);
    RUN_TEST(test_bytes_ctor);
    RUN_TEST(test_bytes_ctor_null_data);
    RUN_TEST(test_sensitive_bytes_null);
    RUN_TEST(test_sensitive_free_with_null_data_field);
    return UNITY_END();
}
