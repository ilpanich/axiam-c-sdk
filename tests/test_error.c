#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"

void setUp(void) {}
void tearDown(void) {}

static void test_status_mapping(void) {
    /* CONTRACT.md §2 table. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_error_kind_from_http_status(200));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_error_kind_from_http_status(204));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(400));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_error_kind_from_http_status(401));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_error_kind_from_http_status(403));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(408));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_error_kind_from_http_status(409));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(429));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(500));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(503));
}

static void test_set_reset(void) {
    axiam_error_t err;
    axiam_error_set(&err, AXIAM_ERR_AUTH, 401, "bad creds");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, err.kind);
    TEST_ASSERT_EQUAL_INT(401, (int)err.transport_cause);
    TEST_ASSERT_EQUAL_STRING("bad creds", err.message);
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, err.kind);
    TEST_ASSERT_EQUAL_STRING("", err.message);
    /* NULL-safety */
    axiam_error_set(NULL, AXIAM_ERR_AUTH, 0, "x");
    axiam_error_reset(NULL);
}

static void test_message_truncation(void) {
    axiam_error_t err;
    char big[600];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    axiam_error_set(&err, AXIAM_ERR_NETWORK, 0, big);
    TEST_ASSERT_TRUE(strlen(err.message) < sizeof(err.message));
}

static void test_kind_str(void) {
    TEST_ASSERT_EQUAL_STRING("ok", axiam_error_kind_str(AXIAM_OK));
    TEST_ASSERT_EQUAL_STRING("auth", axiam_error_kind_str(AXIAM_ERR_AUTH));
    TEST_ASSERT_EQUAL_STRING("authz", axiam_error_kind_str(AXIAM_ERR_AUTHZ));
    TEST_ASSERT_EQUAL_STRING("network", axiam_error_kind_str(AXIAM_ERR_NETWORK));
}

/* D2: an unmapped 3xx (redirect) status falls through the switch and the
 * >= 500 check, hitting the final "unexpected status" catch-all. */
static void test_status_mapping_redirect_fallthrough(void) {
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_error_kind_from_http_status(302));
}

/* D2: axiam_error_set with a NULL msg clears the message instead of copying. */
static void test_set_with_null_message(void) {
    axiam_error_t err;
    axiam_error_set(&err, AXIAM_ERR_NETWORK, 12, "leftover");
    TEST_ASSERT_EQUAL_STRING("leftover", err.message);
    axiam_error_set(&err, AXIAM_ERR_NETWORK, 34, NULL);
    TEST_ASSERT_EQUAL_INT(34, (int)err.transport_cause);
    TEST_ASSERT_EQUAL_STRING("", err.message);
}

/* D2: an out-of-range kind value hits axiam_error_kind_str's default arm. */
static void test_kind_str_unknown_default(void) {
    TEST_ASSERT_EQUAL_STRING("unknown", axiam_error_kind_str((axiam_error_kind_t)999));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_status_mapping);
    RUN_TEST(test_set_reset);
    RUN_TEST(test_message_truncation);
    RUN_TEST(test_kind_str);
    RUN_TEST(test_status_mapping_redirect_fallthrough);
    RUN_TEST(test_set_with_null_message);
    RUN_TEST(test_kind_str_unknown_default);
    return UNITY_END();
}
