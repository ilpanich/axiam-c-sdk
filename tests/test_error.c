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

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_status_mapping);
    RUN_TEST(test_set_reset);
    RUN_TEST(test_message_truncation);
    RUN_TEST(test_kind_str);
    return UNITY_END();
}
