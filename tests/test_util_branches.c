/* C2: src/util.c thin-branch depth — direct unit tests on the small
 * internal helpers (via src/internal.h), independent of any transport.
 *
 * Targets (per claude_dev/test-coverage-round2-plan.md, task C2):
 *  - axiam_strdup0 / axiam_str_ieq / axiam_is_pem NULL-arg branches.
 *  - axiam_kv_append's NULL-key no-op branch.
 *  - axiam_http_response_dispose(NULL).
 *  - axiam_b64url_decode: NULL input, padding-strip loop, invalid length
 *    (remainder == 1), invalid characters in the full-block / 2-char-tail /
 *    3-char-tail arms, a NULL out_len, and the '-' / '_' alphabet chars
 *    (src/util.c:75-77 — b64url_val's dash/underscore/default arms).
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "internal.h"

void setUp(void) {}
void tearDown(void) {}

static void test_strdup0_null(void) {
    TEST_ASSERT_NULL(axiam_strdup0(NULL));
}

static void test_strdup0_value(void) {
    char *s = axiam_strdup0("hello");
    TEST_ASSERT_EQUAL_STRING("hello", s);
    free(s);
}

static void test_str_ieq_null_args(void) {
    TEST_ASSERT_TRUE(axiam_str_ieq(NULL, NULL));   /* a == b (both NULL) */
    TEST_ASSERT_FALSE(axiam_str_ieq("x", NULL));
    TEST_ASSERT_FALSE(axiam_str_ieq(NULL, "x"));
}

static void test_str_ieq_case_insensitive(void) {
    TEST_ASSERT_TRUE(axiam_str_ieq("Content-Type", "content-type"));
    TEST_ASSERT_FALSE(axiam_str_ieq("Content-Type", "X-Other"));
}

static void test_is_pem_null(void) {
    TEST_ASSERT_EQUAL_INT(0, axiam_is_pem(NULL));
}

static void test_kv_append_null_key_is_noop(void) {
    axiam_kv_t *head = axiam_kv_append(NULL, NULL, "value");
    TEST_ASSERT_NULL(head);
    head = axiam_kv_append(NULL, "k", "v");
    axiam_kv_t *same = axiam_kv_append(head, NULL, "ignored");
    TEST_ASSERT_EQUAL_PTR(head, same);
    axiam_kv_free(head);
}

static void test_kv_append_null_value_stored_as_empty_string(void) {
    /* The `value ? value : ""` ternary's false arm (src/util.c:33). */
    axiam_kv_t *head = axiam_kv_append(NULL, "k", NULL);
    TEST_ASSERT_NOT_NULL(head);
    TEST_ASSERT_EQUAL_STRING("", axiam_kv_get(head, "k"));
    axiam_kv_free(head);
}

static void test_http_response_dispose_null(void) {
    axiam_http_response_dispose(NULL); /* must not crash */
}

static void test_secure_zero_null(void) {
    axiam_secure_zero(NULL, 8); /* src/util.c:27, false arm never exercised elsewhere */
}

/* --- axiam_url_is_secure (src/config.c only reaches it with a non-NULL,
 * non-empty base_url, so a handful of its own edge cases — a NULL argument,
 * an empty authority, an unterminated IPv6 literal, a same-length-but-wrong
 * scheme — are never exercised through that caller and are covered directly
 * here instead, via internal.h. */

static void test_url_is_secure_null(void) {
    TEST_ASSERT_EQUAL_INT(0, axiam_url_is_secure(NULL));
}

static void test_url_is_secure_five_char_scheme_that_is_not_https(void) {
    /* src/util.c:54 — scheme_len == 5 but strncasecmp() against "https"
     * fails, so the compound condition's second operand actually runs and
     * returns false, rather than short-circuiting on the length check alone. */
    TEST_ASSERT_EQUAL_INT(0, axiam_url_is_secure("httpx://iam.example.com"));
}

static void test_url_is_secure_empty_authority(void) {
    /* src/util.c:73 — host_len == 0, so the IPv6-bracket check's first
     * operand is false and the second is never evaluated. */
    TEST_ASSERT_EQUAL_INT(0, axiam_url_is_secure("http://"));
    TEST_ASSERT_EQUAL_INT(0, axiam_url_is_secure("http://:8080"));
}

static void test_url_is_secure_unterminated_ipv6_literal(void) {
    /* src/util.c:74-75 — host starts with '[' but no ']' ever appears, so
     * `close` is NULL and the bracket is NOT stripped from host_len. */
    TEST_ASSERT_EQUAL_INT(0, axiam_url_is_secure("http://[::1"));
}

/* --- axiam_b64url_decode --- */

static void test_b64url_decode_null_input(void) {
    size_t out_len = 999;
    TEST_ASSERT_NULL(axiam_b64url_decode(NULL, 0, &out_len));
}

static void test_b64url_decode_strips_padding(void) {
    /* "Zg==" is the padded base64 of the single byte 'f'; the '=' padding is
     * tolerated and stripped (src/util.c:83), leaving a 2-char remainder. */
    size_t out_len = 0;
    unsigned char *out = axiam_b64url_decode("Zg==", 4, &out_len);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_UINT(1, out_len);
    TEST_ASSERT_EQUAL_UINT8('f', out[0]);
    free(out);
}

static void test_b64url_decode_invalid_length_remainder_one(void) {
    /* 5 chars, no '=' to strip -> in_len % 4 == 1 -> invalid (src/util.c:86). */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCDE", 5, &out_len));
}

static void test_b64url_decode_invalid_char_full_block(void) {
    /* '!' is outside the base64url alphabet -> b64url_val returns -1 for the
     * full 4-char block (src/util.c:97). */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("AB!D", 4, &out_len));
}

static void test_b64url_decode_invalid_char_remainder_two(void) {
    /* One valid full block + an invalid 2-char tail (src/util.c:107). */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCD!!", 6, &out_len));
}

static void test_b64url_decode_invalid_char_remainder_three(void) {
    /* One valid full block + an invalid 3-char tail (src/util.c:114). */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCD!!!", 7, &out_len));
}

static void test_b64url_decode_valid_remainder_two_and_three(void) {
    /* rem==2 ("AA" -> 1 byte) and rem==3 ("AAA" -> 2 bytes) success arms. */
    size_t out_len = 0;
    unsigned char *out2 = axiam_b64url_decode("AA", 2, &out_len);
    TEST_ASSERT_NOT_NULL(out2);
    TEST_ASSERT_EQUAL_UINT(1, out_len);
    free(out2);

    unsigned char *out3 = axiam_b64url_decode("AAA", 3, &out_len);
    TEST_ASSERT_NOT_NULL(out3);
    TEST_ASSERT_EQUAL_UINT(2, out_len);
    free(out3);
}

static void test_b64url_decode_null_out_len(void) {
    /* The `if (out_len) *out_len = o;` guard, false arm (src/util.c:120). */
    unsigned char *out = axiam_b64url_decode("QUJD", 4, NULL); /* "ABC" */
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_MEMORY("ABC", out, 3);
    free(out);
}

static void test_b64url_decode_dash_and_underscore_alphabet(void) {
    /* Exercises b64url_val's '-' -> 62 and '_' -> 63 arms directly
     * (src/util.c:75-76); any 4-char block built only from these chars must
     * decode without error. */
    size_t out_len = 0;
    unsigned char *out = axiam_b64url_decode("--__", 4, &out_len);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_UINT(3, out_len);
    free(out);
}

static void test_b64url_decode_lowercase_alphabet(void) {
    /* b64url_val's 'a'-'z' arm (src/util.c:130) — every prior test used only
     * uppercase, digits, '-' and '_'. */
    size_t out_len = 0;
    unsigned char *out = axiam_b64url_decode("abcd", 4, &out_len);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_UINT(3, out_len);
    free(out);
}

static void test_b64url_decode_empty_string(void) {
    /* src/util.c:140 — the padding-strip while loop's own false arm: an
     * empty (non-NULL) input never enters the loop at all. */
    size_t out_len = 999;
    unsigned char *out = axiam_b64url_decode("", 0, &out_len);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_UINT(0, out_len);
    free(out);
}

static void test_b64url_decode_invalid_char_each_operand_full_block(void) {
    /* src/util.c:154 — `a<0 || b<0 || c<0 || d<0` for a full 4-char block.
     * The existing suite only ever fails on the THIRD char; independently
     * fail on the first, second and fourth so every `||` operand is actually
     * evaluated and taken at least once. */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("!BCD", 4, &out_len)); /* a<0 */
    TEST_ASSERT_NULL(axiam_b64url_decode("A!CD", 4, &out_len)); /* b<0 */
    TEST_ASSERT_NULL(axiam_b64url_decode("ABC!", 4, &out_len)); /* d<0 */
}

static void test_b64url_decode_invalid_char_each_operand_remainder_two(void) {
    /* src/util.c:164 — `a<0 || b<0` for the 2-char tail. The existing test
     * fails on 'a', short-circuiting before 'b' is ever checked. */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCDA!", 6, &out_len)); /* b<0 */
}

static void test_b64url_decode_invalid_char_each_operand_remainder_three(void) {
    /* src/util.c:171 — `a<0 || b<0 || c<0` for the 3-char tail. The existing
     * test fails on 'a'; cover 'b' and 'c' too. */
    size_t out_len = 0;
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCDA!A", 7, &out_len)); /* b<0 */
    TEST_ASSERT_NULL(axiam_b64url_decode("ABCDAA!", 7, &out_len)); /* c<0 */
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_strdup0_null);
    RUN_TEST(test_strdup0_value);
    RUN_TEST(test_str_ieq_null_args);
    RUN_TEST(test_str_ieq_case_insensitive);
    RUN_TEST(test_is_pem_null);
    RUN_TEST(test_kv_append_null_key_is_noop);
    RUN_TEST(test_kv_append_null_value_stored_as_empty_string);
    RUN_TEST(test_http_response_dispose_null);
    RUN_TEST(test_secure_zero_null);
    RUN_TEST(test_url_is_secure_null);
    RUN_TEST(test_url_is_secure_five_char_scheme_that_is_not_https);
    RUN_TEST(test_url_is_secure_empty_authority);
    RUN_TEST(test_url_is_secure_unterminated_ipv6_literal);
    RUN_TEST(test_b64url_decode_null_input);
    RUN_TEST(test_b64url_decode_strips_padding);
    RUN_TEST(test_b64url_decode_invalid_length_remainder_one);
    RUN_TEST(test_b64url_decode_invalid_char_full_block);
    RUN_TEST(test_b64url_decode_invalid_char_remainder_two);
    RUN_TEST(test_b64url_decode_invalid_char_remainder_three);
    RUN_TEST(test_b64url_decode_valid_remainder_two_and_three);
    RUN_TEST(test_b64url_decode_null_out_len);
    RUN_TEST(test_b64url_decode_dash_and_underscore_alphabet);
    RUN_TEST(test_b64url_decode_lowercase_alphabet);
    RUN_TEST(test_b64url_decode_empty_string);
    RUN_TEST(test_b64url_decode_invalid_char_each_operand_full_block);
    RUN_TEST(test_b64url_decode_invalid_char_each_operand_remainder_two);
    RUN_TEST(test_b64url_decode_invalid_char_each_operand_remainder_three);
    return UNITY_END();
}
