/*
 * CONTRACT.md §32.1 – §32.5 (contract 1.56) — the `ssf` management namespace: §32.8's six
 * management tests and the read-modify-write conversion. The receiver helper (§32.7) is
 * tested in test_ssf_receiver.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_helpers.h"
#include "axiam/management_ops.h"
#include "axiam/ssf.h"
#include "cJSON.h"
#include "management_test_util.h"
#include "test_util.h"

cJSON *axiam_mgmt_ssf_stream_build(const axiam_mgmt_ssf_stream_t *value);

#define TENANT "11111111-1111-4111-8111-111111111111"
#define STREAMS "/api/v1/tenants/" TENANT "/ssf/streams"
#define STREAM_ID "14141414-1414-4414-8414-141414141414"

#define STREAM_BASE                                                                         \
    "\"id\":\"" STREAM_ID "\",\"tenant_id\":\"" TENANT "\",\"receiver_client_id\":\"rp\","  \
    "\"audience\":\"https://rp.example\",\"description\":null,"                             \
    "\"endpoint_url\":\"https://rp.example/ssf/push\",\"authorization_header_set\":true,"   \
    "\"events_requested\":[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"],"                       \
    "\"events_delivered\":[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"],"                       \
    "\"last_verification_at\":null,\"created_at\":\"2026-10-04T00:00:00Z\","                \
    "\"updated_at\":\"2026-10-04T00:00:00Z\""
#define STREAM_FIELDS STREAM_BASE ",\"events_allowed\":[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"]"
#define STREAM_BODY                                                                         \
    "{" STREAM_FIELDS ",\"delivery_method\":\"push\",\"subject_format\":\"iss_sub\","        \
    "\"status\":\"enabled\",\"status_reason\":null,\"status_actor\":\"admin\","            \
    "\"transmitter_active\":true}"

static void random_secret(char *out, size_t cap) {
    unsigned char raw[24];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    size_t n = 0;
    for (size_t i = 0; i < sizeof raw && n + 2 < cap; i++, n += 2) snprintf(out + n, 3, "%02x", raw[i]);
    out[n] = '\0';
}

static void assert_no_fragment(const char *haystack, const char *secret) {
    size_t n = strlen(secret);
    for (size_t i = 0; haystack && i + 8 <= n; i++) {
        char frag[9];
        memcpy(frag, secret + i, 8);
        frag[8] = '\0';
        if (strstr(haystack, frag)) {
            char msg[96];
            snprintf(msg, sizeof msg, "an 8-character fragment of a secret (offset %zu) leaked", i);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

static void fill_input(axiam_mgmt_ssf_stream_input_t *in) {
    memset(in, 0, sizeof *in);
    in->receiver_client_id = (char *) "rp";
    in->audience = (char *) "https://rp.example";
    in->delivery_method = AXIAM_MGMT_SSF_DELIVERY_METHOD_PUSH;
    in->events_allowed = (char *) "[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"]";
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- 1. Replacement --------------------------------------------------------------- */

static void test_update_stream_puts_every_member_it_models(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    in.description = (char *) "risk engine";
    in.endpoint_url = (char *) "https://rp.example/ssf/push";
    in.clear_authorization_header = 0;
    in.has_clear_authorization_header = 1;
    in.events_requested = (char *) "[]";
    in.subject_format = AXIAM_MGMT_SSF_SUBJECT_FORMAT_EMAIL;
    in.has_subject_format = 1;
    in.status = AXIAM_MGMT_SSF_STREAM_STATUS_PAUSED;
    in.has_status = 1;
    in.status_reason = (char *) "maintenance";
    mgmt_mount(200, STREAM_BODY);
    axiam_mgmt_ssf_stream_t *stream = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, &stream, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(STREAMS "/" STREAM_ID, mgmt_last_path());
    cJSON *sent = cJSON_Parse(mgmt_last_body());
    static const char *const members[] = {
        "receiver_client_id", "audience", "delivery_method", "events_allowed", "description",
        "endpoint_url", "clear_authorization_header", "events_requested", "subject_format",
        "status", "status_reason",
    };
    for (size_t i = 0; i < sizeof members / sizeof members[0]; i++)
        TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, members[i]), members[i]);
    cJSON_Delete(sent);
    TEST_ASSERT_EQUAL_STRING("https://rp.example", stream->audience);
    TEST_ASSERT_TRUE(stream->authorization_header_set);
    axiam_mgmt_ssf_stream_free(stream);

    /* The input cannot be sent without its four pointer-valued required members (the
     * fourth, delivery_method, is a scalar whose zero is `push`). */
    int before = mgmt_request_count();
    for (int k = 0; k < 3; k++) {
        fill_input(&in);
        if (k == 0) in.receiver_client_id = NULL;
        if (k == 1) in.audience = NULL;
        if (k == 2) in.events_allowed = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    }
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* ---- 2. The header is Sensitive --------------------------------------------------- */

static void test_the_authorization_header_is_sensitive_both_ways(void) {
    char s[64], header[80];
    random_secret(s, sizeof s);
    snprintf(header, sizeof header, "Bearer %s", s);
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    in.endpoint_url = (char *) "https://rp.example/ssf/push";
    in.authorization_header = axiam_sensitive_new(header);
    assert_no_fragment(axiam_sensitive_to_string(in.authorization_header), s);

    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(201, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    TEST_ASSERT_EQUAL_STRING(STREAMS, mgmt_last_path());
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), s) != NULL, "the header is in the body");
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"audience\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    assert_no_fragment(err.message, s);
    axiam_sensitive_free(in.authorization_header);

    /* A response that (wrongly) carries one: dropped, no member, no trace. */
    char leaked[64], body[2048];
    random_secret(leaked, sizeof leaked);
    snprintf(body, sizeof body,
             "{" STREAM_FIELDS ",\"delivery_method\":\"push\",\"subject_format\":\"iss_sub\","
             "\"status\":\"enabled\",\"status_actor\":\"admin\",\"transmitter_active\":true,"
             "\"authorization_header\":\"%s\"}", leaked);
    mgmt_mount(200, body);
    axiam_mgmt_ssf_stream_t *stream = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
    cJSON *wire = axiam_mgmt_ssf_stream_build(stream);
    char *text = cJSON_PrintUnformatted(wire);
    assert_no_fragment(text, leaked);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(wire, "authorization_header"));
    free(text);
    cJSON_Delete(wire);
    axiam_mgmt_ssf_stream_free(stream);
    axiam_client_free(c);
}

/* ---- 3. Open decoding ------------------------------------------------------------- */

static void test_unknown_values_and_an_inactive_transmitter_decode(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(200, "{" STREAM_BASE ",\"delivery_method\":\"carrier_pigeon\","
                    "\"subject_format\":\"opaque\",\"status\":\"hibernating\","
                    "\"status_actor\":\"auditor\",\"events_allowed\":"
                    "[\"https://schemas.openid.net/secevent/caep/event-type/token-claims-change\"],"
                    "\"transmitter_active\":false,"
                    "\"transmitter_inactive_reason\":\"per-tenant issuers are off\"}");
    axiam_mgmt_ssf_stream_t *stream = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_DELIVERY_METHOD_UNKNOWN, stream->delivery_method);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_SUBJECT_FORMAT_UNKNOWN, stream->subject_format);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_STREAM_STATUS_UNKNOWN, stream->status);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_STATUS_ACTOR_UNKNOWN, stream->status_actor);
    TEST_ASSERT_NOT_NULL(strstr(stream->events_allowed, "token-claims-change"));
    TEST_ASSERT_FALSE(stream->transmitter_active);
    TEST_ASSERT_EQUAL_STRING("per-tenant issuers are off", stream->transmitter_inactive_reason);
    axiam_mgmt_ssf_stream_free(stream);

    mgmt_mount(200, "{" STREAM_FIELDS ",\"delivery_method\":\"poll\",\"subject_format\":\"email\","
                    "\"status\":\"disabled\",\"status_actor\":\"receiver\",\"transmitter_active\":false}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
    TEST_ASSERT_FALSE(stream->transmitter_active);
    TEST_ASSERT_NULL(stream->transmitter_inactive_reason);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_DELIVERY_METHOD_POLL, stream->delivery_method);
    axiam_mgmt_ssf_stream_free(stream);

    /* The event-type URIs name their constants by their last path segment, and the
     * receiver's macros spell the same wire values. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_SSF_EVENT_ACCOUNT_PURGED,
                             axiam_mgmt_ssf_event_type_to_wire(AXIAM_MGMT_SSF_EVENT_TYPE_ACCOUNT_PURGED));
    axiam_mgmt_ssf_event_type_t t;
    TEST_ASSERT_EQUAL_INT(0, axiam_mgmt_ssf_event_type_from_wire(AXIAM_SSF_EVENT_CREDENTIAL_CHANGE, &t));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_EVENT_TYPE_CREDENTIAL_CHANGE, t);
    TEST_ASSERT_EQUAL_INT(0, axiam_mgmt_ssf_event_type_from_wire(AXIAM_SSF_EVENT_VERIFICATION, &t));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SSF_EVENT_TYPE_UNKNOWN, t);
    axiam_client_free(c);
}

/* ---- 4. Pagination ---------------------------------------------------------------- */

static void test_list_streams_pages_with_search(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(200, "{\"items\":[" STREAM_BODY "],\"total\":4,\"offset\":0,\"limit\":1}");
    mgmt_mount(200, "{\"items\":[" STREAM_BODY "],\"total\":4,\"offset\":1,\"limit\":1}");
    axiam_mgmt_page_req_t req = {0, 1, "rp.example"};
    axiam_mgmt_ssf_stream_page_t *page = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_list_streams(c, NULL, &req, &page, &err));
    TEST_ASSERT_EQUAL_STRING(STREAMS, mgmt_last_path());
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_url(), "search=rp.example"));
    TEST_ASSERT_EQUAL_INT(4, (int) page->total);
    TEST_ASSERT_EQUAL_INT(1, (int) page->count);
    axiam_mgmt_ssf_stream_page_free(page);

    /* The auto-pager walks to the empty page, the term on every request (§32.8 t4). */
    axiam_client_free(c);
    mgmt_reset();
    c = mgmt_signed_in_client();
    mgmt_mount(200, "{\"items\":[" STREAM_BODY "," STREAM_BODY "],\"total\":3,\"offset\":0,\"limit\":2}");
    mgmt_mount(200, "{\"items\":[" STREAM_BODY "],\"total\":3,\"offset\":2,\"limit\":2}");
    mgmt_mount(200, "{\"items\":[],\"total\":3,\"offset\":4,\"limit\":2}");
    int before = mgmt_request_count();
    axiam_mgmt_page_req_t first = {0, 2, "rp.example"};
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_list_streams_all(c, NULL, &first, &page, &err));
    TEST_ASSERT_EQUAL_INT(3, mgmt_request_count() - before);
    static const char *const offsets[] = {"offset=0", "offset=2", "offset=4"};
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(before + i), "search=rp.example"));
        TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(before + i), offsets[i]));
    }
    TEST_ASSERT_EQUAL_INT(3, (int) page->count);
    TEST_ASSERT_EQUAL_INT(3, (int) page->total);
    axiam_mgmt_ssf_stream_page_free(page);
    axiam_client_free(c);
}

/* ---- 5. No retry ------------------------------------------------------------------ */

static void test_no_write_is_retried_on_503(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    for (int k = 0; k < 3; k++) {
        int before = mgmt_request_count();
        mgmt_mount(503, NULL);
        mgmt_mount_next(200, STREAM_BODY);
        axiam_error_kind_t rc;
        switch (k) {
            case 0: rc = axiam_ssf_create_stream(c, NULL, &in, NULL, &err); break;
            case 1: rc = axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err); break;
            default: rc = axiam_ssf_delete_stream(c, NULL, STREAM_ID, &err); break;
        }
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
        TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "exactly one request");
        mgmt_reset();
        axiam_client_free(c);
        c = mgmt_signed_in_client();
    }
    axiam_client_free(c);
}

/* ---- 6. Errors -------------------------------------------------------------------- */

static void test_errors_map_per_section_2(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"endpoint_url: moving it needs the header again\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "needs the header again"));
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"audience\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"no\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_ssf_get_stream(c, NULL, STREAM_ID, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    mgmt_mount(401, "{\"error\":\"unauthorized\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_ssf_get_stream(c, NULL, STREAM_ID, NULL, &err));
    axiam_client_free(c);
}

static void test_a_read_converts_into_the_replacement_body_without_the_header(void) {
    mgmt_mount(200, STREAM_BODY);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_t *stream = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
    axiam_mgmt_ssf_stream_input_t *in = axiam_mgmt_ssf_stream_to_input(stream);
    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NULL_MESSAGE(in->authorization_header, "absent keeps the stored header");
    TEST_ASSERT_EQUAL_STRING("https://rp.example", in->audience);
    TEST_ASSERT_EQUAL_STRING("https://rp.example/ssf/push", in->endpoint_url);
    TEST_ASSERT_TRUE(in->has_status);
    mgmt_mount(200, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, in, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "authorization_header"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "events_delivered"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "transmitter_active"));
    axiam_mgmt_ssf_stream_input_free(in);
    axiam_mgmt_ssf_stream_free(stream);
    TEST_ASSERT_NULL(axiam_mgmt_ssf_stream_to_input(NULL));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_update_stream_puts_every_member_it_models);
    RUN_TEST(test_the_authorization_header_is_sensitive_both_ways);
    RUN_TEST(test_unknown_values_and_an_inactive_transmitter_decode);
    RUN_TEST(test_list_streams_pages_with_search);
    RUN_TEST(test_no_write_is_retried_on_503);
    RUN_TEST(test_errors_map_per_section_2);
    RUN_TEST(test_a_read_converts_into_the_replacement_body_without_the_header);
    return UNITY_END();
}
