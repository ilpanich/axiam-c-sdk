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

#ifndef AXIAM_REPO_ROOT
#error "AXIAM_REPO_ROOT must be defined by the build (see tests/CMakeLists.txt)."
#endif

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
/* The same stream with `events_requested` and `updated_at` taken out, for the cases that
 * choose them. */
#define STREAM_BASE_NO_EVENTS_REQUESTED                                                     \
    "\"id\":\"" STREAM_ID "\",\"tenant_id\":\"" TENANT "\",\"receiver_client_id\":\"rp\","  \
    "\"audience\":\"https://rp.example\",\"description\":null,"                             \
    "\"endpoint_url\":\"https://rp.example/ssf/push\",\"authorization_header_set\":true,"   \
    "\"events_delivered\":[],\"last_verification_at\":null,"                                \
    "\"created_at\":\"2026-10-04T00:00:00Z\",\"updated_at\":\"2026-10-04T00:00:00.5Z\""
#define STREAM_TAIL                                                                         \
    "\"events_allowed\":[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"],"                          \
    "\"delivery_method\":\"push\",\"subject_format\":\"iss_sub\",\"status\":\"enabled\","  \
    "\"status_reason\":null,\"status_actor\":\"admin\",\"transmitter_active\":true"
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
    /* Contract 1.61 (§32.8 test 1): an `events_requested` of [] is sent as [] ... */
    const cJSON *er = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsArray(er) && cJSON_GetArraySize(er) == 0,
                             "events_requested [] is sent as []");
    /* ... and `expected_updated_at`, unset, is absent from the body (never null). */
    TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at"),
                             "expected_updated_at is omitted when unset");
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

/* ---- Contract 1.61 (§32.2, §32.3 rule 4, §32.8 test 1) -------------------------------- */

static void test_expected_updated_at_is_sent_as_given_and_an_unset_events_requested_is_absent(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    /* Fewer fractional digits than a server would store: sent verbatim, not re-formatted. */
    in.expected_updated_at = (char *) "2026-10-04T00:00:00.123456789+02:00";
    mgmt_mount(200, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    cJSON *sent = cJSON_Parse(mgmt_last_body());
    const cJSON *ea = cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at");
    TEST_ASSERT_TRUE(cJSON_IsString(ea));
    TEST_ASSERT_EQUAL_STRING("2026-10-04T00:00:00.123456789+02:00", ea->valuestring);
    TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "events_requested"),
                             "an unset events_requested is absent, not [] and not null");
    cJSON_Delete(sent);

    /* Unset: no key at all, and never null. */
    fill_input(&in);
    mgmt_mount(200, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "expected_updated_at"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "null"));
    axiam_client_free(c);
}

static void test_a_409_on_update_is_the_conflict_class_and_is_not_retried(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    fill_input(&in);
    in.expected_updated_at = (char *) "2026-10-04T00:00:00Z";
    int before = mgmt_request_count();
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"the stream changed\"}");
    mgmt_mount_next(200, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "a 409 is not retried");
    axiam_client_free(c);
}

/* The read-modify-write form sends back what it read: the stream's `updated_at` as the
 * string the response carried, and `events_requested` -- a [] as [], a list as the list. */
static void test_the_read_modify_write_sends_back_events_requested_and_expected_updated_at(void) {
    static const char *const bodies[] = {
        "{" STREAM_BASE_NO_EVENTS_REQUESTED ",\"events_requested\":[]," STREAM_TAIL "}",
        "{" STREAM_BASE_NO_EVENTS_REQUESTED ",\"events_requested\":[\"" AXIAM_SSF_EVENT_SESSION_REVOKED "\"]," STREAM_TAIL "}",
    };
    for (int k = 0; k < 2; k++) {
        axiam_client_t *c = mgmt_signed_in_client();
        axiam_error_t err;
        axiam_mgmt_ssf_stream_t *stream = NULL;
        mgmt_mount(200, bodies[k]);
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
        axiam_mgmt_ssf_stream_input_t *in = axiam_mgmt_ssf_stream_to_input(stream);
        TEST_ASSERT_NOT_NULL(in);
        TEST_ASSERT_EQUAL_STRING("2026-10-04T00:00:00.5Z", in->expected_updated_at);
        mgmt_mount(200, STREAM_BODY);
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, in, NULL, &err));
        cJSON *sent = cJSON_Parse(mgmt_last_body());
        const cJSON *ea = cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at");
        TEST_ASSERT_TRUE(cJSON_IsString(ea));
        TEST_ASSERT_EQUAL_STRING_MESSAGE("2026-10-04T00:00:00.5Z", ea->valuestring,
                                         "the updated_at it read, verbatim");
        const cJSON *er = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
        TEST_ASSERT_TRUE_MESSAGE(cJSON_IsArray(er), "events_requested is sent back, never omitted");
        TEST_ASSERT_EQUAL_INT(k == 0 ? 0 : 1, cJSON_GetArraySize(er));
        cJSON_Delete(sent);
        axiam_mgmt_ssf_stream_input_free(in);
        axiam_mgmt_ssf_stream_free(stream);
        axiam_client_free(c);
        mgmt_reset();
    }
}

/* ---- §32.8 test 7 (contract 1.62): the change-taking form ----------------------------- */

#define EV_A AXIAM_SSF_EVENT_SESSION_REVOKED
#define EV_B AXIAM_SSF_EVENT_CREDENTIAL_CHANGE
#define EV_C AXIAM_SSF_EVENT_ACCOUNT_DISABLED
/* The server's own spelling of the instant: a `+00:00` offset and nine fraction digits. */
#define UPDATED_AT_NINE "2026-10-04T00:00:00.123456789+00:00"

#define STREAM_THREE_TWO(REQUESTED)                                                         \
    "{\"id\":\"" STREAM_ID "\",\"tenant_id\":\"" TENANT "\",\"receiver_client_id\":\"rp\"," \
    "\"audience\":\"https://rp.example\",\"description\":null,"                             \
    "\"endpoint_url\":\"https://rp.example/ssf/push\",\"authorization_header_set\":true,"   \
    "\"events_allowed\":[\"" EV_A "\",\"" EV_B "\",\"" EV_C "\"],"                          \
    "\"events_requested\":" REQUESTED ",\"events_delivered\":[],"                           \
    "\"last_verification_at\":null,\"created_at\":\"2026-10-04T00:00:00Z\","                \
    "\"updated_at\":\"" UPDATED_AT_NINE "\",\"delivery_method\":\"push\","                   \
    "\"subject_format\":\"iss_sub\",\"status\":\"enabled\",\"status_reason\":null,"        \
    "\"status_actor\":\"admin\",\"transmitter_active\":true}"

static axiam_mgmt_ssf_stream_t *read_stream(axiam_client_t *c, const char *body) {
    axiam_error_t err;
    axiam_mgmt_ssf_stream_t *stream = NULL;
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_get_stream(c, NULL, STREAM_ID, &stream, &err));
    TEST_ASSERT_NOT_NULL(stream);
    return stream;
}

static cJSON *send_update(axiam_client_t *c, const axiam_mgmt_ssf_stream_input_t *in) {
    axiam_error_t err;
    mgmt_mount(200, STREAM_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_ssf_update_stream(c, NULL, STREAM_ID, in, NULL, &err));
    cJSON *sent = cJSON_Parse(mgmt_last_body());
    TEST_ASSERT_TRUE(cJSON_IsObject(sent));
    return sent;
}

static void test_the_change_taking_form_cuts_events_requested_to_a_lowered_ceiling(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_ssf_stream_t *stream = read_stream(c, STREAM_THREE_TWO("[\"" EV_A "\",\"" EV_B "\"]"));

    /* Lower the ceiling to ONE of the two requested: only that one is left. */
    char ceiling[256];
    snprintf(ceiling, sizeof ceiling, "[\"%s\"]", EV_B);
    axiam_mgmt_ssf_stream_changes_t changes;
    memset(&changes, 0, sizeof changes);
    changes.events_allowed = ceiling;
    axiam_mgmt_ssf_stream_input_t *in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    TEST_ASSERT_NOT_NULL(in);
    cJSON *sent = send_update(c, in);
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(sent, "events_allowed");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(allowed));
    const cJSON *requested = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsArray(requested), "sent, never omitted");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, cJSON_GetArraySize(requested), "only what is in the new ceiling");
    TEST_ASSERT_EQUAL_STRING(EV_B, cJSON_GetArrayItem(requested, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING(UPDATED_AT_NINE,
                             cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at")->valuestring);
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    /* A ceiling that holds none of the requested ones leaves `[]`, not an absent member
     * (absent would RESET the stream to every allowed event). */
    snprintf(ceiling, sizeof ceiling, "[\"%s\"]", EV_C);
    in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    sent = send_update(c, in);
    requested = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
    TEST_ASSERT_TRUE(cJSON_IsArray(requested));
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(requested));
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    /* The order of the read list survives the cut. */
    snprintf(ceiling, sizeof ceiling, "[\"%s\",\"%s\"]", EV_B, EV_A);
    in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    sent = send_update(c, in);
    requested = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(requested));
    TEST_ASSERT_EQUAL_STRING(EV_A, cJSON_GetArrayItem(requested, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING(EV_B, cJSON_GetArrayItem(requested, 1)->valuestring);
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    /* An events_requested the caller names is sent as given: the server judges it. */
    snprintf(ceiling, sizeof ceiling, "[\"%s\"]", EV_B);
    char own[128];
    snprintf(own, sizeof own, "[\"%s\"]", EV_A);
    changes.events_requested = own;
    in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    sent = send_update(c, in);
    requested = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(requested));
    TEST_ASSERT_EQUAL_STRING(EV_A, cJSON_GetArrayItem(requested, 0)->valuestring);
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    axiam_mgmt_ssf_stream_free(stream);
    axiam_client_free(c);
}

static void test_the_change_taking_form_sends_what_it_read_when_events_are_untouched(void) {
    const char *requested_cases[] = { "[]", "[\"" EV_A "\",\"" EV_B "\"]" };
    const char *bodies[] = { STREAM_THREE_TWO("[]"), STREAM_THREE_TWO("[\"" EV_A "\",\"" EV_B "\"]") };
    for (int k = 0; k < 2; k++) {
        mgmt_reset();
        axiam_client_t *c = mgmt_signed_in_client();
        axiam_mgmt_ssf_stream_t *stream = read_stream(c, bodies[k]);
        axiam_mgmt_ssf_stream_changes_t changes;
        memset(&changes, 0, sizeof changes);
        changes.description = "edited"; /* a change that says nothing about events */
        axiam_mgmt_ssf_stream_input_t *in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
        cJSON *sent = send_update(c, in);
        cJSON *want = cJSON_Parse(requested_cases[k]);
        const cJSON *er = cJSON_GetObjectItemCaseSensitive(sent, "events_requested");
        TEST_ASSERT_TRUE_MESSAGE(cJSON_IsArray(er), "as read: an [] stays [], never omitted");
        TEST_ASSERT_TRUE(cJSON_Compare(er, want, 1));
        TEST_ASSERT_EQUAL_STRING("edited", cJSON_GetObjectItemCaseSensitive(sent, "description")->valuestring);
        /* The response's own string, byte for byte: a `+00:00` offset and nine fraction
         * digits come back as they went out, not re-rendered as `Z` or rounded. */
        TEST_ASSERT_EQUAL_STRING(UPDATED_AT_NINE,
                                 cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at")->valuestring);
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mgmt_last_body(), "\"" UPDATED_AT_NINE "\""), "verbatim in the wire text");
        TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "authorization_header"),
                                 "absent keeps the stored header");
        cJSON_Delete(want);
        cJSON_Delete(sent);
        axiam_mgmt_ssf_stream_input_free(in);
        axiam_mgmt_ssf_stream_free(stream);
        axiam_client_free(c);
    }
}

static void test_an_assigned_none_for_expected_updated_at_leaves_the_key_out(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_ssf_stream_t *stream = read_stream(c, STREAM_THREE_TWO("[\"" EV_A "\"]"));
    axiam_mgmt_ssf_stream_changes_t changes;
    memset(&changes, 0, sizeof changes);
    changes.no_expected_updated_at = 1;
    axiam_mgmt_ssf_stream_input_t *in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    TEST_ASSERT_NULL(in->expected_updated_at);
    cJSON *sent = send_update(c, in);
    TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at"), "the key is omitted");
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "null"), "null is never sent");
    TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "events_requested"),
                                 "the rest of what was read still goes back");
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    /* A value of the caller's own is sent as given. */
    changes.no_expected_updated_at = 0;
    changes.expected_updated_at = "2026-10-05T00:00:00Z";
    in = axiam_mgmt_ssf_stream_apply_changes(stream, &changes);
    sent = send_update(c, in);
    TEST_ASSERT_EQUAL_STRING("2026-10-05T00:00:00Z",
                             cJSON_GetObjectItemCaseSensitive(sent, "expected_updated_at")->valuestring);
    cJSON_Delete(sent);
    axiam_mgmt_ssf_stream_input_free(in);

    /* No changes at all is the plain converter. */
    in = axiam_mgmt_ssf_stream_apply_changes(stream, NULL);
    TEST_ASSERT_EQUAL_STRING(UPDATED_AT_NINE, in->expected_updated_at);
    axiam_mgmt_ssf_stream_input_free(in);
    TEST_ASSERT_NULL(axiam_mgmt_ssf_stream_apply_changes(NULL, &changes));
    axiam_mgmt_ssf_stream_free(stream);
    axiam_client_free(c);
}

/* A text file with its comment decoration collapsed ("\n * " and runs of blanks become one
 * space), so a phrase the wrapper split across lines is still one phrase. */
static char *read_flat(const char *relative) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", AXIAM_REPO_ROOT, relative);
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *raw = (char *) malloc((size_t) n + 1);
    TEST_ASSERT_EQUAL_UINT((size_t) n, fread(raw, 1, (size_t) n, f));
    raw[n] = '\0';
    fclose(f);
    char *flat = (char *) malloc((size_t) n + 1);
    size_t o = 0;
    for (size_t i = 0; raw[i]; i++) {
        if (raw[i] == '\n') {
            while (raw[i + 1] == ' ' || raw[i + 1] == '*') i++;
            flat[o++] = ' ';
        } else {
            flat[o++] = raw[i];
        }
    }
    flat[o] = '\0';
    free(raw);
    return flat;
}

/* A documentation check, not a mock: the header a caller reads at the call states the three
 * meanings of `events_requested`, and the plain converter's header names the caller's duty. */
static void test_the_update_stream_documentation_states_the_three_meanings(void) {
    char *ops = read_flat("include/axiam/management_ops.h");
    const char *at = strstr(ops, "axiam_error_kind_t axiam_ssf_update_stream(");
    TEST_ASSERT_NOT_NULL(at);
    /* The doc comment of the declaration: from the last comment opener before it. */
    const char *start = NULL;
    for (const char *p = ops; p < at;) {
        const char *q = strstr(p, "/** ");
        if (!q || q >= at) break;
        start = q;
        p = q + 3;
    }
    TEST_ASSERT_NOT_NULL(start);
    char *block = (char *) malloc((size_t) (at - start) + 1);
    memcpy(block, start, (size_t) (at - start));
    block[at - start] = '\0';
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "three meanings of `events_requested`"), "named");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "*resets* the stream to every event of"), "absent resets");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "**`[]`** is stored as the receiver's \"none\""), "[] is none");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "stored as given and refused (`400`)"), "a list");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "raw API client"), "the raw client is bound too");
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(block, "omitted `description`"), "the defaults of the omitted members");
    free(block);
    free(ops);

    char *helpers = read_flat("include/axiam/management_helpers.h");
    TEST_ASSERT_NOT_NULL_MESSAGE(
        strstr(helpers, "Cutting `events_requested` to the new `events_allowed` is the caller's duty"),
        "the plain converter names the caller's duty");
    TEST_ASSERT_NOT_NULL(strstr(helpers, "three meanings of `events_requested`"));
    TEST_ASSERT_NOT_NULL(strstr(helpers, "`409`"));
    free(helpers);
}

/* ---- B5 (contract 1.60; P12.2 (a)) ---------------------------------------------------
 *
 * Every local refusal is ONE category. C's row of §28.7 is `NULL` with `axiam_error_t` for a
 * constructor and the same `axiam_error_t` on the kind-returning operations: the SDK's
 * local ValidationError, which here is AXIAM_ERR_NETWORK with cause 400 -- the class
 * AXIAM_MGMT_ERR_VALIDATION, as the server's own 400 -- and a message that says no request
 * was sent. Not a different kind per refusal, and never an unclassified failure. */
static void test_B5_every_local_refusal_is_the_one_validation_category(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_ssf_stream_input_t in;
    int before = mgmt_request_count();

    /* A missing required member. */
    fill_input(&in);
    in.audience = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_create_stream(c, NULL, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(400, err.transport_cause);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));

    /* The same on the other write, and with no body at all. */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_update_stream(c, NULL, STREAM_ID, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(400, err.transport_cause);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));
    fill_input(&in);
    in.events_allowed = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_ssf_update_stream(c, NULL, STREAM_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));

    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), "a refusal sends nothing");
    axiam_client_free(c);

    /* The constructor's row: NULL, and the error out-parameter filled. */
    axiam_client_t *none = axiam_client_new(NULL, &err);
    TEST_ASSERT_NULL(none);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
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
    RUN_TEST(test_expected_updated_at_is_sent_as_given_and_an_unset_events_requested_is_absent);
    RUN_TEST(test_a_409_on_update_is_the_conflict_class_and_is_not_retried);
    RUN_TEST(test_the_read_modify_write_sends_back_events_requested_and_expected_updated_at);
    RUN_TEST(test_the_change_taking_form_cuts_events_requested_to_a_lowered_ceiling);
    RUN_TEST(test_the_change_taking_form_sends_what_it_read_when_events_are_untouched);
    RUN_TEST(test_an_assigned_none_for_expected_updated_at_leaves_the_key_out);
    RUN_TEST(test_the_update_stream_documentation_states_the_three_meanings);
    RUN_TEST(test_B5_every_local_refusal_is_the_one_validation_category);
    return UNITY_END();
}
