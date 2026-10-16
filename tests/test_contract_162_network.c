/*
 * CONTRACT.md contract 1.62 (§34.6 item l, §36.8): the `network` namespace -- segments,
 * reply profiles and the tenant's Session-Timeout cap -- against the fake transport.
 *
 * The generated suite (test_management_generated.c) already proves every one of the
 * twelve operations reaches its route, discards its result, rejects a wrong-shaped body and
 * survives an allocation failure at every point. What it cannot know are §36.8's five
 * required assertions, which are about the CONTENT of what is sent and what is surfaced:
 *
 *   1. the surface: twelve operations, and nothing that reaches the decision route;
 *   2. versions: each write carries the version it was given, exactly, and a 409 is one
 *      request that exposes its `reason_code`;
 *   3. closed bodies: exactly the keys §36.2 names for the members set;
 *   4. open decoding and pagination;
 *   5. errors: 403 with `action` / `resource_id`, 400, 404, 401, 429 and 503.
 *
 * Also here, because the network operations are what made them necessary: §36.4's
 * `reason_code` and §2's SDK-Q02 `action` / `resource_id` are members of `axiam_error_t`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_models.h"
#include "axiam/management_ops.h"
#include "cJSON.h"
#include "management_test_util.h"
#include "test_util.h"

#ifndef AXIAM_REPO_ROOT
#error "AXIAM_REPO_ROOT must be defined by the build (see tests/CMakeLists.txt)."
#endif

#define UUID "11111111-1111-4111-8111-111111111111"
#define SEG_ID "22222222-2222-4222-8222-222222222222"

#define SEGMENT_JSON(KIND) \
    "{\"id\":\"" SEG_ID "\",\"tenant_id\":\"" UUID "\",\"path\":\"/network/zones/hq/a\"," \
    "\"name\":\"a\",\"site_key\":\"hq\",\"kind\":\"" KIND "\",\"vlan_id\":10," \
    "\"filter_ids\":[\"f1\",\"f2\"],\"rank\":1,\"enabled\":true,\"version\":3," \
    "\"created_by\":\"" UUID "\",\"updated_by\":\"" UUID "\"," \
    "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}"

#define PROFILE_JSON(ACTION, SERVICE) \
    "{\"segment_id\":\"" SEG_ID "\",\"tenant_id\":\"" UUID "\"," \
    "\"dictionary\":\"axiam-radius-reply/1\",\"session_timeout_secs\":3600," \
    "\"session_timeout_clamped\":true,\"termination_action\":\"" ACTION "\"," \
    "\"idle_timeout_secs\":600,\"filter_id\":\"f1\",\"service_type\":\"" SERVICE "\"," \
    "\"version\":2,\"created_by\":\"" UUID "\",\"updated_by\":\"" UUID "\"," \
    "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}"

#define POLICY_JSON \
    "{\"tenant_id\":\"" UUID "\",\"session_timeout_max_secs\":3600,\"version\":0}"

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- helpers -------------------------------------------------------------------- */

static cJSON *sent_body(void) {
    cJSON *j = cJSON_Parse(mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsObject(j), "the body is a JSON object");
    return j;
}

/* Assert `obj` has EXACTLY the keys listed (a NULL-terminated list), in any order:
 * asserting a key is present passes when every other member went along as null. */
static void assert_exact_keys(const cJSON *obj, const char *const *keys) {
    size_t want = 0;
    for (; keys[want]; want++)
        TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(obj, keys[want]), keys[want]);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int) want, cJSON_GetArraySize(obj),
                                  "the body carries no key beyond the ones named");
    for (const cJSON *m = obj->child; m; m = m->next)
        TEST_ASSERT_FALSE_MESSAGE(cJSON_IsNull(m), "no member is ever sent as null");
}

static int has_substr(const char *hay, const char *needle) { return hay && strstr(hay, needle) != NULL; }

/* The text of a repository file, malloc'd, or NULL. */
static char *slurp(const char *relative) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", AXIAM_REPO_ROOT, relative);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *) malloc((size_t) n + 1);
    if (buf && fread(buf, 1, (size_t) n, f) != (size_t) n) { free(buf); buf = NULL; }
    if (buf) buf[n] = '\0';
    fclose(f);
    return buf;
}

/* ---- 1. the surface ------------------------------------------------------------- */

static void test_the_registry_has_twelve_network_operations_and_no_decision_route(void) {
    char *text = slurp("management-registry.json");
    TEST_ASSERT_NOT_NULL(text);
    cJSON *reg = cJSON_Parse(text);
    free(text);
    TEST_ASSERT_NOT_NULL(reg);
    TEST_ASSERT_EQUAL_INT(202, (int) cJSON_GetObjectItemCaseSensitive(reg, "operation_count")->valuedouble);
    TEST_ASSERT_EQUAL_INT(29, (int) cJSON_GetObjectItemCaseSensitive(reg, "namespace_count")->valuedouble);
    const cJSON *ns = cJSON_GetObjectItemCaseSensitive(reg, "namespaces");
    const cJSON *net = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(ns, "network"), "operations");
    TEST_ASSERT_NOT_NULL(net);
    static const char *const ops[] = {
        "list_segments", "create_segment", "get_segment", "replace_segment", "delete_segment",
        "list_profiles", "create_profile", "get_profile", "replace_profile", "delete_profile",
        "get_policy", "replace_policy", NULL};
    size_t n = 0;
    for (; ops[n]; n++)
        TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(net, ops[n]), ops[n]);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int) n, cJSON_GetArraySize(net), "exactly the twelve");
    TEST_ASSERT_NOT_NULL_MESSAGE(
        cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(reg, "excluded_operations"),
                                         "POST /api/v1/network/decide"),
        "the registry excludes the decision route by name (§27.0)");
    cJSON_Delete(reg);

    /* What the generator wrote: the twelve are in, the decision route is not. */
    for (int f = 0; f < 2; f++) {
        char *src = slurp(f ? "include/axiam/management_ops.h" : "src/management_ops.c");
        TEST_ASSERT_NOT_NULL(src);
        TEST_ASSERT_FALSE_MESSAGE(has_substr(src, "network/decide"), "no method reaches the decision route");
        TEST_ASSERT_FALSE(has_substr(src, "network_decide"));
        for (size_t i = 0; ops[i]; i++) {
            char sym[96];
            snprintf(sym, sizeof sym, "axiam_network_%s(", ops[i]);
            TEST_ASSERT_TRUE_MESSAGE(has_substr(src, sym), sym);
        }
        free(src);
    }
}

static void test_each_operation_uses_its_method_and_path(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    axiam_mgmt_network_segment_response_page_t *sp = NULL;
    mgmt_mount(200, "{\"items\":[" SEGMENT_JSON("access") "],\"total\":1,\"offset\":0,\"limit\":50}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_list_segments(c, "hq", NULL, &sp, &err));
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/segments", mgmt_last_path());
    TEST_ASSERT_TRUE(has_substr(mgmt_last_url(), "site=hq"));
    axiam_mgmt_network_segment_response_page_free(sp);

    axiam_mgmt_network_segment_response_t *seg = NULL;
    mgmt_mount(200, SEGMENT_JSON("access"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_segment(c, SEG_ID, &seg, &err));
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/segments/" SEG_ID, mgmt_last_path());
    axiam_mgmt_network_segment_response_free(seg);

    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_delete_segment(c, SEG_ID, 3, &err));
    TEST_ASSERT_EQUAL_STRING("DELETE", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/segments/" SEG_ID, mgmt_last_path());

    axiam_mgmt_network_reply_profile_t *pr = NULL;
    mgmt_mount(200, PROFILE_JSON("radius_request", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_profile(c, SEG_ID, &pr, &err));
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/profiles/" SEG_ID, mgmt_last_path());
    axiam_mgmt_network_reply_profile_free(pr);

    axiam_mgmt_network_reply_profile_page_t *pp = NULL;
    mgmt_mount(200, "{\"items\":[],\"total\":0}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_list_profiles(c, NULL, &pp, &err));
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/profiles", mgmt_last_path());
    axiam_mgmt_network_reply_profile_page_free(pp);

    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_delete_profile(c, SEG_ID, 2, &err));
    TEST_ASSERT_EQUAL_STRING("DELETE", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/profiles/" SEG_ID, mgmt_last_path());

    axiam_mgmt_network_policy_response_t *po = NULL;
    mgmt_mount(200, POLICY_JSON);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_policy(c, &po, &err));
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING("/api/v1/network/policy", mgmt_last_path());
    TEST_ASSERT_EQUAL_INT(3600, (int) po->session_timeout_max_secs);
    TEST_ASSERT_EQUAL_INT(0, (int) po->version);
    TEST_ASSERT_NULL_MESSAGE(po->updated_at, "absent while it is the default");
    axiam_mgmt_network_policy_response_free(po);
    axiam_client_free(c);
}

/* ---- 2. versions ---------------------------------------------------------------- */

static void test_replace_segment_sends_the_version_it_was_given(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char *filter_ids[2] = {(char *) "f1", (char *) "f2"};
    axiam_mgmt_replace_network_segment_request_t body;
    memset(&body, 0, sizeof body);
    body.version = 41;
    body.vlan_id = 20;
    body.enabled = 1;
    body.filter_ids = filter_ids;
    body.filter_ids_count = 2;
    body.rank = 4;
    body.has_rank = 1;
    axiam_mgmt_network_segment_response_t *out = NULL;
    mgmt_mount(200, SEGMENT_JSON("access"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_replace_segment(c, SEG_ID, &body, &out, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    cJSON *sent = sent_body();
    TEST_ASSERT_EQUAL_INT(41, (int) cJSON_GetObjectItemCaseSensitive(sent, "version")->valuedouble);
    cJSON_Delete(sent);
    axiam_mgmt_network_segment_response_free(out);
    axiam_client_free(c);
}

static void test_deletes_send_the_version_as_a_query_parameter_exactly(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_delete_segment(c, SEG_ID, 7, &err));
    TEST_ASSERT_TRUE_MESSAGE(has_substr(mgmt_last_url(), "/api/v1/network/segments/" SEG_ID "?version=7"),
                             mgmt_last_url());
    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_delete_profile(c, SEG_ID, 12, &err));
    TEST_ASSERT_TRUE_MESSAGE(has_substr(mgmt_last_url(), "/api/v1/network/profiles/" SEG_ID "?version=12"),
                             mgmt_last_url());
    /* §36.8 test 2: "cannot be called without one". The parameter is a `long`, so the
     * requirement is the signature's -- there is no NULL for a caller to pass -- and what
     * it is given is what is sent, a zero included (the policy's first write is version 0;
     * a segment's server answer to 0 is its own to give). */
    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_delete_segment(c, SEG_ID, 0, &err));
    TEST_ASSERT_TRUE(has_substr(mgmt_last_url(), "?version=0"));
    axiam_client_free(c);
}

static void test_profile_writes_send_segment_version_and_version(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_network_reply_profile_input_t input;
    memset(&input, 0, sizeof input);
    input.session_timeout_secs = 3000;

    axiam_mgmt_create_network_reply_profile_request_t create;
    memset(&create, 0, sizeof create);
    create.segment_id = (char *) SEG_ID;
    create.segment_version = 5;
    create.profile = &input;
    axiam_mgmt_network_reply_profile_t *out = NULL;
    mgmt_mount(201, PROFILE_JSON("radius_request", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_profile(c, &create, &out, &err));
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    cJSON *sent = sent_body();
    TEST_ASSERT_EQUAL_INT(5, (int) cJSON_GetObjectItemCaseSensitive(sent, "segment_version")->valuedouble);
    TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "version"), "create has no profile version");
    cJSON_Delete(sent);
    axiam_mgmt_network_reply_profile_free(out);

    axiam_mgmt_replace_network_reply_profile_request_t replace;
    memset(&replace, 0, sizeof replace);
    replace.version = 8;
    replace.segment_version = 9;
    replace.profile = &input;
    out = NULL;
    mgmt_mount(200, PROFILE_JSON("radius_request", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_replace_profile(c, SEG_ID, &replace, &out, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    sent = sent_body();
    TEST_ASSERT_EQUAL_INT(8, (int) cJSON_GetObjectItemCaseSensitive(sent, "version")->valuedouble);
    TEST_ASSERT_EQUAL_INT(9, (int) cJSON_GetObjectItemCaseSensitive(sent, "segment_version")->valuedouble);
    cJSON_Delete(sent);
    axiam_mgmt_network_reply_profile_free(out);
    axiam_client_free(c);
}

static void test_replace_policy_sends_the_version_including_zero(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_replace_network_policy_request_t body;
    memset(&body, 0, sizeof body);
    body.session_timeout_max_secs = 1800;
    body.version = 0; /* a tenant that has never written one: the first write */
    axiam_mgmt_network_policy_response_t *out = NULL;
    mgmt_mount(200, "{\"tenant_id\":\"" UUID "\",\"session_timeout_max_secs\":1800,\"version\":1,"
                    "\"updated_by\":\"" UUID "\",\"updated_at\":\"2026-10-16T00:00:00Z\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_replace_policy(c, &body, &out, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    cJSON *sent = sent_body();
    const char *keys[] = {"session_timeout_max_secs", "version", NULL};
    assert_exact_keys(sent, keys);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int) cJSON_GetObjectItemCaseSensitive(sent, "version")->valuedouble,
                                  "version 0 is a value, sent");
    cJSON_Delete(sent);
    TEST_ASSERT_EQUAL_INT(1, (int) out->version);
    axiam_mgmt_network_policy_response_free(out);
    axiam_client_free(c);
}

/* One of the seven writes, by index, against `status` and `body`; returns its kind. */
static axiam_error_kind_t run_write(axiam_client_t *c, int which, axiam_error_t *err) {
    axiam_mgmt_network_reply_profile_input_t input;
    memset(&input, 0, sizeof input);
    input.session_timeout_secs = 3000;
    char *filter_ids[1] = {(char *) "f1"};
    switch (which) {
        case 0: {
            axiam_mgmt_create_network_segment_request_t b;
            memset(&b, 0, sizeof b);
            b.name = (char *) "a"; b.site_key = (char *) "hq"; b.vlan_id = 10;
            b.rank = 1; b.has_rank = 1;
            return axiam_network_create_segment(c, &b, NULL, err);
        }
        case 1: {
            axiam_mgmt_replace_network_segment_request_t b;
            memset(&b, 0, sizeof b);
            b.version = 3; b.vlan_id = 10; b.enabled = 1; b.filter_ids = filter_ids; b.filter_ids_count = 1;
            return axiam_network_replace_segment(c, SEG_ID, &b, NULL, err);
        }
        case 2: return axiam_network_delete_segment(c, SEG_ID, 3, err);
        case 3: {
            axiam_mgmt_create_network_reply_profile_request_t b;
            memset(&b, 0, sizeof b);
            b.segment_id = (char *) SEG_ID; b.segment_version = 3; b.profile = &input;
            return axiam_network_create_profile(c, &b, NULL, err);
        }
        case 4: {
            axiam_mgmt_replace_network_reply_profile_request_t b;
            memset(&b, 0, sizeof b);
            b.version = 2; b.segment_version = 3; b.profile = &input;
            return axiam_network_replace_profile(c, SEG_ID, &b, NULL, err);
        }
        case 5: return axiam_network_delete_profile(c, SEG_ID, 2, err);
        default: {
            axiam_mgmt_replace_network_policy_request_t b;
            memset(&b, 0, sizeof b);
            b.session_timeout_max_secs = 1800;
            return axiam_network_replace_policy(c, &b, NULL, err);
        }
    }
}
#define WRITE_COUNT 7

static void test_a_409_on_each_write_is_one_request_and_exposes_its_reason_code(void) {
    for (int w = 0; w < WRITE_COUNT; w++) {
        mgmt_reset();
        axiam_client_t *c = mgmt_signed_in_client();
        axiam_error_t err;
        mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"the row changed\",\"reason_code\":\"stale_version\"}");
        int before = mgmt_request_count();
        axiam_error_kind_t rc = run_write(c, w, &err);
        char label[32];
        snprintf(label, sizeof label, "write %d", w);
        TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_AUTHZ, rc, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err), label);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("stale_version", err.reason_code, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "exactly one request: never retried");
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, mgmt_sleep_count(), "no backoff was asked for");
        axiam_client_free(c);
    }
}

static void test_an_already_exists_409_exposes_its_reason_code_too(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(409, "{\"error\":\"already_exists\",\"message\":\"VLAN 10 is taken\",\"reason_code\":\"duplicate_vlan\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 0, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_STRING("duplicate_vlan", err.reason_code);
    axiam_client_free(c);
}

static void test_the_reason_code_vocabulary_is_open_and_absence_is_empty(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    /* A value this SDK has never heard of is surfaced verbatim. */
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"m\",\"reason_code\":\"a_future_code\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 6, &err));
    TEST_ASSERT_EQUAL_STRING("a_future_code", err.reason_code);
    /* A server that predates the member: empty, never invented, never parsed out of the
     * message. */
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"stale_version\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 6, &err));
    TEST_ASSERT_EQUAL_STRING("", err.reason_code);
    /* A reason_code on anything but a 409 is not this member. */
    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"m\",\"reason_code\":\"stale_version\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, run_write(c, 6, &err));
    TEST_ASSERT_EQUAL_STRING("", err.reason_code);
    /* A later failure on the same struct does not inherit it. */
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"m\",\"reason_code\":\"has_children\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 2, &err));
    TEST_ASSERT_EQUAL_STRING("has_children", err.reason_code);
    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"m\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 2, &err));
    TEST_ASSERT_EQUAL_STRING("", err.reason_code);
    axiam_client_free(c);
}

/* ---- 3. closed bodies ----------------------------------------------------------- */

static void test_create_segment_carries_exactly_the_members_set(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_create_network_segment_request_t body;
    memset(&body, 0, sizeof body);
    body.kind = AXIAM_MGMT_NETWORK_SEGMENT_KIND_ACCESS;
    body.site_key = (char *) "hq";
    body.name = (char *) "lab";
    body.vlan_id = 30;
    body.rank = 2;
    body.has_rank = 1;

    mgmt_mount(201, SEGMENT_JSON("access"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_segment(c, &body, NULL, &err));
    cJSON *sent = sent_body();
    const char *access_keys[] = {"kind", "site_key", "name", "vlan_id", "rank", NULL};
    assert_exact_keys(sent, access_keys);
    TEST_ASSERT_EQUAL_STRING("access", cJSON_GetObjectItemCaseSensitive(sent, "kind")->valuestring);
    cJSON_Delete(sent);

    /* A quarantine segment: `rank` unset is ABSENT, not null, and the wire spelling is
     * `quarantine`. */
    body.kind = AXIAM_MGMT_NETWORK_SEGMENT_KIND_QUARANTINE;
    body.has_rank = 0;
    mgmt_mount(201, SEGMENT_JSON("quarantine"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_segment(c, &body, NULL, &err));
    sent = sent_body();
    const char *quarantine_keys[] = {"kind", "site_key", "name", "vlan_id", NULL};
    assert_exact_keys(sent, quarantine_keys);
    TEST_ASSERT_EQUAL_STRING("quarantine", cJSON_GetObjectItemCaseSensitive(sent, "kind")->valuestring);
    cJSON_Delete(sent);

    /* Every optional member set: exactly the seven. */
    char *filter_ids[2] = {(char *) "f2", (char *) "f1"};
    body.has_rank = 1;
    body.has_enabled = 1;
    body.enabled = 0;
    body.filter_ids = filter_ids;
    body.filter_ids_count = 2;
    body.kind = AXIAM_MGMT_NETWORK_SEGMENT_KIND_ACCESS;
    mgmt_mount(201, SEGMENT_JSON("access"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_segment(c, &body, NULL, &err));
    sent = sent_body();
    const char *all_keys[] = {"kind", "site_key", "name", "vlan_id", "rank", "enabled", "filter_ids", NULL};
    assert_exact_keys(sent, all_keys);
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(sent, "filter_ids");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("f2", cJSON_GetArrayItem(arr, 0)->valuestring, "the order given is the order sent");
    cJSON_Delete(sent);
    axiam_client_free(c);
}

static void test_replace_segment_carries_no_kind_site_key_or_name(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char *none[1] = {NULL};
    axiam_mgmt_replace_network_segment_request_t body;
    memset(&body, 0, sizeof body);
    body.version = 3;
    body.vlan_id = 10;
    body.enabled = 1;
    body.filter_ids = none; /* an EMPTY envelope is a value: it is sent as [] */
    body.filter_ids_count = 0;
    mgmt_mount(200, SEGMENT_JSON("quarantine"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_replace_segment(c, SEG_ID, &body, NULL, &err));
    cJSON *sent = sent_body();
    const char *keys[] = {"version", "vlan_id", "filter_ids", "enabled", NULL};
    assert_exact_keys(sent, keys);
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(sent, "filter_ids")));
    cJSON_Delete(sent);
    axiam_client_free(c);
}

static void test_a_profile_input_has_no_vlan_and_omits_what_is_unset(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_network_reply_profile_input_t input;
    memset(&input, 0, sizeof input);
    input.session_timeout_secs = 3000;
    axiam_mgmt_create_network_reply_profile_request_t body;
    memset(&body, 0, sizeof body);
    body.segment_id = (char *) SEG_ID;
    body.segment_version = 3;
    body.profile = &input;
    mgmt_mount(201, PROFILE_JSON("radius_request", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_profile(c, &body, NULL, &err));
    cJSON *sent = sent_body();
    const char *outer[] = {"segment_id", "segment_version", "profile", NULL};
    assert_exact_keys(sent, outer);
    const char *inner[] = {"session_timeout_secs", NULL};
    assert_exact_keys(cJSON_GetObjectItemCaseSensitive(sent, "profile"), inner);
    cJSON_Delete(sent);

    /* All of the optional members set: the five, and still no VLAN anywhere. */
    input.dictionary = (char *) "axiam-radius-reply/1";
    input.termination_action = AXIAM_MGMT_RADIUS_TERMINATION_ACTION_DEFAULT;
    input.has_termination_action = 1;
    input.idle_timeout_secs = 600;
    input.has_idle_timeout_secs = 1;
    input.filter_id = (char *) "f1";
    input.service_type = AXIAM_MGMT_RADIUS_SERVICE_TYPE_FRAMED_USER;
    input.has_service_type = 1;
    mgmt_mount(201, PROFILE_JSON("default", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_create_profile(c, &body, NULL, &err));
    sent = sent_body();
    const char *full[] = {"dictionary", "session_timeout_secs", "termination_action", "idle_timeout_secs",
                          "filter_id", "service_type", NULL};
    const cJSON *profile = cJSON_GetObjectItemCaseSensitive(sent, "profile");
    assert_exact_keys(profile, full);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(profile, "vlan_id"));
    TEST_ASSERT_EQUAL_STRING("default", cJSON_GetObjectItemCaseSensitive(profile, "termination_action")->valuestring);
    TEST_ASSERT_EQUAL_STRING("framed_user", cJSON_GetObjectItemCaseSensitive(profile, "service_type")->valuestring);
    cJSON_Delete(sent);
    axiam_client_free(c);
}

static void test_the_replace_types_are_refused_without_their_required_members(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    int before = mgmt_request_count();

    axiam_mgmt_replace_network_segment_request_t seg;
    memset(&seg, 0, sizeof seg); /* filter_ids is required: NULL is "not given" */
    seg.version = 3;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_network_replace_segment(c, SEG_ID, &seg, NULL, &err));

    axiam_mgmt_replace_network_reply_profile_request_t prof;
    memset(&prof, 0, sizeof prof); /* profile is required */
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_network_replace_profile(c, SEG_ID, &prof, NULL, &err));

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_network_replace_segment(c, SEG_ID, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), "refused with zero wire calls");
    axiam_client_free(c);
}

static void test_an_unknown_enum_value_is_refused_and_never_sent(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_create_network_segment_request_t body;
    memset(&body, 0, sizeof body);
    body.kind = AXIAM_MGMT_NETWORK_SEGMENT_KIND_UNKNOWN;
    body.site_key = (char *) "hq";
    body.name = (char *) "a";
    body.vlan_id = 10;
    int before = mgmt_request_count();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_network_create_segment(c, &body, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), "R-22: never re-sent as \"\"");
    axiam_client_free(c);
}

/* ---- 4. open decoding and pagination -------------------------------------------- */

static void test_unknown_enum_values_decode(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_network_segment_response_t *seg = NULL;
    mgmt_mount(200, SEGMENT_JSON("a_future_kind"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_segment(c, SEG_ID, &seg, &err));
    TEST_ASSERT_NOT_NULL(seg);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_NETWORK_SEGMENT_KIND_UNKNOWN, seg->kind);
    TEST_ASSERT_EQUAL_INT(10, (int) seg->vlan_id);
    TEST_ASSERT_EQUAL_INT(2, (int) seg->filter_ids_count);
    TEST_ASSERT_EQUAL_INT(3, (int) seg->version);
    axiam_mgmt_network_segment_response_free(seg);

    axiam_mgmt_network_reply_profile_t *pr = NULL;
    mgmt_mount(200, PROFILE_JSON("a_future_action", "a_future_service"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_profile(c, SEG_ID, &pr, &err));
    TEST_ASSERT_NOT_NULL(pr);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_RADIUS_TERMINATION_ACTION_UNKNOWN, pr->termination_action);
    TEST_ASSERT_TRUE(pr->has_service_type);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_RADIUS_SERVICE_TYPE_UNKNOWN, pr->service_type);
    axiam_mgmt_network_reply_profile_free(pr);
    axiam_client_free(c);
}

static void test_a_clamped_profile_decodes_with_both_members(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_network_reply_profile_t *pr = NULL;
    mgmt_mount(200, PROFILE_JSON("radius_request", "framed_user"));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_get_profile(c, SEG_ID, &pr, &err));
    TEST_ASSERT_TRUE_MESSAGE(pr->session_timeout_clamped, "the effective value was lowered");
    TEST_ASSERT_EQUAL_INT(3600, (int) pr->session_timeout_secs);
    TEST_ASSERT_EQUAL_INT(600, (int) pr->idle_timeout_secs);
    TEST_ASSERT_EQUAL_STRING("f1", pr->filter_id);
    axiam_mgmt_network_reply_profile_free(pr);
    axiam_client_free(c);
}

static void test_both_lists_return_a_page_with_a_total_and_the_pager_carries_search_and_site(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    /* total is the server's, and differs from the items on the page. */
    axiam_mgmt_network_segment_response_page_t *page = NULL;
    mgmt_mount(200, "{\"items\":[" SEGMENT_JSON("access") "],\"total\":57,\"offset\":0,\"limit\":1}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_list_segments(c, NULL, NULL, &page, &err));
    TEST_ASSERT_EQUAL_INT(1, (int) page->count);
    TEST_ASSERT_EQUAL_INT(57, (int) page->total);
    axiam_mgmt_network_segment_response_page_free(page);

    axiam_mgmt_network_reply_profile_page_t *ppage = NULL;
    mgmt_mount(200, "{\"items\":[" PROFILE_JSON("radius_request", "framed_user") "],\"total\":9}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_list_profiles(c, NULL, &ppage, &err));
    TEST_ASSERT_EQUAL_INT(1, (int) ppage->count);
    TEST_ASSERT_EQUAL_INT(9, (int) ppage->total);
    axiam_mgmt_network_reply_profile_page_free(ppage);
    axiam_client_free(c);

    /* The auto-pager: search and site on EVERY request of the walk. */
    mgmt_reset();
    c = mgmt_signed_in_client();
    mgmt_mount(200, "{\"items\":[" SEGMENT_JSON("access") "," SEGMENT_JSON("access") "],\"total\":3}");
    mgmt_mount_next(200, "{\"items\":[" SEGMENT_JSON("access") "],\"total\":3}");
    mgmt_mount_next(200, "{\"items\":[],\"total\":3}");
    axiam_mgmt_page_req_t req = {0, 2, "edge"};
    page = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_network_list_segments_all(c, "hq", &req, &page, &err));
    TEST_ASSERT_EQUAL_INT(3, (int) page->count);
    TEST_ASSERT_EQUAL_INT(4, mgmt_request_count()); /* the sign-in and three pages */
    for (int i = 1; i <= 3; i++) {
        TEST_ASSERT_TRUE_MESSAGE(has_substr(mgmt_url_at(i), "search=edge"), mgmt_url_at(i));
        TEST_ASSERT_TRUE_MESSAGE(has_substr(mgmt_url_at(i), "site=hq"), mgmt_url_at(i));
    }
    TEST_ASSERT_TRUE(has_substr(mgmt_url_at(1), "offset=0"));
    TEST_ASSERT_TRUE(has_substr(mgmt_url_at(2), "offset=2"));
    TEST_ASSERT_TRUE(has_substr(mgmt_url_at(3), "offset=4"));
    axiam_mgmt_network_segment_response_page_free(page);
    axiam_client_free(c);
}

/* ---- 5. errors ------------------------------------------------------------------ */

static void test_a_403_exposes_action_and_resource_id(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(403, "{\"error\":\"authorization_denied\",\"message\":\"missing permission\","
                    "\"action\":\"network:grant\",\"resource_id\":\"" SEG_ID "\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 4, &err));
    TEST_ASSERT_EQUAL_STRING("network:grant", err.action);
    TEST_ASSERT_EQUAL_STRING(SEG_ID, err.resource_id);
    TEST_ASSERT_EQUAL_STRING("", err.reason_code);

    /* H3 is a 403 that names no permission: the members are empty, not invented. */
    mgmt_mount(403, "{\"error\":\"authorization_denied\","
                    "\"message\":\"session_timeout_secs is above the tenant's cap of 3600\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, run_write(c, 4, &err));
    TEST_ASSERT_EQUAL_STRING("", err.action);
    TEST_ASSERT_EQUAL_STRING("", err.resource_id);
    TEST_ASSERT_EQUAL_INT_MESSAGE(403, err.transport_cause, "a plain AuthzError: not a rule 7 sub-type");
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NONE, axiam_mgmt_error_class(&err));
    axiam_client_free(c);
}

static void test_400_404_401_map_as_section_36_4_says(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"vlan_id must be 1 to 4094\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, run_write(c, 1, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err.message, "vlan_id must be 1 to 4094"), "carries the server's message");

    axiam_mgmt_network_reply_profile_t *pr = NULL;
    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"no such profile\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_network_get_profile(c, SEG_ID, &pr, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    axiam_client_free(c);

    /* A service-account token is a 401 no refresh can cure (§36.1): the refresh is tried
     * once and the 401 is what the caller gets. */
    mgmt_reset();
    c = mgmt_signed_in_client();
    mgmt_mount(401, "{\"error\":\"unauthorized\",\"message\":\"human callers only\"}");
    mgmt_mount_next(401, "{\"error\":\"unauthorized\",\"message\":\"human callers only\"}");
    mgmt_mount_next(401, "{\"error\":\"unauthorized\",\"message\":\"human callers only\"}");
    axiam_mgmt_network_policy_response_t *po = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_network_get_policy(c, &po, &err));
    TEST_ASSERT_NULL(po);
    axiam_client_free(c);
}

static void test_429_and_503_on_each_write_are_one_request(void) {
    static const long statuses[] = {429, 503};
    for (int s = 0; s < 2; s++) {
        for (int w = 0; w < WRITE_COUNT; w++) {
            mgmt_reset();
            axiam_client_t *c = mgmt_signed_in_client();
            axiam_error_t err;
            mgmt_mount(statuses[s], "{\"error\":\"unavailable\",\"message\":\"try later\"}");
            int before = mgmt_request_count();
            char label[48];
            snprintf(label, sizeof label, "write %d, status %ld", w, statuses[s]);
            TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK, run_write(c, w, &err), label);
            TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), label);
            TEST_ASSERT_EQUAL_INT_MESSAGE(0, mgmt_sleep_count(), label);
            axiam_client_free(c);
        }
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_registry_has_twelve_network_operations_and_no_decision_route);
    RUN_TEST(test_each_operation_uses_its_method_and_path);
    RUN_TEST(test_replace_segment_sends_the_version_it_was_given);
    RUN_TEST(test_deletes_send_the_version_as_a_query_parameter_exactly);
    RUN_TEST(test_profile_writes_send_segment_version_and_version);
    RUN_TEST(test_replace_policy_sends_the_version_including_zero);
    RUN_TEST(test_a_409_on_each_write_is_one_request_and_exposes_its_reason_code);
    RUN_TEST(test_an_already_exists_409_exposes_its_reason_code_too);
    RUN_TEST(test_the_reason_code_vocabulary_is_open_and_absence_is_empty);
    RUN_TEST(test_create_segment_carries_exactly_the_members_set);
    RUN_TEST(test_replace_segment_carries_no_kind_site_key_or_name);
    RUN_TEST(test_a_profile_input_has_no_vlan_and_omits_what_is_unset);
    RUN_TEST(test_the_replace_types_are_refused_without_their_required_members);
    RUN_TEST(test_an_unknown_enum_value_is_refused_and_never_sent);
    RUN_TEST(test_unknown_enum_values_decode);
    RUN_TEST(test_a_clamped_profile_decodes_with_both_members);
    RUN_TEST(test_both_lists_return_a_page_with_a_total_and_the_pager_carries_search_and_site);
    RUN_TEST(test_a_403_exposes_action_and_resource_id);
    RUN_TEST(test_400_404_401_map_as_section_36_4_says);
    RUN_TEST(test_429_and_503_on_each_write_are_one_request);
    return UNITY_END();
}
