/*
 * CONTRACT.md §27.6.2 (contract 1.62), required tests of §27.9 "Manifest, `network`":
 * the `network` namespace in a declarative manifest -- the policy, the segments and the
 * profiles; natural keys; the version-conditional `replace_*` bodies built from the read;
 * a `409` and its `reason_code` as the action's failure; and the four 2026-10-16 answers
 * (wire `kind`, `filter_ids` as a set, a stated `null` as none, a value judged on the read).
 *
 * The rig sits at the bottom of the real client, as in every §27 test: `plan` and `apply`
 * run for real, and what is asserted is what reached the transport, in order.
 */
#include <stdio.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_manifest.h"
#include "cJSON.h"
#include "management_test_util.h"
#include "test_util.h"

#define TENANT "11111111-1111-4111-8111-111111111111"
#define SEG_A "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define SEG_B "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define NEW_SEG "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- fixtures ------------------------------------------------------------------- */

static char g_seg[4][1024];
static int g_seg_n;

/* A NetworkSegmentResponse. `rank` < 0 omits it; `filters` is the inside of the array. */
static const char *seg_json(const char *id, const char *site, const char *kind, const char *name,
                            int vlan, int rank, const char *filters, int enabled, int version) {
    char *b = g_seg[g_seg_n++ % 4];
    char rankpart[32] = "";
    if (rank >= 0) snprintf(rankpart, sizeof rankpart, "\"rank\":%d,", rank);
    snprintf(b, sizeof g_seg[0],
             "{\"id\":\"%s\",\"tenant_id\":\"" TENANT "\",\"path\":\"/network/zones/%s/%s\","
             "\"name\":\"%s\",\"site_key\":\"%s\",\"kind\":\"%s\",\"vlan_id\":%d,"
             "\"filter_ids\":[%s],%s\"enabled\":%s,\"version\":%d,"
             "\"created_by\":\"" TENANT "\",\"updated_by\":\"" TENANT "\","
             "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}",
             id, site, name, name, site, kind, vlan, filters, rankpart, enabled ? "true" : "false", version);
    return b;
}

static char g_prof[4][1024];
static int g_prof_n;

/* A NetworkReplyProfile (the effective one). idle < 0 omits it; filter NULL omits it. */
static const char *prof_json(const char *segment_id, int secs, int clamped, int idle,
                             const char *filter, int version) {
    char *b = g_prof[g_prof_n++ % 4];
    char idlepart[48] = "", filterpart[64] = "";
    if (idle >= 0) snprintf(idlepart, sizeof idlepart, "\"idle_timeout_secs\":%d,", idle);
    if (filter) snprintf(filterpart, sizeof filterpart, "\"filter_id\":\"%s\",", filter);
    snprintf(b, sizeof g_prof[0],
             "{\"segment_id\":\"%s\",\"tenant_id\":\"" TENANT "\",\"dictionary\":\"axiam-radius-reply/1\","
             "\"session_timeout_secs\":%d,\"session_timeout_clamped\":%s,"
             "\"termination_action\":\"radius_request\",%s%s\"service_type\":\"framed_user\","
             "\"version\":%d,\"created_by\":\"" TENANT "\",\"updated_by\":\"" TENANT "\","
             "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}",
             segment_id, secs, clamped ? "true" : "false", idlepart, filterpart, version);
    return b;
}

static char g_page[2048];

/* The items page the auto-pager reads, followed by the empty one that ends the walk. */
static void mount_walk(const char *items) {
    if (items && *items) {
        snprintf(g_page, sizeof g_page, "{\"items\":[%s],\"total\":1}", items);
        mgmt_mount(200, g_page);
    }
    mgmt_mount_next(200, "{\"items\":[],\"total\":1}");
}

static void mount_policy(int cap, int version) {
    char b[256];
    snprintf(b, sizeof b, "{\"tenant_id\":\"" TENANT "\",\"session_timeout_max_secs\":%d,\"version\":%d}", cap, version);
    mgmt_mount_next(200, b);
}

/* ---- specs ---------------------------------------------------------------------- */

static axiam_mgmt_network_segment_spec_t seg_spec(const char *key, const char *name, long vlan) {
    axiam_mgmt_network_segment_spec_t s;
    memset(&s, 0, sizeof s);
    s.key = key;
    s.site = "hq";
    s.kind = "access";
    s.name = name;
    s.vlan_id = vlan;
    return s;
}

static axiam_mgmt_network_profile_spec_t prof_spec(const char *segment_key, long secs) {
    axiam_mgmt_network_profile_spec_t p;
    memset(&p, 0, sizeof p);
    p.segment = segment_key;
    p.session_timeout_secs = secs;
    return p;
}

static cJSON *body_at(int i) {
    const char *b = mgmt_body_at(i);
    TEST_ASSERT_NOT_NULL(b);
    cJSON *j = cJSON_Parse(b);
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsObject(j), b);
    return j;
}

static int key_count(const cJSON *o) { return cJSON_GetArraySize(o); }

static int has(const cJSON *o, const char *k) { return cJSON_GetObjectItemCaseSensitive(o, k) != NULL; }

static double num(const cJSON *o, const char *k) {
    const cJSON *m = cJSON_GetObjectItemCaseSensitive(o, k);
    TEST_ASSERT_NOT_NULL_MESSAGE(m, k);
    return m->valuedouble;
}

static void assert_only_reads_after_login(void) {
    for (int i = 1; i < mgmt_request_count(); i++)
        TEST_ASSERT_EQUAL_STRING_MESSAGE("GET", mgmt_method_at(i), "plan sends GETs only");
}

/* ---- tests ---------------------------------------------------------------------- */

/* plan of a manifest with a policy, a segment and a profile issues get_policy,
 * list_segments and list_profiles, and nothing else. */
static void test_plan_issues_gets_only(void) {
    axiam_mgmt_network_policy_spec_t pol = { 3600 };
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    axiam_mgmt_network_profile_spec_t prof = prof_spec("lab", 3000);
    axiam_mgmt_manifest_t m = {0};
    m.network_policy = &pol;
    m.network_segments = &seg;
    m.network_segments_count = 1;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    mount_policy(3600, 0);
    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3));
    mount_walk(prof_json(SEG_A, 3000, 0, -1, NULL, 2));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    assert_only_reads_after_login();
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(1), "/api/v1/network/policy"));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(2), "/api/v1/network/segments"));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(4), "/api/v1/network/profiles"));
    TEST_ASSERT_EQUAL_INT(3, (int) plan->network_count);
    TEST_ASSERT_EQUAL_INT(0, (int) plan->network_pending);
    /* Order: the policy, the segments, the profiles (§27.6.2 item 2). */
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_NETWORK_POLICY, plan->network[0].item);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_NETWORK_SEGMENT, plan->network[1].item);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_NETWORK_PROFILE, plan->network[2].item);
    for (size_t i = 0; i < plan->network_count; i++)
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->network[i].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* The policy always exists, so it is never a Create. */
static void test_the_policy_is_nochange_or_update_never_create(void) {
    axiam_mgmt_network_policy_spec_t pol = { 1800 };
    axiam_mgmt_manifest_t m = {0};
    m.network_policy = &pol;
    mount_policy(3600, 0);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UPDATE, plan->network[0].action);
    axiam_mgmt_plan_free(plan);

    /* apply sends replace_policy with the version it read (0: the first write). */
    mount_policy(3600, 0);
    mgmt_mount_next(200, "{\"tenant_id\":\"" TENANT "\",\"session_timeout_max_secs\":1800,\"version\":1}");
    axiam_mgmt_apply_report_t report;
    int before = mgmt_request_count();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(before + 1));
    cJSON *b = body_at(before + 1);
    TEST_ASSERT_EQUAL_INT(2, key_count(b));
    TEST_ASSERT_EQUAL_INT(1800, (int) num(b, "session_timeout_max_secs"));
    TEST_ASSERT_EQUAL_INT(0, (int) num(b, "version"));
    cJSON_Delete(b);
    TEST_ASSERT_EQUAL_INT(1, (int) report.network_applied);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* On an empty tenant apply creates the segment and then the profile, and the profile carries
 * the NEW segment's id and the version of the create response. plan afterwards is NoChange. */
static void test_apply_on_an_empty_tenant_creates_the_segment_then_the_profile(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    seg.rank_state = AXIAM_MGMT_FIELD_SET;
    seg.rank = 1;
    axiam_mgmt_network_profile_spec_t prof = prof_spec("lab", 3000);
    prof.idle_timeout_state = AXIAM_MGMT_FIELD_SET;
    prof.idle_timeout_secs = 600;
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    mount_walk(NULL);
    mount_walk(NULL);
    mgmt_mount_next(201, seg_json(NEW_SEG, "hq", "access", "lab", 10, 1, "", 1, 7));
    mgmt_mount_next(201, prof_json(NEW_SEG, 3000, 0, 600, NULL, 1));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_INT(5, mgmt_request_count()); /* login, the two reads, the two writes */
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_method_at(3));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(3), "/api/v1/network/segments"));
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_method_at(4));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(4), "/api/v1/network/profiles"));

    cJSON *sb = body_at(3);
    TEST_ASSERT_EQUAL_STRING("access", cJSON_GetObjectItemCaseSensitive(sb, "kind")->valuestring);
    TEST_ASSERT_EQUAL_STRING("hq", cJSON_GetObjectItemCaseSensitive(sb, "site_key")->valuestring);
    cJSON_Delete(sb);

    cJSON *pb = body_at(4);
    TEST_ASSERT_EQUAL_STRING(NEW_SEG, cJSON_GetObjectItemCaseSensitive(pb, "segment_id")->valuestring);
    TEST_ASSERT_EQUAL_INT_MESSAGE(7, (int) num(pb, "segment_version"), "the create response's version");
    cJSON_Delete(pb);
    TEST_ASSERT_EQUAL_INT(2, (int) report.network_applied);
    axiam_mgmt_apply_report_dispose(&report);

    /* Idempotence (§27.6 rule 6): the tenant now holds what the manifest states. */
    mgmt_reset();
    mount_walk(seg_json(NEW_SEG, "hq", "access", "lab", 10, 1, "", 1, 7));
    mount_walk(prof_json(NEW_SEG, 3000, 0, 600, NULL, 1));
    axiam_client_free(c);
    c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT(0, (int) plan->network_pending);
    for (size_t i = 0; i < plan->network_count; i++)
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->network[i].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* A segment Update sends the FULL replacement: the version as read, the stated members, every
 * unstated one carried from the read, and no kind, site_key or name. */
static void test_a_segment_update_is_a_full_replacement_built_from_the_read(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 20); /* read: vlan 10 */
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;

    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, 4, "\"f1\",\"f2\"", 0, 9));
    mgmt_mount_next(200, seg_json(SEG_A, "hq", "access", "lab", 20, 4, "\"f1\",\"f2\"", 0, 10));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(3));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(3), "/api/v1/network/segments/" SEG_A));
    cJSON *b = body_at(3);
    TEST_ASSERT_EQUAL_INT_MESSAGE(5, key_count(b), "exactly version, vlan_id, rank, filter_ids, enabled");
    TEST_ASSERT_EQUAL_INT(9, (int) num(b, "version"));
    TEST_ASSERT_EQUAL_INT_MESSAGE(20, (int) num(b, "vlan_id"), "the stated member");
    TEST_ASSERT_EQUAL_INT_MESSAGE(4, (int) num(b, "rank"), "carried from the read");
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(b, "filter_ids")));
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(b, "enabled")),
                             "enabled=false is carried, not defaulted to true");
    TEST_ASSERT_FALSE(has(b, "kind"));
    TEST_ASSERT_FALSE(has(b, "site_key"));
    TEST_ASSERT_FALSE(has(b, "name"));
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* A stated null on an optional profile member leaves the key out; an unstated one is carried. */
static void test_a_stated_null_leaves_the_key_out_and_silence_is_carried(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    axiam_mgmt_network_profile_spec_t prof = prof_spec("lab", 2400); /* read: 3000 */
    prof.idle_timeout_state = AXIAM_MGMT_FIELD_NULL;                 /* clear it */
    /* filter_id unstated: carried ("f1") */
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "\"f1\"", 1, 3));
    mount_walk(prof_json(SEG_A, 3000, 0, 600, "f1", 5));
    mgmt_mount_next(200, prof_json(SEG_A, 2400, 0, -1, "f1", 6));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_INT(6, mgmt_request_count());
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(5));
    cJSON *b = body_at(5);
    TEST_ASSERT_EQUAL_INT(5, (int) num(b, "version"));
    TEST_ASSERT_EQUAL_INT_MESSAGE(3, (int) num(b, "segment_version"), "the segment was not written: as read");
    const cJSON *p = cJSON_GetObjectItemCaseSensitive(b, "profile");
    TEST_ASSERT_EQUAL_INT(2400, (int) num(p, "session_timeout_secs"));
    TEST_ASSERT_FALSE_MESSAGE(has(p, "idle_timeout_secs"), "a stated null is left out, never sent");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("f1", cJSON_GetObjectItemCaseSensitive(p, "filter_id")->valuestring,
                                     "silence carries the read's value");
    TEST_ASSERT_EQUAL_STRING("radius_request", cJSON_GetObjectItemCaseSensitive(p, "termination_action")->valuestring);
    TEST_ASSERT_EQUAL_STRING("axiam-radius-reply/1", cJSON_GetObjectItemCaseSensitive(p, "dictionary")->valuestring);
    TEST_ASSERT_NULL(strstr(mgmt_body_at(5), "null"));
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* A manifest that changes a segment and its profile in one apply sends replace_segment and then
 * replace_profile, and the profile's segment_version is the replace_segment RESPONSE's. */
static void test_the_profile_follows_the_segment_write_version(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 30); /* read: 10 */
    axiam_mgmt_network_profile_spec_t prof = prof_spec("lab", 1800);    /* read: 3000 */
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3));
    mount_walk(prof_json(SEG_A, 3000, 0, -1, NULL, 2));
    mgmt_mount_next(200, seg_json(SEG_A, "hq", "access", "lab", 30, -1, "", 1, 4)); /* moved 3 -> 4 */
    mgmt_mount_next(200, prof_json(SEG_A, 1800, 0, -1, NULL, 3));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(5));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(5), "/segments/"));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(6));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(6), "/profiles/"));
    cJSON *b = body_at(6);
    TEST_ASSERT_EQUAL_INT_MESSAGE(4, (int) num(b, "segment_version"), "the replace_segment response's, not plan's 3");
    TEST_ASSERT_EQUAL_INT(2, (int) num(b, "version"));
    cJSON_Delete(b);
    TEST_ASSERT_EQUAL_INT(2, (int) report.network_applied);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* A 409 on a network write makes exactly one request, stops the apply, and the outcome exposes
 * the reason_code -- for `conflict` and `already_exists` alike. */
static void conflict_case(const char *error_slug, const char *reason) {
    mgmt_reset();
    axiam_mgmt_network_segment_spec_t segs[2];
    segs[0] = seg_spec("a", "a", 10); /* read: vlan 11 -> Update, the write that conflicts */
    segs[1] = seg_spec("b", "b", 20); /* read: vlan 21 -> Update, never attempted */
    axiam_mgmt_network_profile_spec_t prof = prof_spec("a", 1800);
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = segs;
    m.network_segments_count = 2;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    char both[2200];
    snprintf(both, sizeof both, "%s,%s", seg_json(SEG_A, "hq", "access", "a", 11, -1, "", 1, 3),
             seg_json(SEG_B, "hq", "access", "b", 21, -1, "", 1, 3));
    mount_walk(both);
    mount_walk(prof_json(SEG_A, 3000, 0, -1, NULL, 2));
    char body[256];
    snprintf(body, sizeof body, "{\"error\":\"%s\",\"message\":\"human text\",\"reason_code\":\"%s\"}", error_slug, reason);
    mgmt_mount_next(409, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(6, mgmt_request_count(), "login, four reads, and exactly ONE write");
    TEST_ASSERT_EQUAL_STRING(reason, err.reason_code);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(reason, report.network_reason_code, "the outcome exposes it");
    TEST_ASSERT_EQUAL_INT(0, (int) report.network_applied);
    TEST_ASSERT_EQUAL_INT(0, (int) report.failed_network);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, (int) report.network_remaining, "later actions were not attempted");
    TEST_ASSERT_EQUAL_INT(0, mgmt_sleep_count());
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_a_409_stops_the_apply_and_exposes_the_reason_code(void) {
    conflict_case("conflict", "stale_version");
    conflict_case("already_exists", "duplicate_vlan");
}

/* Pruning is off: this port has no delete, so a segment the manifest omits is left alone. */
static void test_omission_is_never_deletion(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;
    char both[2200];
    snprintf(both, sizeof both, "%s,%s", seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3),
             seg_json(SEG_B, "hq", "access", "other", 40, -1, "", 1, 3));
    mount_walk(both);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    for (int i = 0; i < mgmt_request_count(); i++)
        TEST_ASSERT_NOT_EQUAL(0, strcmp("DELETE", mgmt_method_at(i)));
    TEST_ASSERT_EQUAL_INT(0, (int) report.network_applied);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* Refused with zero wire calls: a repeated natural key, a profile whose segment names nothing,
 * a Filter-Id listed twice, a second profile for one segment, and a `zones` kind. */
static void assert_refused_before_any_request(const axiam_mgmt_manifest_t *m, const char *what) {
    axiam_client_t *c = mgmt_signed_in_client();
    int before = mgmt_request_count();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK, axiam_mgmt_plan(c, m, &plan, &err), what);
    TEST_ASSERT_NULL(plan);
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK, axiam_mgmt_apply(c, m, &report, &err), what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_ERR_NETWORK, axiam_mgmt_manifest_validate(m, &err), what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), what);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

static void test_invalid_manifests_are_refused_with_zero_wire_calls(void) {
    axiam_mgmt_network_segment_spec_t two[2];
    two[0] = seg_spec("x", "lab", 10);
    two[1] = seg_spec("y", "lab", 11); /* same site, kind and name under another key */
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = two;
    m.network_segments_count = 2;
    assert_refused_before_any_request(&m, "two segments with one site, kind and name");

    axiam_mgmt_network_segment_spec_t one = seg_spec("x", "lab", 10);
    axiam_mgmt_network_profile_spec_t dangling = prof_spec("nobody", 1800);
    memset(&m, 0, sizeof m);
    m.network_segments = &one;
    m.network_segments_count = 1;
    m.network_profiles = &dangling;
    m.network_profiles_count = 1;
    assert_refused_before_any_request(&m, "a profile whose segment names no segment spec");

    axiam_mgmt_network_profile_spec_t twice[2] = { prof_spec("x", 1800), prof_spec("x", 2400) };
    m.network_profiles = twice;
    m.network_profiles_count = 2;
    assert_refused_before_any_request(&m, "two profiles for one segment");

    const char *dup[3] = { "f1", "f2", "f1" };
    axiam_mgmt_network_segment_spec_t with_dup = seg_spec("x", "lab", 10);
    with_dup.filter_ids = dup;
    with_dup.filter_ids_count = 3;
    memset(&m, 0, sizeof m);
    m.network_segments = &with_dup;
    m.network_segments_count = 1;
    assert_refused_before_any_request(&m, "a Filter-Id listed twice in one segment");

    axiam_mgmt_network_segment_spec_t zones = seg_spec("x", "lab", 10);
    zones.kind = "zones";
    m.network_segments = &zones;
    assert_refused_before_any_request(&m, "kind zones: the wire spelling is access or quarantine");
}

/* A segment whose kind is stated `access` is NoChange against a read that says "access", and
 * its create_segment body carries "access" (the string). */
static void test_kind_is_the_wire_spelling_in_the_key_and_the_body(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;

    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UNCHANGED, plan->network[0].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);

    /* The same name under the OTHER kind is another segment: a quarantine read does not
     * satisfy an access spec, so this is a Create. */
    mgmt_reset();
    mount_walk(seg_json(SEG_A, "hq", "quarantine", "lab", 10, -1, "", 1, 3));
    mgmt_mount_next(201, seg_json(NEW_SEG, "hq", "access", "lab", 10, -1, "", 1, 1));
    c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    cJSON *b = body_at(3);
    TEST_ASSERT_EQUAL_STRING("access", cJSON_GetObjectItemCaseSensitive(b, "kind")->valuestring);
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* filter_ids is a SET when compared and an ORDERED list when sent. */
static void test_filter_ids_compare_as_a_set_and_are_sent_in_the_stated_order(void) {
    const char *reordered[2] = { "f2", "f1" };
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    seg.filter_ids = reordered;
    seg.filter_ids_count = 2;
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;

    /* The same names in another order: NoChange, and apply makes no write. */
    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "\"f1\",\"f2\"", 1, 3));
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_apply_report_t report;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(3, mgmt_request_count(), "login and the two reads: no write");
    TEST_ASSERT_EQUAL_INT(0, (int) report.network_applied);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);

    /* An Update for another member sends them in the order the manifest states. */
    mgmt_reset();
    seg.vlan_id = 99;
    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "\"f1\",\"f2\"", 1, 3));
    mgmt_mount_next(200, seg_json(SEG_A, "hq", "access", "lab", 99, -1, "\"f2\",\"f1\"", 1, 4));
    c = mgmt_signed_in_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    cJSON *b = body_at(3);
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(b, "filter_ids");
    TEST_ASSERT_EQUAL_STRING("f2", cJSON_GetArrayItem(arr, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING("f1", cJSON_GetArrayItem(arr, 1)->valuestring);
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);

    /* ... and so does a Create. */
    mgmt_reset();
    mount_walk(NULL);
    mgmt_mount_next(201, seg_json(NEW_SEG, "hq", "access", "lab", 99, -1, "\"f2\",\"f1\"", 1, 1));
    c = mgmt_signed_in_client();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_apply(c, &m, &report, &err));
    b = body_at(2);
    arr = cJSON_GetObjectItemCaseSensitive(b, "filter_ids");
    TEST_ASSERT_EQUAL_STRING("f2", cJSON_GetArrayItem(arr, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING("f1", cJSON_GetArrayItem(arr, 1)->valuestring);
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);

    /* A member the read has and the manifest does not IS drift (a set, not a subset). */
    mgmt_reset();
    const char *one[1] = { "f1" };
    seg.vlan_id = 10;
    seg.filter_ids = one;
    seg.filter_ids_count = 1;
    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "\"f1\",\"f2\"", 1, 3));
    c = mgmt_signed_in_client();
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CHANGE_UPDATE, plan->network[0].action);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

/* A profile read with clamped:true and secs == the cap: stating that value is NoChange;
 * stating a value above the cap is an Update, and apply sends exactly one replace_profile,
 * receives 403, stops without a retry, and the outcome carries the server's message. */
static void test_a_clamped_profile_is_judged_on_the_read(void) {
    axiam_mgmt_network_segment_spec_t seg = seg_spec("lab", "lab", 10);
    axiam_mgmt_network_profile_spec_t prof = prof_spec("lab", 1800); /* == the cap as read */
    axiam_mgmt_manifest_t m = {0};
    m.network_segments = &seg;
    m.network_segments_count = 1;
    m.network_profiles = &prof;
    m.network_profiles_count = 1;

    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3));
    mount_walk(prof_json(SEG_A, 1800, 1, -1, NULL, 2)); /* stored 3600, effective 1800 */
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_MGMT_CHANGE_UNCHANGED, plan->network[1].action,
                                  "the stated value equals the effective one");
    TEST_ASSERT_TRUE(plan->network[1].read_profile->session_timeout_clamped);
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);

    /* Above the cap: an Update in plan, a refusal at apply. A second segment follows it, to
     * show that nothing after the failure is attempted. */
    mgmt_reset();
    axiam_mgmt_network_segment_spec_t segs[2] = { seg_spec("a", "lab", 10), seg_spec("b", "zzz", 11) };
    axiam_mgmt_network_profile_spec_t above = prof_spec("a", 3600);
    memset(&m, 0, sizeof m);
    m.network_segments = segs;
    m.network_segments_count = 2;
    m.network_profiles = &above;
    m.network_profiles_count = 1;
    mount_walk(seg_json(SEG_A, "hq", "access", "lab", 10, -1, "", 1, 3));
    mount_walk(prof_json(SEG_A, 1800, 1, -1, NULL, 2));
    mgmt_mount_next(201, seg_json(NEW_SEG, "hq", "access", "zzz", 11, -1, "", 1, 1));
    mgmt_mount_next(403, "{\"error\":\"authorization_denied\","
                         "\"message\":\"session_timeout_secs is above the tenant's cap of 1800\"}");
    c = mgmt_signed_in_client();
    axiam_mgmt_apply_report_t report;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &m, &report, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, rc);
    TEST_ASSERT_EQUAL_INT(403, (int) err.transport_cause);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err.message, "above the tenant's cap of 1800"),
                                 "the outcome carries the server's message");
    /* login, 2+2 reads (the zzz segment is not on the server), the create of zzz, and the
     * one replace_profile that was refused: no retry. */
    TEST_ASSERT_EQUAL_INT(7, mgmt_request_count());
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_method_at(mgmt_request_count() - 1));
    TEST_ASSERT_EQUAL_INT(1, (int) report.network_applied);
    TEST_ASSERT_EQUAL_INT(2, (int) report.failed_network);
    TEST_ASSERT_EQUAL_STRING("", report.network_reason_code);
    cJSON *b = body_at(mgmt_request_count() - 1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(3600, (int) num(cJSON_GetObjectItemCaseSensitive(b, "profile"), "session_timeout_secs"),
                                  "the SDK sends what was stated: it does not lower it to the cap");
    cJSON_Delete(b);
    axiam_mgmt_apply_report_dispose(&report);
    axiam_client_free(c);
}

/* A manifest without a network section plans exactly as before: no network request at all. */
static void test_a_manifest_without_network_sends_no_network_request(void) {
    axiam_mgmt_manifest_t m = {0};
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_plan_t *plan = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mgmt_plan(c, &m, &plan, &err));
    TEST_ASSERT_EQUAL_INT(0, (int) plan->network_count);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, mgmt_request_count(), "only the sign-in");
    axiam_mgmt_plan_free(plan);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_plan_issues_gets_only);
    RUN_TEST(test_the_policy_is_nochange_or_update_never_create);
    RUN_TEST(test_apply_on_an_empty_tenant_creates_the_segment_then_the_profile);
    RUN_TEST(test_a_segment_update_is_a_full_replacement_built_from_the_read);
    RUN_TEST(test_a_stated_null_leaves_the_key_out_and_silence_is_carried);
    RUN_TEST(test_the_profile_follows_the_segment_write_version);
    RUN_TEST(test_a_409_stops_the_apply_and_exposes_the_reason_code);
    RUN_TEST(test_omission_is_never_deletion);
    RUN_TEST(test_invalid_manifests_are_refused_with_zero_wire_calls);
    RUN_TEST(test_kind_is_the_wire_spelling_in_the_key_and_the_body);
    RUN_TEST(test_filter_ids_compare_as_a_set_and_are_sent_in_the_stated_order);
    RUN_TEST(test_a_clamped_profile_is_judged_on_the_read);
    RUN_TEST(test_a_manifest_without_network_sends_no_network_request);
    return UNITY_END();
}
