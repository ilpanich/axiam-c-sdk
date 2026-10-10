/*
 * CONTRACT.md §31 (contract 1.57) — the `scim_targets` management namespace: §31.8's six
 * required tests, the local refusal of an unknown union arm, and the read-modify-write
 * conversion.
 *
 * The credential is generated at run time; a failing redaction assertion names an
 * offset, never the credential or the rendering it was found in.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_helpers.h"
#include "axiam/management_ops.h"
#include "cJSON.h"
#include "management_test_util.h"
#include "test_util.h"

cJSON *axiam_mgmt_scim_target_response_build(const axiam_mgmt_scim_target_response_t *value);

#define TARGETS "/api/v1/scim-targets"
#define TARGET_ID "12121212-1212-4212-8212-121212121212"

#define STATE "{\"last_success_at\":null,\"last_failure_at\":null,\"last_failure_reason\":null," \
              "\"consecutive_failures\":0,\"dead_lettered_total\":0,\"last_reconciled_at\":null}"

static void target_body(char *out, size_t cap, const char *auth, const char *extra) {
    snprintf(out, cap,
             "{\"id\":\"" TARGET_ID "\",\"tenant_id\":\"11111111-1111-4111-8111-111111111111\","
             "\"name\":\"Downstream\",\"base_url\":\"https://idp.example/scim/v2\",\"enabled\":true,"
             "\"auth\":%s,\"scope\":{\"type\":\"all_users\"},\"push_groups\":false,"
             "\"user_name_from\":\"username\",\"deprovision\":\"deactivate\","
             "\"created_at\":\"2026-10-05T00:00:00Z\",\"updated_at\":\"2026-10-05T00:00:00Z\","
             "\"state\":" STATE "%s}",
             auth, extra ? extra : "");
}

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

/* A replacement carrying the four required members, with constructed unions the
 * caller frees. */
static void fill_input(axiam_mgmt_scim_target_input_t *in) {
    memset(in, 0, sizeof *in);
    in->name = (char *) "Downstream";
    in->base_url = (char *) "https://idp.example/scim/v2";
    in->auth = axiam_mgmt_scim_target_auth_bearer();
    in->scope = axiam_mgmt_scim_target_scope_all_users();
}

static void dispose_input(axiam_mgmt_scim_target_input_t *in) {
    axiam_mgmt_scim_target_auth_free(in->auth);
    axiam_mgmt_scim_target_scope_free(in->scope);
    axiam_sensitive_free(in->credential);
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- 1. Redaction ----------------------------------------------------------------- */

static void test_the_credential_reaches_the_wire_and_no_rendering(void) {
    char s[64];
    random_secret(s, sizeof s);
    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);
    in.credential = axiam_sensitive_new(s);
    assert_no_fragment(axiam_sensitive_to_string(in.credential), s);

    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"base_url: not https\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_create(c, &in, NULL, &err));
    assert_no_fragment(err.message, s);
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), s) != NULL, "but it is in the request body");
    dispose_input(&in);
    axiam_client_free(c);
}

/* ---- 2. No credential on the response --------------------------------------------- */

static void test_a_credential_in_a_response_is_dropped(void) {
    char leaked[64], extra[128], body[2048];
    random_secret(leaked, sizeof leaked);
    snprintf(extra, sizeof extra, ",\"credential\":\"%s\"", leaked);
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", extra);
    mgmt_mount(200, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_scim_target_response_t *t = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_get(c, TARGET_ID, &t, &err));
    TEST_ASSERT_EQUAL_STRING(TARGETS "/" TARGET_ID, mgmt_last_path());
    cJSON *wire = axiam_mgmt_scim_target_response_build(t);
    char *text = cJSON_PrintUnformatted(wire);
    assert_no_fragment(text, leaked);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(wire, "credential"));
    free(text);
    cJSON_Delete(wire);
    axiam_mgmt_scim_target_response_free(t);
    axiam_client_free(c);
}

/* ---- 3. Replacement and the omitted credential ------------------------------------ */

static void test_update_omits_an_absent_credential_and_the_variants_have_exact_keys(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char body[2048];
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", NULL);

    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "\"credential\""), "no credential key");

    char s[64];
    random_secret(s, sizeof s);
    in.credential = axiam_sensitive_new(s);
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"credential\":"));
    dispose_input(&in);

    /* The input cannot be sent without name, base_url, auth and scope. */
    int before = mgmt_request_count();
    for (int k = 0; k < 4; k++) {
        fill_input(&in);
        axiam_mgmt_scim_target_auth_t *auth = in.auth;
        axiam_mgmt_scim_target_scope_t *scope = in.scope;
        if (k == 0) in.name = NULL;
        if (k == 1) in.base_url = NULL;
        if (k == 2) in.auth = NULL;
        if (k == 3) in.scope = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_create(c, &in, NULL, &err));
        axiam_mgmt_scim_target_auth_free(auth);
        axiam_mgmt_scim_target_scope_free(scope);
    }
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());

    /* Both auth variants and both scope variants, with exactly §31.2's keys. */
    const char *ids[] = {"13131313-1313-4313-8313-131313131313"};
    struct {
        char *raw;
        const char *expected;
    } cases[5];
    axiam_mgmt_scim_target_auth_t *bearer = axiam_mgmt_scim_target_auth_bearer();
    axiam_mgmt_scim_target_auth_t *cc = axiam_mgmt_scim_target_auth_client_credentials(
        "https://idp.example/token", "axiam", "scim");
    axiam_mgmt_scim_target_auth_t *cc_noscope = axiam_mgmt_scim_target_auth_client_credentials(
        "https://idp.example/token", "axiam", NULL);
    axiam_mgmt_scim_target_scope_t *all = axiam_mgmt_scim_target_scope_all_users();
    axiam_mgmt_scim_target_scope_t *groups = axiam_mgmt_scim_target_scope_groups(ids, 1);
    cases[0].raw = bearer->raw;
    cases[0].expected = "{\"type\":\"bearer\"}";
    cases[1].raw = cc->raw;
    cases[1].expected = "{\"type\":\"oauth2_client_credentials\",\"token_url\":"
                        "\"https://idp.example/token\",\"client_id\":\"axiam\",\"scope\":\"scim\"}";
    cases[2].raw = cc_noscope->raw;
    cases[2].expected = "{\"type\":\"oauth2_client_credentials\",\"token_url\":"
                        "\"https://idp.example/token\",\"client_id\":\"axiam\"}";
    cases[3].raw = all->raw;
    cases[3].expected = "{\"type\":\"all_users\"}";
    cases[4].raw = groups->raw;
    cases[4].expected = "{\"type\":\"groups\",\"group_ids\":[\"13131313-1313-4313-8313-131313131313\"]}";
    for (int i = 0; i < 5; i++) TEST_ASSERT_EQUAL_STRING(cases[i].expected, cases[i].raw);
    TEST_ASSERT_EQUAL_STRING("oauth2_client_credentials", cc->type);
    TEST_ASSERT_EQUAL_STRING("groups", groups->type);

    /* ... and they reach the wire as built. */
    memset(&in, 0, sizeof in);
    in.name = (char *) "Downstream";
    in.base_url = (char *) "https://idp.example/scim/v2";
    in.auth = cc;
    in.scope = groups;
    mgmt_mount(201, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_create(c, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), cases[1].expected));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), cases[4].expected));

    TEST_ASSERT_NULL(axiam_mgmt_scim_target_auth_client_credentials(NULL, "a", NULL));
    TEST_ASSERT_NULL(axiam_mgmt_scim_target_auth_client_credentials("https://t", NULL, NULL));
    TEST_ASSERT_NULL(axiam_mgmt_scim_target_scope_groups(NULL, 1));
    const char *bad[] = {NULL};
    TEST_ASSERT_NULL(axiam_mgmt_scim_target_scope_groups(bad, 1));
    axiam_mgmt_scim_target_scope_t *empty = axiam_mgmt_scim_target_scope_groups(NULL, 0);
    TEST_ASSERT_EQUAL_STRING("{\"type\":\"groups\",\"group_ids\":[]}", empty->raw);
    axiam_mgmt_scim_target_scope_free(empty);

    axiam_mgmt_scim_target_auth_free(bearer);
    axiam_mgmt_scim_target_auth_free(cc);
    axiam_mgmt_scim_target_auth_free(cc_noscope);
    axiam_mgmt_scim_target_scope_free(all);
    axiam_mgmt_scim_target_scope_free(groups);
    axiam_client_free(c);
}

/* §31.8 test 3's contract 1.60 assertion: `expected_updated_at` is sent on `update` exactly
 * as given (the caller's string, not re-formatted) and absent when unset; the `409` a stale
 * version earns surfaces as the conflict class. */
static void test_update_passes_expected_updated_at_through_and_a_409_surfaces(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char body[2048];
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", NULL);

    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "expected_updated_at"), "absent when unset");

    /* An unusual but valid spelling: fractional seconds and an offset. Re-formatting it
     * (to `Z`, or dropping the fraction) would change the version the server compares. */
    in.expected_updated_at = (char *) "2026-10-05T02:00:00.123456+02:00";
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(),
                                "\"expected_updated_at\":\"2026-10-05T02:00:00.123456+02:00\""));

    int before = mgmt_request_count();
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"the target changed since it was read\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(409, err.transport_cause);
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "a 409 is not retried");

    in.expected_updated_at = NULL;
    dispose_input(&in);
    axiam_client_free(c);
}

/* R-22 (contract 1.60 C-12): an unknown `deprovision` or `user_name_from` read from the
 * server decodes to `_UNKNOWN`; carried back through the read-modify-write helper it is
 * refused locally, naming the member, and never sent as "". */
static void test_an_unknown_enum_value_is_refused_not_sent_as_empty(void) {
    char body[2048];
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", NULL);
    char *at = strstr(body, "\"deactivate\"");
    TEST_ASSERT_NOT_NULL(at);
    char unknown[2048];
    snprintf(unknown, sizeof unknown, "%.*s\"archive_forever\"%s",
             (int) (at - body), body, at + strlen("\"deactivate\""));
    mgmt_mount(200, unknown);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_scim_target_response_t *t = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_get(c, TARGET_ID, &t, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_DEPROVISION_POLICY_UNKNOWN, t->deprovision);

    axiam_mgmt_scim_target_input_t *in = axiam_mgmt_scim_target_response_to_input(t);
    TEST_ASSERT_NOT_NULL(in);
    int before = mgmt_request_count();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(400, err.transport_cause);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "deprovision"));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), "refused before any request");

    /* A known value sends; a value outside the enum altogether is refused as well. */
    in->deprovision = AXIAM_MGMT_DEPROVISION_POLICY_DEACTIVATE;
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"deprovision\":\"deactivate\""));
    in->user_name_from = (axiam_mgmt_user_name_source_t) 0x7fff;
    in->has_user_name_from = 1;
    before = mgmt_request_count();
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_create(c, in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "user_name_from"));
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());

    axiam_mgmt_scim_target_input_free(in);
    axiam_mgmt_scim_target_response_free(t);
    axiam_client_free(c);
}

/* ---- 4. Open decoding and pagination ---------------------------------------------- */

static void test_unknown_arms_and_values_decode_and_the_pager_carries_search(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char body[2048];
    snprintf(body, sizeof body,
             "{\"items\":[{\"id\":\"" TARGET_ID "\",\"tenant_id\":\"11111111-1111-4111-8111-111111111111\","
             "\"name\":\"n\",\"base_url\":\"https://idp.example/scim/v2\",\"enabled\":true,"
             "\"auth\":{\"type\":\"mutual_tls\",\"cert_ref\":\"x\"},\"scope\":{\"type\":\"everyone_new\"},"
             "\"push_groups\":true,\"user_name_from\":\"employee_number\",\"deprovision\":\"archive\","
             "\"created_at\":\"2026-10-05T00:00:00Z\",\"updated_at\":\"2026-10-05T00:00:00Z\","
             "\"state\":null},"
             "{\"id\":\"" TARGET_ID "\",\"name\":\"m\",\"auth\":{\"type\":\"bearer\"},"
             "\"scope\":{\"type\":\"all_users\"},\"state\":{\"last_failure_reason\":\"a phrase never seen\","
             "\"consecutive_failures\":3,\"dead_lettered_total\":1}}],"
             "\"total\":3,\"offset\":0,\"limit\":2}");
    mgmt_mount(200, body);
    axiam_mgmt_page_req_t req = {0, 2, "downstream"};
    axiam_mgmt_scim_target_response_page_t *page = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_list(c, &req, &page, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_url(), "search=downstream"));
    TEST_ASSERT_EQUAL_INT(3, (int) page->total);
    TEST_ASSERT_EQUAL_INT(2, (int) page->count);
    axiam_mgmt_scim_target_response_t *t = page->items[0];
    TEST_ASSERT_EQUAL_STRING("mutual_tls", t->auth->type);
    TEST_ASSERT_FALSE(axiam_mgmt_scim_target_auth_is_known(t->auth));
    TEST_ASSERT_EQUAL_STRING("everyone_new", t->scope->type);
    TEST_ASSERT_FALSE(axiam_mgmt_scim_target_scope_is_known(t->scope));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_USER_NAME_SOURCE_UNKNOWN, t->user_name_from);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_DEPROVISION_POLICY_UNKNOWN, t->deprovision);
    TEST_ASSERT_NULL(t->state);
    TEST_ASSERT_EQUAL_STRING("a phrase never seen", page->items[1]->state->last_failure_reason);
    TEST_ASSERT_TRUE(axiam_mgmt_scim_target_auth_is_known(page->items[1]->auth));

    axiam_mgmt_scim_target_response_page_free(page);

    /* The auto-pager (§31.8 t4): walks to the empty page and carries the same term on
     * every request it issues. */
    mgmt_mount(200, body);
    mgmt_mount(200, "{\"items\":[{\"id\":\"" TARGET_ID "\",\"name\":\"o\",\"auth\":{\"type\":\"bearer\"},"
                    "\"scope\":{\"type\":\"all_users\"}}],\"total\":3,\"offset\":2,\"limit\":2}");
    mgmt_mount(200, "{\"items\":[],\"total\":3,\"offset\":4,\"limit\":2}");
    int before = mgmt_request_count();
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_list_all(c, &req, &page, &err));
    TEST_ASSERT_EQUAL_INT(3, mgmt_request_count() - before);
    static const char *const offsets[] = {"offset=0", "offset=2", "offset=4"};
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(before + i), "search=downstream"));
        TEST_ASSERT_NOT_NULL(strstr(mgmt_url_at(before + i), offsets[i]));
    }
    TEST_ASSERT_EQUAL_INT(3, (int) page->count);
    TEST_ASSERT_EQUAL_INT(3, (int) page->total);
    TEST_ASSERT_EQUAL_STRING("o", page->items[2]->name);
    axiam_mgmt_scim_target_response_page_free(page);
    axiam_client_free(c);
}

static void test_an_unknown_arm_is_never_sent(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    int before = mgmt_request_count();
    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);
    /* An arm decoded from a newer server, carried back unchanged. */
    axiam_mgmt_scim_target_auth_t unknown = {(char *) "mutual_tls", (char *) "{\"type\":\"mutual_tls\"}"};
    axiam_mgmt_scim_target_auth_t *built = in.auth;
    in.auth = &unknown;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_create(c, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "auth"));
    /* raw is what goes on the wire, so raw's tag is the one judged. */
    axiam_mgmt_scim_target_auth_t disguised = {(char *) "bearer", (char *) "{\"type\":\"mutual_tls\"}"};
    in.auth = &disguised;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    axiam_mgmt_scim_target_auth_t garbage = {(char *) "bearer", (char *) "{not json"};
    in.auth = &garbage;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    axiam_mgmt_scim_target_auth_t untyped = {(char *) "bearer", (char *) "{\"token_url\":\"x\"}"};
    in.auth = &untyped;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    in.auth = built;
    axiam_mgmt_scim_target_scope_t *all = in.scope;
    axiam_mgmt_scim_target_scope_t odd = {(char *) "everyone_new", NULL};
    in.scope = &odd;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "scope"));
    in.scope = all;
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    TEST_ASSERT_FALSE(axiam_mgmt_scim_target_auth_is_known(NULL));
    TEST_ASSERT_FALSE(axiam_mgmt_scim_target_scope_is_known(NULL));

    /* A tag set without raw is judged by the tag: a known one is sent as {type}. */
    axiam_mgmt_scim_target_scope_t bare = {(char *) "all_users", NULL};
    in.scope = &bare;
    char body[2048];
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", NULL);
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"scope\":{\"type\":\"all_users\"}"));
    in.scope = all;
    dispose_input(&in);
    axiam_client_free(c);
}

/* Contract 1.59 P12.1 (R-20): only DECLARED members are kept from a response -- in a
 * known union arm and in an unknown one, where the discriminator alone is kept. `raw`
 * used to hold the server's whole object, so an undeclared member (a secret a newer
 * server mistakenly echoes, say) was surfaced and, through _to_input, sent back. */
static void test_only_declared_union_members_are_kept(void) {
    char leaked[64], target[4096], auth[512], scope[256];
    random_secret(leaked, sizeof leaked);
    static const char *const auths[] = {
        "{\"type\":\"bearer\",\"token\":\"%s\"}",
        "{\"type\":\"oauth2_client_credentials\",\"token_url\":\"https://as.example/token\","
        "\"client_id\":\"axiam\",\"scope\":null,\"client_secret\":\"%s\"}",
        "{\"type\":\"mutual_tls\",\"cert_ref\":\"x\",\"private_key\":\"%s\"}",
    };
    static const char *const kept[] = {
        "{\"type\":\"bearer\"}",
        "{\"type\":\"oauth2_client_credentials\",\"token_url\":\"https://as.example/token\","
        "\"client_id\":\"axiam\",\"scope\":null}",
        "{\"type\":\"mutual_tls\"}",
    };
    static const char *const scopes[] = {
        "{\"type\":\"groups\",\"group_ids\":[\"g1\"],\"note\":\"%s\"}",
        "{\"type\":\"all_users\",\"note\":\"%s\"}",
        "{\"type\":\"everyone_new\",\"note\":\"%s\"}",
    };
    static const char *const scopes_kept[] = {
        "{\"type\":\"groups\",\"group_ids\":[\"g1\"]}",
        "{\"type\":\"all_users\"}",
        "{\"type\":\"everyone_new\"}",
    };
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    for (int i = 0; i < 3; i++) {
        snprintf(auth, sizeof auth, auths[i], leaked);
        snprintf(scope, sizeof scope, scopes[i], leaked);
        target_body(target, sizeof target, auth, NULL);
        /* Replace the default scope with the one under test. */
        char *at = strstr(target, "\"scope\":{\"type\":\"all_users\"}");
        TEST_ASSERT_NOT_NULL(at);
        char rebuilt[4096];
        snprintf(rebuilt, sizeof rebuilt, "%.*s\"scope\":%s%s", (int) (at - target), target, scope,
                 at + strlen("\"scope\":{\"type\":\"all_users\"}"));
        mgmt_mount(200, rebuilt);
        axiam_mgmt_scim_target_response_t *t = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_get(c, TARGET_ID, &t, &err));
        TEST_ASSERT_NOT_NULL(t->auth);
        assert_no_fragment(t->auth->raw, leaked);
        TEST_ASSERT_EQUAL_STRING(kept[i], t->auth->raw);
        assert_no_fragment(t->scope->raw, leaked);
        TEST_ASSERT_EQUAL_STRING(scopes_kept[i], t->scope->raw);
        /* ... and the read-modify-write conversion cannot echo what was not kept. */
        axiam_mgmt_scim_target_input_t *in = axiam_mgmt_scim_target_response_to_input(t);
        TEST_ASSERT_NOT_NULL(in);
        if (i < 2) {
            mgmt_mount(200, rebuilt);
            TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, in, NULL, &err));
            assert_no_fragment(mgmt_last_body(), leaked);
        }
        axiam_mgmt_scim_target_input_free(in);
        axiam_mgmt_scim_target_response_free(t);
    }
    axiam_client_free(c);
}

/* ---- 5. No retry ------------------------------------------------------------------ */

static void test_no_write_is_retried_on_503(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char body[2048];
    target_body(body, sizeof body, "{\"type\":\"bearer\"}", NULL);
    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);
    for (int k = 0; k < 4; k++) {
        int before = mgmt_request_count();
        mgmt_mount(503, NULL);
        mgmt_mount_next(200, body);
        axiam_error_kind_t rc;
        switch (k) {
            case 0: rc = axiam_scim_targets_create(c, &in, NULL, &err); break;
            case 1: rc = axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err); break;
            case 2: rc = axiam_scim_targets_delete(c, TARGET_ID, &err); break;
            default: rc = axiam_scim_targets_reconcile(c, TARGET_ID, NULL, &err); break;
        }
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
        TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "exactly one request");
        mgmt_reset();
        axiam_client_free(c);
        c = mgmt_signed_in_client();
    }
    dispose_input(&in);
    axiam_client_free(c);
}

/* ---- 6. Errors and reconcile ------------------------------------------------------ */

static void test_errors_and_reconcile(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_scim_target_input_t in;
    fill_input(&in);

    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"auth.type: changing it requires the credential\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "requires the credential"));

    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"changed since it was read\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_scim_targets_update(c, TARGET_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"a run holds the claim\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_scim_targets_reconcile(c, TARGET_ID, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));

    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"no\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_scim_targets_get(c, TARGET_ID, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    mgmt_mount(401, "{\"error\":\"unauthorized\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_scim_targets_get(c, TARGET_ID, NULL, &err));

    mgmt_mount(202, "{\"target_id\":\"" TARGET_ID "\",\"status\":\"started\"}");
    axiam_mgmt_scim_reconcile_accepted_t *accepted = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_reconcile(c, TARGET_ID, &accepted, &err));
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(TARGETS "/" TARGET_ID "/reconcile", mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", mgmt_last_body(), "reconcile sends no body");
    TEST_ASSERT_EQUAL_STRING(TARGET_ID, accepted->target_id);
    TEST_ASSERT_EQUAL_STRING("started", accepted->status);
    axiam_mgmt_scim_reconcile_accepted_free(accepted);
    dispose_input(&in);
    axiam_client_free(c);
}

static void test_a_read_converts_into_the_replacement_body_without_the_credential(void) {
    char body[2048];
    target_body(body, sizeof body,
                "{\"type\":\"oauth2_client_credentials\",\"token_url\":\"https://idp.example/token\","
                "\"client_id\":\"axiam\",\"scope\":null}", NULL);
    mgmt_mount(200, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_scim_target_response_t *t = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_get(c, TARGET_ID, &t, &err));
    axiam_mgmt_scim_target_input_t *in = axiam_mgmt_scim_target_response_to_input(t);
    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NULL_MESSAGE(in->credential, "absent keeps the stored credential");
    TEST_ASSERT_EQUAL_STRING("Downstream", in->name);
    TEST_ASSERT_EQUAL_STRING("oauth2_client_credentials", in->auth->type);
    TEST_ASSERT_TRUE(in->has_enabled);
    TEST_ASSERT_TRUE(in->has_deprovision);
    mgmt_mount(200, body);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_scim_targets_update(c, TARGET_ID, in, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"token_url\":\"https://idp.example/token\""));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "\"state\""));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "\"credential\""));
    axiam_mgmt_scim_target_input_free(in);
    axiam_mgmt_scim_target_response_free(t);
    TEST_ASSERT_NULL(axiam_mgmt_scim_target_response_to_input(NULL));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_credential_reaches_the_wire_and_no_rendering);
    RUN_TEST(test_a_credential_in_a_response_is_dropped);
    RUN_TEST(test_update_omits_an_absent_credential_and_the_variants_have_exact_keys);
    RUN_TEST(test_update_passes_expected_updated_at_through_and_a_409_surfaces);
    RUN_TEST(test_an_unknown_enum_value_is_refused_not_sent_as_empty);
    RUN_TEST(test_unknown_arms_and_values_decode_and_the_pager_carries_search);
    RUN_TEST(test_an_unknown_arm_is_never_sent);
    RUN_TEST(test_only_declared_union_members_are_kept);
    RUN_TEST(test_no_write_is_retried_on_503);
    RUN_TEST(test_errors_and_reconcile);
    RUN_TEST(test_a_read_converts_into_the_replacement_body_without_the_credential);
    return UNITY_END();
}
