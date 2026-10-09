/*
 * CONTRACT.md §30 (contract 1.54) — the `directory` management namespace: §30.8's six
 * required tests, plus the sync-status decoding, the implicit tenant and the
 * read-modify-write conversion.
 *
 * The bind secret is generated at run time: a literal would be a credential in the
 * repository and would let a redaction test pass by coincidence. A failing redaction
 * assertion names an offset, never the secret or the rendering it was found in.
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

/* The generated wire builder, internal to the generated sources: the one serializer a
 * decoded value has, so it is what "serialized for logs" means here. */
cJSON *axiam_mgmt_directory_config_build(const axiam_mgmt_directory_config_t *value);

/* management_test_util.c's clients are configured with this tenant. */
#define TENANT "11111111-1111-4111-8111-111111111111"
#define DIRECTORY "/api/v1/tenants/" TENANT "/directory"

#define CONFIG_BODY                                                                        \
    "{\"id\":\"33333333-3333-4333-8333-333333333333\",\"tenant_id\":\"" TENANT "\","     \
    "\"enabled\":true,\"kind\":\"active_directory\",\"url\":\"ldaps://dc.corp.example\","  \
    "\"start_tls\":false,\"bind_dn\":\"cn=svc,dc=corp\",\"base_dn\":\"dc=corp\","          \
    "\"user_filter\":\"(sAMAccountName={username})\","                                    \
    "\"user_attribute_map\":{\"username\":\"sAMAccountName\",\"email\":\"mail\","          \
    "\"display_name\":\"displayName\",\"external_id\":\"objectGUID\"},"                    \
    "\"group_base_dn\":null,\"group_filter\":null,\"group_member_attribute\":\"member\","  \
    "\"group_nesting_depth\":5,\"group_mappings\":[],\"sync_interval_secs\":3600,"         \
    "\"jit_provisioning\":false,\"trust_anchors_pem\":[],"                                 \
    "\"created_at\":\"2026-10-04T00:00:00Z\",\"updated_at\":\"2026-10-04T00:00:00Z\""

static void random_secret(char *out, size_t cap) {
    unsigned char raw[24];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    out[n++] = 'b';
    for (size_t i = 0; i < sizeof raw && n + 2 < cap; i++) {
        out[n++] = hex[raw[i] >> 4];
        out[n++] = hex[raw[i] & 0xF];
    }
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

/* A replacement body carrying the seven required members. */
static void fill_set(axiam_mgmt_set_directory_config_t *b) {
    memset(b, 0, sizeof *b);
    b->enabled = 1;
    b->kind = AXIAM_MGMT_DIRECTORY_KIND_ACTIVE_DIRECTORY;
    b->url = (char *) "ldaps://dc.corp.example";
    b->start_tls = 0;
    b->bind_dn = (char *) "cn=svc,dc=corp";
    b->base_dn = (char *) "dc=corp";
    b->user_filter = (char *) "(sAMAccountName={username})";
}

/* The keys of a JSON object, sorted and comma-joined, for exact-key-set assertions. */
static void keys_of(const char *json, char *out, size_t cap) {
    cJSON *o = cJSON_Parse(json);
    TEST_ASSERT_TRUE(cJSON_IsObject(o));
    const char *names[32];
    int n = 0;
    for (const cJSON *f = o->child; f && n < 32; f = f->next) names[n++] = f->string;
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--) {
            const char *t = names[j];
            names[j] = names[j - 1];
            names[j - 1] = t;
        }
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        strncat(out, names[i], cap - strlen(out) - 2);
        if (i + 1 < n) strncat(out, ",", cap - strlen(out) - 1);
    }
    cJSON_Delete(o);
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- 1. Redaction ----------------------------------------------------------------- */

static void test_the_bind_secret_reaches_the_wire_and_no_rendering(void) {
    char s[64];
    random_secret(s, sizeof s);
    axiam_mgmt_set_directory_config_t set;
    fill_set(&set);
    set.bind_secret = axiam_sensitive_new(s);
    axiam_mgmt_update_directory_config_t update;
    memset(&update, 0, sizeof update);
    update.bind_secret = axiam_sensitive_new(s);
    /* The only rendering a Sensitive member has. */
    assert_no_fragment(axiam_sensitive_to_string(set.bind_secret), s);
    assert_no_fragment(axiam_sensitive_to_string(update.bind_secret), s);

    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"url: plaintext LDAP is refused\"}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_directory_config_t *out = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, &set, &out, &err));
    assert_no_fragment(err.message, s);
    TEST_ASSERT_TRUE_MESSAGE(strstr(mgmt_last_body(), s) != NULL, "but it is on the wire");

    axiam_sensitive_free(set.bind_secret);
    axiam_sensitive_free(update.bind_secret);
    axiam_client_free(c);
}

/* ---- 2. No secret on the response ------------------------------------------------- */

static void test_a_bind_secret_in_a_response_is_dropped(void) {
    char leaked[64], body[2048];
    random_secret(leaked, sizeof leaked);
    snprintf(body, sizeof body, CONFIG_BODY ",\"bind_secret\":\"%s\"}", leaked);
    mgmt_mount(200, body);
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_directory_config_t *config = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_get(c, NULL, &config, &err));
    TEST_ASSERT_EQUAL_STRING("ldaps://dc.corp.example", config->url);
    /* DirectoryConfig declares no secret member, so the decoder has nowhere to put one:
     * serializing the decoded value finds no trace of it. */
    cJSON *wire = axiam_mgmt_directory_config_build(config);
    char *text = cJSON_PrintUnformatted(wire);
    assert_no_fragment(text, leaked);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(wire, "bind_secret"));
    free(text);
    cJSON_Delete(wire);
    axiam_mgmt_directory_config_free(config);
    axiam_client_free(c);
}

/* ---- 3. Sparse update ------------------------------------------------------------- */

static void test_update_sends_exactly_the_members_it_was_given(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_directory_config_t *out = NULL;
    char keys[256];

    axiam_mgmt_update_directory_config_t u;
    memset(&u, 0, sizeof u);
    u.enabled = 0;
    u.has_enabled = 1;
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_update(c, NULL, &u, &out, &err));
    TEST_ASSERT_EQUAL_STRING("PATCH", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(DIRECTORY, mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING("{\"enabled\":false}", mgmt_last_body());
    axiam_mgmt_directory_config_free(out);

    char s[64];
    random_secret(s, sizeof s);
    memset(&u, 0, sizeof u);
    u.url = (char *) "ldaps://dc2.corp.example";
    u.bind_secret = axiam_sensitive_new(s);
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_update(c, NULL, &u, &out, &err));
    keys_of(mgmt_last_body(), keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("bind_secret,url", keys);
    TEST_ASSERT_TRUE(strstr(mgmt_last_body(), s) != NULL);
    axiam_sensitive_free(u.bind_secret);
    axiam_mgmt_directory_config_free(out);

    /* Explicit null clears; absent keeps (§27.4 rule 5, "null is not absent"). */
    memset(&u, 0, sizeof u);
    u.has_group_filter = 1;
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_update(c, NULL, &u, &out, &err));
    TEST_ASSERT_EQUAL_STRING("{\"group_filter\":null}", mgmt_last_body());
    axiam_mgmt_directory_config_free(out);

    /* A value wins over the flag, and both members can be cleared at once. */
    memset(&u, 0, sizeof u);
    u.group_base_dn = (char *) "ou=groups";
    u.has_group_base_dn = 0;
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_update(c, NULL, &u, NULL, &err));
    TEST_ASSERT_EQUAL_STRING("{\"group_base_dn\":\"ou=groups\"}", mgmt_last_body());
    memset(&u, 0, sizeof u);
    u.has_group_base_dn = 1;
    u.has_group_filter = 1;
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_update(c, NULL, &u, NULL, &err));
    keys_of(mgmt_last_body(), keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("group_base_dn,group_filter", keys);
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"group_base_dn\":null"));
    axiam_client_free(c);
}

/* ---- 4. Replacement --------------------------------------------------------------- */

static void test_set_sends_every_required_member_and_decodes_201_and_200(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    static const long statuses[] = {201, 200};
    for (int i = 0; i < 2; i++) {
        axiam_mgmt_set_directory_config_t set;
        fill_set(&set);
        axiam_mgmt_directory_config_t *out = NULL;
        mgmt_mount(statuses[i], CONFIG_BODY "}");
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_set(c, NULL, &set, &out, &err));
        TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
        TEST_ASSERT_TRUE(out->enabled);
        cJSON *sent = cJSON_Parse(mgmt_last_body());
        static const char *const required[] = {"enabled", "kind", "url", "start_tls",
                                               "bind_dn", "base_dn", "user_filter"};
        for (size_t k = 0; k < 7; k++)
            TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, required[k]),
                                         required[k]);
        TEST_ASSERT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, "bind_secret"),
                                 "absent keeps the stored secret");
        cJSON_Delete(sent);
        axiam_mgmt_directory_config_free(out);
    }

    /* C has no compile-time check, so the operation is the builder that refuses: a
     * replacement missing a required member never reaches the wire. */
    int before = mgmt_request_count();
    static const char *const members[] = {"url", "bind_dn", "base_dn", "user_filter"};
    for (int k = 0; k < 4; k++) {
        axiam_mgmt_set_directory_config_t set;
        fill_set(&set);
        if (k == 0) set.url = NULL;
        if (k == 1) set.bind_dn = NULL;
        if (k == 2) set.base_dn = NULL;
        if (k == 3) set.user_filter = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, &set, NULL, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_NOT_NULL(strstr(err.message, members[k]));
    }
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());
    axiam_client_free(c);
}

/* ---- 5. No retry ------------------------------------------------------------------ */

static void test_no_write_is_retried_on_503(void) {
    axiam_client_t *c = mgmt_signed_in_client(); /* §27.4 rule 8's GET retry is on */
    axiam_error_t err;
    int before;

    char s[64];
    random_secret(s, sizeof s);
    axiam_mgmt_set_directory_config_t set;
    fill_set(&set);
    set.bind_secret = axiam_sensitive_new(s);
    before = mgmt_request_count();
    /* Only the 503 is mounted: a retry would reach the rig's default answer and still
     * count as a second request. */
    mgmt_mount(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, &set, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "set: exactly one request");
    axiam_sensitive_free(set.bind_secret);

    mgmt_reset();
    axiam_client_free(c);
    c = mgmt_signed_in_client();
    axiam_mgmt_update_directory_config_t u;
    memset(&u, 0, sizeof u);
    before = mgmt_request_count();
    mgmt_mount(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_update(c, NULL, &u, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "update: exactly one request");

    before = mgmt_request_count();
    mgmt_mount(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_delete(c, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "delete: exactly one request");

    axiam_mgmt_link_directory_account_t link = {(char *) "44444444-4444-4444-8444-444444444444"};
    before = mgmt_request_count();
    mgmt_mount(503, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_directory_link_account(c, NULL, &link, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "link: exactly one request");

    /* The reads, by contrast, may be retried (§30.7). */
    before = mgmt_request_count();
    mgmt_mount(503, NULL);
    mgmt_mount_next(200, CONFIG_BODY "}");
    axiam_mgmt_directory_config_t *out = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_get(c, NULL, &out, &err));
    TEST_ASSERT_EQUAL_INT(before + 2, mgmt_request_count());
    axiam_mgmt_directory_config_free(out);
    axiam_client_free(c);
}

/* ---- 6. Errors and link_account --------------------------------------------------- */

static void test_errors_map_per_section_2_and_link_account_sends_only_the_user_id(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_set_directory_config_t set;
    fill_set(&set);

    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"url: changing the "
                    "connection requires entering the bind secret again\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_directory_set(c, NULL, &set, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err.message, "bind secret again"),
                                 "the ValidationError carries the server's message");

    axiam_mgmt_update_directory_config_t u;
    memset(&u, 0, sizeof u);
    u.enabled = 1;
    u.has_enabled = 1;
    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"opaque_mode\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_directory_update(c, NULL, &u, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));

    axiam_mgmt_directory_config_t *out = NULL;
    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"none\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_directory_get(c, NULL, &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NULL(out);

    mgmt_mount(401, "{\"error\":\"unauthorized\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, axiam_directory_get(c, NULL, &out, &err));

    const char *user = "55555555-5555-4555-8555-555555555555";
    axiam_mgmt_link_directory_account_t link = {(char *) user};
    mgmt_mount(200, "{\"user_id\":\"55555555-5555-4555-8555-555555555555\","
                    "\"directory_external_id\":\"3f2a-objectguid\","
                    "\"webauthn_credentials_deleted\":2,\"certificates_revoked\":1,"
                    "\"was_already_linked\":false}");
    axiam_mgmt_directory_link_result_t *result = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_link_account(c, NULL, &link, &result, &err));
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(DIRECTORY "/links", mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING("{\"user_id\":\"55555555-5555-4555-8555-555555555555\"}",
                             mgmt_last_body());
    TEST_ASSERT_EQUAL_STRING(user, result->user_id);
    TEST_ASSERT_EQUAL_STRING("3f2a-objectguid", result->directory_external_id);
    TEST_ASSERT_EQUAL_INT(2, (int) result->webauthn_credentials_deleted);
    TEST_ASSERT_EQUAL_INT(1, (int) result->certificates_revoked);
    TEST_ASSERT_FALSE(result->was_already_linked);
    axiam_mgmt_directory_link_result_free(result);
    axiam_client_free(c);
}

/* ---- beyond the six ----------------------------------------------------------------- */

static void test_sync_status_decodes_an_unknown_result_and_the_first_run_nulls(void) {
    mgmt_mount(200, "{\"last_result\":\"something_new\",\"last_attempt_at\":null,"
                    "\"last_full_run_at\":null,\"full_required\":true,\"has_watermark\":false}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_directory_sync_status_t *status = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_get_sync_status(c, NULL, &status, &err));
    TEST_ASSERT_EQUAL_STRING(DIRECTORY "/sync-status", mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING("something_new", status->last_result);
    TEST_ASSERT_NULL(status->last_attempt_at);
    TEST_ASSERT_TRUE(status->full_required);
    TEST_ASSERT_FALSE(status->has_watermark);
    axiam_mgmt_directory_sync_status_free(status);
    axiam_client_free(c);
}

static void test_the_tenant_defaults_from_the_client_and_a_scope_overrides_it(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_delete(c, NULL, &err));
    TEST_ASSERT_EQUAL_STRING("DELETE", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(DIRECTORY, mgmt_last_path());
    axiam_mgmt_call_scope_t scope = {NULL, "66666666-6666-4666-8666-666666666666"};
    mgmt_mount(204, NULL);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_delete(c, &scope, &err));
    TEST_ASSERT_EQUAL_STRING("/api/v1/tenants/66666666-6666-4666-8666-666666666666/directory",
                             mgmt_last_path());
    axiam_client_free(c);
}

static void test_a_read_converts_into_the_replacement_body_without_a_secret(void) {
    mgmt_mount(200, CONFIG_BODY "}");
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_mgmt_directory_config_t *config = NULL;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_get(c, NULL, &config, &err));
    axiam_mgmt_set_directory_config_t *body = axiam_mgmt_directory_config_to_set(config);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NULL_MESSAGE(body->bind_secret, "absent keeps the stored secret");
    TEST_ASSERT_EQUAL_STRING(config->url, body->url);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_DIRECTORY_KIND_ACTIVE_DIRECTORY, body->kind);
    TEST_ASSERT_TRUE(body->has_group_nesting_depth);
    TEST_ASSERT_EQUAL_INT(5, (int) body->group_nesting_depth);
    TEST_ASSERT_EQUAL_INT(3600, (int) body->sync_interval_secs);
    TEST_ASSERT_NOT_NULL(body->user_attribute_map);
    TEST_ASSERT_EQUAL_STRING("objectGUID", body->user_attribute_map->external_id);

    /* ... and goes back as the replacement, unchanged but for what the caller edits. */
    body->jit_provisioning = 1;
    body->has_jit_provisioning = 1;
    mgmt_mount(200, CONFIG_BODY "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_directory_set(c, NULL, body, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"jit_provisioning\":true"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "bind_secret"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "\"id\""));
    axiam_mgmt_set_directory_config_free(body);
    axiam_mgmt_directory_config_free(config);
    TEST_ASSERT_NULL(axiam_mgmt_directory_config_to_set(NULL));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_bind_secret_reaches_the_wire_and_no_rendering);
    RUN_TEST(test_a_bind_secret_in_a_response_is_dropped);
    RUN_TEST(test_update_sends_exactly_the_members_it_was_given);
    RUN_TEST(test_set_sends_every_required_member_and_decodes_201_and_200);
    RUN_TEST(test_no_write_is_retried_on_503);
    RUN_TEST(test_errors_map_per_section_2_and_link_account_sends_only_the_user_id);
    RUN_TEST(test_sync_status_decodes_an_unknown_result_and_the_first_run_nulls);
    RUN_TEST(test_the_tenant_defaults_from_the_client_and_a_scope_overrides_it);
    RUN_TEST(test_a_read_converts_into_the_replacement_body_without_a_secret);
    return UNITY_END();
}
