/*
 * CONTRACT.md contract 1.60, the §27 management additions every SDK owes (§34.4's
 * "every SDK" rows), against the fake transport:
 *
 * - §27.15 note 1: `window_minutes` on the `notification_rules` request and response
 *   models -- passed through as given, never clamped, absent when unset;
 * - §27.15 note 6: `allow_sha1_signatures` -- sent only when set, and a response that lacks
 *   it (an older server) reads false;
 * - §27.15 note 7: `idp_metadata_signing_cert_pem` -- an optional, nullable string on the
 *   three federation configuration models, sent only when set;
 * - §27.15 note 8: every nullable member of `UpdateFederationConfigRequest` distinguishes
 *   "unset" (omitted, left unchanged) from "set to null" (sent as `null`, clears), with
 *   §27.4 rule 5's exact key-set test.
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

#define UUID "11111111-1111-4111-8111-111111111111"
#define RULE_ID "31313131-3131-4313-8313-313131313131"
#define CONFIG_ID "32323232-3232-4323-8323-323232323232"

/* A certificate's PEM armour around a placeholder body: these tests only carry it. */
#define CERT_PEM "-----BEGIN CERTIFICATE-----\nMIIBplaceholder\n-----END CERTIFICATE-----\n"

#define RULE_FIELDS \
    "\"id\":\"" RULE_ID "\",\"tenant_id\":\"" UUID "\",\"name\":\"lockouts\"," \
    "\"description\":\"d\",\"events\":[\"user.locked\"],\"recipient_emails\":[\"ops@example.com\"]," \
    "\"enabled\":true,\"created_at\":\"2026-10-10T00:00:00Z\",\"updated_at\":\"2026-10-10T00:00:00Z\""

#define CONFIG_FIELDS \
    "\"id\":\"" CONFIG_ID "\",\"tenant_id\":\"" UUID "\",\"provider\":\"corp-idp\"," \
    "\"protocol\":\"Saml\",\"client_id\":\"axiam\",\"attribute_map\":{},\"enabled\":true," \
    "\"token_exchange\":null,\"provider_kind\":\"generic_saml\",\"allow_tenant_inheritance\":false," \
    "\"scopes\":[],\"effective_scopes\":[],\"allowed_issuer_tenants\":[],\"allowed_algorithms\":[]," \
    "\"mints_client_secret\":false,\"pkce_required\":false,\"has_bundled_mark\":false," \
    "\"created_at\":\"2026-10-10T00:00:00Z\",\"updated_at\":\"2026-10-10T00:00:00Z\""

/* The members of the last request body, comma-joined in the order sent. */
static void body_keys(char *out, size_t cap) {
    out[0] = '\0';
    cJSON *body = cJSON_Parse(mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsObject(body), "the body is a JSON object");
    size_t n = 0;
    for (const cJSON *m = body->child; m; m = m->next) {
        int w = snprintf(out + n, cap - n, "%s%s", n ? "," : "", m->string);
        TEST_ASSERT_TRUE(w > 0 && (size_t) w < cap - n);
        n += (size_t) w;
    }
    cJSON_Delete(body);
}

static int body_member_is_null(const char *name) {
    cJSON *body = cJSON_Parse(mgmt_last_body());
    int is_null = cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(body, name));
    cJSON_Delete(body);
    return is_null;
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- §27.15 note 1: window_minutes ----------------------------------------------- */

static void test_window_minutes_is_passed_through_never_clamped_and_decoded(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char *emails[] = {(char *) "ops@example.com"};
    axiam_mgmt_create_notification_rule_request_t in;
    memset(&in, 0, sizeof in);
    in.name = (char *) "lockouts";
    in.description = (char *) "d";
    in.events = (char *) "[\"user.locked\"]";
    in.recipient_emails = emails;
    in.recipient_emails_count = 1;

    /* Without it: no such key. */
    mgmt_mount(201, "{" RULE_FIELDS ",\"window_minutes\":15}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_notification_rules_create(c, &in, NULL, &err));
    TEST_ASSERT_NULL_MESSAGE(strstr(mgmt_last_body(), "window_minutes"), "absent when unset");

    /* With it: as given -- including values outside 1 … 1440, which the server judges. */
    const long given[] = {60, 1440, 5000, 0};
    for (size_t i = 0; i < sizeof given / sizeof given[0]; i++) {
        in.window_minutes = given[i];
        in.has_window_minutes = 1;
        mgmt_mount(201, "{" RULE_FIELDS ",\"window_minutes\":15}");
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_notification_rules_create(c, &in, NULL, &err));
        char expected[48];
        snprintf(expected, sizeof expected, "\"window_minutes\":%ld", given[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mgmt_last_body(), expected), "sent exactly as given");
    }

    /* The update model carries it too, and omits it when unset (sparse). */
    axiam_mgmt_update_notification_rule_request_t up;
    memset(&up, 0, sizeof up);
    mgmt_mount(200, "{" RULE_FIELDS ",\"window_minutes\":15}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_notification_rules_update(c, RULE_ID, &up, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "window_minutes"));
    up.window_minutes = 2000;
    up.has_window_minutes = 1;
    mgmt_mount(200, "{" RULE_FIELDS ",\"window_minutes\":15}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_notification_rules_update(c, RULE_ID, &up, NULL, &err));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"window_minutes\":2000"));

    /* A response carrying it decodes it. */
    mgmt_mount(200, "{" RULE_FIELDS ",\"window_minutes\":90}");
    axiam_mgmt_notification_rule_response_t *rule = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_notification_rules_get(c, RULE_ID, &rule, &err));
    TEST_ASSERT_EQUAL_INT(90, (int) rule->window_minutes);
    axiam_mgmt_notification_rule_response_free(rule);
    axiam_client_free(c);
}

/* ---- §27.15 notes 6 and 7: the two federation members ---------------------------- */

static void test_allow_sha1_signatures_reads_false_when_absent_and_is_sent_only_when_set(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_federation_config_response_t *cfg = NULL;

    /* An older server omits both members. */
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_get_config(c, CONFIG_ID, &cfg, &err));
    TEST_ASSERT_FALSE(cfg->allow_sha1_signatures);
    TEST_ASSERT_NULL(cfg->idp_metadata_signing_cert_pem);
    axiam_mgmt_federation_config_response_free(cfg);

    /* A 1.0.0 server sends both; a null certificate reads as NULL. */
    mgmt_mount(200, "{" CONFIG_FIELDS ",\"allow_sha1_signatures\":true,"
                    "\"idp_metadata_signing_cert_pem\":null}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_get_config(c, CONFIG_ID, &cfg, &err));
    TEST_ASSERT_TRUE(cfg->allow_sha1_signatures);
    TEST_ASSERT_NULL(cfg->idp_metadata_signing_cert_pem);
    axiam_mgmt_federation_config_response_free(cfg);
    mgmt_mount(200, "{" CONFIG_FIELDS ",\"allow_sha1_signatures\":false,"
                    "\"idp_metadata_signing_cert_pem\":\"" "-----BEGIN CERTIFICATE-----\\nMIIB\\n"
                    "-----END CERTIFICATE-----\\n" "\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_get_config(c, CONFIG_ID, &cfg, &err));
    TEST_ASSERT_FALSE(cfg->allow_sha1_signatures);
    TEST_ASSERT_NOT_NULL(strstr(cfg->idp_metadata_signing_cert_pem, "BEGIN CERTIFICATE"));
    axiam_mgmt_federation_config_response_free(cfg);

    /* create: neither member unless the caller sets it. */
    axiam_mgmt_create_federation_config_request_t in;
    memset(&in, 0, sizeof in);
    in.provider = (char *) "corp-idp";
    in.protocol = (char *) "Saml";
    in.client_id = (char *) "axiam";
    mgmt_mount(201, "{" CONFIG_FIELDS ",\"allow_sha1_signatures\":false}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_create_config(c, &in, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "allow_sha1_signatures"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "idp_metadata_signing_cert_pem"));

    in.allow_sha1_signatures = 0;
    in.has_allow_sha1_signatures = 1;
    in.idp_metadata_signing_cert_pem = (char *) CERT_PEM;
    mgmt_mount(201, "{" CONFIG_FIELDS ",\"allow_sha1_signatures\":false}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_create_config(c, &in, NULL, &err));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mgmt_last_body(), "\"allow_sha1_signatures\":false"),
                                 "an explicit false is sent");
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"idp_metadata_signing_cert_pem\":\"-----BEGIN"));

    /* update: the same, sparse. */
    axiam_mgmt_update_federation_config_request_t up;
    memset(&up, 0, sizeof up);
    up.allow_sha1_signatures = 1;
    up.has_allow_sha1_signatures = 1;
    mgmt_mount(200, "{" CONFIG_FIELDS ",\"allow_sha1_signatures\":true}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    char keys[512];
    body_keys(keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("allow_sha1_signatures", keys);
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"allow_sha1_signatures\":true"));
    axiam_client_free(c);
}

/* ---- §27.15 note 8: an explicit null clears, an omitted member is left ----------- */

static void test_update_config_null_clears_and_omitted_leaves(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    char keys[512];
    axiam_mgmt_update_federation_config_request_t up;

    /* Nothing set: an empty body, every member left unchanged. */
    memset(&up, 0, sizeof up);
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    body_keys(keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("", keys);

    /* One cleared member: exactly that key, and its value is JSON null. */
    up.has_idp_metadata_signing_cert_pem = 1;
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    body_keys(keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("idp_metadata_signing_cert_pem", keys);
    TEST_ASSERT_TRUE(body_member_is_null("idp_metadata_signing_cert_pem"));

    /* Each of the ten nullable members can be cleared the same way. */
    memset(&up, 0, sizeof up);
    up.has_metadata_url = 1;
    up.has_idp_signing_cert_pem = 1;
    up.has_idp_metadata_signing_cert_pem = 1;
    up.has_provider_slug = 1;
    up.has_authorization_endpoint = 1;
    up.has_token_endpoint = 1;
    up.has_userinfo_endpoint = 1;
    up.has_apple_team_id = 1;
    up.has_apple_key_id = 1;
    up.has_button_icon = 1;
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    static const char *const nullable[] = {
        "metadata_url", "idp_signing_cert_pem", "idp_metadata_signing_cert_pem", "provider_slug",
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "apple_team_id",
        "apple_key_id", "button_icon",
    };
    cJSON *body = cJSON_Parse(mgmt_last_body());
    TEST_ASSERT_EQUAL_INT(10, cJSON_GetArraySize(body));
    for (size_t i = 0; i < sizeof nullable / sizeof nullable[0]; i++) {
        TEST_ASSERT_TRUE_MESSAGE(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(body, nullable[i])),
                                 nullable[i]);
    }
    cJSON_Delete(body);

    /* A value wins over the flag; a value with the flag 0 is sent as itself. */
    memset(&up, 0, sizeof up);
    up.button_icon = (char *) "https://idp.example/icon.svg";
    up.metadata_url = (char *) "https://idp.example/metadata";
    up.has_metadata_url = 1;
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    body_keys(keys, sizeof keys);
    TEST_ASSERT_EQUAL_STRING("button_icon,metadata_url", keys);
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"metadata_url\":\"https://idp.example/metadata\""));

    /* A member that cannot be cleared is still only ever omitted or a value. */
    memset(&up, 0, sizeof up);
    up.provider = NULL;
    up.client_id = NULL;
    mgmt_mount(200, "{" CONFIG_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_federation_update_config(c, CONFIG_ID, &up, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "null"));
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_window_minutes_is_passed_through_never_clamped_and_decoded);
    RUN_TEST(test_allow_sha1_signatures_reads_false_when_absent_and_is_sent_only_when_set);
    RUN_TEST(test_update_config_null_clears_and_omitted_leaves);
    return UNITY_END();
}
