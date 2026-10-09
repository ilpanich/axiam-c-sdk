/*
 * CONTRACT.md §29 (contract 1.55) — the `saml` management namespace: §29.8's eight
 * required tests, against the §27 test rig (management_test_util.c), whose fake transport
 * sits at the bottom of the real client.
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

cJSON *axiam_mgmt_saml_idp_credential_build(const axiam_mgmt_saml_idp_credential_t *value);

#define TENANT "11111111-1111-4111-8111-111111111111"
#define SAML "/api/v1/tenants/" TENANT "/saml"
#define SP_ID "77777777-7777-4777-8777-777777777777"

#define SP_FIELDS                                                                          \
    "\"id\":\"" SP_ID "\",\"tenant_id\":\"" TENANT "\",\"enabled\":true,"                  \
    "\"display_name\":\"Payroll\",\"entity_id\":\"https://payroll.example/sp\","           \
    "\"slo_url\":null,\"slo_binding\":null,\"name_id_format\":\"persistent\","             \
    "\"sign_responses\":true,\"encrypt_assertions\":false,"                                \
    "\"sp_signing_cert_pem\":null,\"sp_encryption_cert_pem\":null,"                        \
    "\"want_authn_requests_signed\":false,\"allow_idp_initiated\":false,"                  \
    "\"attribute_mappings\":[],\"allowed_groups\":[],"                                     \
    "\"created_at\":\"2026-10-04T00:00:00Z\",\"updated_at\":\"2026-10-04T00:00:00Z\""
#define ACS_POST "[{\"url\":\"https://payroll.example/acs\",\"binding\":\"http_post\",\"index\":0,\"is_default\":true}]"
#define SP_BODY "{" SP_FIELDS ",\"acs_urls\":" ACS_POST "}"

#define CREDENTIAL(status)                                                                  \
    "{\"id\":\"88888888-8888-4888-8888-888888888888\",\"tenant_id\":\"" TENANT "\","       \
    "\"issuer_ca_id\":\"99999999-9999-4999-8999-999999999999\","                           \
    "\"certificate_pem\":\"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n\"," \
    "\"serial\":\"0a1b\",\"fingerprint\":\"abab\",\"not_before\":\"2026-10-04T00:00:00Z\","  \
    "\"not_after\":\"2027-10-04T00:00:00Z\",\"status\":\"" status "\","                     \
    "\"created_at\":\"2026-10-04T00:00:00Z\",\"retired_at\":null"

static axiam_mgmt_acs_endpoint_t g_acs = {AXIAM_MGMT_SAML_BINDING_HTTP_POST, 0, 1, 1,
                                          (char *) "https://payroll.example/acs"};
static axiam_mgmt_acs_endpoint_t *g_acs_list[1] = {&g_acs};

/* A minimal replacement: the three required members only. */
static void fill_input(axiam_mgmt_saml_service_provider_input_t *in) {
    memset(in, 0, sizeof *in);
    in->display_name = (char *) "Payroll";
    in->entity_id = (char *) "https://payroll.example/sp";
    in->acs_urls = g_acs_list;
    in->acs_urls_count = 1;
}

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

/* ---- 1. Replacement --------------------------------------------------------------- */

static void test_update_service_provider_puts_the_whole_registration(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;

    /* The read-modify-write form: every member of a read carried over. */
    mgmt_mount(200, SP_BODY);
    axiam_mgmt_saml_service_provider_t *current = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_get_service_provider(c, NULL, SP_ID, &current, &err));
    axiam_mgmt_saml_service_provider_input_t *body = axiam_mgmt_saml_service_provider_to_input(current);
    TEST_ASSERT_NOT_NULL(body);
    free(body->display_name);
    body->display_name = strdup("Payroll (EU)");

    mgmt_mount(200, SP_BODY);
    axiam_mgmt_saml_service_provider_t *sp = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_saml_update_service_provider(c, NULL, SP_ID, body, &sp, &err));
    TEST_ASSERT_EQUAL_STRING("PUT", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(SAML "/service-providers/" SP_ID, mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING("https://payroll.example/sp", sp->entity_id);
    cJSON *sent = cJSON_Parse(mgmt_last_body());
    static const char *const members[] = {
        "acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings",
        "display_name", "enabled", "encrypt_assertions", "entity_id", "name_id_format",
        "sign_responses", "want_authn_requests_signed",
    };
    for (size_t i = 0; i < sizeof members / sizeof members[0]; i++)
        TEST_ASSERT_NOT_NULL_MESSAGE(cJSON_GetObjectItemCaseSensitive(sent, members[i]), members[i]);
    TEST_ASSERT_EQUAL_STRING("Payroll (EU)",
                             cJSON_GetObjectItemCaseSensitive(sent, "display_name")->valuestring);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(sent, "id"));
    cJSON_Delete(sent);

    /* C has no compile-time check: the operation refuses an input without one of the
     * three required members, before any request. */
    int before = mgmt_request_count();
    for (int k = 0; k < 3; k++) {
        axiam_mgmt_saml_service_provider_input_t in;
        fill_input(&in);
        if (k == 0) in.display_name = NULL;
        if (k == 1) in.entity_id = NULL;
        if (k == 2) in.acs_urls = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_saml_update_service_provider(c, NULL, SP_ID, &in, NULL, &err));
        TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                              axiam_saml_create_service_provider(c, NULL, &in, NULL, &err));
    }
    TEST_ASSERT_EQUAL_INT(before, mgmt_request_count());

    axiam_mgmt_saml_service_provider_free(sp);
    axiam_mgmt_saml_service_provider_input_free(body);
    axiam_mgmt_saml_service_provider_free(current);
    axiam_client_free(c);
}

/* ---- 2. No signing switch, open decoding ------------------------------------------ */

static void test_sign_assertions_does_not_exist_and_unknown_values_decode(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    mgmt_mount(200, "{" SP_FIELDS ",\"sign_assertions\":false,\"some_future_member\":1,"
                    "\"acs_urls\":[{\"url\":\"https://payroll.example/acs\","
                    "\"binding\":\"http_artifact\",\"index\":0,\"is_default\":true}]}");
    axiam_mgmt_saml_service_provider_t *sp = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_get_service_provider(c, NULL, SP_ID, &sp, &err));
    TEST_ASSERT_EQUAL_INT(1, (int) sp->acs_urls_count);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SAML_BINDING_UNKNOWN, sp->acs_urls[0]->binding);

    /* An unknown value is decoded, but is never sent as a value: replace it before
     * writing back (its wire spelling is the empty string, which no server accepts). */
    axiam_mgmt_saml_service_provider_input_t *in = axiam_mgmt_saml_service_provider_to_input(sp);
    TEST_ASSERT_EQUAL_STRING("", axiam_mgmt_saml_binding_to_wire(in->acs_urls[0]->binding));
    in->acs_urls[0]->binding = AXIAM_MGMT_SAML_BINDING_HTTP_POST;
    mgmt_mount(200, SP_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_update_service_provider(c, NULL, SP_ID, in, NULL, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "sign_assertions"));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "some_future_member"));
    TEST_ASSERT_NOT_NULL(strstr(mgmt_last_body(), "\"binding\":\"http_post\""));
    axiam_mgmt_saml_service_provider_input_free(in);
    axiam_mgmt_saml_service_provider_free(sp);
    axiam_client_free(c);
}

/* ---- 3. Draft round trip ---------------------------------------------------------- */

#define DRAFT_SP                                                                            \
    "{\"display_name\":\"Imported\",\"entity_id\":\"https://imported.example/sp\","         \
    "\"acs_urls\":[{\"url\":\"https://imported.example/acs\",\"binding\":\"http_post\","    \
    "\"index\":1,\"is_default\":false}],\"want_authn_requests_signed\":true,"               \
    "\"sp_signing_cert_pem\":\"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n\"}"

static void test_parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    const char *draft = "{\"service_provider\":" DRAFT_SP ",\"signing_certificate_fingerprint\":"
                        "\"cdcd\",\"encryption_certificate_fingerprint\":null,"
                        "\"warnings\":[\"the metadata's signature was not evaluated\"]}";

    axiam_mgmt_parse_saml_sp_metadata_t *by_url =
        axiam_mgmt_parse_saml_sp_metadata_from_url("https://imported.example/metadata");
    axiam_mgmt_parse_saml_sp_metadata_t *by_xml =
        axiam_mgmt_parse_saml_sp_metadata_from_xml("<EntityDescriptor/>");
    axiam_mgmt_saml_sp_metadata_draft_t *from_url = NULL;
    mgmt_mount(200, draft);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_parse_sp_metadata(c, NULL, by_url, &from_url, &err));
    TEST_ASSERT_EQUAL_STRING(SAML "/parse-sp-metadata", mgmt_last_path());
    TEST_ASSERT_EQUAL_STRING("{\"metadata_url\":\"https://imported.example/metadata\"}",
                             mgmt_last_body());
    mgmt_mount(200, draft);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_parse_sp_metadata(c, NULL, by_xml, NULL, &err));
    TEST_ASSERT_EQUAL_STRING("{\"metadata_xml\":\"<EntityDescriptor/>\"}", mgmt_last_body());

    /* Both, or neither: a local ValidationError and no request. */
    int before = mgmt_request_count();
    axiam_mgmt_parse_saml_sp_metadata_t both = {(char *) "https://a", (char *) "<x/>"};
    axiam_mgmt_parse_saml_sp_metadata_t neither = {NULL, NULL};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_saml_parse_sp_metadata(c, NULL, &both, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_saml_parse_sp_metadata(c, NULL, &neither, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_saml_parse_sp_metadata(c, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before, mgmt_request_count(), "the refused calls sent nothing");
    TEST_ASSERT_NULL(axiam_mgmt_parse_saml_sp_metadata_from_url(NULL));
    TEST_ASSERT_NULL(axiam_mgmt_parse_saml_sp_metadata_from_xml(NULL));

    /* The draft's service_provider is accepted by create unchanged and sent as its body. */
    TEST_ASSERT_EQUAL_INT(1, (int) from_url->warnings_count);
    mgmt_mount(201, SP_BODY);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_create_service_provider(
                                        c, NULL, from_url->service_provider, NULL, &err));
    TEST_ASSERT_EQUAL_STRING("POST", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(SAML "/service-providers", mgmt_last_path());
    cJSON *sent = cJSON_Parse(mgmt_last_body());
    cJSON *expected = cJSON_Parse(DRAFT_SP);
    TEST_ASSERT_TRUE_MESSAGE(cJSON_Compare(sent, expected, 1), "the draft is sent unchanged");
    cJSON_Delete(sent);
    cJSON_Delete(expected);

    axiam_mgmt_saml_sp_metadata_draft_free(from_url);
    axiam_mgmt_parse_saml_sp_metadata_free(by_url);
    axiam_mgmt_parse_saml_sp_metadata_free(by_xml);
    axiam_client_free(c);
}

/* ---- 4. Credentials carry no key -------------------------------------------------- */

static void test_a_credential_has_no_key_member_and_promotion_may_retire_nothing(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    unsigned char raw[16];
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(raw, (int) sizeof raw));
    char leaked[40];
    for (size_t i = 0; i < sizeof raw; i++) snprintf(leaked + 2 * i, 3, "%02x", raw[i]);
    char body[1024];
    snprintf(body, sizeof body, CREDENTIAL("retired") ",\"private_key_pem\":\"%s\"}", leaked);

    mgmt_mount(200, body);
    axiam_mgmt_saml_idp_credential_t *credential = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_retire_idp_credential(
                                        c, NULL, "88888888-8888-4888-8888-888888888888",
                                        &credential, &err));
    TEST_ASSERT_EQUAL_STRING(SAML "/idp-credentials/88888888-8888-4888-8888-888888888888/retire",
                             mgmt_last_path());
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SAML_IDP_CREDENTIAL_STATUS_RETIRED, credential->status);
    /* The type has no member for it; its one serialization carries no trace of it. */
    cJSON *wire = axiam_mgmt_saml_idp_credential_build(credential);
    char *text = cJSON_PrintUnformatted(wire);
    TEST_ASSERT_TRUE_MESSAGE(strstr(text, leaked) == NULL, "the leaked key value appears");
    TEST_ASSERT_NULL(strstr(text, "private_key_pem"));
    free(text);
    cJSON_Delete(wire);
    axiam_mgmt_saml_idp_credential_free(credential);

    mgmt_mount(200, "{\"active\":" CREDENTIAL("active") "},\"retired\":null}");
    axiam_mgmt_saml_idp_credential_promotion_t *promotion = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_promote_idp_credential(
                                        c, NULL, "88888888-8888-4888-8888-888888888888",
                                        &promotion, &err));
    TEST_ASSERT_NULL(promotion->retired);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SAML_IDP_CREDENTIAL_STATUS_ACTIVE, promotion->active->status);
    axiam_mgmt_saml_idp_credential_promotion_free(promotion);
    axiam_client_free(c);
}

/* ---- 5. Pagination ---------------------------------------------------------------- */

static void test_service_providers_page_with_search_and_credentials_are_a_plain_list(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    /* A walk: two one-item pages, then an empty one that ends it (§27.4 rule 4). */
    mgmt_mount(200, "{\"items\":[" SP_BODY "],\"total\":2,\"offset\":0,\"limit\":1}");
    mgmt_mount(200, "{\"items\":[" SP_BODY "],\"total\":2,\"offset\":1,\"limit\":1}");
    mgmt_mount(200, "{\"items\":[],\"total\":2,\"offset\":2,\"limit\":1}");
    axiam_mgmt_page_req_t req = {0, 1, "payroll"};
    size_t seen = 0;
    int pages = 0;
    for (;;) {
        axiam_mgmt_saml_service_provider_page_t *page = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_list_service_providers(c, NULL, &req, &page, &err));
        pages++;
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(mgmt_last_url(), "search=payroll"),
                                     "the walk carries the search term on every request");
        TEST_ASSERT_EQUAL_INT(2, (int) page->total);
        size_t count = page->count;
        seen += count;
        req = axiam_mgmt_page_next(page->request);
        axiam_mgmt_saml_service_provider_page_free(page);
        if (count == 0) break;
    }
    TEST_ASSERT_EQUAL_INT(3, pages);
    TEST_ASSERT_EQUAL_INT(2, (int) seen);

    mgmt_mount(200, "[" CREDENTIAL("next") "}," CREDENTIAL("active") "}]");
    axiam_mgmt_saml_idp_credential_list_t *list = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_list_idp_credentials(c, NULL, &list, &err));
    TEST_ASSERT_EQUAL_STRING(SAML "/idp-credentials", mgmt_last_path());
    TEST_ASSERT_EQUAL_INT(2, (int) list->count);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SAML_IDP_CREDENTIAL_STATUS_NEXT, list->items[0]->status);
    axiam_mgmt_saml_idp_credential_list_free(list);
    axiam_client_free(c);
}

/* ---- 6. No retry ------------------------------------------------------------------ */

static void test_none_of_the_seven_writes_is_retried_on_503(void) {
    axiam_client_t *c = mgmt_signed_in_client(); /* §27.4 rule 8's GET retry is on */
    axiam_error_t err;
    axiam_mgmt_saml_service_provider_input_t in;
    fill_input(&in);
    axiam_mgmt_parse_saml_sp_metadata_t parse = {(char *) "https://m.example", NULL};
    axiam_mgmt_issue_saml_idp_credential_t issue = {
        (char *) "99999999-9999-4999-8999-999999999999", AXIAM_MGMT_SAML_IDP_SLOT_NEXT, 0, 0};
    const char *id = "88888888-8888-4888-8888-888888888888";

    for (int k = 0; k < 7; k++) {
        int before = mgmt_request_count();
        mgmt_mount(503, NULL);
        mgmt_mount_next(200, SP_BODY);
        axiam_error_kind_t rc;
        switch (k) {
            case 0: rc = axiam_saml_create_service_provider(c, NULL, &in, NULL, &err); break;
            case 1: rc = axiam_saml_update_service_provider(c, NULL, SP_ID, &in, NULL, &err); break;
            case 2: rc = axiam_saml_delete_service_provider(c, NULL, SP_ID, &err); break;
            case 3: rc = axiam_saml_parse_sp_metadata(c, NULL, &parse, NULL, &err); break;
            case 4: rc = axiam_saml_issue_idp_credential(c, NULL, &issue, NULL, &err); break;
            case 5: rc = axiam_saml_promote_idp_credential(c, NULL, id, NULL, &err); break;
            default: rc = axiam_saml_retire_idp_credential(c, NULL, id, NULL, &err); break;
        }
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, rc);
        TEST_ASSERT_EQUAL_INT_MESSAGE(before + 1, mgmt_request_count(), "exactly one request");
        mgmt_reset();
        axiam_client_free(c);
        c = mgmt_signed_in_client();
    }
    axiam_client_free(c);
}

/* ---- 7. Errors -------------------------------------------------------------------- */

static void test_statuses_map_per_section_2(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_saml_service_provider_input_t in;
    fill_input(&in);

    mgmt_mount(400, "{\"error\":\"validation_error\",\"message\":\"entity_id is immutable: "
                    "register a new service provider\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_saml_update_service_provider(c, NULL, SP_ID, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_VALIDATION, axiam_mgmt_error_class(&err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "register a new service provider"));

    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"entity_id\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_saml_create_service_provider(c, NULL, &in, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));

    mgmt_mount(409, "{\"error\":\"conflict\",\"message\":\"not next\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_saml_promote_idp_credential(
                                               c, NULL, "88888888-8888-4888-8888-888888888888",
                                               NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_CONFLICT, axiam_mgmt_error_class(&err));

    mgmt_mount(404, "{\"error\":\"not_found\",\"message\":\"no\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTHZ, axiam_saml_get_service_provider(c, NULL, SP_ID, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NOT_FOUND, axiam_mgmt_error_class(&err));

    axiam_mgmt_parse_saml_sp_metadata_t parse = {(char *) "https://m.example", NULL};
    mgmt_mount(503, "{\"error\":\"service_unavailable\",\"message\":\"saml is not built in\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_saml_parse_sp_metadata(c, NULL, &parse, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_ERR_NONE, axiam_mgmt_error_class(&err));
    axiam_client_free(c);
}

/* ---- 8. Readiness is read, not cached ---------------------------------------------- */

static void test_get_idp_keeps_null_apart_from_absent_and_is_never_cached(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    const char *info =
        "{\"tenant_id\":\"" TENANT "\",\"saml_available\":true,\"saml_idp_enabled\":false,"
        "\"metadata_served\":true,\"entity_id\":\"https://iam.example.com/saml/v2/" TENANT "\","
        "\"metadata_url\":\"https://iam.example.com/saml/v2/" TENANT "/metadata\","
        "\"sso_url\":\"https://iam.example.com/saml/v2/" TENANT "/sso\","
        "\"slo_url\":\"https://iam.example.com/saml/v2/" TENANT "/slo\","
        "\"active_credential_id\":\"88888888-8888-4888-8888-888888888888\","
        "\"next_credential_id\":null}";
    mgmt_mount(200, info);
    mgmt_mount(200, info);
    int before = mgmt_request_count();
    axiam_mgmt_saml_idp_info_t *idp = NULL;
    /* No tenant argument: the configured tenant is in the path (§27.4 rule 3). */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_get_idp(c, NULL, &idp, &err));
    TEST_ASSERT_EQUAL_STRING("GET", mgmt_last_method());
    TEST_ASSERT_EQUAL_STRING(SAML "/idp", mgmt_last_path());
    TEST_ASSERT_TRUE(idp->saml_available);
    TEST_ASSERT_FALSE(idp->saml_idp_enabled);
    TEST_ASSERT_TRUE(idp->metadata_served);
    TEST_ASSERT_NOT_NULL(idp->entity_id);
    TEST_ASSERT_NOT_NULL(idp->metadata_url);
    TEST_ASSERT_NOT_NULL(idp->sso_url);
    TEST_ASSERT_NOT_NULL(idp->slo_url);
    TEST_ASSERT_EQUAL_STRING(TENANT, idp->tenant_id);
    TEST_ASSERT_EQUAL_STRING("88888888-8888-4888-8888-888888888888", idp->active_credential_id);
    TEST_ASSERT_TRUE(idp->has_active_credential_id);
    /* null, kept distinct from absent */
    TEST_ASSERT_NULL(idp->next_credential_id);
    TEST_ASSERT_TRUE_MESSAGE(idp->has_next_credential_id, "an explicit null is present");
    axiam_mgmt_saml_idp_info_free(idp);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_get_idp(c, NULL, &idp, &err));
    TEST_ASSERT_EQUAL_INT_MESSAGE(before + 2, mgmt_request_count(), "two calls, two requests");
    axiam_mgmt_saml_idp_info_free(idp);

    /* A server that stopped sending the members: absent, not null. */
    mgmt_mount(200, "{\"tenant_id\":\"" TENANT "\",\"saml_available\":true}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_saml_get_idp(c, NULL, &idp, &err));
    TEST_ASSERT_FALSE(idp->has_active_credential_id);
    TEST_ASSERT_FALSE(idp->has_next_credential_id);
    axiam_mgmt_saml_idp_info_free(idp);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_update_service_provider_puts_the_whole_registration);
    RUN_TEST(test_sign_assertions_does_not_exist_and_unknown_values_decode);
    RUN_TEST(test_parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates);
    RUN_TEST(test_a_credential_has_no_key_member_and_promotion_may_retire_nothing);
    RUN_TEST(test_service_providers_page_with_search_and_credentials_are_a_plain_list);
    RUN_TEST(test_none_of_the_seven_writes_is_retried_on_503);
    RUN_TEST(test_statuses_map_per_section_2);
    RUN_TEST(test_get_idp_keeps_null_apart_from_absent_and_is_never_cached);
    return UNITY_END();
}
