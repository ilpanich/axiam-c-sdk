/*
 * CONTRACT.md contract 1.61 (§34.5), the §27 model additions every SDK owes, against the
 * fake transport:
 *
 * - §27.11 rule 5: `Certificate.user_id` -- optional and nullable on every read, decoded
 *   the same way for a UUID, `null` and an absent member, and an optional request member on
 *   `certificates.generate` and `certificates.sign_csr` that is sent exactly as given and
 *   whose key is absent (never `null`) when the caller names no account.
 *
 * The SSF half of 1.61 (`SsfStreamInput.expected_updated_at`, §32.8 test 1) is in
 * test_ssf_management.c. `CibaPendingList` is not modelled: no registry operation returns
 * it and this SDK drives no console route (§33.3 rule 16).
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
#define USER "55555555-5555-4555-8555-555555555555"

#define CERT_FIELDS \
    "\"cert_type\":\"User\",\"created_at\":\"2026-10-10T00:00:00Z\"," \
    "\"fingerprint\":\"aa:bb\",\"id\":\"" UUID "\",\"issuer_ca_id\":\"" UUID "\"," \
    "\"key_algorithm\":\"Ed25519\",\"metadata\":{}," \
    "\"not_after\":\"2027-10-10T00:00:00Z\",\"not_before\":\"2026-10-10T00:00:00Z\"," \
    "\"public_cert_pem\":\"-----BEGIN CERTIFICATE-----\",\"status\":\"Active\"," \
    "\"subject\":\"CN=ada\",\"tenant_id\":\"" UUID "\""

void setUp(void) { mgmt_reset(); }
void tearDown(void) {}

static const cJSON *sent_member(cJSON **body, const char *name) {
    *body = cJSON_Parse(mgmt_last_body());
    TEST_ASSERT_TRUE_MESSAGE(cJSON_IsObject(*body), "the body is a JSON object");
    return cJSON_GetObjectItemCaseSensitive(*body, name);
}

static void test_generate_sends_user_id_as_given_and_omits_the_key_without_one(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_create_certificate_request_t body;
    memset(&body, 0, sizeof body);
    body.cert_type = AXIAM_MGMT_CERTIFICATE_TYPE_USER;
    body.issuer_ca_id = (char *) UUID;
    body.subject = (char *) "CN=ada";
    body.validity_days = 30;
    body.user_id = (char *) USER;
    axiam_mgmt_generated_certificate_t *out = NULL;

    mgmt_mount(200, "{" CERT_FIELDS ",\"user_id\":\"" USER "\",\"private_key_pem\":\"k\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_generate(c, &body, &out, &err));
    cJSON *sent = NULL;
    const cJSON *uid = sent_member(&sent, "user_id");
    TEST_ASSERT_TRUE(cJSON_IsString(uid));
    TEST_ASSERT_EQUAL_STRING(USER, uid->valuestring);
    cJSON_Delete(sent);
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_STRING(USER, out->user_id);
    axiam_mgmt_generated_certificate_free(out);

    /* Not judged client-side: whatever string the caller sets goes out as it is. */
    body.user_id = (char *) "not-a-uuid";
    out = NULL;
    mgmt_mount(200, "{" CERT_FIELDS ",\"private_key_pem\":\"k\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_generate(c, &body, &out, &err));
    uid = sent_member(&sent, "user_id");
    TEST_ASSERT_EQUAL_STRING("not-a-uuid", uid->valuestring);
    cJSON_Delete(sent);
    axiam_mgmt_generated_certificate_free(out);

    /* Unset: no `user_id` key at all, and in particular not `null`. */
    body.user_id = NULL;
    out = NULL;
    mgmt_mount(200, "{" CERT_FIELDS ",\"private_key_pem\":\"k\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_generate(c, &body, &out, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "user_id"));
    TEST_ASSERT_NULL(out->user_id);
    axiam_mgmt_generated_certificate_free(out);
    axiam_client_free(c);
}

static void test_sign_csr_sends_user_id_as_given_and_omits_the_key_without_one(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_sign_certificate_csr_request_t body;
    memset(&body, 0, sizeof body);
    body.cert_type = AXIAM_MGMT_CERTIFICATE_TYPE_USER;
    body.issuer_ca_id = (char *) UUID;
    body.csr_pem = (char *) "-----BEGIN CERTIFICATE REQUEST-----";
    body.validity_days = 30;
    body.user_id = (char *) USER;
    axiam_mgmt_certificate_t *out = NULL;

    mgmt_mount(200, "{" CERT_FIELDS ",\"user_id\":\"" USER "\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_sign_csr(c, &body, &out, &err));
    TEST_ASSERT_EQUAL_STRING("/api/v1/certificates/sign-csr", mgmt_last_path());
    cJSON *sent = NULL;
    const cJSON *uid = sent_member(&sent, "user_id");
    TEST_ASSERT_TRUE(cJSON_IsString(uid));
    TEST_ASSERT_EQUAL_STRING(USER, uid->valuestring);
    cJSON_Delete(sent);
    TEST_ASSERT_EQUAL_STRING(USER, out->user_id);
    axiam_mgmt_certificate_free(out);

    body.user_id = NULL;
    out = NULL;
    mgmt_mount(200, "{" CERT_FIELDS ",\"user_id\":null}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_sign_csr(c, &body, &out, &err));
    TEST_ASSERT_NULL(strstr(mgmt_last_body(), "user_id"));
    axiam_mgmt_certificate_free(out);
    axiam_client_free(c);
}

/* A Certificate body carrying a UUID, one carrying null and one lacking the member each
 * decode; the last two give "no account named" (NULL), never a nil UUID or a value taken
 * from `metadata` or the subject. */
static void test_a_certificate_decodes_a_uuid_a_null_and_an_absent_user_id(void) {
    axiam_client_t *c = mgmt_signed_in_client();
    axiam_error_t err;
    axiam_mgmt_certificate_t *one = NULL;

    mgmt_mount(200, "{" CERT_FIELDS ",\"user_id\":\"" USER "\"}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_get(c, UUID, &one, &err));
    TEST_ASSERT_EQUAL_STRING(USER, one->user_id);
    axiam_mgmt_certificate_free(one);

    one = NULL;
    mgmt_mount(200, "{" CERT_FIELDS ",\"user_id\":null}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_get(c, UUID, &one, &err));
    TEST_ASSERT_NOT_NULL(one);
    TEST_ASSERT_NULL_MESSAGE(one->user_id, "null is no account named");
    axiam_mgmt_certificate_free(one);

    one = NULL;
    mgmt_mount(200, "{" CERT_FIELDS "}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_get(c, UUID, &one, &err));
    TEST_ASSERT_NOT_NULL(one);
    TEST_ASSERT_NULL_MESSAGE(one->user_id, "an absent member (a pre-1.0.1 server) is no account named");
    axiam_mgmt_certificate_free(one);

    /* The list projection carries it too, and an item without it still decodes. */
    axiam_mgmt_certificate_page_t *page = NULL;
    mgmt_mount(200, "{\"items\":[{" CERT_FIELDS ",\"user_id\":\"" USER "\"},{" CERT_FIELDS "}],\"total\":2}");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_certificates_list(c, NULL, &page, &err));
    TEST_ASSERT_EQUAL_INT(2, (int) page->count);
    TEST_ASSERT_EQUAL_STRING(USER, page->items[0]->user_id);
    TEST_ASSERT_NULL(page->items[1]->user_id);
    axiam_mgmt_certificate_page_free(page);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_generate_sends_user_id_as_given_and_omits_the_key_without_one);
    RUN_TEST(test_sign_csr_sends_user_id_as_given_and_omits_the_key_without_one);
    RUN_TEST(test_a_certificate_decodes_a_uuid_a_null_and_an_absent_user_id);
    return UNITY_END();
}
