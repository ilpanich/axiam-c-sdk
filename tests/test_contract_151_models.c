/*
 * CONTRACT.md §27.13 (contract 1.51) — the generated-model regressions the re-vendor
 * exposed, mirroring the Rust reference's tests/contract_151_models_test.rs.
 *
 * Two generator defects were found while regenerating scripts/gen_management.py's
 * output against contract 1.51 (see the "re-vendor + regenerate" commit):
 *
 *   1. `SubjectAltName` is an externally tagged `oneOf` -- `{"dns": "..."}` or
 *      `{"ip": "..."}`. The generator had no case for that shape at all: it fell
 *      through to the plain-model path, which reads `properties`/`allOf` and found
 *      neither (a `oneOf`'s variants carry those, not the union schema itself), so it
 *      produced a model with NO fields. Every `if fields: ...` guard downstream then
 *      skipped it -- no struct, no `_parse`, no `_build`, no `_free` -- while
 *      `subject_alt_names` still referenced `axiam_mgmt_subject_alt_name_t *`. That does
 *      not compile, which is a stronger failure than the Rust port's ("serializes as
 *      `{}`, which the server refuses"), but the fix is the one item 2 of C-1's EXECUTED
 *      block describes: emit the tagged shape properly, one enum constant per wire key.
 *
 *   2. `inherit` is REQUIRED on the three role-side listings
 *      (RoleUserAssignment/RoleGroupAssignment/RoleServiceAccountAssignment) and OPTIONAL
 *      on the three subject-side ones (RoleAssignment, via users.list_roles/
 *      groups.list_roles/service_accounts.list_roles). A server older than contract 1.51
 *      omits the field on either shape, and a plain required-bool field would decode
 *      that absence as `out->inherit = 0` (false) -- turning every pre-1.51 assignment
 *      into a non-inheritable one on the client's side of the wire, which is exactly
 *      backwards (§27.13 S-10 rule 3: absence means true). Fixed with a name-keyed
 *      default-true-on-absent list in the generator (DEFAULT_TRUE_WHEN_ABSENT), mirroring
 *      the Rust fix's OMIT_WHEN_EMPTY-shaped table.
 *
 * `CertificateType` already decoded an unrecognised value openly (every generated enum
 * carries an appended `_UNKNOWN` constant unconditionally) -- §27.13 S-7 rule 2 needed a
 * test here, not a generator change, exactly as the reference found.
 *
 * Each fix was mutated once (see the commit message) and confirmed to turn the
 * corresponding assertion below red before being restored.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "axiam/management_models.h"
#include "cJSON.h"

/* management_models.c's parse/build/free are declared to every generated TU rather
 * than the public header (a caller has the typed operations and never hands raw cJSON
 * to a model) -- this test declares the ones it needs itself, the same way the
 * generator's own emit_model_test() output does. */
axiam_mgmt_subject_alt_name_t *axiam_mgmt_subject_alt_name_parse(const cJSON *src);
cJSON *axiam_mgmt_subject_alt_name_build(const axiam_mgmt_subject_alt_name_t *value);
axiam_mgmt_role_user_assignment_t *axiam_mgmt_role_user_assignment_parse(const cJSON *src);
axiam_mgmt_role_group_assignment_t *axiam_mgmt_role_group_assignment_parse(const cJSON *src);
axiam_mgmt_role_service_account_assignment_t *
axiam_mgmt_role_service_account_assignment_parse(const cJSON *src);
axiam_mgmt_role_assignment_t *axiam_mgmt_role_assignment_parse(const cJSON *src);
axiam_mgmt_certificate_t *axiam_mgmt_certificate_parse(const cJSON *src);

void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------------------
 * 1. SubjectAltName -- the externally-tagged oneOf.
 * ---------------------------------------------------------------------- */

static void test_subject_alt_name_dns_round_trips(void) {
    cJSON *src = cJSON_Parse("{\"dns\": \"api.lakeside.internal\"}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_subject_alt_name_t *model = axiam_mgmt_subject_alt_name_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SUBJECT_ALT_NAME_DNS, model->kind);
    TEST_ASSERT_EQUAL_STRING("api.lakeside.internal", model->value);

    cJSON *rebuilt = axiam_mgmt_subject_alt_name_build(model);
    TEST_ASSERT_NOT_NULL(rebuilt);
    /* The wire shape is {"dns": "..."} -- never {}, and never a `kind`/`value` pair of
     * this SDK's own invention. */
    cJSON *dns = cJSON_GetObjectItemCaseSensitive(rebuilt, "dns");
    TEST_ASSERT_TRUE(cJSON_IsString(dns));
    TEST_ASSERT_EQUAL_STRING("api.lakeside.internal", dns->valuestring);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(rebuilt, "ip"));
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(rebuilt));

    char *rendered = cJSON_PrintUnformatted(rebuilt);
    TEST_ASSERT_NOT_NULL(rendered);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(rendered, "{}"));
    free(rendered);

    cJSON_Delete(rebuilt);
    axiam_mgmt_subject_alt_name_free(model);
    cJSON_Delete(src);
}

static void test_subject_alt_name_ip_round_trips(void) {
    cJSON *src = cJSON_Parse("{\"ip\": \"10.0.0.5\"}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_subject_alt_name_t *model = axiam_mgmt_subject_alt_name_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_SUBJECT_ALT_NAME_IP, model->kind);
    TEST_ASSERT_EQUAL_STRING("10.0.0.5", model->value);

    cJSON *rebuilt = axiam_mgmt_subject_alt_name_build(model);
    TEST_ASSERT_NOT_NULL(rebuilt);
    cJSON *ip = cJSON_GetObjectItemCaseSensitive(rebuilt, "ip");
    TEST_ASSERT_TRUE(cJSON_IsString(ip));
    TEST_ASSERT_EQUAL_STRING("10.0.0.5", ip->valuestring);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(rebuilt, "dns"));
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(rebuilt));

    cJSON_Delete(rebuilt);
    axiam_mgmt_subject_alt_name_free(model);
    cJSON_Delete(src);
}

/* The regression this guards directly: the pre-fix generator's empty struct built
 * `{}`, which the server refuses -- a `Server` certificate request that named names
 * would silently carry none. */
static void test_subject_alt_name_never_serializes_empty(void) {
    cJSON *src = cJSON_Parse("{\"dns\": \"x\"}");
    axiam_mgmt_subject_alt_name_t *model = axiam_mgmt_subject_alt_name_parse(src);
    TEST_ASSERT_NOT_NULL(model);

    cJSON *rebuilt = axiam_mgmt_subject_alt_name_build(model);
    char *rendered = cJSON_PrintUnformatted(rebuilt);
    TEST_ASSERT_NOT_NULL(rendered);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(rendered, "{}"),
                                  "SubjectAltName must never serialize as {}");
    free(rendered);
    cJSON_Delete(rebuilt);
    axiam_mgmt_subject_alt_name_free(model);
    cJSON_Delete(src);
}

/* An object naming neither known key is a shape this SDK's copy of the spec does not
 * recognise -- fail closed rather than guess a variant. */
static void test_subject_alt_name_unrecognised_shape_fails_closed(void) {
    cJSON *src = cJSON_Parse("{}");
    TEST_ASSERT_NULL(axiam_mgmt_subject_alt_name_parse(src));
    cJSON_Delete(src);

    cJSON *other = cJSON_Parse("{\"uri\": \"spiffe://x\"}");
    TEST_ASSERT_NULL(axiam_mgmt_subject_alt_name_parse(other));
    cJSON_Delete(other);
}

/* build(NULL) and free(NULL) are the same "safe on NULL" contract every generated
 * model in this SDK carries. */
static void test_subject_alt_name_null_safe(void) {
    TEST_ASSERT_NULL(axiam_mgmt_subject_alt_name_build(NULL));
    axiam_mgmt_subject_alt_name_free(NULL); /* must not crash */
}

/* ------------------------------------------------------------------------
 * 2. `inherit` -- required-but-absent decodes as true, never false.
 * ---------------------------------------------------------------------- */

#define UUID "11111111-1111-4111-8111-111111111111"

/* Role-side listing (roles.list_users): a pre-1.51 server's response carries no
 * `inherit` key at all, though the 1.51 spec now calls it required. */
static void test_role_user_assignment_absent_inherit_defaults_true(void) {
    cJSON *src = cJSON_Parse(
        "{\"user\":{\"id\":\"" UUID "\",\"username\":\"alice\",\"email\":\"a@x.io\","
        "\"tenant_id\":\"" UUID "\",\"status\":\"Active\",\"created_at\":"
        "\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_user_assignment_t *model = axiam_mgmt_role_user_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, model->inherit,
        "absent `inherit` on a role-side listing MUST decode as true, not the "
        "calloc'd zero a plain required bool would give it");

    axiam_mgmt_role_user_assignment_free(model);
    cJSON_Delete(src);
}

/* The same listing when the server DOES send `inherit: false` -- a real value is never
 * overridden by the default. */
static void test_role_user_assignment_explicit_false_is_honoured(void) {
    cJSON *src = cJSON_Parse(
        "{\"inherit\": false, \"user\":{\"id\":\"" UUID "\",\"username\":\"alice\","
        "\"email\":\"a@x.io\",\"tenant_id\":\"" UUID "\",\"status\":\"Active\","
        "\"created_at\":\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_user_assignment_t *model = axiam_mgmt_role_user_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(0, model->inherit);

    axiam_mgmt_role_user_assignment_free(model);
    cJSON_Delete(src);
}

static void test_role_group_assignment_absent_inherit_defaults_true(void) {
    cJSON *src = cJSON_Parse(
        "{\"group\":{\"id\":\"" UUID "\",\"name\":\"eng\",\"tenant_id\":\"" UUID "\","
        "\"created_at\":\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_group_assignment_t *model = axiam_mgmt_role_group_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(1, model->inherit);

    axiam_mgmt_role_group_assignment_free(model);
    cJSON_Delete(src);
}

static void test_role_service_account_assignment_absent_inherit_defaults_true(void) {
    cJSON *src = cJSON_Parse(
        "{\"service_account\":{\"id\":\"" UUID "\",\"name\":\"svc\",\"client_id\":"
        "\"cid\",\"tenant_id\":\"" UUID "\",\"created_at\":\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_service_account_assignment_t *model =
        axiam_mgmt_role_service_account_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(1, model->inherit);

    axiam_mgmt_role_service_account_assignment_free(model);
    cJSON_Delete(src);
}

/* Subject-side listing (users.list_roles / groups.list_roles /
 * service_accounts.list_roles -> RoleAssignment): `inherit` is OPTIONAL in the 1.51
 * spec, and §27.13 S-10 rule 3 is explicit that absence still means true, not "unset". */
static void test_role_assignment_absent_inherit_defaults_true_and_is_known(void) {
    cJSON *src = cJSON_Parse(
        "{\"role\":{\"id\":\"" UUID "\",\"name\":\"editor\",\"tenant_id\":\"" UUID "\","
        "\"is_global\":false,\"created_at\":\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_assignment_t *model = axiam_mgmt_role_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, model->inherit, "absence MUST read as true");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, model->has_inherit,
        "the field is now a KNOWN value (true), not merely unset");

    axiam_mgmt_role_assignment_free(model);
    cJSON_Delete(src);
}

static void test_role_assignment_explicit_false_is_honoured(void) {
    cJSON *src = cJSON_Parse(
        "{\"inherit\": false, \"role\":{\"id\":\"" UUID "\",\"name\":\"editor\","
        "\"tenant_id\":\"" UUID "\",\"is_global\":false,\"created_at\":"
        "\"2026-08-26T00:00:00Z\"}}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_role_assignment_t *model = axiam_mgmt_role_assignment_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(0, model->inherit);
    TEST_ASSERT_EQUAL_INT(1, model->has_inherit);

    axiam_mgmt_role_assignment_free(model);
    cJSON_Delete(src);
}

/* ------------------------------------------------------------------------
 * 3. CertificateType::Server -- already decoded openly; pinned here, not fixed here
 *    (§27.13 S-7 rule 2).
 * ---------------------------------------------------------------------- */

static void test_certificate_unknown_cert_type_decodes_openly(void) {
    /* "Server" is known to THIS build (it is in the 1.51 spec this SDK just
     * re-vendored), so the open-decoding claim is pinned against a value that is
     * unknown to any build: a certificate.list projection is exactly where §27.11
     * rule 1 first drew this line, for TenantKind, and S-7 rule 2 restates it for
     * CertificateType. */
    cJSON *src = cJSON_Parse(
        "{\"id\":\"" UUID "\",\"cert_type\":\"QuantumBeacon\",\"subject\":\"cn=x\","
        "\"issuer_ca_id\":\"" UUID "\",\"tenant_id\":\"" UUID "\",\"status\":\"Active\","
        "\"not_before\":\"2026-08-26T00:00:00Z\",\"not_after\":\"2027-08-26T00:00:00Z\","
        "\"created_at\":\"2026-08-26T00:00:00Z\"}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_certificate_t *model = axiam_mgmt_certificate_parse(src);
    TEST_ASSERT_NOT_NULL_MESSAGE(model,
        "an unrecognised cert_type MUST NOT fail the whole record (CONTRACT.md "
        "\xc2\xa7""27.11 rule 1 / \xc2\xa7""27.13 S-7 rule 2)");
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CERTIFICATE_TYPE_UNKNOWN, model->cert_type);

    axiam_mgmt_certificate_free(model);
    cJSON_Delete(src);
}

/* The value this SDK's OWN copy of the 1.51 spec now lists decodes to the real
 * constant, not to UNKNOWN -- the companion assertion that keeps the test above
 * honest: it is testing open decoding of a genuinely unrecognised value, not a bug in
 * `_from_wire` that reads every value as unknown. */
static void test_certificate_server_cert_type_decodes_known(void) {
    cJSON *src = cJSON_Parse(
        "{\"id\":\"" UUID "\",\"cert_type\":\"Server\",\"subject\":\"cn=x\","
        "\"issuer_ca_id\":\"" UUID "\",\"tenant_id\":\"" UUID "\",\"status\":\"Active\","
        "\"not_before\":\"2026-08-26T00:00:00Z\",\"not_after\":\"2027-08-26T00:00:00Z\","
        "\"created_at\":\"2026-08-26T00:00:00Z\"}");
    TEST_ASSERT_NOT_NULL(src);

    axiam_mgmt_certificate_t *model = axiam_mgmt_certificate_parse(src);
    TEST_ASSERT_NOT_NULL(model);
    TEST_ASSERT_EQUAL_INT(AXIAM_MGMT_CERTIFICATE_TYPE_SERVER, model->cert_type);

    axiam_mgmt_certificate_free(model);
    cJSON_Delete(src);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_subject_alt_name_dns_round_trips);
    RUN_TEST(test_subject_alt_name_ip_round_trips);
    RUN_TEST(test_subject_alt_name_never_serializes_empty);
    RUN_TEST(test_subject_alt_name_unrecognised_shape_fails_closed);
    RUN_TEST(test_subject_alt_name_null_safe);
    RUN_TEST(test_role_user_assignment_absent_inherit_defaults_true);
    RUN_TEST(test_role_user_assignment_explicit_false_is_honoured);
    RUN_TEST(test_role_group_assignment_absent_inherit_defaults_true);
    RUN_TEST(test_role_service_account_assignment_absent_inherit_defaults_true);
    RUN_TEST(test_role_assignment_absent_inherit_defaults_true_and_is_known);
    RUN_TEST(test_role_assignment_explicit_false_is_honoured);
    RUN_TEST(test_certificate_unknown_cert_type_decodes_openly);
    RUN_TEST(test_certificate_server_cert_type_decodes_known);
    return UNITY_END();
}
