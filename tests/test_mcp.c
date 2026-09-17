/*
 * CONTRACT.md §28.9 required tests 1 and 2 — the two that need no request
 * pipeline: the document's shape and its validation negatives, and the
 * challenge's quoting and its refusals. Plus the §28.5 rule 2/3 configuration
 * refusals, which in this SDK live on axiam_client_config_validate() and
 * axiam_mcp_check_resource_metadata() rather than on a `serve_` call this
 * language does not have (see axiam/mcp.h).
 *
 * §28.9 asks for the same five assertions, on the same fixtures, in every SDK
 * repository, so a divergence between this port and the TypeScript reference
 * implementation (axiam-typescript-sdk, test/middleware/mcp.contract.test.ts)
 * shows up as a different expected value rather than as a different test.
 *
 * Tests 3, 4 and 5 — the ones that exercise a guard against a real request —
 * are in test_mcp_guard.c, built the same way test_uma_challenge.c already
 * builds them for §20.3: against axiam_require_auth_mcp() /
 * axiam_require_access_mcp() directly, with a fake transport standing in for
 * AXIAM. C has no HTTP framework of its own to run an Express/Fastify-style
 * suite against (§28.3, §28.7); this SDK's guard already takes headers and
 * returns a status with no socket involved, so the guard-level assertions
 * need no pipeline C does not have.
 */
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "unity.h"
#include "axiam/axiam.h"

#define RESOURCE            "https://mcp.example.com/mcp"
#define AUTH_SERVER         "https://axiam.example.com"
#define DOCUMENTATION       "https://mcp.example.com/docs"
#define METADATA_PATH       "/.well-known/oauth-protected-resource/mcp"
#define METADATA_URL        "https://mcp.example.com" METADATA_PATH
#define EXPECTED_AUDIENCE   RESOURCE

void setUp(void) {}
void tearDown(void) {}

static const char *SCOPES[] = {"mcp:read", "mcp:tools"};
static const char *SERVERS[] = {AUTH_SERVER};

static axiam_protected_resource_metadata_options_t fixture(void) {
    axiam_protected_resource_metadata_options_t o;
    memset(&o, 0, sizeof(o));
    o.resource = RESOURCE;
    o.authorization_servers = SERVERS;
    o.authorization_server_count = 1;
    o.scopes_supported = SCOPES;
    o.scopes_supported_count = 2;
    o.resource_documentation = DOCUMENTATION;
    return o;
}

/* Assert building the document from `o` is refused, and that `_path`/`_url`
 * agree (§28.2: validation is at construction time, before anything is
 * derived — no half-refusal where `_json` fails but `_path` still returns a
 * value for the same bad input). */
static void assert_refused(const axiam_protected_resource_metadata_options_t *o) {
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(o, &err);
    TEST_ASSERT_NULL(json);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    free(json);

    axiam_error_t err2;
    char *path = axiam_protected_resource_metadata_path(o, &err2);
    TEST_ASSERT_NULL(path);
    free(path);

    axiam_error_t err3;
    char *url = axiam_protected_resource_metadata_url(o, &err3);
    TEST_ASSERT_NULL(url);
    free(url);
}

/* ------------------------------------------------------------------ */
/* §28.9 test 1 — the document and its validation                     */
/* ------------------------------------------------------------------ */

static void test_produces_the_exact_json_of_28_2(void) {
    axiam_protected_resource_metadata_options_t o = fixture();
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    TEST_ASSERT_NOT_NULL(json);

    cJSON *doc = cJSON_Parse(json);
    TEST_ASSERT_NOT_NULL(doc);
    TEST_ASSERT_EQUAL_STRING(RESOURCE, cJSON_GetObjectItem(doc, "resource")->valuestring);
    cJSON *servers = cJSON_GetObjectItem(doc, "authorization_servers");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(servers));
    TEST_ASSERT_EQUAL_STRING(AUTH_SERVER, cJSON_GetArrayItem(servers, 0)->valuestring);
    cJSON *scopes = cJSON_GetObjectItem(doc, "scopes_supported");
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(scopes));
    TEST_ASSERT_EQUAL_STRING("mcp:read", cJSON_GetArrayItem(scopes, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING("mcp:tools", cJSON_GetArrayItem(scopes, 1)->valuestring);
    cJSON *methods = cJSON_GetObjectItem(doc, "bearer_methods_supported");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(methods));
    TEST_ASSERT_EQUAL_STRING("header", cJSON_GetArrayItem(methods, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING(DOCUMENTATION,
                             cJSON_GetObjectItem(doc, "resource_documentation")->valuestring);

    /* §28.2: member order is fixed in the emitted bytes. */
    cJSON *item = doc->child;
    const char *expected_order[] = {"resource", "authorization_servers", "scopes_supported",
                                    "bearer_methods_supported", "resource_documentation"};
    for (size_t i = 0; i < 5; i++) {
        TEST_ASSERT_NOT_NULL(item);
        TEST_ASSERT_EQUAL_STRING(expected_order[i], item->string);
        item = item->next;
    }
    TEST_ASSERT_NULL(item);
    cJSON_Delete(doc);
    free(json);

    axiam_error_t perr;
    char *path = axiam_protected_resource_metadata_path(&o, &perr);
    TEST_ASSERT_EQUAL_STRING(METADATA_PATH, path);
    free(path);

    axiam_error_t uerr;
    char *url = axiam_protected_resource_metadata_url(&o, &uerr);
    TEST_ASSERT_EQUAL_STRING(METADATA_URL, url);
    free(url);
}

static void test_derives_every_metadata_path_in_28_3s_table(void) {
    struct { const char *resource; const char *path; } cases[] = {
        {"https://mcp.example.com", "/.well-known/oauth-protected-resource"},
        {"https://mcp.example.com/", "/.well-known/oauth-protected-resource"},
        {"https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"},
        {"https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"},
        {"https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        axiam_protected_resource_metadata_options_t o = fixture();
        o.resource = cases[i].resource;
        axiam_error_t err;
        char *path = axiam_protected_resource_metadata_path(&o, &err);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].path, path, cases[i].resource);
        free(path);

        char expected_url[256];
        snprintf(expected_url, sizeof(expected_url), "https://mcp.example.com%s", cases[i].path);
        axiam_error_t uerr;
        char *url = axiam_protected_resource_metadata_url(&o, &uerr);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(expected_url, url, cases[i].resource);
        free(url);

        /* The document keeps the resource exactly as written — a trailing
         * slash is not trimmed. */
        axiam_error_t jerr;
        char *json = axiam_protected_resource_metadata_json(&o, &jerr);
        cJSON *doc = cJSON_Parse(json);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].resource,
                                         cJSON_GetObjectItem(doc, "resource")->valuestring,
                                         cases[i].resource);
        cJSON_Delete(doc);
        free(json);
    }
}

static void test_refuses_a_relative_resource_or_one_with_a_fragment_or_query(void) {
    axiam_protected_resource_metadata_options_t o;

    o = fixture(); o.resource = "/mcp"; assert_refused(&o);
    o = fixture(); o.resource = "mcp.example.com/mcp"; assert_refused(&o);
    o = fixture(); o.resource = "https://mcp.example.com/mcp#tools"; assert_refused(&o);
    /* §28.3 derives the document's own URL from this value and a query makes
     * that derivation ambiguous — §28 forbids what RFC 8707 permits. */
    o = fixture(); o.resource = "https://mcp.example.com/mcp?tenant_id=acme"; assert_refused(&o);
    o = fixture(); o.resource = ""; assert_refused(&o);
    o = fixture(); o.resource = NULL; assert_refused(&o);
}

static void test_refuses_http_on_a_routable_host_and_accepts_it_on_loopback(void) {
    axiam_protected_resource_metadata_options_t o;

    o = fixture(); o.resource = "http://mcp.example.com/mcp"; assert_refused(&o);

    o = fixture();
    o.resource = "http://127.0.0.1:8080/mcp";
    static const char *loopback_servers[] = {"http://localhost:9000"};
    o.authorization_servers = loopback_servers;
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    TEST_ASSERT_NOT_NULL(json);
    cJSON *doc = cJSON_Parse(json);
    TEST_ASSERT_EQUAL_STRING("http://127.0.0.1:8080/mcp",
                             cJSON_GetObjectItem(doc, "resource")->valuestring);
    cJSON_Delete(doc);
    free(json);
    axiam_error_t uerr;
    char *url = axiam_protected_resource_metadata_url(&o, &uerr);
    TEST_ASSERT_EQUAL_STRING("http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp", url);
    free(url);

    /* The carve-out is the HOST, not a substring of it: an authority whose
     * userinfo merely reads "localhost" resolves to a routable host. */
    o = fixture(); o.resource = "http://localhost@evil.example.com/mcp"; assert_refused(&o);

    /* [::1] is the third named loopback host, brackets included. */
    o = fixture();
    o.resource = "http://[::1]:8080/mcp";
    static const char *v6_servers[] = {"http://[::1]:9000"};
    o.authorization_servers = v6_servers;
    axiam_error_t v6err;
    char *v6url = axiam_protected_resource_metadata_url(&o, &v6err);
    TEST_ASSERT_EQUAL_STRING("http://[::1]:8080/.well-known/oauth-protected-resource/mcp", v6url);
    free(v6url);

    o = fixture(); o.resource = "http://[2001:db8::1]:8080/mcp"; assert_refused(&o);
}

static void test_refuses_empty_authorization_servers_and_a_bad_entry(void) {
    axiam_protected_resource_metadata_options_t o;

    o = fixture(); o.authorization_servers = NULL; o.authorization_server_count = 0;
    assert_refused(&o);

    static const char *with_query[] = {"https://axiam.example.com?tenant_id=a"};
    o = fixture(); o.authorization_servers = with_query; assert_refused(&o);

    static const char *with_fragment[] = {"https://axiam.example.com#frag"};
    o = fixture(); o.authorization_servers = with_fragment; assert_refused(&o);

    static const char *dup[] = {"https://axiam.example.com", "https://axiam.example.com"};
    o = fixture(); o.authorization_servers = dup; o.authorization_server_count = 2;
    assert_refused(&o);
}

static void test_refuses_a_duplicate_or_invalid_scope_and_preserves_order(void) {
    axiam_protected_resource_metadata_options_t o;

    static const char *dup_scope[] = {"mcp:read", "mcp:read"};
    o = fixture(); o.scopes_supported = dup_scope; assert_refused(&o);

    static const char *space_scope[] = {"mcp read"};
    o = fixture(); o.scopes_supported = space_scope; o.scopes_supported_count = 1;
    assert_refused(&o);

    static const char *quoted_scope[] = {"mcp:\"read\""};
    o = fixture(); o.scopes_supported = quoted_scope; o.scopes_supported_count = 1;
    assert_refused(&o);

    static const char *empty_scope[] = {""};
    o = fixture(); o.scopes_supported = empty_scope; o.scopes_supported_count = 1;
    assert_refused(&o);

    /* The order is the caller's, never sorted. */
    static const char *reordered[] = {"mcp:tools", "mcp:read"};
    o = fixture(); o.scopes_supported = reordered;
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    cJSON *doc = cJSON_Parse(json);
    cJSON *scopes = cJSON_GetObjectItem(doc, "scopes_supported");
    TEST_ASSERT_EQUAL_STRING("mcp:tools", cJSON_GetArrayItem(scopes, 0)->valuestring);
    TEST_ASSERT_EQUAL_STRING("mcp:read", cJSON_GetArrayItem(scopes, 1)->valuestring);
    cJSON_Delete(doc);
    free(json);
}

static void test_refuses_any_bearer_methods_supported_that_is_not_exactly_header(void) {
    axiam_protected_resource_metadata_options_t o;

    static const char *query_method[] = {"query"};
    o = fixture(); o.bearer_methods_supported = query_method; o.bearer_methods_supported_count = 1;
    assert_refused(&o);

    static const char *two_methods[] = {"header", "body"};
    o = fixture(); o.bearer_methods_supported = two_methods; o.bearer_methods_supported_count = 2;
    assert_refused(&o);

    /* An explicit empty list (non-NULL pointer, zero count) is refused —
     * ["header"] is the only accepted value, and empty is not it. */
    static const char *empty_methods[1] = {NULL};
    o = fixture(); o.bearer_methods_supported = empty_methods; o.bearer_methods_supported_count = 0;
    assert_refused(&o);

    static const char *dup_method[] = {"header", "header"};
    o = fixture(); o.bearer_methods_supported = dup_method; o.bearer_methods_supported_count = 2;
    assert_refused(&o);

    /* NULL means "not specified" and defaults to ["header"]. */
    o = fixture();
    o.bearer_methods_supported = NULL;
    o.bearer_methods_supported_count = 0;
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    TEST_ASSERT_NOT_NULL(json);
    cJSON *doc = cJSON_Parse(json);
    cJSON *methods = cJSON_GetObjectItem(doc, "bearer_methods_supported");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(methods));
    TEST_ASSERT_EQUAL_STRING("header", cJSON_GetArrayItem(methods, 0)->valuestring);
    cJSON_Delete(doc);
    free(json);
}

static void test_omits_scopes_supported_when_empty_and_documentation_when_absent(void) {
    axiam_protected_resource_metadata_options_t o = fixture();
    o.scopes_supported = NULL;
    o.scopes_supported_count = 0;
    o.resource_documentation = NULL;

    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    TEST_ASSERT_NOT_NULL(json);
    cJSON *doc = cJSON_Parse(json);
    /* An empty scopes_supported would assert that this resource server
     * understands no scopes — a different and almost always false claim. And
     * an explicit `null` is not an omission. */
    TEST_ASSERT_NULL(cJSON_GetObjectItem(doc, "scopes_supported"));
    TEST_ASSERT_NULL(cJSON_GetObjectItem(doc, "resource_documentation"));
    TEST_ASSERT_NULL(strstr(json, "null"));
    cJSON_Delete(doc);
    free(json);
}

static void test_accepts_documentation_with_query_and_fragment_refuses_http(void) {
    axiam_protected_resource_metadata_options_t o = fixture();
    o.resource_documentation = "https://mcp.example.com/docs?v=2#tools";
    axiam_error_t err;
    char *json = axiam_protected_resource_metadata_json(&o, &err);
    TEST_ASSERT_NOT_NULL(json);
    cJSON *doc = cJSON_Parse(json);
    TEST_ASSERT_EQUAL_STRING("https://mcp.example.com/docs?v=2#tools",
                             cJSON_GetObjectItem(doc, "resource_documentation")->valuestring);
    cJSON_Delete(doc);
    free(json);

    o = fixture(); o.resource_documentation = "http://docs.example.com/mcp";
    assert_refused(&o);
}

/* ------------------------------------------------------------------ */
/* §28.9 test 2 — challenge quoting                                    */
/* ------------------------------------------------------------------ */

static void test_produces_28_4s_four_vectors_as_exact_strings(void) {
    axiam_bearer_challenge_options_t o;
    axiam_error_t err;
    char *s;

    memset(&o, 0, sizeof(o));
    o.resource_metadata_url = METADATA_URL;
    s = axiam_bearer_challenge(&o, &err);
    TEST_ASSERT_EQUAL_STRING("Bearer resource_metadata=\"" METADATA_URL "\"", s);
    free(s);

    o.error = AXIAM_BEARER_ERROR_INVALID_TOKEN;
    s = axiam_bearer_challenge(&o, &err);
    TEST_ASSERT_EQUAL_STRING(
        "Bearer error=\"invalid_token\", resource_metadata=\"" METADATA_URL "\"", s);
    free(s);

    memset(&o, 0, sizeof(o));
    o.resource_metadata_url = METADATA_URL;
    o.error = AXIAM_BEARER_ERROR_INSUFFICIENT_SCOPE;
    o.scope = "mcp:tools";
    s = axiam_bearer_challenge(&o, &err);
    TEST_ASSERT_EQUAL_STRING(
        "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", "
        "resource_metadata=\"" METADATA_URL "\"",
        s);
    free(s);

    memset(&o, 0, sizeof(o));
    o.resource_metadata_url = METADATA_URL;
    o.error = AXIAM_BEARER_ERROR_INVALID_REQUEST;
    o.error_description = "The access token is malformed";
    o.scope = "mcp:read mcp:tools";
    s = axiam_bearer_challenge(&o, &err);
    TEST_ASSERT_EQUAL_STRING(
        "Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", "
        "scope=\"mcp:read mcp:tools\", resource_metadata=\"" METADATA_URL "\"",
        s);
    free(s);
}

static void test_refuses_an_error_code_28_1_does_not_define(void) {
    axiam_bearer_challenge_options_t o;
    memset(&o, 0, sizeof(o));
    o.resource_metadata_url = METADATA_URL;
    o.error = "invalid_grant"; /* a token-endpoint error, not a challenge one */
    axiam_error_t err;
    TEST_ASSERT_NULL(axiam_bearer_challenge(&o, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
}

static void test_refuses_rather_than_escapes_a_bad_error_description(void) {
    const char *bad[] = {"he said \"no\"", "a back\\slash", "two\nlines",
                         "a control\x01", "non-ASCII: caf\xc3\xa9", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        axiam_bearer_challenge_options_t o;
        memset(&o, 0, sizeof(o));
        o.resource_metadata_url = METADATA_URL;
        o.error = AXIAM_BEARER_ERROR_INVALID_REQUEST;
        o.error_description = bad[i];
        axiam_error_t err;
        char *s = axiam_bearer_challenge(&o, &err);
        TEST_ASSERT_NULL_MESSAGE(s, bad[i]);
        /* No escaping occurred: the refusal is an error, never a challenge
         * carrying a backslash-escaped quote. */
        TEST_ASSERT_NULL(strstr(err.message, "\\\""));
    }
}

static void test_refuses_a_malformed_scope(void) {
    const char *bad[] = {" mcp:read", "mcp:read ", "mcp:read  mcp:tools", "", " ", "mcp:\"read\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        axiam_bearer_challenge_options_t o;
        memset(&o, 0, sizeof(o));
        o.resource_metadata_url = METADATA_URL;
        o.error = AXIAM_BEARER_ERROR_INSUFFICIENT_SCOPE;
        o.scope = bad[i];
        axiam_error_t err;
        TEST_ASSERT_NULL_MESSAGE(axiam_bearer_challenge(&o, &err), bad[i]);
    }
}

static void test_refuses_a_resource_metadata_that_is_not_an_encoded_absolute_url(void) {
    const char *bad[] = {
        "https://mcp.example.com/.well-known/oauth protected resource",
        "https://mcp.example.com/\"quoted\"",
        "https://mcp.example.com/back\\slash",
        "/.well-known/oauth-protected-resource/mcp",
        "http://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        axiam_bearer_challenge_options_t o;
        memset(&o, 0, sizeof(o));
        o.resource_metadata_url = bad[i];
        axiam_error_t err;
        TEST_ASSERT_NULL_MESSAGE(axiam_bearer_challenge(&o, &err), bad[i]);
    }

    /* It MAY carry a query and a fragment, unlike the resource identifier. */
    axiam_bearer_challenge_options_t o;
    memset(&o, 0, sizeof(o));
    o.resource_metadata_url = METADATA_URL "?v=2#x";
    axiam_error_t err;
    char *s = axiam_bearer_challenge(&o, &err);
    TEST_ASSERT_EQUAL_STRING("Bearer resource_metadata=\"" METADATA_URL "?v=2#x\"", s);
    free(s);
}

/* ------------------------------------------------------------------ */
/* §28.5 rule 2 — the configuration refusal                            */
/* ------------------------------------------------------------------ */

static void test_config_refuses_resource_metadata_url_without_expected_audience(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_resource_metadata_url(cfg, METADATA_URL);

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(cfg, &err));
    /* The refusal names both options so the fix is one line. */
    TEST_ASSERT_NOT_NULL(strstr(err.message, "resource_metadata_url"));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "expected_audience"));
    axiam_client_config_free(cfg);
}

static void test_config_accepts_the_pair_and_refuses_a_malformed_url(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_expected_audience(cfg, EXPECTED_AUDIENCE);
    axiam_client_config_set_resource_metadata_url(cfg, METADATA_URL);

    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);

    axiam_client_config_t *bad = axiam_client_config_new();
    axiam_client_config_set_base_url(bad, "https://iam.example.com");
    axiam_client_config_set_tenant_id(bad, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_expected_audience(bad, EXPECTED_AUDIENCE);
    axiam_client_config_set_resource_metadata_url(bad, "/relative/path");
    axiam_error_t berr;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_client_config_validate(bad, &berr));
    axiam_client_config_free(bad);
}

/* With resource_metadata_url left unset, the new field changes nothing about
 * an otherwise-valid config — the §28.9 off-by-default regression, applied to
 * configuration rather than to a guarded request. */
static void test_config_without_resource_metadata_url_is_unaffected(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-1111-1111-111111111111");
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_validate(cfg, &err));
    axiam_client_config_free(cfg);
}

/* ------------------------------------------------------------------ */
/* §28.5 rule 3 — the serve_-less cross-check                          */
/* ------------------------------------------------------------------ */

static void test_check_resource_metadata_agrees_or_refuses(void) {
    axiam_protected_resource_metadata_options_t o = fixture();

    axiam_client_config_t *ok = axiam_client_config_new();
    axiam_client_config_set_base_url(ok, "https://iam.example.com");
    axiam_client_config_set_tenant_id(ok, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_expected_audience(ok, EXPECTED_AUDIENCE);
    axiam_client_config_set_resource_metadata_url(ok, METADATA_URL);
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mcp_check_resource_metadata(ok, &o, &err));
    axiam_client_config_free(ok);

    /* §28.5 rule 3, first equality: a challenge pointing at a document that
     * is not this resource server's. */
    axiam_client_config_t *wrong_url = axiam_client_config_new();
    axiam_client_config_set_base_url(wrong_url, "https://iam.example.com");
    axiam_client_config_set_tenant_id(wrong_url, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_expected_audience(wrong_url, EXPECTED_AUDIENCE);
    axiam_client_config_set_resource_metadata_url(wrong_url, METADATA_URL "/");
    axiam_error_t uerr;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_mcp_check_resource_metadata(wrong_url, &o, &uerr));
    axiam_client_config_free(wrong_url);

    /* Second equality: the document announces one identifier and the guard
     * checks aud against another — the two strings compared are DIFFERENT
     * strings (resource vs. metadata_url), never each other. */
    axiam_client_config_t *wrong_aud = axiam_client_config_new();
    axiam_client_config_set_base_url(wrong_aud, "https://iam.example.com");
    axiam_client_config_set_tenant_id(wrong_aud, "11111111-1111-1111-1111-111111111111");
    axiam_client_config_set_expected_audience(wrong_aud, RESOURCE "/");
    axiam_client_config_set_resource_metadata_url(wrong_aud, METADATA_URL);
    axiam_error_t aerr;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_mcp_check_resource_metadata(wrong_aud, &o, &aerr));
    axiam_client_config_free(wrong_aud);

    /* §28 off: nothing to check, nothing refused. */
    axiam_client_config_t *off = axiam_client_config_new();
    axiam_client_config_set_base_url(off, "https://iam.example.com");
    axiam_client_config_set_tenant_id(off, "11111111-1111-1111-1111-111111111111");
    axiam_error_t oerr;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_mcp_check_resource_metadata(off, &o, &oerr));
    axiam_client_config_free(off);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_produces_the_exact_json_of_28_2);
    RUN_TEST(test_derives_every_metadata_path_in_28_3s_table);
    RUN_TEST(test_refuses_a_relative_resource_or_one_with_a_fragment_or_query);
    RUN_TEST(test_refuses_http_on_a_routable_host_and_accepts_it_on_loopback);
    RUN_TEST(test_refuses_empty_authorization_servers_and_a_bad_entry);
    RUN_TEST(test_refuses_a_duplicate_or_invalid_scope_and_preserves_order);
    RUN_TEST(test_refuses_any_bearer_methods_supported_that_is_not_exactly_header);
    RUN_TEST(test_omits_scopes_supported_when_empty_and_documentation_when_absent);
    RUN_TEST(test_accepts_documentation_with_query_and_fragment_refuses_http);
    RUN_TEST(test_produces_28_4s_four_vectors_as_exact_strings);
    RUN_TEST(test_refuses_an_error_code_28_1_does_not_define);
    RUN_TEST(test_refuses_rather_than_escapes_a_bad_error_description);
    RUN_TEST(test_refuses_a_malformed_scope);
    RUN_TEST(test_refuses_a_resource_metadata_that_is_not_an_encoded_absolute_url);
    RUN_TEST(test_config_refuses_resource_metadata_url_without_expected_audience);
    RUN_TEST(test_config_accepts_the_pair_and_refuses_a_malformed_url);
    RUN_TEST(test_config_without_resource_metadata_url_is_unaffected);
    RUN_TEST(test_check_resource_metadata_agrees_or_refuses);
    return UNITY_END();
}
