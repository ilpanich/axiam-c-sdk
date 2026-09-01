/*
 * CONTRACT.md §12.1 — the four public login-provider operations added at
 * contract 1.37, with rule 12a as it stands at 1.38: axiam_sso_providers(),
 * axiam_sso_start_oauth2(), axiam_sso_complete_oauth2() and
 * axiam_sso_complete_handoff().
 *
 * The assertions here are about WHAT WENT ON THE WIRE and HOW MANY TIMES, for
 * the same reason the rest of the §12 suite is: every rule these operations
 * carry is a statement about requests. Note 9 is "the empty list is the
 * success" — which is a claim that the call REACHED the wire and came back
 * `200`, not that a helper returned an empty array. Note 12 is "a failed
 * redemption is never retried" — a count. Rule 12a is "a 400 is a
 * configuration error, distinct from the 401" — a mapping, asserted against
 * both statuses so the distinction cannot quietly collapse.
 */

#include "unity.h"
#include "oidc_test_util.h"

#define FED_CONFIG_ID "44444444-4444-4444-4444-444444444444"
#define FED_REDIRECT  "https://app.test/callback"

#define PROVIDERS_TWO                                                          \
    "{\"providers\":["                                                         \
    "{\"id\":\"11111111-1111-1111-1111-111111111111\","                        \
    "\"provider_kind\":\"google\",\"display_name\":\"Google\","                \
    "\"protocol\":\"OidcConnect\",\"has_bundled_mark\":true,"                  \
    "\"button_icon\":null,\"inherited\":true},"                                \
    "{\"id\":\"22222222-2222-2222-2222-222222222222\","                        \
    "\"provider_kind\":\"generic_oauth2\",\"display_name\":\"Acme SSO\","      \
    "\"protocol\":\"OAuth2\",\"has_bundled_mark\":false,"                      \
    "\"button_icon\":\"data:image/png;base64,iVBORw0KGgo=\","                  \
    "\"inherited\":false}]}"

/* The third entry's provider_kind is DELIBERATELY "google" while its protocol
 * is Saml: an SDK that dispatched on the kind would send it to sso_start, which
 * the server refuses with 400 (§12.1 note 10). */
#define PROVIDERS_THREE_PROTOCOLS                                              \
    "{\"providers\":["                                                         \
    "{\"id\":\"aaaa\",\"provider_kind\":\"google\",\"display_name\":\"G\","    \
    "\"protocol\":\"OidcConnect\",\"has_bundled_mark\":true,\"inherited\":false},"\
    "{\"id\":\"bbbb\",\"provider_kind\":\"github\",\"display_name\":\"GH\","   \
    "\"protocol\":\"OAuth2\",\"has_bundled_mark\":true,\"inherited\":false},"  \
    "{\"id\":\"cccc\",\"provider_kind\":\"google\",\"display_name\":\"GW\","   \
    "\"protocol\":\"Saml\",\"has_bundled_mark\":true,\"inherited\":false}]}"

#define OAUTH2_START_OK                                                        \
    "{\"authorize_url\":\"https://github.com/login/oauth/authorize?state=s\"," \
    "\"state\":\"the-state\",\"expires_in_secs\":300}"

#define SESSION_OK                                                             \
    "{\"user_id\":\"66666666-6666-6666-6666-666666666666\","                   \
    "\"session_id\":\"77777777-7777-7777-7777-777777777777\","                 \
    "\"expires_in\":3600,\"redirect_uri\":\"https://app.test/dashboard\"}"

void setUp(void) { oidc_reset(); }
void tearDown(void) {}

/* A client carrying both a tenant UUID and an org slug — what a login page has
 * once the user has typed an organization. */
static axiam_client_t *providers_client(const char *org_id, const char *org_slug) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    if (org_id) axiam_client_config_set_org_id(cfg, org_id);
    if (org_slug) axiam_client_config_set_org_slug(cfg, org_slug);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

/* ------------------------------------------------------------------ */
/* sso_providers — the wire shape                                      */
/* ------------------------------------------------------------------ */

static void test_providers_is_a_get_with_the_identifiers_in_the_query_string(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, PROVIDERS_TWO, 0};
    axiam_client_t *c = providers_client(NULL, "acme");
    TEST_ASSERT_NOT_NULL(c);

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));

    int i = oidc_last_call("/federation/providers");
    TEST_ASSERT_TRUE(i >= 0);
    TEST_ASSERT_EQUAL_STRING("GET", g_oidc.methods[i]);
    /* No body, and no Content-Type: this is the one §12 GET. */
    TEST_ASSERT_EQUAL_STRING("", g_oidc.bodies[i]);
    TEST_ASSERT_EQUAL_STRING("", g_oidc.content_types[i]);
    /* The identifiers are QUERY parameters, not a body. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "org_slug=acme"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=" AXIAM_TEST_TENANT_ID));

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* §5.1, as everywhere else: the UUID form replaces the matching slug form. */
static void test_providers_prefers_the_uuid_form_over_the_slug_form(void) {
    axiam_client_t *c = providers_client("33333333-3333-3333-3333-333333333333", "acme");
    TEST_ASSERT_NOT_NULL(c);

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));

    int i = oidc_last_call("/federation/providers");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "org_id=33333333-3333-3333-3333-333333333333"));
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "org_slug"));

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* A login page resolves the org from what the user typed, not from how the
 * client was built. */
static void test_providers_arguments_override_the_configured_workspace(void) {
    axiam_client_t *c = providers_client(NULL, "acme");
    TEST_ASSERT_NOT_NULL(c);

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    /* The tenant argument is the UUID form, because §5.1's precedence is
     * form-first and not argument-first: a caller's slug does not displace the
     * UUID this client was constructed with, here or in sso_start. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, "typed by the user",
                            "99999999-9999-9999-9999-999999999999", NULL, &list, &err));

    int i = oidc_last_call("/federation/providers");
    /* And the value is percent-encoded, not pasted in raw. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "org_slug=typed%20by%20the%20user"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=99999999-9999-9999-9999-999999999999"));
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "acme"));
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], AXIAM_TEST_TENANT_ID));

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

static void test_providers_decodes_every_field_including_the_nullable_button_icon(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, PROVIDERS_TWO, 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)list.count);

    TEST_ASSERT_EQUAL_STRING("11111111-1111-1111-1111-111111111111", list.items[0].id);
    TEST_ASSERT_EQUAL_STRING("google", list.items[0].provider_kind);
    TEST_ASSERT_EQUAL_STRING("Google", list.items[0].display_name);
    TEST_ASSERT_EQUAL_STRING(AXIAM_FEDERATION_PROTOCOL_OIDC_CONNECT, list.items[0].protocol);
    TEST_ASSERT_EQUAL_INT(1, list.items[0].has_bundled_mark);
    TEST_ASSERT_NULL(list.items[0].button_icon);   /* absent for most providers */
    TEST_ASSERT_EQUAL_INT(1, list.items[0].inherited); /* note 13, server-side */

    TEST_ASSERT_EQUAL_STRING(AXIAM_FEDERATION_PROTOCOL_OAUTH2, list.items[1].protocol);
    TEST_ASSERT_EQUAL_INT(0, list.items[1].has_bundled_mark);
    TEST_ASSERT_EQUAL_STRING("data:image/png;base64,iVBORw0KGgo=", list.items[1].button_icon);
    TEST_ASSERT_EQUAL_INT(0, list.items[1].inherited);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* A protocol this build predates must not fail the parse of the whole list —
 * which is why `protocol` is the wire string and not an enum. */
static void test_providers_keeps_an_unknown_protocol_rather_than_failing_the_list(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200,
        "{\"providers\":["
        "{\"id\":\"a\",\"provider_kind\":\"google\",\"display_name\":\"G\","
        "\"protocol\":\"OidcConnect\",\"has_bundled_mark\":true,\"inherited\":false},"
        "{\"id\":\"b\",\"provider_kind\":\"future_kind\",\"display_name\":\"L\","
        "\"protocol\":\"SomethingNewer\",\"has_bundled_mark\":false,\"inherited\":false}]}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)list.count);
    TEST_ASSERT_EQUAL_STRING("SomethingNewer", list.items[1].protocol);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* An entry with no id or no protocol cannot start a login. It is dropped so the
 * buttons that ARE usable still render — the listing is not all-or-nothing. */
static void test_providers_drops_an_entry_that_could_not_start_a_login(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200,
        "{\"providers\":["
        "{\"provider_kind\":\"google\",\"display_name\":\"no id\","
        "\"protocol\":\"OidcConnect\"},"
        "{\"id\":\"b\",\"provider_kind\":\"github\",\"display_name\":\"no protocol\"},"
        "7,"
        "{\"id\":\"c\",\"provider_kind\":\"github\",\"display_name\":\"GH\","
        "\"protocol\":\"OAuth2\",\"has_bundled_mark\":true,\"inherited\":false}]}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)list.count);
    TEST_ASSERT_EQUAL_STRING("c", list.items[0].id);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* A slug-only client sends the slug forms — §5.1's other arm, and the shape a
 * login page has when the user typed names rather than pasted UUIDs. */
static void test_providers_sends_the_slug_forms_when_that_is_what_the_client_has(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":[]}", 0};
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_slug(cfg, "engineering");
    axiam_client_config_set_org_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    axiam_federation_provider_list_t list;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));

    int i = oidc_last_call("/federation/providers");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "org_slug=acme"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_slug=engineering"));
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "tenant_id="));

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 note 9 — the empty list is a success, and the only success    */
/* ------------------------------------------------------------------ */

static void test_an_unknown_organization_answers_an_empty_list_not_an_error(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":[]}", 0};
    axiam_client_t *c = providers_client(NULL, "no-such-org");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)list.count);
    TEST_ASSERT_NULL(list.items);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, err.kind);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

static void test_a_known_organization_with_no_providers_answers_the_same_way(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":[]}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)list.count);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/*
 * The third arm, and the one an SDK is most tempted to get wrong: a request
 * naming NO workspace at all is still a request, still reaches the wire, and
 * still answers 200 with an empty list. A client-side refusal here would
 * restore exactly the two-valued organization-slug oracle note 9 removes.
 */
static void test_no_workspace_at_all_still_reaches_the_wire_and_succeeds(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":[]}", 0};
    /* §5 makes a tenant identifier non-optional on the client, so the narrowest
     * request this SDK can send is "no ORGANIZATION named at all" — which is
     * exactly the arm note 9 calls out, and the one a login page issues before
     * the user has typed a slug. */
    axiam_client_t *c = providers_client(NULL, NULL);
    TEST_ASSERT_NOT_NULL(c);

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)list.count);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.sso_providers_calls);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, err.kind);

    int i = oidc_last_call("/federation/providers");
    /* Nothing is invented for an organization the caller did not name. */
    TEST_ASSERT_NULL(strstr(g_oidc.urls[i], "org_"));

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

/* Note 9 makes the EMPTY LIST a success, not every answer the endpoint gives. */
static void test_a_non_2xx_from_providers_is_still_an_error(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){503, "{}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)list.count);

    axiam_client_free(c);
}

static void test_a_malformed_providers_body_is_a_network_error(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":\"not-a-list\"}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));

    axiam_client_free(c);
}

static void test_a_transport_failure_on_providers_is_a_network_error(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){0, NULL, 1};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.1 note 10 — `protocol` selects the start operation              */
/* ------------------------------------------------------------------ */

static void test_protocol_selects_the_start_operation_and_provider_kind_never_does(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, PROVIDERS_THREE_PROTOCOLS, 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t list;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_UINT(3, (unsigned)list.count);

    /* The dispatch a login page performs, written out so all three arms run. */
    const char *routed[3];
    for (size_t i = 0; i < list.count; i++) {
        const char *proto = list.items[i].protocol;
        if (strcmp(proto, AXIAM_FEDERATION_PROTOCOL_OIDC_CONNECT) == 0)
            routed[i] = "sso_start";
        else if (strcmp(proto, AXIAM_FEDERATION_PROTOCOL_OAUTH2) == 0)
            routed[i] = "sso_start_oauth2";
        else if (strcmp(proto, AXIAM_FEDERATION_PROTOCOL_SAML) == 0)
            routed[i] = "saml_login";
        else
            routed[i] = "unsupported";
    }
    TEST_ASSERT_EQUAL_STRING("sso_start", routed[0]);
    TEST_ASSERT_EQUAL_STRING("sso_start_oauth2", routed[1]);
    TEST_ASSERT_EQUAL_STRING("saml_login", routed[2]);

    /* The third entry's KIND is "google"; only its protocol says SAML. */
    TEST_ASSERT_EQUAL_STRING("google", list.items[2].provider_kind);
    TEST_ASSERT_EQUAL_STRING(AXIAM_FEDERATION_PROTOCOL_SAML, list.items[2].protocol);

    axiam_federation_provider_list_dispose(&list);
    axiam_client_free(c);
}

static void test_the_protocol_and_handoff_constants_are_the_contract_values(void) {
    TEST_ASSERT_EQUAL_STRING("OidcConnect", AXIAM_FEDERATION_PROTOCOL_OIDC_CONNECT);
    TEST_ASSERT_EQUAL_STRING("OAuth2", AXIAM_FEDERATION_PROTOCOL_OAUTH2);
    TEST_ASSERT_EQUAL_STRING("Saml", AXIAM_FEDERATION_PROTOCOL_SAML);
    TEST_ASSERT_EQUAL_STRING("axiam_handoff", AXIAM_HANDOFF_QUERY_PARAM);
    TEST_ASSERT_EQUAL_INT(60, AXIAM_HANDOFF_CODE_TTL_SECONDS);
}

/* ------------------------------------------------------------------ */
/* sso_start_oauth2                                                    */
/* ------------------------------------------------------------------ */

static void test_start_oauth2_posts_json_to_its_own_path_carrying_no_pkce(void) {
    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){200, OAUTH2_START_OK, 0};
    axiam_client_t *c = oidc_make_client();
    TEST_ASSERT_NOT_NULL(c);

    axiam_sso_start_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));
    TEST_ASSERT_EQUAL_STRING("the-state", out.state);
    TEST_ASSERT_EQUAL_INT(300, (int)out.expires_in_secs);
    TEST_ASSERT_EQUAL_STRING("https://github.com/login/oauth/authorize?state=s",
                             out.authorize_url);

    int i = oidc_last_call("/federation/oauth2/start");
    TEST_ASSERT_TRUE(i >= 0);
    TEST_ASSERT_EQUAL_STRING("POST", g_oidc.methods[i]);
    TEST_ASSERT_EQUAL_STRING("application/json", g_oidc.content_types[i]);
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"federation_config_id\":\"" FED_CONFIG_ID "\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"redirect_uri\":\"" FED_REDIRECT "\""));
    /* §5.1: the workspace is in the BODY here, unlike sso_providers. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\""));
    /* §12.1 note 11: PKCE is generated and held server-side. Nothing is sent. */
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "code_verifier"));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "code_challenge"));
    /* §12.1 note 8: unauthenticated, so no CSRF header is invented. */
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[i]);

    axiam_sso_start_result_dispose(&out);
    axiam_client_free(c);
}

/*
 * §12.1 rule 12a. A 400 means the deployment does not accept this
 * redirect_uri's ORIGIN. §2 puts that on the NETWORK row — this taxonomy's
 * configuration/programming-error member — and it is not retried.
 */
static void test_start_oauth2_maps_a_400_to_the_configuration_error_and_does_not_retry(void) {
    g_oidc.sso_oauth2_start_answer =
        (oidc_answer_t){400, "{\"error\":\"redirect_uri origin is not permitted\"}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_start_result_t out;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, "https://attacker.test/cb", &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
    TEST_ASSERT_EQUAL_INT(400, err.transport_cause);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.sso_oauth2_start_calls);

    axiam_client_free(c);
}

/* The companion, so rule 12a's distinction cannot collapse into "any
 * federation failure": a 401 is an AUTH error, not a configuration one. */
static void test_start_oauth2_maps_a_401_to_an_auth_error(void) {
    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){401, "{\"error\":\"unknown workspace\"}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_start_result_t out;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));

    axiam_client_free(c);
}

static void test_start_oauth2_rejects_a_malformed_response(void) {
    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){200, "{\"state\":\"s\"}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_start_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));

    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){200, "not json at all", 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));

    axiam_client_free(c);
}

/* A client built with a tenant SLUG and an org slug sends both slug forms. */
static void test_start_oauth2_sends_the_slug_forms_when_that_is_what_the_client_has(void) {
    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){200, OAUTH2_START_OK, 0};
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    axiam_client_config_set_tenant_slug(cfg, "engineering");
    axiam_client_config_set_org_slug(cfg, "acme");
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    axiam_sso_start_result_t out;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));
    int i = oidc_last_call("/federation/oauth2/start");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"tenant_slug\":\"engineering\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"org_slug\":\"acme\""));

    axiam_sso_start_result_dispose(&out);
    axiam_client_free(c);

    /* And the UUID forms when it has those — the same §5.1 precedence. */
    oidc_reset();
    g_oidc.sso_oauth2_start_answer = (oidc_answer_t){200, OAUTH2_START_OK, 0};
    c = providers_client("33333333-3333-3333-3333-333333333333", "acme");
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &out, &err));
    i = oidc_last_call("/federation/oauth2/start");
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i],
        "\"org_id\":\"33333333-3333-3333-3333-333333333333\""));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "org_slug"));
    axiam_sso_start_result_dispose(&out);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* sso_complete_oauth2                                                 */
/* ------------------------------------------------------------------ */

static void test_complete_oauth2_posts_state_and_code_and_returns_no_token_material(void) {
    g_oidc.sso_oauth2_callback_answer = (oidc_answer_t){200, SESSION_OK, 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_complete_oauth2(c, "the-code", "the-state", &out, &err));
    TEST_ASSERT_EQUAL_STRING("66666666-6666-6666-6666-666666666666", out.user_id);
    TEST_ASSERT_EQUAL_STRING("77777777-7777-7777-7777-777777777777", out.session_id);
    TEST_ASSERT_EQUAL_INT(3600, (int)out.expires_in);
    TEST_ASSERT_EQUAL_STRING("https://app.test/dashboard", out.redirect_uri);

    int i = oidc_last_call("/federation/oauth2/callback");
    TEST_ASSERT_EQUAL_STRING("POST", g_oidc.methods[i]);
    TEST_ASSERT_EQUAL_STRING("application/json", g_oidc.content_types[i]);
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"state\":\"the-state\""));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"code\":\"the-code\""));
    /* §12.1 note 6: nothing token-shaped comes back — the session is a cookie. */
    TEST_ASSERT_NULL(strstr(SESSION_OK, "access_token"));

    axiam_sso_complete_result_dispose(&out);
    axiam_client_free(c);
}

static void test_complete_oauth2_maps_a_401_to_an_auth_error(void) {
    g_oidc.sso_oauth2_callback_answer = (oidc_answer_t){401, "{}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
        axiam_sso_complete_oauth2(c, "c", "s", &out, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.sso_oauth2_callback_calls);

    axiam_client_free(c);
}

static void test_complete_oauth2_rejects_a_response_missing_the_session(void) {
    g_oidc.sso_oauth2_callback_answer = (oidc_answer_t){200, "{\"user_id\":\"u\"}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(c, "c", "s", &out, &err));

    g_oidc.sso_oauth2_callback_answer = (oidc_answer_t){200, "not json", 0};
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(c, "c", "s", &out, &err));

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* sso_complete_handoff — §12.1 note 12                                */
/* ------------------------------------------------------------------ */

static void test_complete_handoff_posts_only_the_code(void) {
    g_oidc.sso_handoff_answer = (oidc_answer_t){200, SESSION_OK, 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_sso_complete_handoff(c, "the-handoff-code", &out, &err));
    TEST_ASSERT_EQUAL_STRING("77777777-7777-7777-7777-777777777777", out.session_id);

    int i = oidc_last_call("/federation/handoff");
    TEST_ASSERT_EQUAL_STRING("POST", g_oidc.methods[i]);
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "\"code\":\"the-handoff-code\""));
    /* The code is the whole request: no state, no workspace. */
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "state"));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "tenant"));

    axiam_sso_complete_result_dispose(&out);
    axiam_client_free(c);
}

/*
 * Unknown, expired and already-redeemed all answer the same 401, deliberately,
 * and the code is gone either way — so the 401 is TERMINAL and the redemption
 * is issued exactly once.
 */
static void test_a_handoff_401_is_terminal_and_the_redemption_is_never_retried(void) {
    g_oidc.sso_handoff_answer = (oidc_answer_t){401, "{}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    axiam_error_reset(&err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH,
        axiam_sso_complete_handoff(c, "spent-code", &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, err.kind);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.sso_handoff_calls);
    /* And nothing was left half-built for the caller to free or read. */
    TEST_ASSERT_NULL(out.user_id);
    TEST_ASSERT_NULL(out.session_id);

    axiam_client_free(c);
}

static void test_a_handoff_transport_failure_is_a_network_error(void) {
    g_oidc.sso_handoff_answer = (oidc_answer_t){0, NULL, 1};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(c, "code", &out, &err));

    axiam_client_free(c);
}

static void test_handoff_rejects_a_malformed_session_response(void) {
    g_oidc.sso_handoff_answer = (oidc_answer_t){200, "{\"session_id\":\"s\"}", 0};
    axiam_client_t *c = oidc_make_client();

    axiam_sso_complete_result_t out;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(c, "code", &out, &err));

    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §12.3 cross-cutting rules and the C argument contract               */
/* ------------------------------------------------------------------ */

/* §18.1 rule 4: a closed client refuses, and refuses before the wire. */
static void test_all_four_refuse_on_a_closed_client(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_client_close(c);

    axiam_federation_provider_list_t list;
    axiam_sso_start_result_t start;
    axiam_sso_complete_result_t done;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, &start, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(c, "c", "s", &done, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(c, "c", &done, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    axiam_client_free(c);
}

/* A NULL out-parameter or a NULL required argument is refused, not dereferenced. */
static void test_null_arguments_are_refused(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_sso_start_result_t start;
    axiam_sso_complete_result_t done;

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(c, NULL, NULL, NULL, NULL, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, NULL, FED_REDIRECT, &start, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, NULL, &start, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(c, FED_CONFIG_ID, FED_REDIRECT, NULL, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(c, NULL, "s", &done, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(c, "c", NULL, &done, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(c, NULL, &done, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(c, "c", NULL, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);

    /* And a NULL client is refused rather than dereferenced. */
    axiam_federation_provider_list_t list;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_providers(NULL, NULL, NULL, NULL, NULL, &list, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_start_oauth2(NULL, FED_CONFIG_ID, FED_REDIRECT, &start, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_oauth2(NULL, "c", "s", &done, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_sso_complete_handoff(NULL, "c", &done, &err));

    axiam_client_free(c);
}

/* Disposal is safe on NULL and on a zeroed struct, like every other dispose. */
static void test_provider_list_dispose_is_safe_on_null_and_zeroed(void) {
    axiam_federation_provider_list_dispose(NULL);
    axiam_federation_provider_list_t zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    axiam_federation_provider_list_dispose(&zeroed);
    axiam_federation_provider_list_dispose(&zeroed);   /* idempotent */
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)zeroed.count);
}

/* §12.3 rule 1: nothing is cached. Two calls are two requests, so a workspace
 * switch can never be answered from a stale provider list. */
static void test_providers_is_not_cached(void) {
    g_oidc.sso_providers_answer = (oidc_answer_t){200, "{\"providers\":[]}", 0};
    axiam_client_t *c = providers_client(NULL, "acme");

    axiam_federation_provider_list_t a, b;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_providers(c, NULL, NULL, NULL, NULL, &a, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_providers(c, NULL, NULL, NULL, NULL, &b, &err));
    TEST_ASSERT_EQUAL_INT(2, g_oidc.sso_providers_calls);

    axiam_federation_provider_list_dispose(&a);
    axiam_federation_provider_list_dispose(&b);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_providers_is_a_get_with_the_identifiers_in_the_query_string);
    RUN_TEST(test_providers_prefers_the_uuid_form_over_the_slug_form);
    RUN_TEST(test_providers_arguments_override_the_configured_workspace);
    RUN_TEST(test_providers_decodes_every_field_including_the_nullable_button_icon);
    RUN_TEST(test_providers_keeps_an_unknown_protocol_rather_than_failing_the_list);
    RUN_TEST(test_providers_drops_an_entry_that_could_not_start_a_login);
    RUN_TEST(test_providers_sends_the_slug_forms_when_that_is_what_the_client_has);
    RUN_TEST(test_an_unknown_organization_answers_an_empty_list_not_an_error);
    RUN_TEST(test_a_known_organization_with_no_providers_answers_the_same_way);
    RUN_TEST(test_no_workspace_at_all_still_reaches_the_wire_and_succeeds);
    RUN_TEST(test_a_non_2xx_from_providers_is_still_an_error);
    RUN_TEST(test_a_malformed_providers_body_is_a_network_error);
    RUN_TEST(test_a_transport_failure_on_providers_is_a_network_error);
    RUN_TEST(test_protocol_selects_the_start_operation_and_provider_kind_never_does);
    RUN_TEST(test_the_protocol_and_handoff_constants_are_the_contract_values);
    RUN_TEST(test_start_oauth2_posts_json_to_its_own_path_carrying_no_pkce);
    RUN_TEST(test_start_oauth2_maps_a_400_to_the_configuration_error_and_does_not_retry);
    RUN_TEST(test_start_oauth2_maps_a_401_to_an_auth_error);
    RUN_TEST(test_start_oauth2_rejects_a_malformed_response);
    RUN_TEST(test_start_oauth2_sends_the_slug_forms_when_that_is_what_the_client_has);
    RUN_TEST(test_complete_oauth2_posts_state_and_code_and_returns_no_token_material);
    RUN_TEST(test_complete_oauth2_maps_a_401_to_an_auth_error);
    RUN_TEST(test_complete_oauth2_rejects_a_response_missing_the_session);
    RUN_TEST(test_complete_handoff_posts_only_the_code);
    RUN_TEST(test_a_handoff_401_is_terminal_and_the_redemption_is_never_retried);
    RUN_TEST(test_a_handoff_transport_failure_is_a_network_error);
    RUN_TEST(test_handoff_rejects_a_malformed_session_response);
    RUN_TEST(test_all_four_refuse_on_a_closed_client);
    RUN_TEST(test_null_arguments_are_refused);
    RUN_TEST(test_provider_list_dispose_is_safe_on_null_and_zeroed);
    RUN_TEST(test_providers_is_not_cached);
    return UNITY_END();
}
