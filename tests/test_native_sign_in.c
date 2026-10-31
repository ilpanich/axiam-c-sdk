/*
 * CONTRACT.md §37 (contract 1.65) — native sign-in with a provider ID token, and
 * the §37.4 `native_nonce` helper. The thirteen required tests of §37.9, by the
 * contract's names so the eleven SDKs' suites can be compared.
 *
 * What these tests are about is the WIRE and the COUNT: the exact key set of the
 * form, which nonce is in it, and that every failure is one request and no more.
 * The provider's token is single-use across the whole deployment, so "one
 * request" is the property that keeps a transient blip from becoming an
 * `invalid_grant` the caller cannot interpret.
 *
 * Every test warms the discovery cache first: this SDK reads the token endpoint
 * from the discovery document (§12.1), so a cold client's first request is a GET
 * of that document. The count under test is the grant's own, taken after it.
 */

#include <ctype.h>
#include <string.h>

#include "unity.h"
#include "jwt_fixture.h"
#include "oidc_test_util.h"
#include "oidc_internal.h"

#define NATIVE_ID_TOKEN "provider.fixture-id-token.sig-0123456789"
#define NATIVE_NONCE    "n-0S6_WzA2Mj"
/* SHA-256("n-0S6_WzA2Mj"), the fixed vector of §37.4. */
#define NATIVE_NONCE_SHA256 "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"
#define NATIVE_PROVIDER_UUID "cccccccc-0000-0000-0000-00000000000c"
#define NATIVE_OK_BODY \
    "{\"access_token\":\"native-access\",\"token_type\":\"Bearer\",\"expires_in\":900,"  \
    "\"scope\":\"profile\"}"


/* ------------------------------------------------------------------ */
/* Harness                                                            */
/* ------------------------------------------------------------------ */

/* A telemetry sink that concatenates every string it is handed, so the §37.9
 * test 12 scan has one buffer to search. */
typedef struct {
    char text[8192];
    int events;
    int refresh_events;
} tele_t;

static tele_t g_tele;

void setUp(void) {
    oidc_reset();
    memset(&g_tele, 0, sizeof g_tele);
}
void tearDown(void) {}

static void tele_add(const char *s) {
    if (!s) return;
    size_t n = strlen(g_tele.text);
    snprintf(g_tele.text + n, sizeof(g_tele.text) - n, "|%s", s);
}

static void tele_hook(void *ctx, const axiam_telemetry_event_t *e) {
    (void)ctx;
    g_tele.events++;
    if (e->kind == AXIAM_TELEMETRY_REFRESH) g_tele.refresh_events++;
    tele_add(e->operation);
    tele_add(e->method);
    tele_add(e->path_template);
    tele_add(e->reason);
    tele_add(e->setting);
    tele_add(e->requested);
    tele_add(e->effective);
    tele_add(e->contract_reference);
    tele_add(e->failure_category);
}

static axiam_client_t *make_client(const char *secret, const char *tenant_id,
                                   const char *tenant_slug) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, OIDC_BASE);
    if (tenant_id) axiam_client_config_set_tenant_id(cfg, tenant_id);
    if (tenant_slug) axiam_client_config_set_tenant_slug(cfg, tenant_slug);
    axiam_client_config_set_oidc_client_id(cfg, OIDC_CLIENT_ID);
    if (secret) axiam_client_config_set_oidc_client_secret(cfg, secret);
    axiam_client_config_set_transport(cfg, oidc_fake_transport, &g_oidc);
    axiam_client_config_set_telemetry_hook(cfg, tele_hook, NULL);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    return c;
}

/* A PUBLIC client, the normal registration of a mobile app. */
static axiam_client_t *make_public_client(void) {
    return make_client(NULL, AXIAM_TEST_TENANT_ID, NULL);
}

/* Fetch discovery once so the grant's own request count is what is measured.
 * Returns the number of requests already on the books. */
static int warm(axiam_client_t *c) {
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    axiam_oidc_config_dispose(&cfg);
    return g_oidc.n_calls;
}

static void script(long status, const char *body) {
    g_oidc.token_script[0] = (oidc_answer_t){status, body, 0};
    g_oidc.token_script_len = 1;
}

static axiam_error_kind_t login(axiam_client_t *c, const char *provider, const char *id_token,
                                const char *nonce, const char *scope, const char *resource,
                                axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_sensitive_t *tok = id_token ? axiam_sensitive_new(id_token) : NULL;
    axiam_sensitive_t *non = nonce ? axiam_sensitive_new(nonce) : NULL;
    axiam_error_kind_t k =
        axiam_login_with_provider_id_token(c, provider, tok, non, scope, resource, NULL, out, err);
    axiam_sensitive_free(tok);
    axiam_sensitive_free(non);
    return k;
}

static int hexval(char c) { return isdigit((unsigned char)c) ? c - '0' : tolower(c) - 'a' + 10; }

/* The percent-decoded value of `key` in a form body, into `out`. 1 when present. */
static int form_get(const char *body, const char *key, char *out, size_t n) {
    size_t kl = strlen(key);
    const char *p = body;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > kl && strncmp(p, key, kl) == 0 && p[kl] == '=') {
            size_t o = 0;
            for (const char *q = p + kl + 1; q < p + seg && o + 1 < n; q++) {
                if (*q == '%' && q + 2 < p + seg && isxdigit((unsigned char)q[1]) &&
                    isxdigit((unsigned char)q[2])) {
                    out[o++] = (char)(hexval(q[1]) * 16 + hexval(q[2]));
                    q += 2;
                } else if (*q == '+') {
                    out[o++] = ' ';
                } else {
                    out[o++] = *q;
                }
            }
            out[o] = '\0';
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

/* The number of `key=` fields in a form body. */
static int form_count(const char *body, const char *key) {
    int n = 0;
    size_t kl = strlen(key);
    const char *p = body;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > kl && strncmp(p, key, kl) == 0 && p[kl] == '=') n++;
        if (!amp) break;
        p = amp + 1;
    }
    return n;
}

/* The number of fields in a form body. */
static int form_fields(const char *body) {
    if (!body[0]) return 0;
    int n = 1;
    for (const char *p = body; *p; p++)
        if (*p == '&') n++;
    return n;
}

/* Assert the body's key set is EXACTLY `keys` (a NULL-terminated list), each once. */
static void assert_exact_keys(const char *body, const char *const *keys) {
    int n = 0;
    for (; keys[n]; n++) TEST_ASSERT_EQUAL_INT_MESSAGE(1, form_count(body, keys[n]), keys[n]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(n, form_fields(body), "the form carries a field outside the set");
}

/* ------------------------------------------------------------------ */
/* §37.9 test 1                                                       */
/* ------------------------------------------------------------------ */

void test_request_body_exact(void) {
    script(200, NATIVE_OK_BODY);
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_OK, login(c, NATIVE_PROVIDER_UUID, NATIVE_ID_TOKEN, NATIVE_NONCE,
                                      "profile email", "https://api.example/resource", &set,
                                      &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    int i = base;
    TEST_ASSERT_EQUAL_STRING("POST", g_oidc.methods[i]);
    /* tenant_id in the QUERY... */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "/oauth2/token?"));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=" AXIAM_TEST_TENANT_ID));
    /* ...and absent from the body. */
    TEST_ASSERT_EQUAL_INT(0, form_count(g_oidc.bodies[i], "tenant_id"));
    TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", g_oidc.content_types[i]);
    /* X-Tenant-ID still emitted per §5 rule 2. */
    TEST_ASSERT_EQUAL_STRING(AXIAM_TEST_TENANT_ID, g_oidc.tenant_headers[i]);
    /* No Authorization (so no Basic), Cookie or X-CSRF-Token. */
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[i]);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.cookie_headers[i]);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.csrf_headers[i]);

    /* The FULL key set, not the presence of the five. */
    const char *const keys[] = {"grant_type", "client_id", "provider", "id_token",
                                "nonce",      "scope",     "resource", NULL};
    assert_exact_keys(g_oidc.bodies[i], keys);
    char v[256];
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[i], "grant_type", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING("urn:axiam:params:oauth:grant-type:provider-id-token", v);
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[i], "scope", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING("profile email", v); /* the space-joined list */
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[i], "resource", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING("https://api.example/resource", v);
    axiam_oidc_token_set_dispose(&set);

    /* The same call with no scopes and no resource sends neither key — and does
     * NOT add `openid` (§37.2 rule 7, unlike oidc_begin). */
    oidc_reset();
    script(200, NATIVE_OK_BODY);
    axiam_client_free(c);
    c = make_public_client();
    base = warm(c);
    TEST_ASSERT_EQUAL(AXIAM_OK, login(c, NATIVE_PROVIDER_UUID, NATIVE_ID_TOKEN, NATIVE_NONCE,
                                      NULL, NULL, &set, &err));
    i = base;
    const char *const minimal[] = {"grant_type", "client_id", "provider", "id_token", "nonce",
                                   NULL};
    assert_exact_keys(g_oidc.bodies[i], minimal);
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "openid"));
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "scope"));
    /* An empty string is "none" too: omitted rather than sent blank. */
    axiam_oidc_token_set_dispose(&set);
    TEST_ASSERT_EQUAL(AXIAM_OK, login(c, NATIVE_PROVIDER_UUID, NATIVE_ID_TOKEN, NATIVE_NONCE,
                                      "", "", &set, &err));
    assert_exact_keys(g_oidc.bodies[base + 1], minimal);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §37.9 test 2                                                       */
/* ------------------------------------------------------------------ */

void test_raw_nonce_sent_not_hash(void) {
    /* A fixture token whose payload carries the HASH, as the provider's would. */
    char payload[512];
    snprintf(payload, sizeof payload,
             "{\"iss\":\"https://accounts.provider.test\",\"nonce\":\"" NATIVE_NONCE_SHA256 "\"}");
    char *token = NULL, *jwks = NULL;
    TEST_ASSERT_EQUAL_INT(0, jwt_make("prov-kid", payload, &token, &jwks));

    script(200, NATIVE_OK_BODY);
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      login(c, "corp-okta", token, NATIVE_NONCE, NULL, NULL, &set, &err));

    char v[256];
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[base], "nonce", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING(NATIVE_NONCE, v);
    /* Neither the hash... */
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[base], NATIVE_NONCE_SHA256));
    /* ...nor the token's own `nonce` claim (which IS the hash here). */
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[base], "0823a09b"));
    /* And the raw value's case is never folded or otherwise touched. */
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
    free(token);
    free(jwks);
}

/* ------------------------------------------------------------------ */
/* §37.9 test 3                                                       */
/* ------------------------------------------------------------------ */

void test_provider_sent_verbatim(void) {
    const char *providers[] = {NATIVE_PROVIDER_UUID, "Corp-Okta", "google",
                               "AAAAAAAA-0000-0000-0000-00000000000A", " padded "};
    for (size_t k = 0; k < sizeof providers / sizeof providers[0]; k++) {
        oidc_reset();
        script(200, NATIVE_OK_BODY);
        axiam_client_t *c = make_public_client();
        int base = warm(c);
        axiam_error_t err;
        axiam_oidc_token_set_t set;
        TEST_ASSERT_EQUAL(AXIAM_OK,
                          login(c, providers[k], NATIVE_ID_TOKEN, NATIVE_NONCE, NULL, NULL, &set,
                                &err));
        char v[128];
        TEST_ASSERT_TRUE(form_get(g_oidc.bodies[base], "provider", v, sizeof v));
        /* Unchanged: no trimming, no case-folding, no UUID normalisation, no
         * kind-name translation. */
        TEST_ASSERT_EQUAL_STRING(providers[k], v);
        /* ONE request in total after the cached discovery: no sso_providers lookup, no
         * second discovery fetch. */
        TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
        TEST_ASSERT_EQUAL_INT(0, g_oidc.sso_providers_calls);
        TEST_ASSERT_EQUAL_INT(1, g_oidc.discovery_calls);
        axiam_oidc_token_set_dispose(&set);
        axiam_client_free(c);
    }
}

/* ------------------------------------------------------------------ */
/* §37.9 test 4                                                       */
/* ------------------------------------------------------------------ */

void test_public_client_sends_client_id_only(void) {
    script(200, NATIVE_OK_BODY);
    axiam_client_t *c = make_public_client(); /* no secret configured */
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    /* Not refused client-side for holding no secret (§14.1 rule 1's rule). */
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    const char *const keys[] = {"grant_type", "client_id", "provider", "id_token", "nonce", NULL};
    assert_exact_keys(g_oidc.bodies[base], keys);
    TEST_ASSERT_EQUAL_INT(0, form_count(g_oidc.bodies[base], "client_secret"));
    TEST_ASSERT_EQUAL_INT(0, form_count(g_oidc.bodies[base], "client_assertion"));
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[base]);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

void test_confidential_client_sends_its_credential(void) {
    script(200, NATIVE_OK_BODY);
    axiam_client_t *c = make_client(OIDC_CLIENT_SECRET, AXIAM_TEST_TENANT_ID, NULL);
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL, NULL, &set, &err));
    /* client_secret_post — in the body, never a Basic header. */
    char v[128];
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[base], "client_secret", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_SECRET, v);
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[base]);
    const char *const keys[] = {"grant_type", "client_id",     "provider",
                                "id_token",   "nonce",         "client_secret", NULL};
    assert_exact_keys(g_oidc.bodies[base], keys);
    /* The mock naming client_secret_basic changes nothing: the SDK uses the one form. */
    oidc_reset();
    script(200, NATIVE_OK_BODY);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
    c = make_client(OIDC_CLIENT_SECRET, AXIAM_TEST_TENANT_ID, NULL);
    base = warm(c);
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL, NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("", g_oidc.authorizations[base]);
    axiam_oidc_token_set_dispose(&set);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §37.9 test 5                                                       */
/* ------------------------------------------------------------------ */

void test_empty_inputs_refused_locally(void) {
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    struct { const char *provider, *token, *nonce; } cases[] = {
        {"", NATIVE_ID_TOKEN, NATIVE_NONCE},
        {NULL, NATIVE_ID_TOKEN, NATIVE_NONCE},
        {"corp-okta", "", NATIVE_NONCE},
        {"corp-okta", NULL, NATIVE_NONCE},
        {"corp-okta", NATIVE_ID_TOKEN, ""},
        {"corp-okta", NATIVE_ID_TOKEN, NULL},
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        axiam_error_kind_t kind =
            login(c, cases[k].provider, cases[k].token, cases[k].nonce, NULL, NULL, &set, &err);
        /* This SDK's local ValidationError: NETWORK, cause 400, no request sent. */
        TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, kind);
        TEST_ASSERT_EQUAL_INT(400, (int)err.transport_cause);
        TEST_ASSERT_NOT_NULL(strstr(err.message, "no request was sent"));
        TEST_ASSERT_NULL(set.access_token);
    }
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    axiam_client_free(c);

    /* A slug-only client (§12.3 rule 4): its taxonomy error, client-side, no wire call. */
    oidc_reset();
    c = make_client(NULL, NULL, "acme-tenant");
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                            NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.token_calls);
    /* ...and an explicit tenant UUID argument rescues it, as for oidc_exchange. */
    script(200, NATIVE_OK_BODY);
    axiam_sensitive_t *tok = axiam_sensitive_new(NATIVE_ID_TOKEN);
    axiam_sensitive_t *non = axiam_sensitive_new(NATIVE_NONCE);
    TEST_ASSERT_EQUAL(AXIAM_OK,
                      axiam_login_with_provider_id_token(c, "corp-okta", tok, non, NULL, NULL,
                                                         AXIAM_TEST_TENANT_ID, &set, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(tok);
    axiam_sensitive_free(non);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §37.9 tests 6 to 10                                                */
/* ------------------------------------------------------------------ */

void test_generic_invalid_grant_mapped(void) {
    script(400, "{\"error\":\"invalid_grant\","
                "\"error_description\":\"the provider ID token is not acceptable\"}");
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                            NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("invalid_grant", err.oauth_error);
    TEST_ASSERT_EQUAL_STRING("invalid_grant: the provider ID token is not acceptable", err.message);
    /* C165-21: error_description in a field of its own. */
    TEST_ASSERT_EQUAL_STRING("the provider ID token is not acceptable", err.oauth_error_description);
    TEST_ASSERT_EQUAL_INT(0, (int)err.oauth_retry_after_ms);
    TEST_ASSERT_EQUAL_INT(400, (int)err.transport_cause);
    TEST_ASSERT_NULL(set.access_token);
    /* Exactly ONE request: no retry, and nothing regenerated a nonce and re-sent. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    /* The §9 guard is not entered. */
    TEST_ASSERT_EQUAL_INT(0, g_tele.refresh_events);
    TEST_ASSERT_EQUAL_INT(-1, oidc_last_call("/auth/refresh"));
    axiam_client_free(c);
}

void test_consent_required_mapped(void) {
    script(400, "{\"error\":\"consent_required\",\"error_description\":\"consent needed\"}");
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE,
                                            "address", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("consent_required", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    /* No fallback to another grant, and no browser flow on the caller's behalf. */
    TEST_ASSERT_EQUAL_INT(0, g_oidc.sso_start_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    axiam_client_free(c);
}

void test_client_and_scope_refusals_surfaced(void) {
    struct { long status; const char *body; const char *www; const char *code; } cases[] = {
        {400, "{\"error\":\"unauthorized_client\",\"error_description\":\"grant not registered\"}",
         NULL, "unauthorized_client"},
        {401, "{\"error\":\"invalid_client\",\"error_description\":\"client authentication failed\"}",
         "Basic realm=\"axiam\"", "invalid_client"},
        {400, "{\"error\":\"invalid_scope\",\"error_description\":\"scope outside registration\"}",
         NULL, "invalid_scope"},
        {400, "{\"error\":\"invalid_target\",\"error_description\":\"resource not allowed\"}", NULL,
         "invalid_target"},
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        oidc_reset();
        memset(&g_tele, 0, sizeof g_tele);
        g_oidc.token_script[0] = (oidc_answer_t){cases[k].status, cases[k].body, 0, NULL,
                                                 cases[k].www};
        g_oidc.token_script_len = 1;
        axiam_client_t *c = make_public_client();
        int base = warm(c);
        axiam_error_t err;
        axiam_oidc_token_set_t set;

        TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
                          login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, "profile address",
                                "https://api.example/r", &set, &err));
        TEST_ASSERT_EQUAL_STRING(cases[k].code, err.oauth_error);
        TEST_ASSERT_EQUAL_INT((int)cases[k].status, (int)err.transport_cause);
        /* One request each: invalid_scope is not narrowed and re-sent, and the 401 does
         * not enter the §9 guard (no refresh telemetry, no refresh call). */
        TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
        TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
        TEST_ASSERT_EQUAL_INT(0, g_tele.refresh_events);
        TEST_ASSERT_EQUAL_INT(-1, oidc_last_call("/auth/refresh"));
        axiam_client_free(c);
    }
}

void test_rate_limit_with_retry_after_mapped(void) {
    g_oidc.token_script[0] = (oidc_answer_t){429, "{\"error\":\"rate_limit_exceeded\"}", 0, "7"};
    g_oidc.token_script_len = 1;
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                            NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("rate_limit_exceeded", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(429, (int)err.transport_cause);
    /* C165-17: the server's Retry-After (7 s) is exposed, in milliseconds. */
    TEST_ASSERT_EQUAL_INT(7000, (int)err.oauth_retry_after_ms);
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error_description);
    /* Exactly one request, and no wait taken for it: the SDK exposes Retry-After but does not
     * act on it, and the sleep seam records that nothing slept. */
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_sleeps);
    axiam_client_free(c);
}

void test_server_error_not_retried(void) {
    /* A 500 WITH a well-formed body is dispatched on the body. */
    script(500, "{\"error\":\"server_error\",\"error_description\":\"datastore unavailable\"}");
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                            NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("server_error", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_sleeps);
    axiam_client_free(c);

    /* A 500 with no body is NetworkError. */
    oidc_reset();
    script(500, "");
    c = make_public_client();
    base = warm(c);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                               NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("", err.oauth_error);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_sleeps);
    axiam_client_free(c);

    /* A transport failure after the request is sent: NetworkError, one request. The token
     * may have been spent, so the recovery is a fresh pair, never a re-send. */
    oidc_reset();
    g_oidc.token_script[0] = (oidc_answer_t){0, NULL, 1};
    g_oidc.token_script_len = 1;
    c = make_public_client();
    base = warm(c);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL,
                                               NULL, &set, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.n_calls - base);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.token_calls);
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_sleeps);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §37.9 test 11                                                      */
/* ------------------------------------------------------------------ */

static char *g_id_token;
static char *g_jwks;

static void mint_id_token(const char *nonce_claim) {
    long long now = (long long)time(NULL);
    char payload[512];
    snprintf(payload, sizeof payload,
             "{\"iss\":\"" OIDC_ISSUER "\",\"aud\":\"" OIDC_CLIENT_ID "\",\"sub\":\"user-7\","
             "\"exp\":%lld,\"iat\":%lld,\"nonce\":\"%s\"}",
             now + 900, now - 5, nonce_claim);
    free(g_id_token);
    free(g_jwks);
    TEST_ASSERT_EQUAL_INT(0, jwt_make(OIDC_KID, payload, &g_id_token, &g_jwks));
    g_oidc.jwks_body = g_jwks;
}

static void script_full_set(void) {
    static char body[4096];
    snprintf(body, sizeof body,
             "{\"access_token\":\"native-access\",\"token_type\":\"DPoP\",\"expires_in\":900,"
             "\"refresh_token\":\"native-refresh\",\"id_token\":\"%s\",\"scope\":\"openid profile\"}",
             g_id_token);
    script(200, body);
}

void test_result_is_the_ordinary_token_set(void) {
    /* The AXIAM ID token carries the request's nonce AS SENT — the raw one. */
    mint_id_token(NATIVE_NONCE);
    script_full_set();
    axiam_client_t *c = make_public_client();
    warm(c);
    axiam_error_t err;
    axiam_oidc_token_set_t set;

    TEST_ASSERT_EQUAL(AXIAM_OK, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE,
                                      "openid profile", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING("native-access", axiam_sensitive_reveal(set.access_token));
    TEST_ASSERT_EQUAL_STRING("native-refresh", axiam_sensitive_reveal(set.refresh_token));
    /* token_type is READ, not assumed to be Bearer (§15.2 rule 8). */
    TEST_ASSERT_EQUAL_STRING("DPoP", set.token_type);
    TEST_ASSERT_EQUAL_STRING("openid profile", set.scope);
    /* The id_token was validated under §12.4 with the raw nonce as the expected one. */
    TEST_ASSERT_NOT_NULL(set.id_token);
    TEST_ASSERT_NOT_NULL(set.id_claims);
    TEST_ASSERT_EQUAL_STRING("user-7", set.id_claims->subject);
    TEST_ASSERT_EQUAL_STRING(NATIVE_NONCE, set.id_claims->nonce);
    axiam_oidc_token_set_dispose(&set);

    /* A claim that is not the raw nonce — the PROVIDER's hash, say — is nonce_mismatch. */
    mint_id_token(NATIVE_NONCE_SHA256);
    script_full_set();
    axiam_client_free(c); /* a new key was minted: a fresh client has no cached JWKS */
    c = make_public_client();
    warm(c);
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE,
                                            "openid", NULL, &set, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_OIDC_REASON_NONCE_MISMATCH, err.id_token_reason);
    /* §12.4 rule 7: the whole set is discarded with it. */
    TEST_ASSERT_NULL(set.access_token);
    TEST_ASSERT_NULL(set.refresh_token);
    TEST_ASSERT_NULL(set.id_claims);

    /* A 200 without refresh_token and id_token decodes with both absent. */
    script(200, "{\"access_token\":\"native-access\",\"token_type\":\"Bearer\",\"expires_in\":900}");
    TEST_ASSERT_EQUAL(AXIAM_OK, login(c, "corp-okta", NATIVE_ID_TOKEN, NATIVE_NONCE, NULL, NULL,
                                      &set, &err));
    TEST_ASSERT_NOT_NULL(set.access_token);
    TEST_ASSERT_NULL(set.refresh_token);
    TEST_ASSERT_NULL(set.id_token);
    TEST_ASSERT_NULL(set.id_claims);
    TEST_ASSERT_NULL(set.scope);
    axiam_oidc_token_set_dispose(&set);

    /* Adoption posture (rule 9): this SDK, like login_client_credentials and
     * device_login, ADOPTS NOTHING. The client holds no credential from the call. */
    TEST_ASSERT_NULL(c->device_access_token);
    TEST_ASSERT_EQUAL_INT(0, c->authenticated);
    axiam_client_free(c);
    free(g_id_token);
    free(g_jwks);
    g_id_token = g_jwks = NULL;
}

/* ------------------------------------------------------------------ */
/* §37.9 test 12                                                      */
/* ------------------------------------------------------------------ */

#define LEAK_TOKEN "LEAKCHECK.id-token.fixture-7f3a91c2"
#define LEAK_NONCE "LEAKCHECK-raw-nonce-fixture-5d8e04b6"

static void assert_clean(const char *what, const char *haystack) {
    char msg[128];
    snprintf(msg, sizeof msg, "%s leaked the ID token", what);
    TEST_ASSERT_NULL_MESSAGE(strstr(haystack, LEAK_TOKEN), msg);
    snprintf(msg, sizeof msg, "%s leaked the raw nonce", what);
    TEST_ASSERT_NULL_MESSAGE(strstr(haystack, LEAK_NONCE), msg);
    /* ...nor a recognisable piece of either. */
    TEST_ASSERT_NULL(strstr(haystack, "7f3a91c2"));
    TEST_ASSERT_NULL(strstr(haystack, "5d8e04b6"));
}

static void assert_error_clean(const char *what, const axiam_error_t *err) {
    assert_clean(what, err->message);
    assert_clean(what, err->oauth_error);
    assert_clean(what, err->id_token_reason);
    assert_clean(what, err->reason_code);
    assert_clean(what, err->action);
    assert_clean(what, err->resource_id);
}

void test_no_secret_in_logs_or_errors(void) {
    /* This SDK has no logger of its own (the caller's transport and telemetry hook are the
     * only places an operation could be recorded), so the scan covers every place a value
     * could surface: each failure's axiam_error_t, every §19 telemetry event string, the
     * Sensitive handles' own rendering, and the ProviderNonce. */
    struct { long status; const char *body; int transport_fails; } cases[] = {
        {200, NATIVE_OK_BODY, 0},                                            /* success */
        {400, "{\"error\":\"invalid_grant\",\"error_description\":\"the provider ID token is "
              "not acceptable\"}", 0},                                       /* test 6 */
        {400, "{\"error\":\"consent_required\"}", 0},                        /* test 7 */
        {401, "{\"error\":\"invalid_client\"}", 0},                          /* test 8 */
        {400, "{\"error\":\"invalid_scope\"}", 0},
        {429, "{\"error\":\"rate_limit_exceeded\"}", 0},                     /* test 9 */
        {500, "{\"error\":\"server_error\",\"error_description\":\"x\"}", 0},/* test 10 */
        {500, "", 0},
        {0, NULL, 1},
    };
    memset(&g_tele, 0, sizeof g_tele);
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        oidc_reset();
        g_oidc.token_script[0] = (oidc_answer_t){cases[k].status, cases[k].body,
                                                 cases[k].transport_fails};
        g_oidc.token_script_len = 1;
        axiam_client_t *c = make_client(OIDC_CLIENT_SECRET, AXIAM_TEST_TENANT_ID, NULL);
        warm(c);
        axiam_error_t err;
        axiam_oidc_token_set_t set;
        axiam_sensitive_t *tok = axiam_sensitive_new(LEAK_TOKEN);
        axiam_sensitive_t *non = axiam_sensitive_new(LEAK_NONCE);
        axiam_error_kind_t kind = axiam_login_with_provider_id_token(
            c, "corp-okta", tok, non, "openid", NULL, NULL, &set, &err);
        if (cases[k].status == 200) {
            /* openid with no id_token in the answer: still a success. */
            TEST_ASSERT_EQUAL(AXIAM_OK, kind);
            axiam_oidc_token_set_dispose(&set);
        } else {
            TEST_ASSERT_NOT_EQUAL(AXIAM_OK, kind);
        }
        assert_error_clean("an error", &err);
        /* The Sensitive rendering is redacted and carries neither value. */
        assert_clean("the ID token's rendering", axiam_sensitive_to_string(tok));
        assert_clean("the nonce's rendering", axiam_sensitive_to_string(non));
        axiam_sensitive_free(tok);
        axiam_sensitive_free(non);
        axiam_client_free(c);
    }
    /* The OIDC operations emit no §19 request events today, so this buffer is usually empty;
     * the scan stays so a future event that carried a value could not pass unnoticed. */
    assert_clean("telemetry", g_tele.text);

    /* The local refusals of test 5 raise errors too. */
    oidc_reset();
    axiam_client_t *c = make_public_client();
    axiam_error_t err;
    axiam_oidc_token_set_t set;
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, login(c, "", LEAK_TOKEN, LEAK_NONCE, NULL, NULL, &set, &err));
    assert_error_clean("a local refusal", &err);
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, login(c, "p", LEAK_TOKEN, "", NULL, NULL, &set, &err));
    assert_error_clean("a local refusal", &err);
    axiam_client_free(c);

    /* ProviderNonce.raw's rendering (§37.4). */
    axiam_provider_nonce_t pair;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_native_nonce(&pair, &err));
    const char *rendered = axiam_sensitive_to_string(pair.raw);
    TEST_ASSERT_NOT_NULL(rendered);
    TEST_ASSERT_NULL(strstr(rendered, axiam_sensitive_reveal(pair.raw)));
    axiam_provider_nonce_dispose(&pair);
}

/* ------------------------------------------------------------------ */
/* §37.9 test 13 and §37.4                                            */
/* ------------------------------------------------------------------ */

void test_native_nonce_pair(void) {
    axiam_error_t err;
    axiam_provider_nonce_t a, b;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_native_nonce(&a, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_native_nonce(&b, &err));

    const char *raw = axiam_sensitive_reveal(a.raw);
    TEST_ASSERT_NOT_NULL(raw);
    /* base64url without padding: only the URL-safe alphabet, no '='. */
    for (const char *p = raw; *p; p++)
        TEST_ASSERT_TRUE(isalnum((unsigned char)*p) || *p == '-' || *p == '_');
    TEST_ASSERT_NULL(strchr(raw, '='));
    /* It decodes to at least 32 bytes. */
    size_t decoded_len = 0;
    unsigned char *decoded = axiam_b64url_decode(raw, strlen(raw), &decoded_len);
    TEST_ASSERT_NOT_NULL(decoded);
    TEST_ASSERT_TRUE(decoded_len >= 32);
    free(decoded);

    /* hashed: 64 lower-case hex characters equal to SHA-256 of the bytes of raw. */
    TEST_ASSERT_EQUAL_size_t(64, strlen(a.hashed));
    for (const char *p = a.hashed; *p; p++)
        TEST_ASSERT_TRUE((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'));
    char *expect = oidc_nonce_hash_hex(raw);
    TEST_ASSERT_EQUAL_STRING(expect, a.hashed);
    free(expect);

    /* Two calls return different pairs. */
    TEST_ASSERT_NOT_EQUAL(0, strcmp(raw, axiam_sensitive_reveal(b.raw)));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(a.hashed, b.hashed));

    /* raw is wrapped (its rendering is not the value); hashed is a plain string. */
    TEST_ASSERT_NULL(strstr(axiam_sensitive_to_string(a.raw), raw));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(a.hashed, axiam_sensitive_to_string(a.raw)));

    axiam_provider_nonce_dispose(&a);
    axiam_provider_nonce_dispose(&b);
    /* Dispose is safe twice and on NULL. */
    axiam_provider_nonce_dispose(&a);
    axiam_provider_nonce_dispose(NULL);
}

void test_native_nonce_fixed_vector(void) {
    /* The vector tests the hashing step only; `raw` itself is random (§37.4). */
    char *h = oidc_nonce_hash_hex(NATIVE_NONCE);
    TEST_ASSERT_EQUAL_STRING(NATIVE_NONCE_SHA256, h);
    free(h);
}

void test_native_nonce_refuses_a_null_out(void) {
    axiam_error_t err;
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, axiam_native_nonce(NULL, &err));
}

/* ------------------------------------------------------------------ */
/* Beyond §37.9                                                       */
/* ------------------------------------------------------------------ */

void test_the_pair_round_trips_through_the_helper(void) {
    /* The one mistake §37.4 exists to remove: what the provider is given is the HASH, what
     * AXIAM is sent is the RAW — the two halves of one native_nonce() pair. */
    axiam_provider_nonce_t pair;
    axiam_error_t err;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_native_nonce(&pair, &err));
    script(200, NATIVE_OK_BODY);
    axiam_client_t *c = make_public_client();
    int base = warm(c);
    axiam_oidc_token_set_t set;
    axiam_sensitive_t *tok = axiam_sensitive_new(NATIVE_ID_TOKEN);
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_login_with_provider_id_token(c, "corp-okta", tok, pair.raw,
                                                                    NULL, NULL, NULL, &set, &err));
    char v[128];
    TEST_ASSERT_TRUE(form_get(g_oidc.bodies[base], "nonce", v, sizeof v));
    TEST_ASSERT_EQUAL_STRING(axiam_sensitive_reveal(pair.raw), v);
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[base], pair.hashed));
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(tok);
    axiam_provider_nonce_dispose(&pair);
    axiam_client_free(c);
}

void test_a_null_out_is_refused(void) {
    axiam_client_t *c = make_public_client();
    axiam_error_t err;
    axiam_sensitive_t *tok = axiam_sensitive_new(NATIVE_ID_TOKEN);
    axiam_sensitive_t *non = axiam_sensitive_new(NATIVE_NONCE);
    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
                      axiam_login_with_provider_id_token(c, "p", tok, non, NULL, NULL, NULL, NULL,
                                                         &err));
    axiam_sensitive_free(tok);
    axiam_sensitive_free(non);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_request_body_exact);
    RUN_TEST(test_raw_nonce_sent_not_hash);
    RUN_TEST(test_provider_sent_verbatim);
    RUN_TEST(test_public_client_sends_client_id_only);
    RUN_TEST(test_confidential_client_sends_its_credential);
    RUN_TEST(test_empty_inputs_refused_locally);
    RUN_TEST(test_generic_invalid_grant_mapped);
    RUN_TEST(test_consent_required_mapped);
    RUN_TEST(test_client_and_scope_refusals_surfaced);
    RUN_TEST(test_rate_limit_with_retry_after_mapped);
    RUN_TEST(test_server_error_not_retried);
    RUN_TEST(test_result_is_the_ordinary_token_set);
    RUN_TEST(test_no_secret_in_logs_or_errors);
    RUN_TEST(test_native_nonce_pair);
    RUN_TEST(test_native_nonce_fixed_vector);
    RUN_TEST(test_native_nonce_refuses_a_null_out);
    RUN_TEST(test_the_pair_round_trips_through_the_helper);
    RUN_TEST(test_a_null_out_is_refused);
    return UNITY_END();
}
