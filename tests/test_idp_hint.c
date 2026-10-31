/*
 * CONTRACT.md §12.1 "idp_hint — choosing the provider" and §26.2 rule 8 (contract 1.65).
 *
 * `oidc_begin` gains one optional input, emitted as the query parameter
 * `axiam_idp_hint`: the ninth parameter of §12.1 rule 5, present only when set. Under PAR
 * the same hint rides the PUSHED body and never the redirect.
 *
 * The assertions are on the PARSED parameter list, not on a substring: "exactly once" and
 * "exactly eight" are counts, and a substring match passes for a URL that carries the hint
 * twice.
 *
 * C adaptation of `idp_hint_not_duplicated`: axiam_oidc_begin() accepts no caller-supplied
 * extra query parameters (rule 5 makes that a MAY), so there is no second source of
 * `axiam_idp_hint` for the option to beat. The test pins the observable the rule exists for
 * (one `axiam_idp_hint`, the option's, on every route) and that an unrelated query already
 * on the discovered endpoint does not disturb it.
 */

#include <ctype.h>
#include <string.h>

#include "unity.h"
#include "oidc_test_util.h"

#define PAR_REQUEST_URI "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"

#define PAR_DISCOVERY_BODY                                                     \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"pushed_authorization_request_endpoint\":\"" OIDC_BASE "/oauth2/par\","  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\",\"profile\"]}"

void setUp(void) {
    oidc_reset();
    g_oidc.discovery_body = PAR_DISCOVERY_BODY;
    g_oidc.par_answer.body = "{\"request_uri\":\"" PAR_REQUEST_URI "\",\"expires_in\":90}";
}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* A parsed query                                                     */
/* ------------------------------------------------------------------ */

#define MAX_PARAMS 24

typedef struct {
    char key[48];
    char value[1024];
} param_t;

typedef struct {
    param_t p[MAX_PARAMS];
    int n;
} params_t;

static int hexv(char c) { return isdigit((unsigned char)c) ? c - '0' : tolower(c) - 'a' + 10; }

static void decode_into(char *dst, size_t cap, const char *src, size_t len) {
    size_t o = 0;
    for (size_t i = 0; i < len && o + 1 < cap; i++) {
        if (src[i] == '%' && i + 2 < len && isxdigit((unsigned char)src[i + 1]) && isxdigit((unsigned char)src[i + 2])) {
            dst[o++] = (char)(hexv(src[i + 1]) * 16 + hexv(src[i + 2]));
            i += 2;
        } else {
            dst[o++] = src[i];
        }
    }
    dst[o] = '\0';
}

/* Parse the query of a URL, or a bare form body when `url` has no '?'. */
static void parse(params_t *out, const char *url) {
    memset(out, 0, sizeof *out);
    const char *q = strchr(url, '?');
    const char *p = q ? q + 1 : url;
    while (*p && out->n < MAX_PARAMS) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg);
        size_t kl = eq ? (size_t)(eq - p) : seg;
        decode_into(out->p[out->n].key, sizeof out->p[out->n].key, p, kl);
        if (eq) decode_into(out->p[out->n].value, sizeof out->p[out->n].value, eq + 1, seg - kl - 1);
        out->n++;
        if (!amp) break;
        p = amp + 1;
    }
}

static int count_of(const params_t *q, const char *key) {
    int n = 0;
    for (int i = 0; i < q->n; i++)
        if (strcmp(q->p[i].key, key) == 0) n++;
    return n;
}

static const char *value_of(const params_t *q, const char *key) {
    for (int i = 0; i < q->n; i++)
        if (strcmp(q->p[i].key, key) == 0) return q->p[i].value;
    return NULL;
}

static const char *const EIGHT[] = {"response_type", "client_id",  "redirect_uri",
                                    "scope",         "state",      "nonce",
                                    "code_challenge", "code_challenge_method", NULL};

static void assert_the_eight(const params_t *q) {
    for (int i = 0; EIGHT[i]; i++) TEST_ASSERT_EQUAL_INT_MESSAGE(1, count_of(q, EIGHT[i]), EIGHT[i]);
    TEST_ASSERT_EQUAL_STRING("code", value_of(q, "response_type"));
    TEST_ASSERT_EQUAL_STRING("S256", value_of(q, "code_challenge_method"));
    TEST_ASSERT_EQUAL_STRING(OIDC_CLIENT_ID, value_of(q, "client_id"));
    TEST_ASSERT_EQUAL_STRING(OIDC_REDIRECT_URI, value_of(q, "redirect_uri"));
}

static axiam_error_kind_t begin(axiam_client_t *c, const char *hint,
                                axiam_authorization_request_t *req, axiam_error_t *err) {
    axiam_oidc_config_t cfg;
    axiam_error_kind_t k = axiam_oidc_discover(c, &cfg, err);
    if (k != AXIAM_OK) return k;
    k = axiam_oidc_begin_with_hint(c, &cfg, OIDC_REDIRECT_URI, "openid profile", hint, req, err);
    axiam_oidc_config_dispose(&cfg);
    return k;
}

/* ------------------------------------------------------------------ */
/* §12.1 — the four oidc_begin tests                                  */
/* ------------------------------------------------------------------ */

void test_idp_hint_emitted_once(void) {
    const char *hints[] = {"corp-okta", "aaaaaaaa-0000-0000-0000-00000000000a", "Google"};
    for (size_t k = 0; k < sizeof hints / sizeof hints[0]; k++) {
        axiam_client_t *c = oidc_make_client();
        axiam_error_t err;
        axiam_authorization_request_t req;
        TEST_ASSERT_EQUAL(AXIAM_OK, begin(c, hints[k], &req, &err));

        params_t q;
        parse(&q, req.url);
        /* Exactly once, beside the other eight unchanged: nine in all. */
        TEST_ASSERT_EQUAL_INT(1, count_of(&q, "axiam_idp_hint"));
        TEST_ASSERT_EQUAL_STRING(hints[k], value_of(&q, "axiam_idp_hint")); /* "Google" not folded */
        assert_the_eight(&q);
        TEST_ASSERT_EQUAL_INT(9, q.n);
        TEST_ASSERT_EQUAL_INT(0, count_of(&q, "kc_idp_hint"));
        axiam_authorization_request_dispose(&req);
        axiam_client_free(c);
    }

    /* A hint that needs percent-encoding round-trips through the parsed query intact. */
    const char *awkward = "Corp Okta/ünï&x=1+é#frag?q=%41";
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_authorization_request_t req;
    TEST_ASSERT_EQUAL(AXIAM_OK, begin(c, awkward, &req, &err));
    params_t q;
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_STRING(awkward, value_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_INT(0, count_of(&q, "x")); /* the '&' did not split it */
    TEST_ASSERT_EQUAL_INT(9, q.n);
    assert_the_eight(&q);
    axiam_authorization_request_dispose(&req);
    axiam_client_free(c);
}

void test_idp_hint_omitted_when_unset(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_authorization_request_t req;

    /* Both spellings of "unset": the new call with NULL, and the original call. */
    TEST_ASSERT_EQUAL(AXIAM_OK, begin(c, NULL, &req, &err));
    params_t q;
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_INT(0, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_INT(0, count_of(&q, "kc_idp_hint"));
    TEST_ASSERT_EQUAL_INT(8, q.n);
    assert_the_eight(&q);
    TEST_ASSERT_NULL(strstr(req.url, "idp_hint"));
    axiam_authorization_request_dispose(&req);

    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_INT(8, q.n);
    TEST_ASSERT_NULL(strstr(req.url, "idp_hint"));
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_idp_hint_not_duplicated(void) {
    /* An unrelated query on the discovered endpoint, as a router-fronted deployment
     * publishes: the hint is still the one `axiam_idp_hint` of the URL. */
    static const char doc[] =
        "{\"issuer\":\"" OIDC_ISSUER "\","
        "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize?ui_locales=en\","
        "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","
        "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\"}";
    g_oidc.discovery_body = doc;
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_authorization_request_t req;
    TEST_ASSERT_EQUAL(AXIAM_OK, begin(c, "corp-okta", &req, &err));

    params_t q;
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_STRING("corp-okta", value_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "ui_locales"));
    assert_the_eight(&q);
    TEST_ASSERT_EQUAL_INT(10, q.n);
    axiam_authorization_request_dispose(&req);

    /* Two builds on one client: each URL has its own single hint, and nothing carries over. */
    axiam_authorization_request_t second;
    TEST_ASSERT_EQUAL(AXIAM_OK, begin(c, "github", &second, &err));
    parse(&q, second.url);
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_STRING("github", value_of(&q, "axiam_idp_hint"));
    axiam_authorization_request_dispose(&second);
    axiam_client_free(c);
}

void test_idp_hint_bounds(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    int base = g_oidc.n_calls;
    axiam_authorization_request_t req;

    char h257[258], h256[257], two_byte[260];
    memset(h257, 'a', 257);
    h257[257] = '\0';
    memset(h256, 'b', 256);
    h256[256] = '\0';
    /* 129 two-byte characters = 258 BYTES: the bound is bytes, not characters. */
    for (int i = 0; i < 129; i++) memcpy(two_byte + 2 * i, "\xC3\xA9", 2);
    two_byte[258] = '\0';

    const char *refused[] = {"", h257, two_byte};
    for (size_t k = 0; k < sizeof refused / sizeof refused[0]; k++) {
        axiam_error_reset(&err);
        TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK,
                          axiam_oidc_begin_with_hint(c, &cfg, OIDC_REDIRECT_URI, "openid",
                                                     refused[k], &req, &err));
        /* The local ValidationError: no URL built, nothing drawn, no request sent. */
        TEST_ASSERT_EQUAL_INT(400, (int)err.transport_cause);
        TEST_ASSERT_NOT_NULL(strstr(err.message, "idp_hint"));
        TEST_ASSERT_NULL(req.url);
        TEST_ASSERT_NULL(req.state);
        TEST_ASSERT_NULL(req.nonce);
        TEST_ASSERT_NULL(req.code_verifier);
    }
    TEST_ASSERT_EQUAL_INT(0, g_oidc.n_calls - base);

    /* 256 bytes is accepted, unchanged. */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_begin_with_hint(c, &cfg, OIDC_REDIRECT_URI, "openid",
                                                           h256, &req, &err));
    params_t q;
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_STRING(h256, value_of(&q, "axiam_idp_hint"));
    axiam_authorization_request_dispose(&req);

    /* The value is not trimmed, and a lone space is a value (non-empty), not "unset". */
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_begin_with_hint(c, &cfg, OIDC_REDIRECT_URI, "openid",
                                                           "  corp  ", &req, &err));
    parse(&q, req.url);
    TEST_ASSERT_EQUAL_STRING("  corp  ", value_of(&q, "axiam_idp_hint"));
    axiam_authorization_request_dispose(&req);

    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §26.6 — par_idp_hint_in_pushed_body                                */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t push(axiam_client_t *c, const char *hint,
                               axiam_authorization_request_t *req,
                               axiam_pushed_authorization_request_t *out, axiam_error_t *err) {
    axiam_oidc_config_t cfg;
    axiam_error_kind_t k = axiam_oidc_discover(c, &cfg, err);
    if (k != AXIAM_OK) return k;
    k = axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid profile", req, err);
    if (k == AXIAM_OK) {
        k = axiam_oidc_par_with_hint(c, &cfg, req, OIDC_REDIRECT_URI, "openid profile", NULL,
                                     NULL, hint, out, err);
    }
    axiam_oidc_config_dispose(&cfg);
    return k;
}

void test_par_idp_hint_in_pushed_body(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;
    params_t q;

    /* With a hint: the pushed form carries it exactly once. */
    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "corp-okta", &req, &par, &err));
    int i = oidc_last_call("/oauth2/par");
    TEST_ASSERT_TRUE(i >= 0);
    parse(&q, g_oidc.bodies[i]);
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_STRING("corp-okta", value_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_EQUAL_INT(0, count_of(&q, "kc_idp_hint"));
    /* ...and the authorization URL built from the request_uri carries EXACTLY client_id and
     * request_uri: the hint did not leak into it "to be safe". */
    parse(&q, par.url);
    TEST_ASSERT_EQUAL_INT(2, q.n);
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "client_id"));
    TEST_ASSERT_EQUAL_INT(1, count_of(&q, "request_uri"));
    TEST_ASSERT_EQUAL_INT(0, count_of(&q, "axiam_idp_hint"));
    TEST_ASSERT_NULL(strstr(par.url, "idp_hint"));
    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);

    /* Without one: the field is absent from the push, and the URL is the same two. */
    oidc_reset();
    g_oidc.discovery_body = PAR_DISCOVERY_BODY;
    g_oidc.par_answer.body = "{\"request_uri\":\"" PAR_REQUEST_URI "\",\"expires_in\":90}";
    axiam_client_free(c);
    c = oidc_make_client();
    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, NULL, &req, &par, &err));
    i = oidc_last_call("/oauth2/par");
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "idp_hint"));
    parse(&q, par.url);
    TEST_ASSERT_EQUAL_INT(2, q.n);
    TEST_ASSERT_NULL(strstr(par.url, "idp_hint"));
    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);

    /* axiam_oidc_par_ex() is the same call with no hint: nothing existing changes. */
    axiam_oidc_config_t cfg;
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_par_ex(c, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL,
                                                  NULL, &par, &err));
    i = oidc_last_call("/oauth2/par");
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], "idp_hint"));
    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_par_idp_hint_bounds_refuse_before_the_push(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;
    char h257[258];
    memset(h257, 'a', 257);
    h257[257] = '\0';

    const char *refused[] = {"", h257};
    for (size_t k = 0; k < sizeof refused / sizeof refused[0]; k++) {
        axiam_error_kind_t kind = push(c, refused[k], &req, &par, &err);
        TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, kind);
        TEST_ASSERT_EQUAL_INT(400, (int)err.transport_cause);
        TEST_ASSERT_NULL(par.url);
        TEST_ASSERT_NULL(par.request_uri);
        TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);
        axiam_authorization_request_dispose(&req);
    }
    /* 256 bytes is pushed unchanged. */
    char h256[257];
    memset(h256, 'c', 256);
    h256[256] = '\0';
    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, h256, &req, &par, &err));
    int i = oidc_last_call("/oauth2/par");
    params_t q;
    parse(&q, g_oidc.bodies[i]);
    TEST_ASSERT_EQUAL_STRING(h256, value_of(&q, "axiam_idp_hint"));
    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_idp_hint_emitted_once);
    RUN_TEST(test_idp_hint_omitted_when_unset);
    RUN_TEST(test_idp_hint_not_duplicated);
    RUN_TEST(test_idp_hint_bounds);
    RUN_TEST(test_par_idp_hint_in_pushed_body);
    RUN_TEST(test_par_idp_hint_bounds_refuse_before_the_push);
    return UNITY_END();
}
