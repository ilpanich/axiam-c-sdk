/*
 * Pushed Authorization Requests, RFC 9126 — CONTRACT.md §26.
 *
 * PAR moves the authorization request off the browser: instead of putting
 * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
 * agent carries, the client POSTs them straight to AXIAM and puts an opaque
 * handle in the redirect. What travels through the browser is then a random
 * string that cannot be edited into meaning something else.
 *
 * TWO OF THESE TESTS ARE THE ONES THAT CATCH REAL BUGS.
 *
 *  - The 201 test. RFC 9126 §2.2 answers Created, and a success predicate
 *    written `== 200` treats every successful push as a failure while passing
 *    every other assertion in this file.
 *  - The "exactly two parameters" test. The server REFUSES a request mixing a
 *    request_uri with inline authorization parameters rather than merging them,
 *    because merging is where parameter confusion lives — so an SDK that
 *    re-adds `scope` "for compatibility" has restored the attack.
 */

#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "oidc_test_util.h"

#define PAR_REQUEST_URI "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"

/* A document that advertises PAR. */
#define PAR_DISCOVERY_BODY                                                     \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize\","           \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"pushed_authorization_request_endpoint\":\"" OIDC_BASE "/oauth2/par\","  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"                   \
    "\"scopes_supported\":[\"openid\",\"profile\"]}"

/*
 * The same document with a query already on the authorization endpoint. A real
 * deployment behind a router does this, and §26.2 rule 2 says the pre-existing
 * query is DROPPED rather than merged.
 */
#define PAR_DISCOVERY_WITH_QUERY                                               \
    "{\"issuer\":\"" OIDC_ISSUER "\","                                         \
    "\"authorization_endpoint\":\"" OIDC_BASE "/oauth2/authorize?ui_locales=en&prompt=login\"," \
    "\"token_endpoint\":\"" OIDC_BASE "/oauth2/token\","                       \
    "\"jwks_uri\":\"" OIDC_BASE "/oauth2/jwks\","                              \
    "\"pushed_authorization_request_endpoint\":\"" OIDC_BASE "/oauth2/par\","  \
    "\"response_types_supported\":[\"code\"],"                                 \
    "\"id_token_signing_alg_values_supported\":[\"EdDSA\"]}"

#define PAR_OK_BODY \
    "{\"request_uri\":\"" PAR_REQUEST_URI "\",\"expires_in\":90}"

void setUp(void) {
    oidc_reset();
    g_oidc.discovery_body = PAR_DISCOVERY_BODY;
    g_oidc.par_answer.body = PAR_OK_BODY;
}
void tearDown(void) {}

/* Discover, begin, push — the three steps every test below needs. */
static axiam_error_kind_t push(axiam_client_t *c, const char *scope,
                               axiam_oidc_config_t *cfg,
                               axiam_authorization_request_t *req,
                               axiam_pushed_authorization_request_t *out,
                               axiam_error_t *err) {
    axiam_error_kind_t k = axiam_oidc_discover(c, cfg, err);
    if (k != AXIAM_OK) return k;
    k = axiam_oidc_begin(c, cfg, OIDC_REDIRECT_URI, scope, req, err);
    if (k != AXIAM_OK) return k;
    return axiam_oidc_par(c, cfg, req, OIDC_REDIRECT_URI, scope, NULL, out, err);
}

/* The value of `field` in the last PAR form body, copied into `buf`. */
static int par_form_value(char *buf, size_t n, const char *field) {
    int i = oidc_last_call("/oauth2/par");
    if (i < 0) return 0;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", field);
    const char *body = g_oidc.bodies[i];
    const char *p = body;
    while ((p = strstr(p, pattern)) != NULL) {
        if (p == body || p[-1] == '&') break;
        p += strlen(pattern);
    }
    if (!p) return 0;
    p += strlen(pattern);
    const char *end = strchr(p, '&');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len >= n) len = n - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/* §26.1 — discovery and the push                                     */
/* ------------------------------------------------------------------ */

void test_a_successful_push_answers_201_not_200(void) {
    /* RFC 9126 §2.2. This is the single most likely way to get §26 wrong: every
     * other assertion in this file passes for an implementation whose success
     * predicate is `== 200`, and every real push fails. */
    g_oidc.par_answer.status = 201;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid profile", &cfg, &req, &par, &err));
    TEST_ASSERT_EQUAL_STRING(PAR_REQUEST_URI, axiam_sensitive_reveal(par.request_uri));
    TEST_ASSERT_EQUAL_INT(90, (int)par.expires_in);
    TEST_ASSERT_EQUAL_INT(1, g_oidc.par_calls);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_200_is_also_accepted(void) {
    /* The check is on the 2xx range, not on one status: a deployment behind a
     * gateway that normalises to 200 is not a failure. */
    g_oidc.par_answer.status = 200;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_server_without_par_is_refused_client_side_with_no_wire_call(void) {
    /* §12.7.2 rule 1's discipline, applied to §26.1: never synthesise the URL
     * from the issuer. A server that does not advertise the endpoint does not
     * have it, and guessing `/oauth2/par` produces a 404 that reads like a
     * broken request. */
    g_oidc.discovery_body = OIDC_DISCOVERY_BODY;  /* no PAR endpoint */

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_NULL(cfg.pushed_authorization_request_endpoint);
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));

    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "RFC 9126"));

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_the_push_carries_the_tenant_and_the_form_content_type(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    int i = oidc_last_call("/oauth2/par");
    TEST_ASSERT_EQUAL_STRING("POST", g_oidc.methods[i]);
    TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", g_oidc.content_types[i]);
    /* §12.1 rule 2: the /oauth2 family takes the tenant as a query parameter,
     * in UUID form. */
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.urls[i], "tenant_id=" AXIAM_TEST_TENANT_ID));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §26.2 rule 1 — one generator, not two                              */
/* ------------------------------------------------------------------ */

void test_the_push_reuses_begins_state_nonce_and_pkce(void) {
    /* Two sources for `state` or the PKCE pair are two things that can
     * disagree, and when they do the failure surfaces at the exchange as an
     * opaque `invalid_grant` — a long way from the code that caused it. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    char value[512];
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "state"));
    TEST_ASSERT_EQUAL_STRING(req.state, value);
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "nonce"));
    TEST_ASSERT_EQUAL_STRING(req.nonce, value);
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "code_challenge_method"));
    TEST_ASSERT_EQUAL_STRING("S256", value);

    /* And they come BACK OUT, so the caller has one object to persist rather
     * than two to keep in step. */
    TEST_ASSERT_EQUAL_STRING(req.state, par.state);
    TEST_ASSERT_EQUAL_STRING(req.nonce, par.nonce);
    TEST_ASSERT_EQUAL_STRING(axiam_sensitive_reveal(req.code_verifier),
                             axiam_sensitive_reveal(par.code_verifier));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_the_verifier_itself_never_goes_on_the_wire(void) {
    /* PKCE's whole point: the push carries the CHALLENGE, and the verifier
     * stays with the client until the exchange. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    int i = oidc_last_call("/oauth2/par");
    TEST_ASSERT_NULL(strstr(g_oidc.bodies[i], axiam_sensitive_reveal(req.code_verifier)));
    TEST_ASSERT_NOT_NULL(strstr(g_oidc.bodies[i], "code_challenge="));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_openid_is_added_to_the_pushed_scope_when_absent(void) {
    /* §12.1 rule 4, applied to the push exactly as oidc_begin applies it —
     * otherwise the two halves of one authorization request ask for different
     * scopes. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "profile email", &cfg, &req, &par, &err));

    char value[512];
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "scope"));
    TEST_ASSERT_NOT_NULL(strstr(value, "openid"));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §26.2 rule 2 — the redirect carries exactly two parameters         */
/* ------------------------------------------------------------------ */

void test_the_redirect_url_carries_exactly_client_id_and_request_uri(void) {
    /* THE SECURITY ASSERTION OF §26. The server refuses a request that mixes a
     * request_uri with inline authorization parameters rather than merging
     * them: merging is where parameter confusion lives — an attacker supplies
     * the inline value they want and lets the pushed copy satisfy whichever
     * check reads the other one. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid profile", &cfg, &req, &par, &err));

    const char *q = strchr(par.url, '?');
    TEST_ASSERT_NOT_NULL(q);
    int amps = 0;
    for (const char *p = q; *p; p++) {
        if (*p == '&') amps++;
    }
    TEST_ASSERT_EQUAL_INT(1, amps);  /* exactly two parameters */
    TEST_ASSERT_NOT_NULL(strstr(par.url, "client_id=" OIDC_CLIENT_ID));
    TEST_ASSERT_NOT_NULL(strstr(par.url, "request_uri="));

    /* None of the pushed parameters is re-added "for compatibility". */
    TEST_ASSERT_NULL(strstr(par.url, "scope="));
    TEST_ASSERT_NULL(strstr(par.url, "redirect_uri="));
    TEST_ASSERT_NULL(strstr(par.url, "state="));
    TEST_ASSERT_NULL(strstr(par.url, "nonce="));
    TEST_ASSERT_NULL(strstr(par.url, "code_challenge="));
    TEST_ASSERT_NULL(strstr(par.url, "response_type="));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_pre_existing_query_on_the_endpoint_is_dropped(void) {
    /* Same rule, from the other direction: a deployment whose discovered
     * authorization endpoint already carries a query does not get those
     * parameters smuggled into a PAR redirect. */
    g_oidc.discovery_body = PAR_DISCOVERY_WITH_QUERY;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    TEST_ASSERT_NULL(strstr(par.url, "ui_locales"));
    TEST_ASSERT_NULL(strstr(par.url, "prompt="));
    TEST_ASSERT_NOT_NULL(strstr(par.url, "/oauth2/authorize?client_id="));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_the_request_uri_is_percent_encoded_in_the_redirect(void) {
    /* A `urn:` contains colons; unencoded it is a URL a strict parser rejects
     * and a lenient one truncates. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));

    TEST_ASSERT_NOT_NULL(strstr(par.url, "request_uri=urn%3Aietf%3A"));
    TEST_ASSERT_NULL(strstr(par.url, "request_uri=urn:"));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §26.2 rule 4 — never retried                                       */
/* ------------------------------------------------------------------ */

void test_the_push_is_not_retried_on_a_5xx(void) {
    /* A POST that creates server state falls outside §16.2's read-only
     * eligibility exactly as oidc_exchange does. The safe recovery is a FRESH
     * push, which costs one round trip and cannot double-consume anything. */
    g_oidc.par_answer.status = 503;
    g_oidc.par_answer.body = "{\"error\":\"server_error\"}";

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.par_calls);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_the_push_is_not_retried_on_a_transport_failure(void) {
    g_oidc.par_answer.transport_fails = 1;

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, push(c, "openid", &cfg, &req, &par, &err));
    TEST_ASSERT_EQUAL_INT(1, g_oidc.par_calls);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_an_oauth2_error_body_is_surfaced(void) {
    g_oidc.par_answer.status = 400;
    g_oidc.par_answer.body =
        "{\"error\":\"invalid_request\",\"error_description\":\"redirect_uri not registered\"}";

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "invalid_request"));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_response_without_a_request_uri_is_a_failure(void) {
    /* A 201 with no handle is not a successful push with a missing field; there
     * is nothing to redirect with, and returning AXIAM_OK would hand the caller
     * a URL naming an empty request_uri. */
    g_oidc.par_answer.body = "{\"expires_in\":90}";

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_ERR_NETWORK, push(c, "openid", &cfg, &req, &par, &err));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* §26.5 / §7 — the handle is a secret for the length of the window   */
/* ------------------------------------------------------------------ */

void test_the_request_uri_does_not_render(void) {
    /* Between the push and the redirect it is a bearer handle to a fully-formed
     * authorization request, and a log line is the wrong place for it to sit
     * for the length of that window. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(par.request_uri));
    TEST_ASSERT_EQUAL_STRING("[SENSITIVE]", axiam_sensitive_to_string(par.code_verifier));
    /* `state` and `nonce` stay readable — the caller has to compare them on
     * return, so wrapping them would make §12.4 rule 6 unimplementable. */
    TEST_ASSERT_NOT_NULL(par.state);
    TEST_ASSERT_NOT_NULL(par.nonce);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_failed_push_never_echoes_the_verifier(void) {
    g_oidc.par_answer.status = 400;
    g_oidc.par_answer.body = "{\"error\":\"invalid_request\"}";

    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_NULL(strstr(err.message, axiam_sensitive_reveal(req.code_verifier)));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

/* ------------------------------------------------------------------ */
/* Housekeeping                                                       */
/* ------------------------------------------------------------------ */

void test_null_arguments_are_refused_with_no_wire_call(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(NULL, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, NULL, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, &cfg, NULL, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, &cfg, &req, NULL, "openid", NULL, &par, &err));
    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, &cfg, &req, "", "openid", NULL, &par, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_dispose_is_safe_on_null_and_on_a_zeroed_struct(void) {
    axiam_pushed_authorization_request_dispose(NULL);
    axiam_pushed_authorization_request_t par;
    memset(&par, 0, sizeof(par));
    axiam_pushed_authorization_request_dispose(&par);
}

void test_a_closed_client_refuses_the_push(void) {
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    axiam_client_close(c);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK,
        axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_null_scope_still_asks_for_openid(void) {
    /* §12.1 rule 4 has no exception for "the caller passed nothing". A push
     * with an empty scope is a request the server will reject as not an OIDC
     * one, at the far end of a redirect the user has already taken. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, NULL, &cfg, &req, &par, &err));

    char value[512];
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "scope"));
    TEST_ASSERT_EQUAL_STRING("openid", value);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_scope_that_merely_contains_openid_still_gets_the_token_added(void) {
    /* Whole-token matching: "openid_extra" is not `openid`, and a substring
     * check would silently drop the one scope that makes this OIDC. */
    axiam_client_t *c = oidc_make_client();
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid_extra", &cfg, &req, &par, &err));

    char value[512];
    TEST_ASSERT_TRUE(par_form_value(value, sizeof(value), "scope"));
    TEST_ASSERT_EQUAL_STRING("openid%20openid_extra", value);

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_public_client_pushes_without_a_secret(void) {
    /* A native app is a public client. It has no secret to send, and an SDK
     * that required one would put PAR — and therefore FAPI 2.0 — out of reach
     * of the clients that most need the request off the browser. */
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, NULL, AXIAM_TEST_TENANT_ID, NULL);
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, push(c, "openid", &cfg, &req, &par, &err));
    TEST_ASSERT_EQUAL_INT(0, oidc_body_has_field("/oauth2/par", "client_secret"));

    axiam_pushed_authorization_request_dispose(&par);
    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

void test_a_slug_only_client_is_refused_client_side(void) {
    /* §12.3 rule 4: the /oauth2 family takes the tenant as a UUID, and a slug
     * is never a substitute. Refused before the wire, because the 400 the
     * server would answer names a field the caller never set. */
    axiam_client_t *c = oidc_make_client_ex(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, NULL, "acme");
    axiam_error_t err;
    axiam_error_reset(&err);
    axiam_oidc_config_t cfg;
    axiam_authorization_request_t req;
    axiam_pushed_authorization_request_t par;

    TEST_ASSERT_EQUAL(AXIAM_OK, axiam_oidc_discover(c, &cfg, &err));
    TEST_ASSERT_EQUAL(AXIAM_OK,
        axiam_oidc_begin(c, &cfg, OIDC_REDIRECT_URI, "openid", &req, &err));
    TEST_ASSERT_EQUAL(AXIAM_ERR_AUTH,
        axiam_oidc_par(c, &cfg, &req, OIDC_REDIRECT_URI, "openid", NULL, &par, &err));
    TEST_ASSERT_EQUAL_INT(0, g_oidc.par_calls);

    axiam_authorization_request_dispose(&req);
    axiam_oidc_config_dispose(&cfg);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_a_successful_push_answers_201_not_200);
    RUN_TEST(test_a_200_is_also_accepted);
    RUN_TEST(test_a_server_without_par_is_refused_client_side_with_no_wire_call);
    RUN_TEST(test_the_push_carries_the_tenant_and_the_form_content_type);
    RUN_TEST(test_the_push_reuses_begins_state_nonce_and_pkce);
    RUN_TEST(test_the_verifier_itself_never_goes_on_the_wire);
    RUN_TEST(test_openid_is_added_to_the_pushed_scope_when_absent);
    RUN_TEST(test_the_redirect_url_carries_exactly_client_id_and_request_uri);
    RUN_TEST(test_a_pre_existing_query_on_the_endpoint_is_dropped);
    RUN_TEST(test_the_request_uri_is_percent_encoded_in_the_redirect);
    RUN_TEST(test_the_push_is_not_retried_on_a_5xx);
    RUN_TEST(test_the_push_is_not_retried_on_a_transport_failure);
    RUN_TEST(test_an_oauth2_error_body_is_surfaced);
    RUN_TEST(test_a_response_without_a_request_uri_is_a_failure);
    RUN_TEST(test_the_request_uri_does_not_render);
    RUN_TEST(test_a_failed_push_never_echoes_the_verifier);
    RUN_TEST(test_null_arguments_are_refused_with_no_wire_call);
    RUN_TEST(test_dispose_is_safe_on_null_and_on_a_zeroed_struct);
    RUN_TEST(test_a_closed_client_refuses_the_push);
    RUN_TEST(test_a_null_scope_still_asks_for_openid);
    RUN_TEST(test_a_scope_that_merely_contains_openid_still_gets_the_token_added);
    RUN_TEST(test_a_public_client_pushes_without_a_secret);
    RUN_TEST(test_a_slug_only_client_is_refused_client_side);
    return UNITY_END();
}
