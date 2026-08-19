/* axiam_login_srp end to end against a fake transport that really speaks
 * SRP-6a (src/client.c, CONTRACT.md §23).
 *
 * tests/test_srp_vectors.c proves the arithmetic reproduces the cross-language
 * vectors. It says nothing about the two HTTP calls around it: which identity
 * is bound into x, what happens when the server names a group other than the
 * one A was opened in, whether a tenant with SRP disabled stays
 * distinguishable from a wrong password, and — the one that matters most —
 * whether a server that cannot prove it holds the verifier is refused rather
 * than quietly accepted.
 *
 * So the fake here is not a canned response: it holds a verifier, picks its
 * own b, and computes B, M1 and M2 from whatever A the client sends. A client
 * that got u, the padding or the exponent wrong fails against it, which a
 * fixture-replaying fake could never detect. */

#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"
#include "test_util.h"

/* PBKDF2 rather than Argon2id: the derivation under test is the transport's,
 * not the KDF's, and OpenSSL grows ARGON2ID only at 3.2 (§23.8). A low
 * iteration count keeps the suite fast. */
#define TEST_KDF_NAME "pbkdf2_sha256"
#define TEST_KDF_ITERATIONS 1000u

/* ------------------------------------------------------------------------
 * The server half of one exchange
 * ---------------------------------------------------------------------- */

typedef struct {
    const srp_group_t *group;
    const char *wire_name;
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *k;
    BIGNUM *v;       /* verifier */
    BIGNUM *b_priv;
    BIGNUM *b_pub;
    char *salt_hex;
    unsigned char salt[32];
    char identity[64];
} srp_server_t;

/* PAD(x) to the group width — §23.3 rule 8, in the fake as well as in the SDK.
 * A fake that skipped it would agree with a client that skipped it. */
static unsigned char *server_pad(const srp_server_t *s, const BIGNUM *value, int *out_len) {
    unsigned char *buf = calloc(1, (size_t)s->group->byte_len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE(BN_bn2binpad(value, buf, s->group->byte_len) > 0);
    *out_len = s->group->byte_len;
    return buf;
}

static void server_sha256(const unsigned char *const *parts, const size_t *lens,
                          size_t count, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestInit_ex(ctx, EVP_sha256(), NULL));
    for (size_t i = 0; i < count; i++)
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestUpdate(ctx, parts[i], lens[i]));
    unsigned int len = 0;
    TEST_ASSERT_EQUAL_INT(1, EVP_DigestFinal_ex(ctx, out, &len));
    TEST_ASSERT_EQUAL_UINT(32u, len);
    EVP_MD_CTX_free(ctx);
}

static void server_dispose(srp_server_t *s) {
    if (!s) return;
    BN_free(s->n);
    BN_free(s->g);
    BN_free(s->k);
    BN_clear_free(s->v);
    BN_clear_free(s->b_priv);
    BN_free(s->b_pub);
    free(s->salt_hex);
    memset(s, 0, sizeof(*s));
}

/* Enrol identity/password in `group` and pick this exchange's b. */
static void server_enrol(srp_server_t *s, const char *group_wire,
                         const char *identity, const char *password) {
    memset(s, 0, sizeof(*s));
    s->group = axiam_srp_group_from_wire(group_wire);
    TEST_ASSERT_NOT_NULL(s->group);
    s->wire_name = group_wire;
    snprintf(s->identity, sizeof(s->identity), "%s", identity);

    TEST_ASSERT_TRUE(BN_hex2bn(&s->n, s->group->modulus_hex) > 0);
    s->g = BN_new();
    TEST_ASSERT_NOT_NULL(s->g);
    TEST_ASSERT_EQUAL_INT(1, BN_set_word(s->g, s->group->generator));

    /* k = H(N | PAD(g)). */
    int nl = 0, gl = 0;
    unsigned char *pn = server_pad(s, s->n, &nl);
    unsigned char *pg = server_pad(s, s->g, &gl);
    const unsigned char *kparts[2] = { pn, pg };
    size_t klens[2] = { (size_t)nl, (size_t)gl };
    unsigned char kdigest[32];
    server_sha256(kparts, klens, 2, kdigest);
    s->k = BN_bin2bn(kdigest, 32, NULL);
    TEST_ASSERT_NOT_NULL(s->k);
    free(pn);
    free(pg);

    /* A salt is 32 fresh bytes per §23.3 rule 11 — here too, so the fixture
     * cannot accidentally depend on one particular salt. */
    TEST_ASSERT_EQUAL_INT(1, RAND_bytes(s->salt, sizeof(s->salt)));
    s->salt_hex = axiam_srp_hex(s->salt, sizeof(s->salt));
    TEST_ASSERT_NOT_NULL(s->salt_hex);

    axiam_srp_kdf_params_t kdf = { TEST_KDF_NAME, TEST_KDF_ITERATIONS, 0, 0 };
    unsigned char x[32];
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x(identity, password, s->salt,
                                                sizeof(s->salt), &kdf, x));

    BN_CTX *ctx = BN_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    BIGNUM *xn = BN_bin2bn(x, 32, NULL);
    OPENSSL_cleanse(x, sizeof(x));
    TEST_ASSERT_NOT_NULL(xn);
    TEST_ASSERT_EQUAL_INT(1, BN_mod(xn, xn, s->n, ctx));
    s->v = BN_new();
    TEST_ASSERT_NOT_NULL(s->v);
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(s->v, s->g, xn, s->n, ctx));
    BN_clear_free(xn);

    /* B = k*v + g^b mod N. */
    s->b_priv = BN_new();
    TEST_ASSERT_NOT_NULL(s->b_priv);
    TEST_ASSERT_EQUAL_INT(1, BN_rand(s->b_priv, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY));
    BIGNUM *gb = BN_new();
    BIGNUM *kv = BN_new();
    s->b_pub = BN_new();
    TEST_ASSERT_NOT_NULL(gb);
    TEST_ASSERT_NOT_NULL(kv);
    TEST_ASSERT_NOT_NULL(s->b_pub);
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(gb, s->g, s->b_priv, s->n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_mul(kv, s->k, s->v, s->n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_add(s->b_pub, kv, gb, s->n, ctx));
    BN_free(gb);
    BN_free(kv);
    BN_CTX_free(ctx);
}

static char *server_b_pub_hex(const srp_server_t *s) {
    int len = 0;
    unsigned char *padded = server_pad(s, s->b_pub, &len);
    char *hex = axiam_srp_hex(padded, (size_t)len);
    free(padded);
    return hex;
}

/* (M1, M2) for the A the client actually sent. Caller frees both. */
static void server_proofs(const srp_server_t *s, const char *a_pub_hex,
                          char **out_m1, char **out_m2) {
    BIGNUM *a_pub = NULL;
    TEST_ASSERT_TRUE(BN_hex2bn(&a_pub, a_pub_hex) > 0);
    BN_CTX *ctx = BN_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);

    int al = 0, bl = 0;
    unsigned char *pa = server_pad(s, a_pub, &al);
    unsigned char *pb = server_pad(s, s->b_pub, &bl);
    const unsigned char *uparts[2] = { pa, pb };
    size_t ulens[2] = { (size_t)al, (size_t)bl };
    unsigned char udigest[32];
    server_sha256(uparts, ulens, 2, udigest);
    BIGNUM *u = BN_bin2bn(udigest, 32, NULL);
    TEST_ASSERT_NOT_NULL(u);

    /* S = (A * v^u)^b mod N — the server's route to the same secret. */
    BIGNUM *vu = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *sval = BN_new();
    TEST_ASSERT_NOT_NULL(vu);
    TEST_ASSERT_NOT_NULL(base);
    TEST_ASSERT_NOT_NULL(sval);
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(vu, s->v, u, s->n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_mul(base, a_pub, vu, s->n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(sval, base, s->b_priv, s->n, ctx));

    int sl = 0;
    unsigned char *ps = server_pad(s, sval, &sl);
    const unsigned char *sparts[1] = { ps };
    size_t slens[1] = { (size_t)sl };
    unsigned char session_key[32];
    server_sha256(sparts, slens, 1, session_key);

    int nl = 0, gl = 0;
    unsigned char *pn = server_pad(s, s->n, &nl);
    unsigned char *pg = server_pad(s, s->g, &gl);
    unsigned char h_n[32], h_g[32], xored[32], h_i[32];
    const unsigned char *one[1];
    size_t onelen[1];
    one[0] = pn;
    onelen[0] = (size_t)nl;
    server_sha256(one, onelen, 1, h_n);
    one[0] = pg;
    onelen[0] = (size_t)gl;
    server_sha256(one, onelen, 1, h_g);
    for (int i = 0; i < 32; i++) xored[i] = (unsigned char)(h_n[i] ^ h_g[i]);
    one[0] = (const unsigned char *)s->identity;
    onelen[0] = strlen(s->identity);
    server_sha256(one, onelen, 1, h_i);

    const unsigned char *m1parts[6] = { xored, h_i, s->salt, pa, pb, session_key };
    size_t m1lens[6] = { 32, 32, sizeof(s->salt), (size_t)al, (size_t)bl, 32 };
    unsigned char m1[32];
    server_sha256(m1parts, m1lens, 6, m1);

    const unsigned char *m2parts[3] = { pa, m1, session_key };
    size_t m2lens[3] = { (size_t)al, 32, 32 };
    unsigned char m2[32];
    server_sha256(m2parts, m2lens, 3, m2);

    *out_m1 = axiam_srp_hex(m1, sizeof(m1));
    *out_m2 = axiam_srp_hex(m2, sizeof(m2));

    OPENSSL_cleanse(session_key, sizeof(session_key));
    free(pa);
    free(pb);
    free(ps);
    free(pn);
    free(pg);
    BN_free(a_pub);
    BN_free(u);
    BN_free(vu);
    BN_free(base);
    BN_clear_free(sval);
    BN_CTX_free(ctx);
}

/* ------------------------------------------------------------------------
 * The fake transport
 * ---------------------------------------------------------------------- */

/* What the fake should do once the client's proof arrives. */
typedef enum {
    VERIFY_SUCCESS,      /* 200 with a correct M2 */
    VERIFY_MFA,          /* 202 with a correct M2 */
    VERIFY_WRONG_PROOF,  /* 200 with an M2 that does not verify */
    VERIFY_NO_PROOF,     /* 200 with no M2 at all */
    VERIFY_REJECT,       /* 401 — what a wrong password produces */
    VERIFY_TRANSPORT_ERR /* the verify round trip never completes */
} verify_outcome_t;

typedef struct {
    test_recorder_t rec;
    srp_server_t *server;

    /* Challenge behaviour. */
    long challenge_status;      /* 0 => 200 with the server's own parameters */
    const char *challenge_body; /* non-NULL => sent verbatim instead */
    const char *first_group;    /* non-NULL => named on the FIRST challenge only */
    long second_challenge_status; /* non-zero => status for the SECOND challenge */
    int challenge_transport_err;

    verify_outcome_t outcome;
    int challenge_count;
    int verify_count;
    char last_a_pub[1200];
    char last_client_proof[80];
    char *expected_m1;
} fake_state_t;

static fake_state_t g_fake;

/* Pull a JSON string member out of a request body without a parser: the
 * bodies here are the SDK's own, and a parser in the fake would only be
 * another thing to get wrong. */
static void extract_member(const char *body, const char *name, char *out, size_t n) {
    out[0] = '\0';
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", name);
    const char *p = body ? strstr(body, needle) : NULL;
    if (!p) return;
    p += strlen(needle);
    const char *end = strchr(p, '"');
    if (!end) return;
    size_t len = (size_t)(end - p);
    if (len >= n) len = n - 1;
    memcpy(out, p, len);
    out[len] = '\0';
}

static char *challenge_json(const srp_server_t *s, const char *group_override) {
    char *b_pub = server_b_pub_hex(s);
    size_t cap = strlen(b_pub) + strlen(s->salt_hex) + 512;
    char *out = malloc(cap);
    TEST_ASSERT_NOT_NULL(out);
    snprintf(out, cap,
             "{\"srp_session\":\"srp-session-1\",\"identity\":\"%s\",\"salt\":\"%s\","
             "\"group\":\"%s\",\"kdf\":\"%s\",\"iterations\":%u,\"b_pub\":\"%s\"}",
             s->identity, s->salt_hex,
             group_override ? group_override : s->wire_name,
             TEST_KDF_NAME, TEST_KDF_ITERATIONS, b_pub);
    free(b_pub);
    return out;
}

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    fake_state_t *st = ctx;
    recorder_capture(&st->rec, req);
    const char *url = req->url ? req->url : "";

    if (strstr(url, "/auth/srp/challenge")) {
        st->challenge_count++;
        extract_member(req->body, "client_public", st->last_a_pub, sizeof(st->last_a_pub));
        if (st->challenge_transport_err) {
            memset(resp, 0, sizeof(*resp));
            resp->status = 0;
            resp->transport_err = 7;
            resp->transport_msg = strdup("Couldn't connect");
            return 1;
        }
        if (st->challenge_body) {
            resp_fill(resp, st->challenge_status ? st->challenge_status : 200,
                      st->challenge_body, NULL);
            return 0;
        }
        if (st->challenge_status && st->challenge_status != 200) {
            resp_fill(resp, st->challenge_status, "{}", NULL);
            return 0;
        }
        if (st->second_challenge_status && st->challenge_count == 2) {
            resp_fill(resp, st->second_challenge_status, "{}", NULL);
            return 0;
        }
        const char *override = (st->challenge_count == 1) ? st->first_group : NULL;
        char *body = challenge_json(st->server, override);
        resp_fill(resp, 200, body, NULL);
        free(body);
        return 0;
    }

    if (strstr(url, "/auth/srp/verify")) {
        st->verify_count++;
        extract_member(req->body, "client_proof", st->last_client_proof,
                       sizeof(st->last_client_proof));
        if (st->outcome == VERIFY_TRANSPORT_ERR) {
            memset(resp, 0, sizeof(*resp));
            resp->status = 0;
            resp->transport_err = 7;
            resp->transport_msg = strdup("Couldn't connect");
            return 1;
        }
        if (st->outcome == VERIFY_REJECT) {
            resp_fill(resp, 401,
                      "{\"error\":\"invalid_credentials\","
                      "\"message\":\"invalid username or password\"}",
                      NULL);
            return 0;
        }

        char *m1 = NULL, *m2 = NULL;
        server_proofs(st->server, st->last_a_pub, &m1, &m2);
        free(st->expected_m1);
        st->expected_m1 = m1;

        char body[1024];
        switch (st->outcome) {
            case VERIFY_SUCCESS:
                snprintf(body, sizeof(body),
                         "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
                         "\"expires_in\":900,\"server_proof\":\"%s\","
                         "\"user\":{\"id\":\"u-1\",\"username\":\"alice\","
                         "\"email\":\"a@x.io\",\"tenant_id\":\"" AXIAM_TEST_TENANT_ID "\"}}",
                         m2);
                resp_fill(resp, 200, body, "csrf-abc");
                break;
            case VERIFY_MFA:
                snprintf(body, sizeof(body),
                         "{\"mfa_required\":true,\"challenge_token\":\"srp-mfa-challenge\","
                         "\"server_proof\":\"%s\"}",
                         m2);
                resp_fill(resp, 202, body, NULL);
                break;
            case VERIFY_WRONG_PROOF:
                /* Flip one hex digit: well-formed, right length, still wrong. */
                m2[0] = (char)(m2[0] == '0' ? '1' : '0');
                snprintf(body, sizeof(body),
                         "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
                         "\"expires_in\":900,\"server_proof\":\"%s\"}",
                         m2);
                resp_fill(resp, 200, body, NULL);
                break;
            case VERIFY_NO_PROOF:
            default:
                resp_fill(resp, 200,
                          "{\"session_id\":\"33333333-3333-3333-3333-333333333333\","
                          "\"expires_in\":900}",
                          NULL);
                break;
        }
        free(m2);
        return 0;
    }

    resp_fill(resp, 404, "{}", NULL);
    return 0;
}

static axiam_client_t *make_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    axiam_client_config_set_transport(cfg, fake_transport, &g_fake);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    return c;
}

void setUp(void) { memset(&g_fake, 0, sizeof(g_fake)); }

void tearDown(void) {
    free(g_fake.expected_m1);
    g_fake.expected_m1 = NULL;
}

/* ------------------------------------------------------------------------
 * The exchange
 * ---------------------------------------------------------------------- */

static void test_full_exchange_authenticates_both_sides(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "correct horse battery staple");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_SUCCESS;

    axiam_client_t *c = make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_login_result_t res;
    axiam_error_t err;
    /* Signed in by EMAIL while the verifier is bound to the USERNAME: §23.3
     * rule 2 says x uses the identity the server named, and this only passes
     * if the SDK honours it. */
    axiam_error_kind_t k =
        axiam_login_srp(c, "alice@example.com", "correct horse battery staple", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.authenticated);
    TEST_ASSERT_EQUAL_INT(900, (int)res.expires_in);
    /* The opening guess was right, so there was exactly one challenge. */
    TEST_ASSERT_EQUAL_INT(1, g_fake.challenge_count);
    TEST_ASSERT_EQUAL_INT(1, g_fake.verify_count);
    /* The fake authenticated the client for real: a client that computed u,
     * the padding or the exponent differently never reaches here. */
    TEST_ASSERT_EQUAL_STRING(g_fake.expected_m1, g_fake.last_client_proof);
    /* §23.3 rule 12: the password never went on the wire. */
    TEST_ASSERT_NULL(strstr(g_fake.rec.body, "correct horse"));
    TEST_ASSERT_NULL(strstr(g_fake.rec.body, "password"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_narrower_group_restarts_the_exchange(void) {
    /* A tenant on a group other than the opening guess must work rather than
     * fail — and the restart has to pick a NEW a, which is why the second
     * challenge carries a different A. */
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_2048, "alice", "a-good-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_SUCCESS;

    axiam_client_t *c = make_client();
    TEST_ASSERT_NOT_NULL(c);
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "a-good-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.authenticated);
    TEST_ASSERT_EQUAL_INT(2, g_fake.challenge_count);
    TEST_ASSERT_EQUAL_STRING(g_fake.expected_m1, g_fake.last_client_proof);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_failed_restart_does_not_fall_back_to_the_wrong_group(void) {
    /* The restart is the one place the exchange runs the challenge twice, and
     * a failure there must surface rather than send a proof computed in the
     * group the server did NOT name. */
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_2048, "alice", "a-good-password");
    g_fake.server = &server;
    g_fake.second_challenge_status = 503;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "a-good-password", &res, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_INT(2, g_fake.challenge_count);
    TEST_ASSERT_EQUAL_INT(0, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_mfa_required_reaches_the_caller(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "another-good-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_MFA;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "another-good-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_FALSE(res.authenticated);
    TEST_ASSERT_TRUE(res.mfa_required);
    TEST_ASSERT_NOT_NULL(res.challenge_token);
    TEST_ASSERT_EQUAL_STRING("srp-mfa-challenge", axiam_sensitive_reveal(res.challenge_token));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_server_whose_proof_does_not_verify_gets_no_session(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "a-perfectly-good-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_WRONG_PROOF;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k =
        axiam_login_srp(c, "alice", "a-perfectly-good-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "failed to prove"));
    /* Nothing may be handed back: an endpoint that cannot prove it holds the
     * verifier is not the server it claims to be. */
    TEST_ASSERT_FALSE(res.authenticated);
    TEST_ASSERT_FALSE(res.mfa_required);
    TEST_ASSERT_NULL(res.challenge_token);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_server_that_returns_no_proof_is_refused(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "yet-another-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_NO_PROOF;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "yet-another-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);
    TEST_ASSERT_FALSE(res.authenticated);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_rejected_proof_is_an_auth_failure(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "the-real-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_REJECT;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "not-the-real-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_AUTH, k);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

/* ------------------------------------------------------------------------
 * Refusals that must not look like a bad password
 * ---------------------------------------------------------------------- */

static void test_srp_disabled_is_a_configuration_fault(void) {
    /* The distinction is the whole point: a caller that saw AXIAM_ERR_AUTH
     * here would send a user off to reset a password that works perfectly. */
    g_fake.challenge_status = 404;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "srp_mode"));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "axiam_login()"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_5xx_on_the_challenge_is_reported_as_itself(void) {
    g_fake.challenge_status = 503;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "SRP challenge failed"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_transport_failure_on_the_challenge_is_a_network_error(void) {
    g_fake.challenge_transport_err = 1;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_EQUAL_INT(0, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_transport_failure_on_the_verify_is_a_network_error(void) {
    srp_server_t server;
    server_enrol(&server, AXIAM_SRP_GROUP_4096, "alice", "a-password");
    g_fake.server = &server;
    g_fake.outcome = VERIFY_TRANSPORT_ERR;

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "a-password", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_EQUAL_INT(1, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
    server_dispose(&server);
}

static void test_a_challenge_that_is_not_json_is_refused(void) {
    g_fake.challenge_body = "not json at all";

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "not JSON"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_an_unimplemented_group_is_refused_rather_than_guessed(void) {
    g_fake.challenge_body =
        "{\"srp_session\":\"s1\",\"identity\":\"alice\",\"salt\":\"00112233\","
        "\"group\":\"rfc5054_1024\",\"kdf\":\"" TEST_KDF_NAME "\",\"iterations\":1000,"
        "\"b_pub\":\"01\"}";

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "does not implement"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_an_unimplemented_kdf_names_itself(void) {
    g_fake.challenge_body =
        "{\"srp_session\":\"s1\",\"identity\":\"alice\",\"salt\":\"00112233\","
        "\"group\":\"" AXIAM_SRP_GROUP_4096 "\",\"kdf\":\"scrypt\",\"iterations\":1,"
        "\"b_pub\":\"01\"}";

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "scrypt"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_a_malformed_salt_is_rejected_before_the_kdf_runs(void) {
    g_fake.challenge_body =
        "{\"srp_session\":\"s1\",\"identity\":\"alice\",\"salt\":\"not-hex\","
        "\"group\":\"" AXIAM_SRP_GROUP_4096 "\",\"kdf\":\"" TEST_KDF_NAME "\","
        "\"iterations\":1000,\"b_pub\":\"01\"}";

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "salt"));

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_b_congruent_to_zero_is_refused_without_a_second_round_trip(void) {
    /* §23.3 rule 5, and the classic SRP break: B ≡ 0 (mod N) makes S
     * predictable. No proof may be sent for one. */
    g_fake.challenge_body =
        "{\"srp_session\":\"s1\",\"identity\":\"alice\",\"salt\":\"00112233\","
        "\"group\":\"" AXIAM_SRP_GROUP_4096 "\",\"kdf\":\"" TEST_KDF_NAME "\","
        "\"iterations\":1000,\"b_pub\":\"00\"}";

    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NOT_NULL(strstr(err.message, "unusable public value"));
    TEST_ASSERT_EQUAL_INT(0, g_fake.verify_count);

    axiam_login_result_dispose(&res);
    axiam_client_free(c);
}

static void test_null_arguments_are_refused(void) {
    axiam_client_t *c = make_client();
    axiam_login_result_t res;
    axiam_error_t err;

    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_srp(NULL, "a", "b", &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_srp(c, NULL, "b", &res, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login_srp(c, "a", NULL, &res, &err));
    TEST_ASSERT_EQUAL_INT(0, g_fake.challenge_count);

    axiam_client_free(c);
}

static void test_a_closed_client_refuses_to_reconnect(void) {
    /* §18.1 rule 4: use-after-close is an error, not a quiet reconnect. */
    axiam_client_t *c = make_client();
    axiam_client_close(c);

    axiam_login_result_t res;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_login_srp(c, "alice", "irrelevant", &res, &err);

    TEST_ASSERT_NOT_EQUAL(AXIAM_OK, k);
    TEST_ASSERT_EQUAL_INT(0, g_fake.challenge_count);

    axiam_client_free(c);
}

/* ------------------------------------------------------------------------
 * The request bodies (§23.5)
 * ---------------------------------------------------------------------- */

static void test_the_challenge_body_carries_no_password(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_org_id(cfg, "22222222-2222-2222-2222-222222222222");
    char *body = axiam_build_srp_challenge_body("alice", "0a0b", cfg);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"username_or_email\":\"alice\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"client_public\":\"0a0b\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"tenant_id\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"org_id\""));
    /* The point of the whole exchange. */
    TEST_ASSERT_NULL(strstr(body, "password"));
    free(body);
    axiam_client_config_free(cfg);
}

static void test_the_challenge_body_falls_back_to_slugs(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_org_slug(cfg, "acme-org");
    char *body = axiam_build_srp_challenge_body("alice", "0a0b", cfg);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"tenant_slug\":\"acme\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"org_slug\":\"acme-org\""));
    TEST_ASSERT_NULL(strstr(body, "\"tenant_id\""));
    free(body);
    axiam_client_config_free(cfg);
}

static void test_the_bodies_tolerate_missing_arguments(void) {
    /* Never called this way by the SDK; asserted so a NULL becomes an empty
     * member rather than a crash in a caller that drives these directly. */
    char *body = axiam_build_srp_challenge_body(NULL, NULL, NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"username_or_email\":\"\""));
    TEST_ASSERT_NULL(strstr(body, "tenant"));
    free(body);

    body = axiam_build_srp_verify_body(NULL, NULL);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"srp_session\":\"\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"client_proof\":\"\""));
    free(body);
}

static void test_the_verify_body_carries_the_session_and_the_proof(void) {
    char *body = axiam_build_srp_verify_body("srp-session-1", "aabb");
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "\"srp_session\":\"srp-session-1\""));
    TEST_ASSERT_NOT_NULL(strstr(body, "\"client_proof\":\"aabb\""));
    free(body);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_full_exchange_authenticates_both_sides);
    RUN_TEST(test_a_narrower_group_restarts_the_exchange);
    RUN_TEST(test_a_failed_restart_does_not_fall_back_to_the_wrong_group);
    RUN_TEST(test_mfa_required_reaches_the_caller);
    RUN_TEST(test_a_server_whose_proof_does_not_verify_gets_no_session);
    RUN_TEST(test_a_server_that_returns_no_proof_is_refused);
    RUN_TEST(test_a_rejected_proof_is_an_auth_failure);
    RUN_TEST(test_srp_disabled_is_a_configuration_fault);
    RUN_TEST(test_a_5xx_on_the_challenge_is_reported_as_itself);
    RUN_TEST(test_a_transport_failure_on_the_challenge_is_a_network_error);
    RUN_TEST(test_a_transport_failure_on_the_verify_is_a_network_error);
    RUN_TEST(test_a_challenge_that_is_not_json_is_refused);
    RUN_TEST(test_an_unimplemented_group_is_refused_rather_than_guessed);
    RUN_TEST(test_an_unimplemented_kdf_names_itself);
    RUN_TEST(test_a_malformed_salt_is_rejected_before_the_kdf_runs);
    RUN_TEST(test_b_congruent_to_zero_is_refused_without_a_second_round_trip);
    RUN_TEST(test_null_arguments_are_refused);
    RUN_TEST(test_a_closed_client_refuses_to_reconnect);
    RUN_TEST(test_the_challenge_body_carries_no_password);
    RUN_TEST(test_the_challenge_body_falls_back_to_slugs);
    RUN_TEST(test_the_bodies_tolerate_missing_arguments);
    RUN_TEST(test_the_verify_body_carries_the_session_and_the_proof);
    return UNITY_END();
}
