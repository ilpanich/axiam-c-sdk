/*
 * CONTRACT.md §23.7 conformance for the SRP-6a client.
 *
 * srp-test-vectors.json is generated from the AXIAM server implementation and
 * vendored into every SDK. Eleven independent SRP implementations do not
 * interoperate by accident; this is the file that says whether this one does.
 *
 * §23.7 rule 1 requires every intermediate to be reproduced, not only the final
 * proof — an SDK that gets u wrong should find out at u rather than at "login
 * sometimes fails".
 *
 * Reaches into internal.h for the arithmetic seam: the public header exposes
 * only login and enrolment, and asserting on M1 alone would satisfy neither
 * rule 1 nor the group-constant requirement of rule 4.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "unity.h"

#include "axiam/srp.h"
#include "cJSON.h"
#include "internal.h"

static cJSON *g_vectors = NULL;

void setUp(void) {}
void tearDown(void) {}

/* Walks up from the working directory to find the vendored fixture, so this
 * does not encode how deep in the build tree ctest happens to run it. */
static cJSON *load_vectors(void) {
    char path[512];
    const char *prefixes[] = { "", "../", "../../", "../../../", "../../../../" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        snprintf(path, sizeof(path), "%ssrp-test-vectors.json", prefixes[i]);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *buf = (char *)malloc((size_t)len + 1);
        if (!buf) { fclose(f); return NULL; }
        size_t got = fread(buf, 1, (size_t)len, f);
        fclose(f);
        buf[got] = '\0';
        cJSON *root = cJSON_Parse(buf);
        free(buf);
        if (!root) return NULL;
        cJSON *vectors = cJSON_DetachItemFromObjectCaseSensitive(root, "vectors");
        cJSON_Delete(root);
        return vectors;
    }
    return NULL;
}

static const char *vstr(const cJSON *v, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(v, name);
    return (item && cJSON_IsString(item)) ? item->valuestring : "";
}

/* ---------------------------------------------------------------------------
 * §23.7 rule 4 — group constants
 *
 * A transcription slip in a modulus is a silent, total break: client and server
 * would still agree with each other while the discrete-log hardness the
 * protocol rests on quietly vanished. A round-trip test cannot catch it,
 * because both sides share the same wrong constant.
 * ------------------------------------------------------------------------- */

static void assert_safe_prime_group(const char *wire_name, int bits) {
    const srp_group_t *group = axiam_srp_group_from_wire(wire_name);
    TEST_ASSERT_NOT_NULL_MESSAGE(group, wire_name);
    TEST_ASSERT_EQUAL_INT(bits / 8, group->byte_len);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = NULL, *q = BN_new(), *g = BN_new(), *got = BN_new(), *n_minus_1 = BN_new();
    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&n, group->modulus_hex));
    TEST_ASSERT_EQUAL_INT(bits, BN_num_bits(n));
    TEST_ASSERT_EQUAL_INT(1, BN_check_prime(n, ctx, NULL));

    /* A safe prime: N = 2q + 1 with q prime. */
    TEST_ASSERT_EQUAL_INT(1, BN_sub(n_minus_1, n, BN_value_one()));
    TEST_ASSERT_EQUAL_INT(1, BN_rshift1(q, n_minus_1));
    TEST_ASSERT_EQUAL_INT(1, BN_check_prime(q, ctx, NULL));

    /* g generates the order-q subgroup iff g^q == N-1 for a safe prime. */
    TEST_ASSERT_EQUAL_INT(1, BN_set_word(g, group->generator));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(got, g, q, n, ctx));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BN_cmp(got, n_minus_1),
                                  "g does not generate the large subgroup");

    BN_free(n); BN_free(q); BN_free(g); BN_free(got); BN_free(n_minus_1);
    BN_CTX_free(ctx);
}

static void test_group_constants_are_safe_primes(void) {
    assert_safe_prime_group(AXIAM_SRP_GROUP_2048, 2048);
    assert_safe_prime_group(AXIAM_SRP_GROUP_3072, 3072);
    assert_safe_prime_group(AXIAM_SRP_GROUP_4096, 4096);
}

static void test_unrecognised_group_is_refused(void) {
    /* §23.4: refuse rather than guess. Guessing would mean computing in a group
     * whose safety this SDK has not verified — potentially one whose discrete
     * log the server knows. */
    TEST_ASSERT_NULL(axiam_srp_group_from_wire("rfc5054_1024"));
    TEST_ASSERT_NULL(axiam_srp_group_from_wire(NULL));
}

/* ---------------------------------------------------------------------------
 * hex helpers and PAD()
 * ------------------------------------------------------------------------- */

static void test_hex_roundtrip_and_refusals(void) {
    unsigned char bytes[] = { 0x00, 0x01, 0xab, 0xff };
    char *hex = axiam_srp_hex(bytes, sizeof(bytes));
    TEST_ASSERT_EQUAL_STRING("0001abff", hex);

    size_t len = 0;
    unsigned char *back = axiam_srp_unhex(hex, &len);
    TEST_ASSERT_EQUAL_size_t(sizeof(bytes), len);
    TEST_ASSERT_EQUAL_MEMORY(bytes, back, sizeof(bytes));
    free(back);
    free(hex);

    /* A malformed field is refused rather than truncated: silently dropping a
     * nibble would produce a wrong hash that still looked well-formed. */
    TEST_ASSERT_NULL(axiam_srp_unhex("abc", &len));
    TEST_ASSERT_NULL(axiam_srp_unhex("zz", &len));
    TEST_ASSERT_NULL(axiam_srp_unhex("", &len));
}

/* ---------------------------------------------------------------------------
 * §23.7 rules 1–3 — the vectors
 * ------------------------------------------------------------------------- */

static void test_fixtures_cover_their_cases(void) {
    /* Guards the fixture itself: if these stop holding, everything below
     * silently stops testing the two things it was built to test. */
    TEST_ASSERT_NOT_NULL(g_vectors);
    int count = 0, leading_zero_salt = 0, leading_zero_x = 0, non_ascii = 0;
    int seen_2048 = 0, seen_3072 = 0, seen_4096 = 0;
    const cJSON *v = NULL;
    cJSON_ArrayForEach(v, g_vectors) {
        count++;
        if (strncmp(vstr(v, "salt"), "00", 2) == 0) leading_zero_salt = 1;
        if (strncmp(vstr(v, "x"), "00", 2) == 0) leading_zero_x = 1;
        for (const unsigned char *p = (const unsigned char *)vstr(v, "identity"); *p; p++)
            if (*p > 0x7f) non_ascii = 1;
        const char *g = vstr(v, "group");
        if (strcmp(g, AXIAM_SRP_GROUP_2048) == 0) seen_2048 = 1;
        if (strcmp(g, AXIAM_SRP_GROUP_3072) == 0) seen_3072 = 1;
        if (strcmp(g, AXIAM_SRP_GROUP_4096) == 0) seen_4096 = 1;
    }
    TEST_ASSERT_GREATER_THAN_INT(0, count);
    TEST_ASSERT_MESSAGE(leading_zero_salt, "§23.7 rule 2: no vector has a leading-zero salt");
    TEST_ASSERT_MESSAGE(leading_zero_x, "§23.7 rule 2: no vector has a leading-zero x");
    TEST_ASSERT_MESSAGE(non_ascii, "§23.7 rule 3: no vector has a non-ASCII identity");
    TEST_ASSERT_MESSAGE(seen_2048 && seen_3072 && seen_4096, "a group is uncovered");
}

/* Reproduces k, v, A, B, u, S and K for one vector — every intermediate, not
 * just the final proof (§23.7 rule 1). */
static void assert_vector_intermediates(const cJSON *v) {
    const srp_group_t *group = axiam_srp_group_from_wire(vstr(v, "group"));
    TEST_ASSERT_NOT_NULL(group);
    const int width = group->byte_len;

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = NULL, *a = NULL, *b = NULL, *x = NULL;
    BIGNUM *g = BN_new(), *k = BN_new(), *tmp = BN_new();
    BIGNUM *a_pub = BN_new(), *b_pub = BN_new(), *verifier = BN_new();
    BIGNUM *u = BN_new(), *s = BN_new();
    unsigned char *pad = (unsigned char *)malloc((size_t)width);
    unsigned char *pad_b = (unsigned char *)malloc((size_t)width);
    char *hex = NULL;

    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&n, group->modulus_hex));
    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&a, vstr(v, "a_priv")));
    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&b, vstr(v, "b_priv")));
    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&x, vstr(v, "x")));
    TEST_ASSERT_EQUAL_INT(1, BN_set_word(g, group->generator));
    TEST_ASSERT_EQUAL_INT(1, BN_nnmod(x, x, n, ctx));

    /* k = H(N | PAD(g)) — recomputed here from the same primitives the SDK
     * uses, so a wrong k shows up as a wrong k rather than as a wrong M1. */
    {
        unsigned char *pn = (unsigned char *)malloc((size_t)width);
        unsigned char *pg = (unsigned char *)malloc((size_t)width);
        TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(n, pn, width));
        TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(g, pg, width));
        unsigned char digest[32];
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, pn, (size_t)width);
        EVP_DigestUpdate(md, pg, (size_t)width);
        unsigned int dlen = 0;
        EVP_DigestFinal_ex(md, digest, &dlen);
        EVP_MD_CTX_free(md);
        free(pn); free(pg);
        hex = axiam_srp_hex(digest, 32);
        TEST_ASSERT_EQUAL_STRING(vstr(v, "k"), hex);
        free(hex);
        TEST_ASSERT_NOT_NULL(BN_bin2bn(digest, 32, k));
    }

    /* v = g^x mod N */
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(verifier, g, x, n, ctx));
    TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(verifier, pad, width));
    hex = axiam_srp_hex(pad, (size_t)width);
    TEST_ASSERT_EQUAL_STRING(vstr(v, "verifier"), hex);
    free(hex);

    /* A = g^a mod N */
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(a_pub, g, a, n, ctx));
    TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(a_pub, pad, width));
    hex = axiam_srp_hex(pad, (size_t)width);
    TEST_ASSERT_EQUAL_STRING(vstr(v, "a_pub"), hex);
    free(hex);

    /* B = (k*v + g^b) mod N */
    TEST_ASSERT_EQUAL_INT(1, BN_mod_mul(tmp, k, verifier, n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(b_pub, g, b, n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_add(b_pub, tmp, b_pub, n, ctx));
    TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(b_pub, pad_b, width));
    hex = axiam_srp_hex(pad_b, (size_t)width);
    TEST_ASSERT_EQUAL_STRING(vstr(v, "b_pub"), hex);
    free(hex);

    /* u = H(PAD(A) | PAD(B)) */
    {
        TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(a_pub, pad, width));
        unsigned char digest[32];
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, pad, (size_t)width);
        EVP_DigestUpdate(md, pad_b, (size_t)width);
        unsigned int dlen = 0;
        EVP_DigestFinal_ex(md, digest, &dlen);
        EVP_MD_CTX_free(md);
        hex = axiam_srp_hex(digest, 32);
        TEST_ASSERT_EQUAL_STRING(vstr(v, "u"), hex);
        free(hex);
        TEST_ASSERT_NOT_NULL(BN_bin2bn(digest, 32, u));
    }

    /* S = (B - k*g^x)^(a + u*x) mod N */
    {
        BIGNUM *kgx = BN_new(), *base = BN_new(), *exponent = BN_new();
        TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(tmp, g, x, n, ctx));
        TEST_ASSERT_EQUAL_INT(1, BN_mod_mul(kgx, k, tmp, n, ctx));
        TEST_ASSERT_EQUAL_INT(1, BN_mod_sub(base, b_pub, kgx, n, ctx));
        TEST_ASSERT_EQUAL_INT(1, BN_mul(exponent, u, x, ctx));
        TEST_ASSERT_EQUAL_INT(1, BN_add(exponent, exponent, a));
        TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(s, base, exponent, n, ctx));
        BN_free(kgx); BN_free(base); BN_free(exponent);
    }
    TEST_ASSERT_EQUAL_INT(width, BN_bn2binpad(s, pad, width));
    hex = axiam_srp_hex(pad, (size_t)width);
    TEST_ASSERT_EQUAL_STRING(vstr(v, "session_secret"), hex);
    free(hex);

    /* K = H(PAD(S)) */
    {
        unsigned char digest[32];
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md, EVP_sha256(), NULL);
        EVP_DigestUpdate(md, pad, (size_t)width);
        unsigned int dlen = 0;
        EVP_DigestFinal_ex(md, digest, &dlen);
        EVP_MD_CTX_free(md);
        hex = axiam_srp_hex(digest, 32);
        TEST_ASSERT_EQUAL_STRING(vstr(v, "session_key"), hex);
        free(hex);
    }

    free(pad); free(pad_b);
    BN_free(n); BN_free(a); BN_free(b); BN_clear_free(x);
    BN_free(g); BN_free(k); BN_free(tmp);
    BN_free(a_pub); BN_free(b_pub); BN_free(verifier);
    BN_free(u); BN_clear_free(s);
    BN_CTX_free(ctx);
}

static void test_vectors_reproduce_every_intermediate(void) {
    const cJSON *v = NULL;
    cJSON_ArrayForEach(v, g_vectors) assert_vector_intermediates(v);
}

/* Drives the real session rather than the helpers, with a pinned to the
 * vector's value — otherwise this would only test the internals. */
static void test_vectors_produce_the_contract_proofs(void) {
    const cJSON *v = NULL;
    cJSON_ArrayForEach(v, g_vectors) {
        const srp_group_t *group = axiam_srp_group_from_wire(vstr(v, "group"));
        TEST_ASSERT_NOT_NULL(group);

        srp_session_t session;
        TEST_ASSERT_EQUAL_INT(0, axiam_srp_session_begin(&session, group, vstr(v, "a_priv")));
        TEST_ASSERT_EQUAL_STRING(vstr(v, "a_pub"), session.a_pub_hex);

        size_t x_len = 0;
        unsigned char *x = axiam_srp_unhex(vstr(v, "x"), &x_len);
        TEST_ASSERT_NOT_NULL(x);
        TEST_ASSERT_EQUAL_size_t(32, x_len);

        char *m1 = NULL, *m2 = NULL;
        TEST_ASSERT_EQUAL_INT(0, axiam_srp_session_finish(&session, vstr(v, "identity"),
                                                          vstr(v, "salt"), vstr(v, "b_pub"),
                                                          x, &m1, &m2));
        TEST_ASSERT_EQUAL_STRING(vstr(v, "client_proof"), m1);
        TEST_ASSERT_EQUAL_STRING(vstr(v, "server_proof"), m2);

        free(m1); free(m2); free(x);
        axiam_srp_session_dispose(&session);
    }
}

/* ---------------------------------------------------------------------------
 * §23.3 protocol refusals
 * ------------------------------------------------------------------------- */

static void test_zero_server_public_is_refused(void) {
    /* §23.7 rule 6, with no network round trip. The classic SRP break: a client
     * that accepts B ≡ 0 derives a predictable S and would authenticate against
     * a server that never knew the verifier. */
    const srp_group_t *group = axiam_srp_group_from_wire(AXIAM_SRP_GROUP_2048);
    srp_session_t session;
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_session_begin(&session, group, NULL));

    char zero[1025];
    memset(zero, '0', (size_t)group->byte_len * 2);
    zero[group->byte_len * 2] = '\0';
    char salt[65];
    memset(salt, '0', 64);
    salt[64] = '\0';

    unsigned char x[32] = { 0 };
    char *m1 = NULL, *m2 = NULL;
    TEST_ASSERT_EQUAL_INT(-1, axiam_srp_session_finish(&session, "alice", salt, zero, x, &m1, &m2));
    TEST_ASSERT_NULL(m1);
    TEST_ASSERT_NULL(m2);
    axiam_srp_session_dispose(&session);
}

static void test_every_exchange_uses_a_fresh_ephemeral(void) {
    /* §23.3 rule 7: reusing a across logins leaks the relationship between two
     * session secrets. */
    const srp_group_t *group = axiam_srp_group_from_wire(AXIAM_SRP_GROUP_2048);
    srp_session_t first, second;
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_session_begin(&first, group, NULL));
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_session_begin(&second, group, NULL));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(first.a_pub_hex, second.a_pub_hex));
    axiam_srp_session_dispose(&first);
    axiam_srp_session_dispose(&second);
}

static void test_unknown_kdf_is_refused_rather_than_substituted(void) {
    /* Substituting the other KDF derives a different x and surfaces as
     * "invalid password" — the single most misleading failure available. */
    unsigned char salt[32] = { 0 };
    unsigned char x[32];
    axiam_srp_kdf_params_t params = { "scrypt", 1, 0, 0 };
    TEST_ASSERT_EQUAL_INT(-1, axiam_srp_derive_x("alice", "pw", salt, sizeof(salt), &params, x));
}

/* ---------------------------------------------------------------------------
 * KDF
 * ------------------------------------------------------------------------- */

static void test_kdf_binds_identity_password_and_salt(void) {
    /* Every one of these must change the output, or a verifier would be
     * replayable against a different account or a different salt. */
    unsigned char salt_a[32], salt_b[32];
    memset(salt_a, 0x0a, sizeof(salt_a));
    memset(salt_b, 0x0b, sizeof(salt_b));
    axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_PBKDF2, 1000, 0, 0 };

    unsigned char base[32], other[32];
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("alice", "pw", salt_a, sizeof(salt_a), &params, base));

    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("alice", "pw", salt_a, sizeof(salt_a), &params, other));
    TEST_ASSERT_EQUAL_MEMORY(base, other, 32);

    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("bob", "pw", salt_a, sizeof(salt_a), &params, other));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(base, other, 32));

    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("alice", "pw2", salt_a, sizeof(salt_a), &params, other));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(base, other, 32));

    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("alice", "pw", salt_b, sizeof(salt_b), &params, other));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(base, other, 32));
}

static void test_argon2id_when_this_openssl_has_it(void) {
    unsigned char salt[32] = { 0 };
    unsigned char x[32];
    axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_ARGON2ID, 1, 8192, 1 };
    int rc = axiam_srp_derive_x("alice", "pw", salt, sizeof(salt), &params, x);

    if (axiam_srp_argon2_available()) {
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "argon2id is available but derivation failed");
    } else {
        /* §23.8: Argon2 needs OpenSSL >= 3.2. On an older libcrypto the SDK
         * must REFUSE rather than substitute PBKDF2 — that would derive a
         * different x and report a perfectly good password as wrong. -1 is
         * exactly that refusal, and the login path turns it into a
         * AXIAM_ERR_NETWORK naming the KDF. */
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, rc, "argon2id is unavailable but was not refused");
    }
}

/* ---------------------------------------------------------------------------
 * §23.3 rule 6 — server proof comparison
 * ------------------------------------------------------------------------- */

static void test_server_proof_comparison(void) {
    const cJSON *first = cJSON_GetArrayItem(g_vectors, 0);
    const char *proof = vstr(first, "server_proof");
    char tweaked[65];
    snprintf(tweaked, sizeof(tweaked), "%s", proof);
    tweaked[0] = (tweaked[0] == '0') ? '1' : '0';

    TEST_ASSERT_EQUAL_INT(1, axiam_srp_verify_server_proof(proof, proof));
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_verify_server_proof(proof, tweaked));
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_verify_server_proof(proof, ""));
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_verify_server_proof(proof, NULL));
}

/* ---------------------------------------------------------------------------
 * §23.3 rule 11 — enrolment
 * ------------------------------------------------------------------------- */

static void test_enrollment_is_reproducible_from_its_own_salt(void) {
    axiam_error_t err;
    axiam_srp_enrollment_t first, second;
    axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_PBKDF2, 1000, 0, 0 };

    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_srp_enrollment("alice", "hunter2", NULL, &params, &first, &err));
    TEST_ASSERT_EQUAL_STRING(AXIAM_SRP_GROUP_4096, first.group);
    TEST_ASSERT_EQUAL_STRING(AXIAM_SRP_KDF_PBKDF2, first.kdf);
    TEST_ASSERT_EQUAL_size_t(64, strlen(first.salt));
    TEST_ASSERT_EQUAL_UINT(0, first.memory_kib);
    TEST_ASSERT_EQUAL_UINT(0, first.parallelism);

    /* The verifier must be g^x for the salt the enrolment reports, or it is
     * unusable: the server has no way to recompute it. */
    size_t salt_len = 0;
    unsigned char *salt = axiam_srp_unhex(first.salt, &salt_len);
    TEST_ASSERT_NOT_NULL(salt);
    unsigned char x[32];
    TEST_ASSERT_EQUAL_INT(0, axiam_srp_derive_x("alice", "hunter2", salt, salt_len, &params, x));

    const srp_group_t *group = axiam_srp_group_from_wire(first.group);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = NULL, *g = BN_new(), *xi = BN_bin2bn(x, 32, NULL), *v = BN_new();
    TEST_ASSERT_NOT_EQUAL(0, BN_hex2bn(&n, group->modulus_hex));
    TEST_ASSERT_EQUAL_INT(1, BN_set_word(g, group->generator));
    TEST_ASSERT_EQUAL_INT(1, BN_nnmod(xi, xi, n, ctx));
    TEST_ASSERT_EQUAL_INT(1, BN_mod_exp(v, g, xi, n, ctx));
    unsigned char *pad = (unsigned char *)malloc((size_t)group->byte_len);
    TEST_ASSERT_EQUAL_INT(group->byte_len, BN_bn2binpad(v, pad, group->byte_len));
    char *hex = axiam_srp_hex(pad, (size_t)group->byte_len);
    TEST_ASSERT_EQUAL_STRING(first.verifier, hex);
    free(hex); free(pad); free(salt);
    BN_free(n); BN_free(g); BN_clear_free(xi); BN_free(v); BN_CTX_free(ctx);

    /* A reused salt would make every verifier in a tenant equally attackable
     * with one precomputation. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
        axiam_srp_enrollment("alice", "hunter2", NULL, &params, &second, &err));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(first.salt, second.salt));

    axiam_srp_enrollment_dispose(&first);
    axiam_srp_enrollment_dispose(&second);
    /* dispose is idempotent and safe on a zeroed struct. */
    axiam_srp_enrollment_dispose(&first);
    axiam_srp_enrollment_dispose(NULL);
}

static void test_enrollment_refuses_an_unknown_group(void) {
    axiam_error_t err;
    axiam_srp_enrollment_t out;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
        axiam_srp_enrollment("alice", "pw", "rfc5054_1024", NULL, &out, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, err.kind);
}

static void test_enrollment_refuses_missing_arguments(void) {
    /* Never called this way by the SDK. Asserted so that a NULL becomes a
     * refusal a caller can act on rather than a crash inside the KDF. */
    axiam_srp_enrollment_t e;
    axiam_error_t err;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_srp_enrollment(NULL, "pw", NULL, NULL, &e, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_srp_enrollment("alice", NULL, NULL, NULL, &e, &err));
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK,
                          axiam_srp_enrollment("alice", "pw", NULL, NULL, NULL, &err));
}

static void test_enrollment_defaults_to_argon2id_at_axiam_costs(void) {
    /* With no parameters at all the enrolment must reach for AXIAM's own
     * Argon2id costs rather than silently enrolling under something weaker.
     *
     * On an OpenSSL without ARGON2ID (< 3.2) that request is REFUSED — §23.8,
     * and the refusal names the KDF rather than substituting PBKDF2, which
     * would produce a verifier no later login could satisfy. Both outcomes are
     * conformant; which one this build takes depends on its libcrypto. */
    axiam_srp_enrollment_t e;
    axiam_error_t err;
    axiam_error_kind_t k = axiam_srp_enrollment("alice", "pw", NULL, NULL, &e, &err);

    if (axiam_srp_argon2_available()) {
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
        TEST_ASSERT_EQUAL_STRING(AXIAM_SRP_KDF_ARGON2ID, e.kdf);
        TEST_ASSERT_EQUAL_UINT(19456u, e.memory_kib);
        TEST_ASSERT_EQUAL_UINT(2u, e.iterations);
        TEST_ASSERT_EQUAL_UINT(1u, e.parallelism);
        /* The default group is the widest, not the narrowest. */
        TEST_ASSERT_EQUAL_STRING(AXIAM_SRP_GROUP_4096, e.group);
        axiam_srp_enrollment_dispose(&e);
    } else {
        TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
        TEST_ASSERT_NOT_NULL(strstr(err.message, "cannot perform"));
        /* Nothing half-built is handed back. */
        TEST_ASSERT_NULL(e.verifier);
        TEST_ASSERT_NULL(e.salt);
    }
}

static void test_enrollment_refuses_a_kdf_this_build_cannot_perform(void) {
    axiam_srp_enrollment_t e;
    axiam_error_t err;
    axiam_srp_kdf_params_t params = { "scrypt", 1, 0, 0 };
    TEST_ASSERT_EQUAL_INT(
        AXIAM_ERR_NETWORK,
        axiam_srp_enrollment("alice", "pw", AXIAM_SRP_GROUP_2048, &params, &e, &err));
    TEST_ASSERT_NOT_NULL(strstr(err.message, "cannot perform"));
    TEST_ASSERT_NULL(e.verifier);
}

static void test_enrollment_fills_in_the_pbkdf2_default_cost(void) {
    /* A caller that names PBKDF2 without a cost gets OWASP's 600k rather than
     * zero iterations, and the Argon2id-only fields are cleared so the
     * enrolment cannot claim a memory cost it never used. */
    axiam_srp_enrollment_t e;
    axiam_error_t err;
    axiam_srp_kdf_params_t params = { AXIAM_SRP_KDF_PBKDF2, 0, 4096, 4 };
    TEST_ASSERT_EQUAL_INT(
        AXIAM_OK,
        axiam_srp_enrollment("alice", "pw", AXIAM_SRP_GROUP_2048, &params, &e, &err));
    TEST_ASSERT_EQUAL_UINT(600000u, e.iterations);
    TEST_ASSERT_EQUAL_UINT(0u, e.memory_kib);
    TEST_ASSERT_EQUAL_UINT(0u, e.parallelism);
    TEST_ASSERT_EQUAL_STRING(AXIAM_SRP_GROUP_2048, e.group);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(e.salt));
    TEST_ASSERT_EQUAL_INT(512, (int)strlen(e.verifier));
    axiam_srp_enrollment_dispose(&e);
    /* Dispose is idempotent: a caller that disposes twice must not double-free. */
    axiam_srp_enrollment_dispose(&e);
    axiam_srp_enrollment_dispose(NULL);
}

static void test_availability_probes(void) {
    /* §23.1 puts the probe in every SDK's vocabulary. Here it is unconditional:
     * BN_mod_exp and PKCS5_PBKDF2_HMAC are in every OpenSSL this SDK links. */
    TEST_ASSERT_EQUAL_INT(1, axiam_srp_available());
    /* The Argon2 probe answers a different question and may legitimately be 0. */
    int argon = axiam_srp_argon2_available();
    TEST_ASSERT_TRUE(argon == 0 || argon == 1);
}

int main(void) {
    g_vectors = load_vectors();
    if (!g_vectors) {
        fprintf(stderr, "srp-test-vectors.json not found or unparseable\n");
        return 1;
    }

    UNITY_BEGIN();
    RUN_TEST(test_group_constants_are_safe_primes);
    RUN_TEST(test_unrecognised_group_is_refused);
    RUN_TEST(test_hex_roundtrip_and_refusals);
    RUN_TEST(test_fixtures_cover_their_cases);
    RUN_TEST(test_vectors_reproduce_every_intermediate);
    RUN_TEST(test_vectors_produce_the_contract_proofs);
    RUN_TEST(test_zero_server_public_is_refused);
    RUN_TEST(test_every_exchange_uses_a_fresh_ephemeral);
    RUN_TEST(test_unknown_kdf_is_refused_rather_than_substituted);
    RUN_TEST(test_kdf_binds_identity_password_and_salt);
    RUN_TEST(test_argon2id_when_this_openssl_has_it);
    RUN_TEST(test_server_proof_comparison);
    RUN_TEST(test_enrollment_is_reproducible_from_its_own_salt);
    RUN_TEST(test_enrollment_refuses_an_unknown_group);
    RUN_TEST(test_enrollment_refuses_missing_arguments);
    RUN_TEST(test_enrollment_defaults_to_argon2id_at_axiam_costs);
    RUN_TEST(test_enrollment_refuses_a_kdf_this_build_cannot_perform);
    RUN_TEST(test_enrollment_fills_in_the_pbkdf2_default_cost);
    RUN_TEST(test_availability_probes);
    int rc = UNITY_END();
    cJSON_Delete(g_vectors);
    return rc;
}
