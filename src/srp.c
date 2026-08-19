/*
 * AXIAM C SDK — SRP-6a protocol arithmetic (CONTRACT.md §23).
 *
 * Everything above the transport boundary lives here: the RFC 5054 groups, the
 * PAD() rule, the two KDFs, and the client half of the exchange. The two HTTP
 * calls and the policy around them are at the bottom of the file.
 *
 * H is SHA-256 throughout. RFC 5054 specifies SHA-1; AXIAM does not use SHA-1
 * anywhere and does not start here.
 *
 * Every BIGNUM allocated here is freed on every path, including the error
 * paths, and every secret intermediate (x, S, K) is zeroized before release.
 * BN_clear_free rather than BN_free for anything derived from the password.
 */
#include "axiam/srp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "cJSON.h"
#include "internal.h"

/* ------------------------------------------------------------------------
 * §23.4 Groups — RFC 5054 Appendix A.
 *
 * Embedded as constants; a modulus is NEVER accepted from the server, because
 * a server-supplied N is a server-supplied trapdoor. tests/test_srp_vectors.c
 * asserts each one's width, primality and safe-primality: a transcription slip
 * here is a silent, total break that a client/server round-trip cannot catch,
 * since both sides would share the same wrong constant.
 * ---------------------------------------------------------------------- */

static const char N_2048_HEX[] =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

static const char N_3072_HEX[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static const char N_4096_HEX[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";


static const srp_group_t SRP_GROUPS[] = {
    { AXIAM_SRP_GROUP_2048, N_2048_HEX, 2, 256 },
    { AXIAM_SRP_GROUP_3072, N_3072_HEX, 5, 384 },
    { AXIAM_SRP_GROUP_4096, N_4096_HEX, 5, 512 },
};
static const size_t SRP_GROUP_COUNT = sizeof(SRP_GROUPS) / sizeof(SRP_GROUPS[0]);

/* Resolves a wire group name, refusing anything this SDK does not recognise
 * rather than guessing (§23.4). NULL means refused; the caller reports it as
 * AXIAM_ERR_NETWORK — a client capability gap, never AXIAM_ERR_AUTH, which
 * means wrong credentials and would send a user to reset a working password. */
const srp_group_t *axiam_srp_group_from_wire(const char *wire_name) {
    if (!wire_name) return NULL;
    for (size_t i = 0; i < SRP_GROUP_COUNT; i++) {
        if (strcmp(SRP_GROUPS[i].wire_name, wire_name) == 0) return &SRP_GROUPS[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------------
 * Hex and PAD()
 * ---------------------------------------------------------------------- */

static const char HEX_DIGITS[] = "0123456789abcdef";

/* Lowercase hex of `len` bytes into a fresh NUL-terminated buffer. */
char *axiam_srp_hex(const unsigned char *bytes, size_t len) {
    char *out = (char *)malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_DIGITS[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = HEX_DIGITS[bytes[i] & 0xf];
    }
    out[len * 2] = '\0';
    return out;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes hex into a fresh buffer, or returns NULL for anything that is not
 * valid hex. Never truncates: a malformed field is refused, because silently
 * dropping a nibble would produce a wrong hash that still looked well-formed. */
unsigned char *axiam_srp_unhex(const char *hex, size_t *out_len) {
    if (!hex) return NULL;
    size_t len = strlen(hex);
    if (len == 0 || len % 2 != 0) return NULL;
    unsigned char *out = (unsigned char *)malloc(len / 2);
    if (!out) return NULL;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { free(out); return NULL; }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return out;
}

/* PAD(v) — §23.3 rule 1. Writes exactly `byte_len` big-endian bytes.
 *
 * Skipping this is the classic SRP interop bug: two implementations agree until
 * a value happens to have a leading zero byte, and then roughly one login in
 * 256 fails in a way that reads as a flaky network. BN_bn2binpad does exactly
 * this and returns -1 if the value is wider than the field, which is a caller
 * error rather than something to truncate. */
static int srp_pad(const BIGNUM *v, unsigned char *out, int byte_len) {
    return BN_bn2binpad(v, out, byte_len) == byte_len ? 0 : -1;
}

/* ------------------------------------------------------------------------
 * Hashing
 * ---------------------------------------------------------------------- */

typedef struct {
    const unsigned char *data;
    size_t len;
} srp_chunk_t;

/* SHA-256 over the concatenation of `count` chunks.
 *
 * Via EVP rather than the SHA256_* one-shots, which OpenSSL 3.0 deprecated —
 * this file must build warning-clean against a modern libcrypto. */
static void srp_hash(const srp_chunk_t *chunks, size_t count, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out, 0, 32); return; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        int ok = 1;
        for (size_t i = 0; i < count && ok; i++)
            ok = EVP_DigestUpdate(ctx, chunks[i].data, chunks[i].len);
        unsigned int len = 0;
        if (!ok || EVP_DigestFinal_ex(ctx, out, &len) != 1 || len != 32) memset(out, 0, 32);
    } else {
        memset(out, 0, 32);
    }
    EVP_MD_CTX_free(ctx);
}

/* k = H(N | PAD(g)) — depends only on the group. */
static BIGNUM *srp_multiplier(const srp_group_t *group, const BIGNUM *n, const BIGNUM *g) {
    unsigned char *pad_n = (unsigned char *)malloc((size_t)group->byte_len);
    unsigned char *pad_g = (unsigned char *)malloc((size_t)group->byte_len);
    BIGNUM *k = NULL;
    if (pad_n && pad_g && srp_pad(n, pad_n, group->byte_len) == 0 &&
        srp_pad(g, pad_g, group->byte_len) == 0) {
        unsigned char digest[32];
        srp_chunk_t chunks[2] = { { pad_n, (size_t)group->byte_len }, { pad_g, (size_t)group->byte_len } };
        srp_hash(chunks, 2, digest);
        k = BN_bin2bn(digest, 32, NULL);
        OPENSSL_cleanse(digest, sizeof(digest));
    }
    free(pad_n);
    free(pad_g);
    return k;
}

/* ------------------------------------------------------------------------
 * §23.3 rules 3 and 4 — x is a KDF output, not a hash
 * ---------------------------------------------------------------------- */

int axiam_srp_available(void) { return 1; }

int axiam_srp_argon2_available(void) {
    /* Argon2id arrives as an OpenSSL EVP_KDF in 3.2. Fetching it is the only
     * honest test: a version macro would answer for the headers this was
     * COMPILED against rather than the libcrypto it is RUNNING against, and
     * those differ routinely on a distribution that ships shared OpenSSL. */
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return 0;
    EVP_KDF_free(kdf);
    return 1;
}

/* x = KDF(identity ":" password, salt), 32 bytes into `out`.
 *
 * RFC 5054's bare-hash x would make a leaked verifier CHEAPER to attack offline
 * than the Argon2id hashes AXIAM stores today, which would make adopting SRP a
 * net regression at rest — so the KDF is memory-hard, and the server dictates
 * which one per exchange.
 *
 * `identity` is the one the server named in the challenge, never what the human
 * typed (§23.3 rule 2). Returns 0 on success, -1 on a KDF this build cannot
 * perform (the caller reports which), -2 on an internal failure. */
int axiam_srp_derive_x(const char *identity, const char *password,
                        const unsigned char *salt, size_t salt_len,
                        const axiam_srp_kdf_params_t *params,
                        unsigned char out[32]) {
    if (!params || !params->kdf) return -1;

    size_t id_len = strlen(identity ? identity : "");
    size_t pw_len = strlen(password ? password : "");
    size_t secret_len = id_len + 1 + pw_len;
    unsigned char *secret = (unsigned char *)OPENSSL_malloc(secret_len);
    if (!secret) return -2;
    if (id_len) memcpy(secret, identity, id_len);
    secret[id_len] = ':';
    if (pw_len) memcpy(secret + id_len + 1, password, pw_len);

    int rc = -2;
    if (strcmp(params->kdf, AXIAM_SRP_KDF_PBKDF2) == 0) {
        unsigned iterations = params->iterations ? params->iterations : 600000;
        rc = PKCS5_PBKDF2_HMAC((const char *)secret, (int)secret_len, salt, (int)salt_len,
                               (int)iterations, EVP_sha256(), 32, out) == 1 ? 0 : -2;
    } else if (strcmp(params->kdf, AXIAM_SRP_KDF_ARGON2ID) == 0) {
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
        if (!kdf) {
            /* §23.8: Argon2 needs OpenSSL >= 3.2. Refuse rather than substitute
             * PBKDF2 — that would derive a different x and surface as "invalid
             * password", the single most misleading failure available here. */
            rc = -1;
        } else {
            EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
            if (ctx) {
                unsigned iterations = params->iterations ? params->iterations : 2;
                unsigned memory_kib = params->memory_kib ? params->memory_kib : 19456;
                unsigned lanes = params->parallelism ? params->parallelism : 1;
                /* OpenSSL wants memory in KiB under "memcost", the time cost
                 * under "iter", and the lane count under "lanes"; "threads"
                 * bounds the actual concurrency and is held at 1 so the result
                 * does not depend on how many cores this host happens to have. */
                unsigned threads = 1;
                OSSL_PARAM p[7];
                size_t n = 0;
                p[n++] = OSSL_PARAM_construct_octet_string("pass", secret, secret_len);
                p[n++] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
                p[n++] = OSSL_PARAM_construct_uint("iter", &iterations);
                p[n++] = OSSL_PARAM_construct_uint("memcost", &memory_kib);
                p[n++] = OSSL_PARAM_construct_uint("lanes", &lanes);
                p[n++] = OSSL_PARAM_construct_uint("threads", &threads);
                p[n] = OSSL_PARAM_construct_end();
                rc = EVP_KDF_derive(ctx, out, 32, p) == 1 ? 0 : -2;
                EVP_KDF_CTX_free(ctx);
            }
            EVP_KDF_free(kdf);
        }
    } else {
        rc = -1;
    }

    OPENSSL_clear_free(secret, secret_len);
    return rc;
}

/* ------------------------------------------------------------------------
 * The client half of the exchange
 * ---------------------------------------------------------------------- */

void axiam_srp_session_dispose(srp_session_t *s) {
    if (!s) return;
    BN_free(s->n);
    BN_free(s->g);
    /* a is secret material: clear before release. */
    BN_clear_free(s->a_priv);
    free(s->a_pub_hex);
    memset(s, 0, sizeof(*s));
}

/* Starts an exchange in `group`. When `fixed_a_hex` is NULL, draws a fresh
 * 256-bit a from the platform CSPRNG (§23.3 rule 7) — reusing a across logins
 * leaks the relationship between two session secrets. A non-NULL value is for
 * the §23.7 vectors ONLY, which pin a so every intermediate is reproducible. */
int axiam_srp_session_begin(srp_session_t *s, const srp_group_t *group,
                             const char *fixed_a_hex) {
    memset(s, 0, sizeof(*s));
    s->group = group;
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *a_pub_bytes = NULL;
    int rc = -1;

    if (!ctx) goto done;
    if (BN_hex2bn(&s->n, group->modulus_hex) == 0) goto done;
    s->g = BN_new();
    if (!s->g || BN_set_word(s->g, group->generator) != 1) goto done;

    if (fixed_a_hex) {
        if (BN_hex2bn(&s->a_priv, fixed_a_hex) == 0) goto done;
    } else {
        unsigned char raw[32];
        if (RAND_bytes(raw, sizeof(raw)) != 1) goto done;
        raw[0] |= 0x80; /* so a is unambiguously >= 2^255 */
        s->a_priv = BN_bin2bn(raw, sizeof(raw), NULL);
        OPENSSL_cleanse(raw, sizeof(raw));
        if (!s->a_priv) goto done;
    }

    BIGNUM *a_pub = BN_new();
    if (!a_pub) goto done;
    if (BN_mod_exp(a_pub, s->g, s->a_priv, s->n, ctx) != 1) { BN_free(a_pub); goto done; }
    a_pub_bytes = (unsigned char *)malloc((size_t)group->byte_len);
    if (!a_pub_bytes || srp_pad(a_pub, a_pub_bytes, group->byte_len) != 0) { BN_free(a_pub); goto done; }
    BN_free(a_pub);
    s->a_pub_hex = axiam_srp_hex(a_pub_bytes, (size_t)group->byte_len);
    if (!s->a_pub_hex) goto done;
    rc = 0;

done:
    free(a_pub_bytes);
    BN_CTX_free(ctx);
    if (rc != 0) axiam_srp_session_dispose(s);
    return rc;
}

/* Completes the exchange: S, K, M1 and the M2 the server must return.
 *
 * `identity` is the server's, `salt_hex` and `b_pub_hex` come from the
 * challenge response, `x` is srp_derive_x's output. Both proofs are written as
 * fresh lowercase-hex strings the caller frees.
 *
 * Returns 0 on success, -1 when the server's values are unusable (B ≡ 0, u = 0,
 * malformed hex) and -2 on an internal failure. */
int axiam_srp_session_finish(const srp_session_t *s, const char *identity,
                              const char *salt_hex, const char *b_pub_hex,
                              const unsigned char x[32],
                              char **out_m1_hex, char **out_m2_hex) {
    const srp_group_t *group = s->group;
    const int width = group->byte_len;

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *b_pub = NULL, *u = NULL, *x_int = NULL, *k = NULL;
    BIGNUM *gx = NULL, *kgx = NULL, *base = NULL, *exponent = NULL, *shared = NULL;
    unsigned char *salt = NULL, *pad_a = NULL, *pad_b = NULL, *pad_s = NULL, *pad_g = NULL;
    size_t salt_len = 0, a_len = 0;
    unsigned char session_key[32], hn[32], hg[32], hxor[32], hi[32], m1[32], m2[32];
    int rc = -2;

    *out_m1_hex = NULL;
    *out_m2_hex = NULL;
    if (!ctx) goto done;

    salt = axiam_srp_unhex(salt_hex, &salt_len);
    pad_a = axiam_srp_unhex(s->a_pub_hex, &a_len);
    if (!salt || !pad_a || (int)a_len != width) { rc = -1; goto done; }

    if (BN_hex2bn(&b_pub, b_pub_hex ? b_pub_hex : "") == 0) { rc = -1; goto done; }

    /* §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable and
     * the exchange would authenticate against a server that never knew the
     * verifier. A broken or hostile server, not a wrong password. */
    BIGNUM *b_mod = BN_new();
    if (!b_mod) goto done;
    if (BN_nnmod(b_mod, b_pub, s->n, ctx) != 1) { BN_free(b_mod); goto done; }
    if (BN_is_zero(b_mod)) { BN_free(b_mod); rc = -1; goto done; }
    BN_free(b_mod);

    pad_b = (unsigned char *)malloc((size_t)width);
    if (!pad_b || srp_pad(b_pub, pad_b, width) != 0) { rc = -1; goto done; }

    /* u = H(PAD(A) | PAD(B)) */
    {
        unsigned char digest[32];
        srp_chunk_t chunks[2] = { { pad_a, (size_t)width }, { pad_b, (size_t)width } };
        srp_hash(chunks, 2, digest);
        u = BN_bin2bn(digest, 32, NULL);
        OPENSSL_cleanse(digest, sizeof(digest));
    }
    if (!u) goto done;
    if (BN_is_zero(u)) { rc = -1; goto done; }

    x_int = BN_bin2bn(x, 32, NULL);
    if (!x_int) goto done;
    if (BN_nnmod(x_int, x_int, s->n, ctx) != 1) goto done;

    k = srp_multiplier(group, s->n, s->g);
    if (!k) goto done;

    /* S = (B - k*g^x)^(a + u*x) mod N */
    gx = BN_new(); kgx = BN_new(); base = BN_new(); exponent = BN_new(); shared = BN_new();
    if (!gx || !kgx || !base || !exponent || !shared) goto done;
    if (BN_mod_exp(gx, s->g, x_int, s->n, ctx) != 1) goto done;
    if (BN_mod_mul(kgx, k, gx, s->n, ctx) != 1) goto done;
    if (BN_mod_sub(base, b_pub, kgx, s->n, ctx) != 1) goto done;
    /* The exponent is NOT reduced: a + u*x is an exponent, and reducing it
     * modulo N rather than the group order would produce a different — wrong —
     * S that still looks perfectly well-formed. */
    if (BN_mul(exponent, u, x_int, ctx) != 1) goto done;
    if (BN_add(exponent, exponent, s->a_priv) != 1) goto done;
    if (BN_mod_exp(shared, base, exponent, s->n, ctx) != 1) goto done;

    pad_s = (unsigned char *)OPENSSL_malloc((size_t)width);
    if (!pad_s || srp_pad(shared, pad_s, width) != 0) goto done;
    {
        srp_chunk_t chunk = { pad_s, (size_t)width };
        srp_hash(&chunk, 1, session_key);
    }

    /* M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K) */
    pad_g = (unsigned char *)malloc((size_t)width);
    if (!pad_g || srp_pad(s->g, pad_g, width) != 0) goto done;
    {
        unsigned char *pad_n = (unsigned char *)malloc((size_t)width);
        if (!pad_n || srp_pad(s->n, pad_n, width) != 0) { free(pad_n); goto done; }
        srp_chunk_t cn = { pad_n, (size_t)width };
        srp_chunk_t cg = { pad_g, (size_t)width };
        srp_hash(&cn, 1, hn);
        srp_hash(&cg, 1, hg);
        free(pad_n);
    }
    for (int i = 0; i < 32; i++) hxor[i] = (unsigned char)(hn[i] ^ hg[i]);
    {
        srp_chunk_t ci = { (const unsigned char *)(identity ? identity : ""),
                           strlen(identity ? identity : "") };
        srp_hash(&ci, 1, hi);
    }
    {
        srp_chunk_t chunks[6] = {
            { hxor, 32 }, { hi, 32 }, { salt, salt_len },
            { pad_a, (size_t)width }, { pad_b, (size_t)width }, { session_key, 32 },
        };
        srp_hash(chunks, 6, m1);
    }

    /* M2 = H(PAD(A) | M1 | K) */
    {
        srp_chunk_t chunks[3] = { { pad_a, (size_t)width }, { m1, 32 }, { session_key, 32 } };
        srp_hash(chunks, 3, m2);
    }

    *out_m1_hex = axiam_srp_hex(m1, 32);
    *out_m2_hex = axiam_srp_hex(m2, 32);
    rc = (*out_m1_hex && *out_m2_hex) ? 0 : -2;
    if (rc != 0) { free(*out_m1_hex); free(*out_m2_hex); *out_m1_hex = NULL; *out_m2_hex = NULL; }

done:
    /* §23.3 rule 8: clear every secret intermediate before release. */
    OPENSSL_cleanse(session_key, sizeof(session_key));
    OPENSSL_cleanse(hn, sizeof(hn));
    OPENSSL_cleanse(hg, sizeof(hg));
    OPENSSL_cleanse(hxor, sizeof(hxor));
    OPENSSL_cleanse(hi, sizeof(hi));
    OPENSSL_cleanse(m1, sizeof(m1));
    OPENSSL_cleanse(m2, sizeof(m2));
    if (pad_s) OPENSSL_clear_free(pad_s, (size_t)width);
    free(salt);
    free(pad_a);
    free(pad_b);
    free(pad_g);
    BN_free(b_pub);
    BN_free(u);
    BN_clear_free(x_int);
    BN_free(k);
    BN_clear_free(gx);
    BN_clear_free(kgx);
    BN_clear_free(base);
    BN_clear_free(exponent);
    BN_clear_free(shared);
    BN_CTX_free(ctx);
    return rc;
}

/* Constant-time comparison of the server's M2 against the expected one
 * (§23.3 rule 6). */
int axiam_srp_verify_server_proof(const char *expected, const char *actual) {
    if (!expected || !actual) return 0;
    size_t len = strlen(expected);
    if (strlen(actual) != len) return 0;
    return CRYPTO_memcmp(expected, actual, len) == 0;
}

/* ------------------------------------------------------------------------
 * §23.5 enrolment
 * ---------------------------------------------------------------------- */

void axiam_srp_enrollment_dispose(axiam_srp_enrollment_t *e) {
    if (!e) return;
    free(e->group);
    free(e->kdf);
    /* §23.3 rule 12: the salt and verifier are secret material and must not
     * survive in freed memory any more than they may appear in a log. */
    if (e->salt) { OPENSSL_cleanse(e->salt, strlen(e->salt)); free(e->salt); }
    if (e->verifier) { OPENSSL_cleanse(e->verifier, strlen(e->verifier)); free(e->verifier); }
    memset(e, 0, sizeof(*e));
}

static char *srp_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

axiam_error_kind_t axiam_srp_enrollment(const char *identity, const char *password,
                                        const char *group_name,
                                        const axiam_srp_kdf_params_t *params,
                                        axiam_srp_enrollment_t *out,
                                        axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!identity || !password || !out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }

    const srp_group_t *group =
        axiam_srp_group_from_wire(group_name ? group_name : AXIAM_SRP_GROUP_4096);
    if (!group) {
        /* §23.4: refuse rather than guess. Computing in an unverified group could
         * mean one whose discrete log the server knows. */
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "SRP: this SDK does not implement the requested group");
        return AXIAM_ERR_NETWORK;
    }

    /* Any zero cost becomes AXIAM's default for the chosen KDF. This is applied
     * on the ENROLMENT path only — a challenge response that omits a cost it is
     * required to send is a server this SDK should not guess on behalf of. */
    axiam_srp_kdf_params_t resolved;
    resolved.kdf = (params && params->kdf) ? params->kdf : AXIAM_SRP_KDF_ARGON2ID;
    resolved.iterations = params ? params->iterations : 0;
    resolved.memory_kib = params ? params->memory_kib : 0;
    resolved.parallelism = params ? params->parallelism : 0;
    if (strcmp(resolved.kdf, AXIAM_SRP_KDF_PBKDF2) == 0) {
        if (!resolved.iterations) resolved.iterations = 600000;
        resolved.memory_kib = 0;
        resolved.parallelism = 0;
    } else {
        if (!resolved.iterations) resolved.iterations = 2;
        if (!resolved.memory_kib) resolved.memory_kib = 19456;
        if (!resolved.parallelism) resolved.parallelism = 1;
    }

    /* §23.3 rule 11: 32 fresh bytes. A reused salt would make every verifier in
     * a tenant equally attackable with one precomputation. */
    unsigned char salt[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "SRP: no entropy for the enrolment salt");
        return AXIAM_ERR_NETWORK;
    }

    unsigned char x[32];
    int rc = axiam_srp_derive_x(identity, password, salt, sizeof(salt), &resolved, x);
    if (rc != 0) {
        OPENSSL_cleanse(salt, sizeof(salt));
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        rc == -1 ? "SRP: this build cannot perform the requested KDF"
                                 : "SRP: key derivation failed");
        return AXIAM_ERR_NETWORK;
    }

    /* v = g^x mod N */
    axiam_error_kind_t kind = AXIAM_ERR_NETWORK;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = NULL, *g = NULL, *x_int = NULL, *v = NULL;
    unsigned char *pad_v = NULL;
    if (ctx && BN_hex2bn(&n, group->modulus_hex) != 0) {
        g = BN_new();
        x_int = BN_bin2bn(x, sizeof(x), NULL);
        v = BN_new();
        pad_v = (unsigned char *)malloc((size_t)group->byte_len);
        if (g && x_int && v && pad_v &&
            BN_set_word(g, group->generator) == 1 &&
            BN_nnmod(x_int, x_int, n, ctx) == 1 &&
            BN_mod_exp(v, g, x_int, n, ctx) == 1 &&
            srp_pad(v, pad_v, group->byte_len) == 0) {
            out->group = srp_strdup(group->wire_name);
            out->kdf = srp_strdup(resolved.kdf);
            out->memory_kib = resolved.memory_kib;
            out->iterations = resolved.iterations;
            out->parallelism = resolved.parallelism;
            out->salt = axiam_srp_hex(salt, sizeof(salt));
            out->verifier = axiam_srp_hex(pad_v, (size_t)group->byte_len);
            if (out->group && out->kdf && out->salt && out->verifier) {
                kind = AXIAM_OK;
            } else {
                axiam_srp_enrollment_dispose(out);
            }
        }
    }
    if (kind != AXIAM_OK) axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "SRP: out of memory");

    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(x, sizeof(x));
    free(pad_v);
    BN_free(n);
    BN_free(g);
    BN_clear_free(x_int);
    BN_free(v);
    BN_CTX_free(ctx);
    return kind;
}
