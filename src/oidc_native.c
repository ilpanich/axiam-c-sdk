/*
 * AXIAM C SDK — native sign-in with a provider ID token (CONTRACT.md §37, contract 1.65).
 *
 * A mobile or desktop app that signs in with Google's, Apple's or Facebook's NATIVE SDK ends
 * up holding an ID token the provider signed for that app, and no authorization code to
 * redeem. It presents the token to AXIAM's token endpoint, which verifies it, resolves the
 * AXIAM user it belongs to, and answers with the client's ordinary sign-in token set.
 *
 * THE THREE THINGS THIS FILE MUST NOT GET WRONG.
 *
 *  1. The nonce on the wire is the RAW one (§37.2 rule 3). The app gave the provider's SDK
 *     SHA-256(raw) as hex; the provider's token carries that hash; AXIAM hashes what it is
 *     sent and compares. This file sends the caller's bytes unchanged — no hashing, no
 *     replacing it with the hash, no reading the token's `nonce` claim, no nonce of its own.
 *     axiam_native_nonce() is the only place a nonce is made, and only on request.
 *  2. The provider's token is single-use across the whole deployment, so this grant is
 *     NEVER retried (§37.2 rule 10, §16.2) and `invalid_grant` is never refined: the server
 *     answers every refusal with one generic description precisely so the caller cannot
 *     tell the causes apart, and nothing here tries.
 *  3. Neither the provider's token nor the raw nonce is a thing this SDK may remember
 *     (§37.2 rule 12). They go into a form body that is scrubbed before it is released, and
 *     no error message, telemetry event or state of the client ever holds either.
 *
 * This is NOT token exchange: §15's axiam_token_exchange() refuses ID tokens by name, and
 * nothing here calls it or falls back to it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "oidc_internal.h"

/* §37.4 rule 1: 32 bytes is the RECOMMENDED size of §12.1 rule 1 (128 bits is the
 * server's documented floor). */
#define NATIVE_NONCE_BYTES 32

/* §37.2 rule 4: a local refusal is this SDK's §2 ValidationError — AXIAM_ERR_NETWORK with
 * `transport_cause` 400 and no request sent (README, "A local refusal"). The message names
 * the missing argument and never a value. */
static axiam_error_kind_t refuse_empty(axiam_error_t *err, const char *what) {
    char msg[160];
    snprintf(msg, sizeof(msg), "login_with_provider_id_token: %s must not be empty "
                               "(no request was sent)", what);
    axiam_error_set(err, AXIAM_ERR_NETWORK, 400, msg);
    return AXIAM_ERR_NETWORK;
}

axiam_error_kind_t axiam_login_with_provider_id_token(axiam_client_t *client,
                                                      const char *provider,
                                                      const axiam_sensitive_t *id_token,
                                                      const axiam_sensitive_t *nonce,
                                                      const char *scope,
                                                      const char *resource,
                                                      const char *tenant_id,
                                                      axiam_oidc_token_set_t *out,
                                                      axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(client, err)) return AXIAM_ERR_NETWORK;

    /* §37.2 rule 4: the three required inputs, refused before any wire call. No other
     * client-side validation of them is permitted — the token's format, issuer and
     * audience are the server's to judge. */
    if (!provider || !provider[0]) return refuse_empty(err, "provider");
    const char *raw_token = axiam_sensitive_reveal(id_token);
    if (!raw_token || !raw_token[0]) return refuse_empty(err, "id_token");
    const char *raw_nonce = axiam_sensitive_reveal(nonce);
    if (!raw_nonce || !raw_nonce[0]) return refuse_empty(err, "nonce");

    const char *client_id = oidc_require_client_id(client, "login_with_provider_id_token", err);
    if (!client_id) return AXIAM_ERR_AUTH;
    /* §12.3 rule 4: a slug-only client fails here, client-side, with no wire call. */
    const char *tenant =
        oidc_require_tenant_uuid(client, tenant_id, "login_with_provider_id_token", err);
    if (!tenant) return AXIAM_ERR_AUTH;

    axiam_oidc_config_t config;
    axiam_error_kind_t kind = axiam_oidc_discover(client, &config, err);
    if (kind != AXIAM_OK) return kind;

    /*
     * §37.1: the form fields, complete. Nothing outside this set is sent, and `scope` and
     * `resource` are omitted (oidc_form_add drops an empty value) rather than sent blank.
     * `provider` goes verbatim (§37.2 rule 2): no trimming, case-folding or resolution.
     * `scope` is passed as given and `openid` is NOT added (rule 7) — this is not
     * axiam_oidc_begin().
     */
    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", AXIAM_PROVIDER_ID_TOKEN_GRANT_TYPE);
    oidc_form_add(&form, "client_id", client_id);
    oidc_form_add(&form, "provider", provider);
    oidc_form_add(&form, "id_token", raw_token);
    oidc_form_add(&form, "nonce", raw_nonce); /* the RAW nonce, byte for byte */
    oidc_form_add(&form, "scope", scope);
    oidc_form_add(&form, "resource", resource);
    /* §37.2 rule 5: the client's credential only when its caller configured one — a public
     * client (the normal registration of a mobile app) sends client_id alone and is not
     * refused for that. client_secret_post, never HTTP Basic (§12.1 rule 3). */
    oidc_form_add(&form, "client_secret", axiam_sensitive_reveal(client->cfg->oidc_client_secret));

    char *body = NULL;
    /* retryable = 0 (§37.2 rule 10): the provider's token is spent by the attempt, and a
     * transport failure after the request left is indeterminate. A 429 is surfaced too. */
    kind = oidc_token_grant(client, &form, &config, tenant, 0, "native sign-in failed", &body,
                            err);
    oidc_form_dispose(&form); /* scrubs: the body held the ID token and the raw nonce */
    if (kind == AXIAM_OK) {
        /* §37.2 rule 8: the SDK's ordinary token set. An id_token that arrives is validated
         * under §12.4 with the RAW nonce as the expected nonce — AXIAM's ID token carries
         * the request's nonce as sent. Not adopted (rule 9): same posture as
         * axiam_login_client_credentials() and axiam_device_login(). */
        kind = oidc_parse_token_set(client, body, &config, raw_nonce, out, err);
    }
    if (body) {
        axiam_secure_zero(body, strlen(body));
        free(body);
    }
    axiam_oidc_config_dispose(&config);
    return kind;
}

/* ------------------------------------------------------------------ */
/* §37.4 native_nonce                                                 */
/* ------------------------------------------------------------------ */

char *oidc_nonce_hash_hex(const char *raw) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, raw, strlen(raw)) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || len != SHA256_DIGEST_LENGTH) return NULL;

    /* §37.4 rule 2: LOWER-case hexadecimal, 64 characters. */
    static const char hex[] = "0123456789abcdef";
    char *out = malloc((size_t)len * 2 + 1);
    if (!out) return NULL;
    for (unsigned int i = 0; i < len; i++) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return out;
}

axiam_error_kind_t axiam_native_nonce(axiam_provider_nonce_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));

    unsigned char bytes[NATIVE_NONCE_BYTES];
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "native_nonce: could not draw cryptographic randomness");
        return AXIAM_ERR_NETWORK;
    }
    /* §37.4 rule 1: base64url WITHOUT padding — ASCII, 43 characters, far under the
     * server's 512-byte bound. */
    char *raw = axiam_b64url_encode(bytes, sizeof(bytes));
    axiam_secure_zero(bytes, sizeof(bytes));
    char *hashed = raw ? oidc_nonce_hash_hex(raw) : NULL;
    if (raw) out->raw = axiam_sensitive_new(raw); /* §37.4 rule 3: raw is wrapped... */
    out->hashed = hashed;                         /* ...hashed is a plain string. */
    if (raw) {
        axiam_secure_zero(raw, strlen(raw));
        free(raw);
    }
    if (!out->raw || !out->hashed) {
        axiam_provider_nonce_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    /* §37.4 rule 4: nothing is stored anywhere — the pair lives only in `out`. */
    return AXIAM_OK;
}

void axiam_provider_nonce_dispose(axiam_provider_nonce_t *n) {
    if (!n) return;
    axiam_sensitive_free(n->raw);
    free(n->hashed);
    memset(n, 0, sizeof(*n));
}
