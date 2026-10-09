/*
 * AXIAM C SDK — CIBA, client-initiated backchannel authentication (CONTRACT.md §33,
 * contract 1.58), including the §33.2 signed request form.
 *
 * See include/axiam/ciba.h. The rules this file is built around, in the order they bite:
 *
 *   - The client ALWAYS authenticates (§33.1): a secret, or the §6.1 certificate. A client
 *     with neither is refused before any request, never sent anonymously.
 *   - ciba_initiate is NEVER retried (§33.7 rule 1): it stores a request and may notify a
 *     person. oidc_post() is called with retryable = 0 and nothing loops around it.
 *   - ciba_poll's protocol answers are decisive and never retried; only a transport
 *     failure, a 5xx, a 408 or a BODILESS 429 is (§33.7 rule 5). That is narrower than
 *     the device grant's loop, which retries a 429 whatever it says.
 *   - ciba_await sleeps BEFORE each poll and checks that the poll it is about to make
 *     falls before the deadline — the same subtlety axiam_device_login() documents.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "axiam/ciba.h"
#include "cJSON.h"
#include "oidc_internal.h"

#define FORM_CONTENT_TYPE "application/x-www-form-urlencoded"

int axiam_error_is_access_denied(const axiam_error_t *err) {
    return err && strcmp(err->oauth_error, "access_denied") == 0;
}

int axiam_error_is_expired_token(const axiam_error_t *err) {
    return err && strcmp(err->oauth_error, "expired_token") == 0;
}

void axiam_ciba_initiate_response_dispose(axiam_ciba_initiate_response_t *r) {
    if (!r) return;
    axiam_sensitive_free(r->auth_req_id);
    memset(r, 0, sizeof(*r));
}

/* ------------------------------------------------------------------ */
/* The signer (§33.2)                                                 */
/* ------------------------------------------------------------------ */

struct axiam_ciba_request_signer {
    axiam_ciba_signing_alg_t alg;
    EVP_PKEY *key;
    char *kid;
};

static const char *alg_name(axiam_ciba_signing_alg_t alg) {
    switch (alg) {
        case AXIAM_CIBA_SIGNING_PS256: return "PS256";
        case AXIAM_CIBA_SIGNING_ES256: return "ES256";
        case AXIAM_CIBA_SIGNING_EDDSA: return "EdDSA";
    }
    return NULL;
}

/* Never prompt for a passphrase: an encrypted PEM is simply not a key we can use. */
static int no_passphrase(char *buf, int size, int rwflag, void *u) {
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return 0;
}

/* A JWS signature over `input` under the signer's algorithm, in JOSE's encoding (raw
 * r||s for ES256), base64url. NULL on any failure. */
static char *jws_sign(const axiam_ciba_request_signer_t *s, const unsigned char *input,
                      size_t input_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = s->alg == AXIAM_CIBA_SIGNING_EDDSA ? NULL : EVP_sha256();
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    char *out = NULL;
    int ok = EVP_DigestSignInit(ctx, &pctx, md, NULL, s->key) == 1;
    if (ok && s->alg == AXIAM_CIBA_SIGNING_PS256) {
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1;
    }
    ok = ok && EVP_DigestSign(ctx, NULL, &sig_len, input, input_len) == 1;
    if (ok) sig = OPENSSL_malloc(sig_len);
    ok = ok && sig && EVP_DigestSign(ctx, sig, &sig_len, input, input_len) == 1;
    if (ok && s->alg == AXIAM_CIBA_SIGNING_ES256) {
        /* OpenSSL produces DER; JWS wants the two 32-byte integers concatenated. */
        const unsigned char *p = sig;
        ECDSA_SIG *ec = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
        unsigned char raw[64];
        ok = ec != NULL;
        if (ok) {
            const BIGNUM *r = NULL, *sv = NULL;
            ECDSA_SIG_get0(ec, &r, &sv);
            ok = BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(sv, raw + 32, 32) == 32;
        }
        ECDSA_SIG_free(ec);
        if (ok) out = axiam_b64url_encode(raw, sizeof(raw));
    } else if (ok) {
        out = axiam_b64url_encode(sig, sig_len);
    }
    OPENSSL_free(sig);
    EVP_MD_CTX_free(ctx);
    return out;
}

/* Whether `key` is a key of the family `alg` names. */
static int key_fits(EVP_PKEY *key, axiam_ciba_signing_alg_t alg) {
    switch (alg) {
        case AXIAM_CIBA_SIGNING_EDDSA:
            return EVP_PKEY_get_base_id(key) == EVP_PKEY_ED25519;
        case AXIAM_CIBA_SIGNING_ES256: {
            char group[64] = {0};
            size_t len = 0;
            return EVP_PKEY_get_base_id(key) == EVP_PKEY_EC &&
                   EVP_PKEY_get_group_name(key, group, sizeof(group), &len) == 1 &&
                   (strcmp(group, "prime256v1") == 0 || strcmp(group, "P-256") == 0);
        }
        case AXIAM_CIBA_SIGNING_PS256:
            return (EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA ||
                    EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA_PSS) &&
                   EVP_PKEY_get_bits(key) >= 2048;
    }
    return 0;
}

axiam_ciba_request_signer_t *axiam_ciba_request_signer_new(axiam_ciba_signing_alg_t alg,
                                                           const axiam_sensitive_t *private_key_pem,
                                                           const char *kid, axiam_error_t *err) {
    axiam_error_reset(err);
    const char *detail = "the key is not a private key that signs under the given algorithm "
                         "(CONTRACT.md \xc2\xa7" "33.2)";
    if (!alg_name(alg)) {
        axiam_local_refusal(err, "ciba_initiate", "signing_alg",
                            "an algorithm is required: PS256, ES256 or EdDSA, as registered "
                            "(CONTRACT.md \xc2\xa7" "33.2)");
        return NULL;
    }
    const unsigned char *pem = axiam_sensitive_bytes(private_key_pem);
    size_t pem_len = axiam_sensitive_len(private_key_pem);
    if (!pem || pem_len == 0) {
        axiam_local_refusal(err, "ciba_initiate", "signing_key", "a private key is required "
                            "(CONTRACT.md \xc2\xa7" "33.2)");
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, no_passphrase, NULL) : NULL;
    BIO_free(bio);
    if (!key || !key_fits(key, alg)) {
        EVP_PKEY_free(key);
        axiam_local_refusal(err, "ciba_initiate", "signing_key", detail);
        return NULL;
    }
    axiam_ciba_request_signer_t *s = calloc(1, sizeof(*s));
    if (!s) {
        EVP_PKEY_free(key);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }
    s->alg = alg;
    s->key = key;
    s->kid = axiam_strdup0(kid);
    /* A key that parses is not yet a key for this algorithm: prove it signs. */
    static const unsigned char probe[] = "axiam-ciba-probe";
    char *sig = jws_sign(s, probe, sizeof(probe) - 1);
    if (!sig || (kid && !s->kid)) {
        free(sig);
        axiam_ciba_request_signer_free(s);
        axiam_local_refusal(err, "ciba_initiate", "signing_key", detail);
        return NULL;
    }
    free(sig);
    return s;
}

void axiam_ciba_request_signer_free(axiam_ciba_request_signer_t *s) {
    if (!s) return;
    EVP_PKEY_free(s->key); /* OpenSSL clears private key material as it frees it */
    free(s->kid);
    free(s);
}

axiam_ciba_signing_alg_t axiam_ciba_request_signer_alg(const axiam_ciba_request_signer_t *s) {
    return s ? s->alg : (axiam_ciba_signing_alg_t)0;
}

/* ------------------------------------------------------------------ */
/* Client authentication (§33.1)                                      */
/* ------------------------------------------------------------------ */

/* The client_id, and the secret when one is configured; refuses a client with neither a
 * secret nor a certificate. */
static axiam_error_kind_t ciba_client_auth(axiam_client_t *c, const char *operation,
                                           const char **client_id, const char **secret,
                                           axiam_error_t *err) {
    *client_id = oidc_require_client_id(c, operation, err);
    if (!*client_id) return AXIAM_ERR_AUTH;
    const char *s = axiam_sensitive_reveal(c->cfg->oidc_client_secret);
    *secret = (s && s[0]) ? s : NULL;
    if (!*secret && !oidc_presents_client_certificate(c)) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%s requires client authentication: a CIBA client is never public -- "
                 "configure an OIDC client secret or a \xc2\xa7" "6.1 client certificate "
                 "(CONTRACT.md \xc2\xa7" "33.1)",
                 operation);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return AXIAM_ERR_AUTH;
    }
    return AXIAM_OK;
}

static void form_add_auth(oidc_form_t *form, const char *client_id, const char *secret) {
    oidc_form_add(form, "client_id", client_id);
    /* tls_client_auth: the certificate authenticates, and only client_id is sent. */
    oidc_form_add(form, "client_secret", secret);
}

/* The discovery document: the caller's, or a fresh/cached one. `*owned` says whether
 * `out` must be disposed. */
static axiam_error_kind_t ciba_config(axiam_client_t *c, const axiam_oidc_config_t *given,
                                      axiam_oidc_config_t *out, const axiam_oidc_config_t **use,
                                      int *owned, axiam_error_t *err) {
    *owned = 0;
    if (given) {
        *use = given;
        return AXIAM_OK;
    }
    axiam_error_kind_t kind = axiam_oidc_discover(c, out, err);
    if (kind != AXIAM_OK) return kind;
    *owned = 1;
    *use = out;
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* ciba_initiate                                                      */
/* ------------------------------------------------------------------ */

static const char *hint_member(axiam_ciba_hint_kind_t kind) {
    return kind == AXIAM_CIBA_ID_TOKEN_HINT ? "id_token_hint" : "login_hint";
}

/* The CIBA Core §7.1.1 signed request: every member inside the JWT, plus iss, aud, iat,
 * nbf, exp and a fresh 128-bit jti. NULL on failure. */
static char *signed_request(axiam_client_t *c, const axiam_ciba_initiate_params_t *p,
                            const char *client_id, const char *issuer) {
    const axiam_ciba_request_signer_t *s = p->signer;
    cJSON *header = cJSON_CreateObject();
    cJSON *claims = cJSON_CreateObject();
    char *header_json = NULL, *claims_json = NULL, *input = NULL, *sig = NULL, *out = NULL;
    char *h64 = NULL, *c64 = NULL;
    unsigned char raw_jti[16];
    char jti[33];
    int ok = header && claims && RAND_bytes(raw_jti, (int)sizeof(raw_jti)) == 1;
    if (ok) {
        for (size_t i = 0; i < sizeof(raw_jti); i++) snprintf(jti + 2 * i, 3, "%02x", raw_jti[i]);
        long long now = (long long)c->clock_fn(c->clock_ctx);
        ok = cJSON_AddStringToObject(header, "alg", alg_name(s->alg)) &&
             (!s->kid || cJSON_AddStringToObject(header, "kid", s->kid)) &&
             cJSON_AddStringToObject(claims, "iss", client_id) &&
             cJSON_AddStringToObject(claims, "aud", issuer) &&
             cJSON_AddNumberToObject(claims, "iat", (double)now) &&
             cJSON_AddNumberToObject(claims, "nbf", (double)now) &&
             cJSON_AddNumberToObject(claims, "exp", (double)(now + AXIAM_CIBA_SIGNED_REQUEST_LIFETIME_S)) &&
             cJSON_AddStringToObject(claims, "jti", jti) &&
             cJSON_AddStringToObject(claims, "scope", p->scope) &&
             cJSON_AddStringToObject(claims, hint_member(p->hint_kind), p->hint) &&
             (!p->binding_message ||
              cJSON_AddStringToObject(claims, "binding_message", p->binding_message)) &&
             /* A NUMBER inside the JWT (CIBA Core §7.1), a string on the form. */
             (!p->has_requested_expiry ||
              cJSON_AddNumberToObject(claims, "requested_expiry", (double)p->requested_expiry)) &&
             (!p->acr_values || cJSON_AddStringToObject(claims, "acr_values", p->acr_values)) &&
             (!p->resource || cJSON_AddStringToObject(claims, "resource", p->resource)) &&
             (p->delivery != AXIAM_CIBA_DELIVERY_PING ||
              cJSON_AddStringToObject(claims, "client_notification_token",
                                      axiam_sensitive_reveal(p->client_notification_token)));
    }
    if (ok) {
        header_json = cJSON_PrintUnformatted(header);
        claims_json = cJSON_PrintUnformatted(claims);
        ok = header_json && claims_json;
    }
    if (ok) {
        h64 = axiam_b64url_encode((const unsigned char *)header_json, strlen(header_json));
        c64 = axiam_b64url_encode((const unsigned char *)claims_json, strlen(claims_json));
        ok = h64 && c64;
    }
    size_t input_len = ok ? strlen(h64) + 1 + strlen(c64) : 0;
    if (ok) {
        input = malloc(input_len + 1);
        ok = input != NULL;
        if (ok) snprintf(input, input_len + 1, "%s.%s", h64, c64);
    }
    if (ok) sig = jws_sign(s, (const unsigned char *)input, input_len);
    if (sig) {
        size_t n = input_len + 1 + strlen(sig) + 1;
        out = malloc(n);
        if (out) snprintf(out, n, "%s.%s", input, sig);
    }
    /* Every intermediate carries the notification token: scrub before release. */
    if (claims_json) axiam_secure_zero(claims_json, strlen(claims_json));
    if (c64) axiam_secure_zero(c64, strlen(c64));
    if (input) axiam_secure_zero(input, input_len);
    cJSON_Delete(header);
    cJSON_Delete(claims);
    free(header_json);
    free(claims_json);
    free(h64);
    free(c64);
    free(input);
    free(sig);
    return out;
}

axiam_error_kind_t axiam_ciba_initiate(axiam_client_t *c, const axiam_ciba_initiate_params_t *p,
                                       axiam_ciba_initiate_response_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !p) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(c, err)) return AXIAM_ERR_NETWORK;

    const char *client_id = NULL, *secret = NULL;
    axiam_error_kind_t kind = ciba_client_auth(c, "ciba_initiate", &client_id, &secret, err);
    if (kind != AXIAM_OK) return kind;

    if (!p->scope || !p->scope[0]) {
        axiam_local_refusal(err, "ciba_initiate", "scope",
                            "a scope is required (CONTRACT.md \xc2\xa7" "33.2)");
        return AXIAM_ERR_NETWORK;
    }
    if (!p->hint || !p->hint[0]) {
        axiam_local_refusal(err, "ciba_initiate", hint_member(p->hint_kind),
                            "exactly one hint is required (CONTRACT.md \xc2\xa7" "33.2)");
        return AXIAM_ERR_NETWORK;
    }
    const char *notify = axiam_sensitive_reveal(p->client_notification_token);
    if (p->delivery == AXIAM_CIBA_DELIVERY_PING && (!notify || !notify[0])) {
        axiam_local_refusal(err, "ciba_initiate", "client_notification_token",
                            "a ping-mode request needs a client_notification_token: without "
                            "one AXIAM has nothing to ping with (CONTRACT.md \xc2\xa7" "33.8)");
        return AXIAM_ERR_NETWORK;
    }
    if (p->delivery != AXIAM_CIBA_DELIVERY_PING && p->client_notification_token) {
        axiam_local_refusal(err, "ciba_initiate", "client_notification_token",
                            "a poll-mode request carries no client_notification_token "
                            "(CONTRACT.md \xc2\xa7" "33.2)");
        return AXIAM_ERR_NETWORK;
    }

    const char *tenant = oidc_require_tenant_uuid(c, p->tenant_id, "ciba_initiate", err);
    if (!tenant) return AXIAM_ERR_AUTH;
    axiam_oidc_config_t fetched;
    const axiam_oidc_config_t *config = NULL;
    int owned = 0;
    kind = ciba_config(c, p->config, &fetched, &config, &owned, err);
    if (kind != AXIAM_OK) return kind;

    const char *endpoint = NULL;
    kind = oidc_preferred_endpoint(c, config,
                                   config->mtls_endpoint_aliases.backchannel_authentication_endpoint,
                                   config->backchannel_authentication_endpoint, &endpoint, err);
    if (kind == AXIAM_OK && !endpoint) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "the discovery document advertises no "
                        "backchannel_authentication_endpoint: this server does not support "
                        "CIBA (CONTRACT.md \xc2\xa7" "33.1)");
        kind = AXIAM_ERR_AUTH;
    }
    char *url = kind == AXIAM_OK ? oidc_endpoint_with_tenant(endpoint, tenant) : NULL;
    char *request = NULL;
    if (kind == AXIAM_OK && url && p->signer) {
        request = signed_request(c, p, client_id, config->issuer ? config->issuer : "");
    }
    if (owned) axiam_oidc_config_dispose(&fetched);
    if (kind != AXIAM_OK) return kind;

    oidc_form_t form;
    oidc_form_init(&form);
    form_add_auth(&form, client_id, secret);
    if (p->signer) {
        /* ONLY client authentication and `request` (§33.2): every member is inside it. */
        oidc_form_add(&form, "request", request);
    } else {
        char expiry[24];
        snprintf(expiry, sizeof(expiry), "%ld", p->requested_expiry);
        oidc_form_add(&form, "scope", p->scope);
        oidc_form_add(&form, hint_member(p->hint_kind), p->hint);
        oidc_form_add(&form, "binding_message", p->binding_message);
        if (p->has_requested_expiry) oidc_form_add(&form, "requested_expiry", expiry);
        oidc_form_add(&form, "acr_values", p->acr_values);
        oidc_form_add(&form, "resource", p->resource);
        if (p->delivery == AXIAM_CIBA_DELIVERY_PING)
            oidc_form_add(&form, "client_notification_token", notify);
    }
    if (request) {
        axiam_secure_zero(request, strlen(request));
        free(request);
        request = NULL;
    } else if (p->signer && url) {
        form.failed = 1; /* the signing failed: never send an unsigned request instead */
    }

    axiam_http_response_t resp = {0};
    /* §33.7 rule 1: retryable = 0, and nothing loops around this call. */
    int rc = (url && !form.failed) ? oidc_post(c, url, FORM_CONTENT_TYPE, form.buf, 0, &resp) : -2;
    oidc_form_dispose(&form);
    free(url);
    if (rc == -2) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        p->signer ? "ciba_initiate: the signed request could not be built"
                                  : "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (resp.status < 200 || resp.status >= 300) {
        kind = oidc_map_grant_error(&resp, "ciba_initiate failed", err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    axiam_http_response_dispose(&resp);
    const cJSON *id = root ? cJSON_GetObjectItemCaseSensitive(root, "auth_req_id") : NULL;
    const cJSON *expires = root ? cJSON_GetObjectItemCaseSensitive(root, "expires_in") : NULL;
    const cJSON *interval = root ? cJSON_GetObjectItemCaseSensitive(root, "interval") : NULL;
    if (!cJSON_IsString(id) || !id->valuestring[0] || !cJSON_IsNumber(expires)) {
        if (root) cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "malformed CibaInitiateResponse");
        return AXIAM_ERR_NETWORK;
    }
    out->auth_req_id = axiam_sensitive_new(id->valuestring);
    /* The response carried the id in a heap string: scrub it before it is freed. */
    axiam_secure_zero(id->valuestring, strlen(id->valuestring));
    out->expires_in = (long)expires->valuedouble;
    out->interval = cJSON_IsNumber(interval) ? (long)interval->valuedouble : 0;
    if (out->interval <= 0) out->interval = AXIAM_CIBA_DEFAULT_INTERVAL_S;
    out->received_at = c->clock_fn(c->clock_ctx);
    cJSON_Delete(root);
    if (!out->auth_req_id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* ciba_poll                                                          */
/* ------------------------------------------------------------------ */

/* 1 when a non-2xx answer carries a non-empty OAuth2 `error`. */
static int has_oauth_error(const axiam_http_response_t *resp) {
    cJSON *root = resp->body ? cJSON_Parse(resp->body) : NULL;
    const cJSON *code = root ? cJSON_GetObjectItemCaseSensitive(root, "error") : NULL;
    int has = cJSON_IsString(code) && code->valuestring[0];
    cJSON_Delete(root);
    return has;
}

/*
 * One CIBA token request against a resolved configuration. `*transient` is set to 1
 * when the failure is one §33.7 rule 5 says the loop survives: a transport failure, a
 * 5xx, 408 or 429 that outlived §16, or the `rate_limit_exceeded` answer.
 */
static axiam_error_kind_t ciba_poll_with(axiam_client_t *c, const axiam_oidc_config_t *config,
                                         const char *auth_req_id, const char *client_id,
                                         const char *secret, const char *tenant,
                                         axiam_oidc_token_set_t *out, int *transient,
                                         axiam_error_t *err) {
    *transient = 0;
    const char *endpoint = NULL;
    axiam_error_kind_t kind = oidc_preferred_endpoint(
        c, config, config->mtls_endpoint_aliases.token_endpoint, config->token_endpoint,
        &endpoint, err);
    if (kind != AXIAM_OK) return kind;
    char *url = endpoint ? oidc_endpoint_with_tenant(endpoint, tenant) : NULL;
    oidc_form_t form;
    oidc_form_init(&form);
    oidc_form_add(&form, "grant_type", AXIAM_CIBA_GRANT_TYPE);
    oidc_form_add(&form, "auth_req_id", auth_req_id);
    form_add_auth(&form, client_id, secret);
    if (!url || form.failed) {
        free(url);
        oidc_form_dispose(&form);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        endpoint ? "out of memory" : "the discovery document has no token_endpoint");
        return AXIAM_ERR_NETWORK;
    }

    int budget = c->retry_enabled ? AXIAM_RETRY_MAX_ATTEMPTS : 1;
    axiam_http_response_t resp = {0};
    int rc = -1;
    for (int attempt = 1; attempt <= budget; attempt++) {
        rc = oidc_post(c, url, FORM_CONTENT_TYPE, form.buf, 0, &resp);
        if (attempt == budget) break;
        /* A protocol answer (`authorization_pending`, `slow_down`, ...) is decisive --
         * a 429 carrying `rate_limit_exceeded` included -- and so is any other 4xx. */
        int retry = axiam_retry_should_retry(rc != 0, resp.status) &&
                    !(rc == 0 && resp.status != 0 && has_oauth_error(&resp));
        if (!retry) break;
        long retry_after = axiam_retry_after_ms(axiam_kv_get(resp.headers, "Retry-After"));
        long delay = axiam_retry_delay_ms(attempt, retry_after, c->jitter_fn(c->jitter_ctx));
        axiam_http_response_dispose(&resp);
        c->sleep_fn(c->sleep_ctx, delay);
    }
    free(url);
    oidc_form_dispose(&form);

    if (rc != 0 || resp.status == 0) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.transport_err,
                        resp.transport_msg ? resp.transport_msg : "network failure");
        *transient = 1;
        kind = AXIAM_ERR_NETWORK;
    } else if (resp.status >= 200 && resp.status < 300) {
        /* §33.7 rule 7: the request is now redeemed. The body is consumed here, once,
         * and a body that does not parse is NOT retried -- a retry would only learn
         * invalid_grant. */
        kind = oidc_parse_token_set(c, resp.body, config, NULL, out, err);
    } else {
        kind = oidc_map_grant_error(&resp, "ciba_poll failed", err);
        if (err && err->oauth_error[0]) {
            *transient = strcmp(err->oauth_error, "rate_limit_exceeded") == 0;
        } else {
            *transient = resp.status >= 500 || resp.status == 408 || resp.status == 429;
        }
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_ciba_poll(axiam_client_t *c, const axiam_sensitive_t *auth_req_id,
                                   const char *tenant_id, const axiam_oidc_config_t *config,
                                   axiam_oidc_token_set_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(c, err)) return AXIAM_ERR_NETWORK;
    const char *client_id = NULL, *secret = NULL;
    axiam_error_kind_t kind = ciba_client_auth(c, "ciba_poll", &client_id, &secret, err);
    if (kind != AXIAM_OK) return kind;
    const char *raw = axiam_sensitive_reveal(auth_req_id);
    if (!raw || !raw[0]) {
        axiam_local_refusal(err, "ciba_poll", "auth_req_id", "an auth_req_id is required");
        return AXIAM_ERR_NETWORK;
    }
    const char *tenant = oidc_require_tenant_uuid(c, tenant_id, "ciba_poll", err);
    if (!tenant) return AXIAM_ERR_AUTH;
    axiam_oidc_config_t fetched;
    const axiam_oidc_config_t *use = NULL;
    int owned = 0;
    kind = ciba_config(c, config, &fetched, &use, &owned, err);
    if (kind != AXIAM_OK) return kind;
    int transient = 0;
    kind = ciba_poll_with(c, use, raw, client_id, secret, tenant, out, &transient, err);
    if (owned) axiam_oidc_config_dispose(&fetched);
    return kind;
}

/* ------------------------------------------------------------------ */
/* ciba_await (§33.7)                                                 */
/* ------------------------------------------------------------------ */

static time_t client_now(void *ctx) {
    axiam_client_t *c = ctx;
    return c->clock_fn(c->clock_ctx);
}

static void client_sleep(void *ctx, long seconds) {
    axiam_client_t *c = ctx;
    c->sleep_fn(c->sleep_ctx, seconds * 1000L);
}

axiam_error_kind_t axiam_ciba_await(axiam_client_t *c, const axiam_ciba_initiate_response_t *initiated,
                                    const char *tenant_id, const axiam_oidc_config_t *config,
                                    const axiam_ciba_clock_t *clock, axiam_oidc_token_set_t *out,
                                    axiam_error_t *err) {
    axiam_error_reset(err);
    if (!out || !initiated) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    memset(out, 0, sizeof(*out));
    if (oidc_client_unusable(c, err)) return AXIAM_ERR_NETWORK;
    const char *client_id = NULL, *secret = NULL;
    axiam_error_kind_t kind = ciba_client_auth(c, "ciba_await", &client_id, &secret, err);
    if (kind != AXIAM_OK) return kind;
    const char *raw = axiam_sensitive_reveal(initiated->auth_req_id);
    if (!raw || !raw[0]) {
        axiam_local_refusal(err, "ciba_await", "auth_req_id", "an auth_req_id is required");
        return AXIAM_ERR_NETWORK;
    }
    const char *tenant = oidc_require_tenant_uuid(c, tenant_id, "ciba_await", err);
    if (!tenant) return AXIAM_ERR_AUTH;
    axiam_oidc_config_t fetched;
    const axiam_oidc_config_t *use = NULL;
    int owned = 0;
    kind = ciba_config(c, config, &fetched, &use, &owned, err);
    if (kind != AXIAM_OK) return kind;

    axiam_ciba_clock_t own = {client_now, client_sleep, c};
    const axiam_ciba_clock_t *clk = (clock && clock->now && clock->sleep) ? clock : &own;
    long interval = initiated->interval > 0 ? initiated->interval : AXIAM_CIBA_DEFAULT_INTERVAL_S;
    time_t deadline = initiated->received_at + (time_t)initiated->expires_in;

    for (;;) {
        /* §33.7 rule 4: the NEXT poll must fall before the deadline. */
        if (clk->now(clk->ctx) + (time_t)interval >= deadline) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "expired_token: the CIBA request expired before it was decided "
                            "(client-side deadline from expires_in; CONTRACT.md \xc2\xa7" "33.7 rule 4)");
            if (err) snprintf(err->oauth_error, sizeof(err->oauth_error), "expired_token");
            kind = AXIAM_ERR_AUTH;
            break;
        }
        /* §33.7 rule 2: the first poll waits too. */
        clk->sleep(clk->ctx, interval);

        axiam_error_t poll_err;
        axiam_error_reset(&poll_err);
        int transient = 0;
        kind = ciba_poll_with(c, use, raw, client_id, secret, tenant, out, &transient, &poll_err);
        if (kind == AXIAM_OK) break;
        if (transient || strcmp(poll_err.oauth_error, "authorization_pending") == 0) continue;
        if (strcmp(poll_err.oauth_error, "slow_down") == 0) {
            /* §33.7 rule 3: permanent and cumulative, never reset. */
            interval += AXIAM_CIBA_SLOW_DOWN_INCREMENT_S;
            continue;
        }
        /* access_denied, expired_token, invalid_grant, an unknown code, a refused call:
         * the answer, with its code intact so the two refusals stay distinct. */
        if (err) *err = poll_err;
        break;
    }
    if (owned) axiam_oidc_config_dispose(&fetched);
    if (kind != AXIAM_OK) axiam_oidc_token_set_dispose(out);
    return kind;
}

/* ------------------------------------------------------------------ */
/* ciba_handle_ping -- pure, no I/O                                   */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_ciba_handle_ping(const axiam_kv_t *headers, const char *body,
                                          size_t body_len,
                                          const axiam_sensitive_t *expected_token,
                                          axiam_sensitive_t **out_auth_req_id,
                                          axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_auth_req_id) *out_auth_req_id = NULL;
    static const char refused[] = "ciba ping refused: the Authorization header is not the "
                                  "expected bearer (CONTRACT.md \xc2\xa7" "33.1)";

    /* 1. Exactly one Authorization header. */
    const char *value = NULL;
    int count = 0;
    for (const axiam_kv_t *h = headers; h; h = h->next) {
        if (h->key && strcasecmp(h->key, "Authorization") == 0) {
            count++;
            value = h->value;
        }
    }
    const char *space = (count == 1 && value) ? strchr(value, ' ') : NULL;
    const unsigned char *expected = axiam_sensitive_bytes(expected_token);
    size_t expected_len = axiam_sensitive_len(expected_token);
    if (!space || (size_t)(space - value) != 6 || strncasecmp(value, "Bearer", 6) != 0 ||
        !expected || expected_len == 0) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, refused);
        return AXIAM_ERR_AUTH;
    }
    /* Exactly one space: a second one becomes part of the presented token, which then
     * cannot equal the expected one. The length is not secret; the bytes are compared in
     * constant time. */
    const char *token = space + 1;
    size_t token_len = strlen(token);
    if (token_len != expected_len || CRYPTO_memcmp(token, expected, expected_len) != 0) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, refused);
        return AXIAM_ERR_AUTH;
    }

    /* 2. A JSON object with a non-empty string auth_req_id; other members ignored. */
    cJSON *root = body ? cJSON_ParseWithLength(body, body_len) : NULL;
    const cJSON *id = cJSON_IsObject(root) ? cJSON_GetObjectItemCaseSensitive(root, "auth_req_id") : NULL;
    if (!cJSON_IsString(id) || !id->valuestring[0]) {
        cJSON_Delete(root);
        axiam_local_refusal(err, "ciba_handle_ping", "auth_req_id",
                            "the ping body is not a JSON object carrying a non-empty "
                            "auth_req_id string");
        return AXIAM_ERR_NETWORK;
    }
    axiam_sensitive_t *result = axiam_sensitive_new(id->valuestring);
    axiam_secure_zero(id->valuestring, strlen(id->valuestring));
    cJSON_Delete(root);
    if (!result) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    if (out_auth_req_id) *out_auth_req_id = result;
    else axiam_sensitive_free(result);
    return AXIAM_OK;
}
