/*
 * AXIAM C SDK — internal shared declarations (NOT installed).
 *
 * This header exposes module-private structure definitions and helpers shared
 * across translation units. The only route to a Sensitive raw value lives here
 * (axiam_sensitive_bytes) — it is deliberately absent from the public headers.
 */
#ifndef AXIAM_INTERNAL_H
#define AXIAM_INTERNAL_H

#include <pthread.h>
#include <stddef.h>
#include <time.h>

#include "axiam/axiam.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Sensitive (module-private raw accessor) ---- */
struct axiam_sensitive {
    unsigned char *data;
    size_t len;
};
/** Module-private: raw bytes of a Sensitive value. NOT a public API (§7). */
const unsigned char *axiam_sensitive_bytes(const axiam_sensitive_t *s);

/* ---- Config ---- */
struct axiam_client_config {
    char *base_url;
    char *tenant_slug;
    char *tenant_id;
    char *org_slug;
    char *org_id;
    char *custom_ca_pem;      /* owned, may be NULL */
    char *client_cert_pem;    /* owned, may be NULL */
    axiam_sensitive_t *client_key; /* mTLS private key behind Sensitive (§7) */
    long timeout_ms;
    long connect_timeout_ms;
    axiam_transport_fn transport;
    void *transport_ctx;
};
axiam_client_config_t *axiam_client_config_clone(const axiam_client_config_t *src);

/* ---- Client ---- */
struct axiam_jwk {
    char *kid;
    unsigned char x[32]; /* raw Ed25519 public key */
    int x_len;
    struct axiam_jwk *next;
};

struct axiam_client {
    axiam_client_config_t *cfg; /* owned clone */
    axiam_transport_fn transport;
    void *transport_ctx;
    void *curl_ctx;             /* owned libcurl ctx when using default transport */

    /* session state */
    int authenticated;          /* set after login/verify_mfa success */

    /* CSRF (§3): last captured X-CSRF-Token */
    pthread_mutex_t state_mtx;
    char *csrf_token;

    /* single-flight refresh (§9) */
    pthread_mutex_t refresh_mtx;
    pthread_cond_t refresh_cond;
    int refresh_in_flight;
    axiam_error_kind_t refresh_result;
    unsigned long refresh_count;

    /* JWKS cache */
    pthread_mutex_t jwks_mtx;
    struct axiam_jwk *jwks;
    time_t jwks_fetched_at;
    int jwks_valid;
};

/* ---- Default libcurl transport ---- */
/* Build a libcurl transport context from a config (applies TLS, mTLS, cookie
 * jar). Returns NULL on failure. */
void *axiam_curl_ctx_new(const axiam_client_config_t *cfg);
void  axiam_curl_ctx_free(void *ctx);
int   axiam_curl_transport(void *ctx, const axiam_http_request_t *req,
                           axiam_http_response_t *resp);

/* Internal: perform a non-state-changing GET and return the body on 2xx. */
axiam_error_kind_t axiam_client_raw_get(axiam_client_t *c, const char *path,
                                        char **out_body, axiam_error_t *err);

/* ---- Small helpers ---- */
char *axiam_strdup0(const char *s); /* strdup that tolerates NULL -> NULL */
int   axiam_str_ieq(const char *a, const char *b);
int   axiam_is_pem(const char *s); /* crude "-----BEGIN" check */

/* base64url decode; returns malloc'd buffer + sets *out_len, or NULL. */
unsigned char *axiam_b64url_decode(const char *in, size_t in_len, size_t *out_len);

/* JSON string escaping into a cJSON-built object is used directly; these are
 * the request builders (return malloc'd JSON strings). */
char *axiam_build_login_body(const char *user, const char *password,
                             const axiam_client_config_t *cfg);
char *axiam_build_mfa_body(const char *challenge_token, const char *totp_code);
char *axiam_build_refresh_body(const axiam_client_config_t *cfg);
char *axiam_build_check_body(const char *action, const char *resource_id,
                             const char *scope, const char *subject_id);
char *axiam_build_batch_body(const axiam_check_input_t *checks, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_INTERNAL_H */
