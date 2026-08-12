/*
 * AXIAM C SDK — internal shared declarations (NOT installed).
 *
 * This header exposes module-private structure definitions and helpers shared
 * across translation units, including axiam_sensitive_bytes(). Since contract
 * 1.11 that is no longer the ONLY route to a raw Sensitive value — §12 needs
 * one the caller can use, so §7 rule 3's single explicit accessor
 * (axiam_sensitive_reveal) is public. This one stays because internal code
 * wants `const unsigned char *` rather than a string.
 */
#ifndef AXIAM_INTERNAL_H
#define AXIAM_INTERNAL_H

#include <pthread.h>
#include <stddef.h>
#include <time.h>

#include "axiam/axiam.h"
#include "axiam/oidc.h"
#include "axiam/uma.h"

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
    /* Optional local-verification expectations (CONTRACT §10.1 rules 5/6).
     * NULL = unset = the corresponding claim is not checked. Never defaulted
     * to a hardcoded value. */
    char *expected_issuer;    /* owned, may be NULL */
    char *expected_audience;  /* owned, may be NULL */
    axiam_sensitive_t *client_key; /* mTLS private key behind Sensitive (§7) */
    /* §12 relying-party identity. client_id is not a per-call argument (§12.1):
     * §12.4 rule 4 compares the ID token's `aud` against the SAME value, and
     * two sources could disagree. The secret is behind Sensitive (§12.3 rule 2). */
    char *oidc_client_id;
    axiam_sensitive_t *oidc_client_secret;
    /* §12.3 rule 6 discovery TTL, seconds, AFTER clamping up to the 5-minute
     * floor. 0 = use the floor. */
    long oidc_discovery_ttl_s;
    /* §12.4 rule 5 clock skew, seconds, AFTER clamping into [0, 60]. -1 = the
     * 60-second default; a larger request is clamped DOWN, not rejected. */
    long oidc_clock_skew_s;
    long timeout_ms;
    long connect_timeout_ms;
    axiam_transport_fn transport;
    void *transport_ctx;
    /* §16: on by default. Only ever lowered to 0 — the table is not settable. */
    int retry_enabled;
    /* §17: requested memo TTL in ms, BEFORE clamping. 0 = disabled. Kept
     * unclamped so the §19 config_clamped event can report what was asked
     * for; the effective value lives on the memo. */
    long decision_memo_ttl_ms;
    /* §19 */
    axiam_telemetry_hook_fn telemetry_hook;
    void *telemetry_ctx;
};
axiam_client_config_t *axiam_client_config_clone(const axiam_client_config_t *src);

/* ---- §19 telemetry dispatch ---- */
typedef struct axiam_telemetry {
    axiam_telemetry_hook_fn fn;
    void *ctx;
} axiam_telemetry_t;

/** 1 when a hook is installed. The whole cost of §19 when one is not. */
int axiam_telemetry_installed(const axiam_telemetry_t *t);
/** Deliver `ev`. No-op when no hook is installed. */
void axiam_telemetry_emit(const axiam_telemetry_t *t, const axiam_telemetry_event_t *ev);
/** Emit a request_start. */
void axiam_telemetry_request_start(const axiam_telemetry_t *t, const char *op,
                                   const char *method, const char *path, int attempt);
/** Emit the request_end closing the pair opened by axiam_telemetry_request_start. */
void axiam_telemetry_request_end(const axiam_telemetry_t *t, const char *op,
                                 const char *method, const char *path, int attempt,
                                 long status, double duration_ms,
                                 axiam_telemetry_outcome_t outcome);
/** Emit a §16.5 retry event. */
void axiam_telemetry_retry(const axiam_telemetry_t *t, const char *op, int attempt,
                           long delay_ms, const char *reason);
/** Emit a §9 refresh event. */
void axiam_telemetry_refresh(const axiam_telemetry_t *t, axiam_refresh_role_t role,
                             double duration_ms);
/** Emit a §19.2 rule 6 config_clamped event. */
void axiam_telemetry_config_clamped(const axiam_telemetry_t *t, const char *setting,
                                    const char *requested, const char *effective,
                                    const char *contract_reference);
/** Monotonic milliseconds, for event durations. */
double axiam_now_ms(void);

/* ---- §16 bounded read-only retry ---- */

/** §16.1: 1 initial attempt + 2 retries. NOT configurable upward. */
#define AXIAM_RETRY_MAX_ATTEMPTS 3
/** §16.1 base delay, milliseconds. */
#define AXIAM_RETRY_BASE_DELAY_MS 200L
/** §16.1 ceiling on any single wait, milliseconds. */
#define AXIAM_RETRY_MAX_DELAY_MS 5000L

/** §16.1 backoff before jitter: min(cap, base << (attempt-1)). */
long axiam_retry_backoff_ms(int attempt);

/**
 * §16.1 wait for `attempt`, given a uniform `fraction` in [0,1] and a
 * `retry_after_ms` of -1 when the server sent no hint.
 *
 * Full jitter: the wait is `backoff * fraction`, i.e. uniform over
 * [0, backoff] — not `backoff ± something`. Retry-After is a FLOOR: it can
 * only lengthen the wait, so a `Retry-After: 0` cannot defeat the backoff.
 */
long axiam_retry_delay_ms(int attempt, long retry_after_ms, double fraction);

/**
 * §16.3: 1 when a completed exchange should be retried. `transport_failed` is
 * nonzero when no HTTP response arrived at all.
 */
int axiam_retry_should_retry(int transport_failed, long status);

/** Parse a Retry-After header (delta-seconds or HTTP-date). -1 when absent or
 *  unparseable — an unparseable hint must not become a zero-length floor. */
long axiam_retry_after_ms(const char *header_value);

/** Uniform fraction in [0,1]. Not cryptographic; §16.1 says it need not be. */
typedef double (*axiam_jitter_fn)(void *ctx);
/** Sleep seam, so a test can observe a delay without taking it. */
typedef void (*axiam_sleep_fn)(void *ctx, long ms);

/**
 * Wall-clock seam, in seconds. The §14.2 rule 4 deadline is the only thing in
 * this SDK whose correctness depends on time PASSING rather than on a duration,
 * and §14.6 requires asserting that polling stops at `expires_in`. With the
 * sleep seam alone a test's clock never advances, so the assertion is
 * unwritable; with both, a 600-second grant runs in microseconds and the
 * intervals themselves become observable. Module-private for the same reason
 * the sleep seam is: a public knob for "what time is it" would be an
 * attractive nuisance.
 */
typedef time_t (*axiam_clock_fn)(void *ctx);

/** Default jitter source (rand_r on a per-client seed). */
double axiam_default_jitter(void *ctx);
/** Default sleep (nanosleep). */
void axiam_default_sleep(void *ctx, long ms);
/** Default clock (time(NULL)). */
time_t axiam_default_clock(void *ctx);

/* ---- §17 client-side decision memo ---- */

/** §17.1 rule 2 ceiling, milliseconds. A larger TTL is clamped, not rejected. */
#define AXIAM_MEMO_MAX_TTL_MS 5000L
/** §17.1 rule 8 entry cap before FIFO eviction. */
#define AXIAM_MEMO_MAX_ENTRIES 1024

struct axiam_memo_entry {
    char *key;
    int allowed;
    char *reason;
    char *reason_code;
    double stored_at_ms;
    struct axiam_memo_entry *next; /* insertion order: head = oldest */
};

typedef struct axiam_memo {
    pthread_mutex_t mtx;
    long ttl_ms; /* AFTER clamping; 0 = disabled */
    size_t count;
    struct axiam_memo_entry *head; /* oldest */
    struct axiam_memo_entry *tail; /* newest */
} axiam_memo_t;

/** Initialise a memo from a requested (unclamped) TTL. */
void axiam_memo_init(axiam_memo_t *m, long requested_ttl_ms);
/** 1 when the memo does anything. 0 for the default configuration. */
int axiam_memo_enabled(const axiam_memo_t *m);
/** The TTL after clamping, milliseconds. */
long axiam_memo_effective_ttl_ms(const axiam_memo_t *m);
/**
 * §17.1 rule 3 key: all four components, absent distinguished from present.
 * Returns a malloc'd string, or NULL on OOM.
 */
char *axiam_memo_key(const char *subject_id, const char *resource_id,
                     const char *action, const char *scope);
/** Copy a live decision into `out` and return 1, or return 0 on a miss. */
int axiam_memo_get(axiam_memo_t *m, const char *key, axiam_check_result_t *out);
/** Memoize a decision the server actually returned (§17.1 rule 7: successes only). */
void axiam_memo_put(axiam_memo_t *m, const char *key, const axiam_check_result_t *r);
/** Drop every entry (§17.1 rule 9). */
void axiam_memo_clear(axiam_memo_t *m);
/** Entry count, for tests. */
size_t axiam_memo_count(axiam_memo_t *m);
/** Release everything the memo owns. */
void axiam_memo_destroy(axiam_memo_t *m);

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

    /* Tenant/org UUIDs resolved from the access-token claims at login (D-14),
     * used to build the refresh body when the client was configured with slugs.
     * Guarded by state_mtx. */
    char *resolved_tenant_id;
    char *resolved_org_id;

    /* single-flight refresh (§9) */
    pthread_mutex_t refresh_mtx;
    pthread_cond_t refresh_cond;
    int refresh_in_flight;
    axiam_error_kind_t refresh_result;
    unsigned long refresh_count;

    /* §20 UMA discovery cache, guarded by state_mtx. An endpoint map is not a
     * credential, and re-fetching it on every guarded request is a
     * self-inflicted round trip. */
    axiam_uma_config_t uma_config;
    time_t uma_config_fetched_at;
    int uma_config_valid;

    /* §12 OIDC discovery cache. Per-client-instance, which satisfies §12.3
     * rule 6's origin rule by construction (a client is bound to one base URL
     * for its lifetime) and is NOT keyed on the tenant, because the document
     * carries no tenant-specific content. Guarded by oidc_config_mtx, which is
     * held across the FETCH as well as the copy: that is the single-flight
     * rule 6 requires, in its simplest correct form — a second caller blocks,
     * then finds the cache warm. */
    pthread_mutex_t oidc_config_mtx;
    axiam_oidc_config_t oidc_config;
    time_t oidc_config_fetched_at;
    int oidc_config_valid;

    /* §12.1 / §9 rule 2 single-flight for oidc_refresh, keyed on the refresh
     * token's digest. AXIAM rotates refresh tokens, so two threads racing on
     * one token would spend it twice and the loser would see an invalid_grant
     * for a token that was good a millisecond earlier. Guarded by
     * oidc_refresh_mtx + oidc_refresh_cond. */
    pthread_mutex_t oidc_refresh_mtx;
    pthread_cond_t oidc_refresh_cond;
    struct axiam_oidc_flight *oidc_refresh_flights;
    unsigned long oidc_refresh_count;

    /* JWKS cache */
    pthread_mutex_t jwks_mtx;
    struct axiam_jwk *jwks;
    time_t jwks_fetched_at;
    int jwks_valid;
    /* §12.4 rule 2: when the unknown-`kid` re-fetch cooldown window closes. An
     * unknown kid inside the window re-consults the cached set with NO network
     * call, so an attacker presenting forged kids cannot drive one JWKS fetch
     * per token. 0 = no window open. */
    time_t jwks_refetch_cooldown_until;

    /* §16 retry. The seams are module-private on purpose: §16.1 forbids
     * raising the table, and a public knob for the jitter source or the sleep
     * would be an attractive nuisance. Tests reach them through internal.h. */
    int retry_enabled;
    axiam_jitter_fn jitter_fn;
    void *jitter_ctx;
    axiam_sleep_fn sleep_fn;
    void *sleep_ctx;
    axiam_clock_fn clock_fn;
    void *clock_ctx;
    unsigned int rand_seed;

    /* §17 decision memo. Disabled unless the config carried a TTL. */
    axiam_memo_t memo;

    /* §19 telemetry. */
    axiam_telemetry_t telemetry;

    /* §18 shutdown flag, guarded by state_mtx and read on every operation. */
    int closed;
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

/* ---- §12.4 verification seam (implemented in jwks.c) ---- */

/**
 * Signature + `alg` pin only, with the §12.4 reason code written into
 * `out_reason` (invalid_alg / unknown_kid / invalid_signature). This is the
 * SAME verifier the §10 guards use — §12.4 says "extend it, never fork it", so
 * §12 layers rules 3–6 on top of this rather than re-implementing key lookup.
 *
 * `out_claims_json` receives the decoded payload on success (caller frees).
 */
axiam_error_kind_t axiam_jwt_verify_reasoned(axiam_client_t *client, const char *token,
                                             char **out_claims_json,
                                             char *out_reason, size_t reason_cap,
                                             axiam_error_t *err);

/* ---- §12 internals shared across the OIDC translation units ---- */

/** Release the members the client owns for §12 (called from close/free). */
void axiam_oidc_client_dispose(axiam_client_t *c);

/* ---- Small helpers ---- */
char *axiam_strdup0(const char *s); /* strdup that tolerates NULL -> NULL */
int   axiam_str_ieq(const char *a, const char *b);
int   axiam_is_pem(const char *s); /* crude "-----BEGIN" check */

/* Overwrite `n` bytes at `p` with zeroes in a way the compiler may not elide
 * (§7 scrub-before-release). Safe on NULL. */
void  axiam_secure_zero(void *p, size_t n);

/* §6 transport-URL guard: 1 when `url` uses `https://`, or a non-TLS scheme
 * against a loopback authority (localhost / 127.0.0.1 / ::1) — the only
 * development exception. 0 for every other (plaintext / scheme-less) URL. */
int   axiam_url_is_secure(const char *url);

/* base64url decode; returns malloc'd buffer + sets *out_len, or NULL. */
unsigned char *axiam_b64url_decode(const char *in, size_t in_len, size_t *out_len);

/* JSON string escaping into a cJSON-built object is used directly; these are
 * the request builders (return malloc'd JSON strings). */
char *axiam_build_login_body(const char *user, const char *password,
                             const axiam_client_config_t *cfg);
char *axiam_build_mfa_body(const char *challenge_token, const char *totp_code);
char *axiam_build_refresh_body(const char *tenant_id, const char *org_id);
char *axiam_build_check_body(const char *action, const char *resource_id,
                             const char *scope, const char *subject_id);
char *axiam_build_batch_body(const axiam_check_input_t *checks, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_INTERNAL_H */
