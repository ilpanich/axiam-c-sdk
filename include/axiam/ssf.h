/**
 * @file ssf.h
 * @brief CONTRACT.md §32.7 — the SSF receiver helper (contract 1.56).
 *
 * AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC security events
 * as Security Event Tokens (RFC 8417) to the relying parties a tenant administrator
 * registered (the §27 `ssf` namespace, `axiam_ssf_*_stream` in axiam/management_ops.h).
 * This header is for the **relying party** that receives them — a different audience
 * from that namespace:
 *
 * | Canonical        | C                       |
 * |------------------|-------------------------|
 * | `ssf.verify_set` | axiam_ssf_verify_set()  |
 * | `ssf.poll`       | axiam_ssf_poll()        |
 *
 * Neither transmits, signs or registers anything, and neither trusts a key it did not
 * fetch from the configured JWKS: no `jwk` or `x5c` header member is honoured (§32.9).
 * Both perform I/O only to fetch the JWKS (or the SSF configuration document) and, for
 * poll, to call the poll endpoint — through the client's transport and so its §6 TLS
 * policy, but never as the client's session: no cookie, no CSRF token, no device bearer.
 *
 * A receiver is safe to share between threads.
 */
#ifndef AXIAM_SSF_H
#define AXIAM_SSF_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @name Event types (§32.6)
 *  The six AXIAM transmits and the two SSF stream events. Event types are OPEN: a SET
 *  whose type is not among these still verifies, and axiam_security_event_t::event_type
 *  carries it verbatim. */
/**@{*/
#define AXIAM_SSF_EVENT_SESSION_REVOKED \
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
#define AXIAM_SSF_EVENT_CREDENTIAL_CHANGE \
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
#define AXIAM_SSF_EVENT_ASSURANCE_LEVEL_CHANGE \
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
#define AXIAM_SSF_EVENT_ACCOUNT_DISABLED \
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
#define AXIAM_SSF_EVENT_ACCOUNT_ENABLED \
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
#define AXIAM_SSF_EVENT_ACCOUNT_PURGED \
    "https://schemas.openid.net/secevent/risc/event-type/account-purged"
#define AXIAM_SSF_EVENT_VERIFICATION \
    "https://schemas.openid.net/secevent/ssf/event-type/verification"
#define AXIAM_SSF_EVENT_STREAM_UPDATED \
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
/**@}*/

/** The replay window's floor AND default, seconds: seven days, the transmitter's buffer
 *  retention (§32.6). A shorter window would forget a `jti` the transmitter can still
 *  re-send, so a configuration asking for one is refused. */
#define AXIAM_SSF_MIN_REPLAY_WINDOW_S (7L * 24L * 60L * 60L)

/** The fetch rate limit, seconds (§32.7 step 4; §34.2 P6). Counted: the refetch an
 *  unknown `kid` forces, whether or not it succeeds, and every FAILED fetch -- a failed
 *  fill of the empty cache, a failed refresh of an expired one. Not counted: a successful
 *  fill or refresh. Within this interval of a counted fetch no fetch is made. */
#define AXIAM_SSF_JWKS_REFETCH_INTERVAL_S 60L

/** The key cache's lifetime, seconds (§34.2 P6, contract 1.60: no later than 10 minutes
 *  after the successful fetch that filled it). The next SET after it fetches again; a key
 *  the transmitter has removed is not used past it. */
#define AXIAM_SSF_JWKS_CACHE_TTL_S 600L

/**
 * Why a SET was refused (§32.7). The typed accessor C offers in place of an exception
 * sub-type: axiam_ssf_verify_set() writes it through its `out_reason` parameter, and each
 * refused SET of a poll carries one.
 */
typedef enum axiam_ssf_reason {
    AXIAM_SSF_REASON_NONE = 0,         /**< Not a refusal. */
    AXIAM_SSF_REASON_MALFORMED,        /**< Step 1: not three base64url parts of JSON objects. */
    AXIAM_SSF_REASON_INVALID_TYPE,     /**< Step 2: `typ` is not `secevent+jwt`. */
    AXIAM_SSF_REASON_INVALID_KEY,      /**< Steps 3–5: `alg`, `kid` or the signature. */
    AXIAM_SSF_REASON_INVALID_ISSUER,   /**< Step 6: `iss` is not the configured issuer. */
    AXIAM_SSF_REASON_INVALID_AUDIENCE, /**< Step 7: `aud` does not name this receiver. */
    AXIAM_SSF_REASON_INVALID_REQUEST,  /**< Step 8: the claims are not a SET's. */
    AXIAM_SSF_REASON_REPLAYED          /**< Step 9: the `jti` was seen within the window. */
} axiam_ssf_reason_t;

/** The reason code: `malformed`, `invalid_type`, `invalid_key`, `invalid_issuer`,
 *  `invalid_audience`, `invalid_request` or `replayed` ("" for NONE). Never NULL. */
const char *axiam_ssf_reason_code(axiam_ssf_reason_t reason);

/**
 * The RFC 8935 §2.4 `err` a push endpoint answers with (`400 {"err": ...}`): the reason
 * code itself for `invalid_key`, `invalid_issuer`, `invalid_audience` and
 * `invalid_request`, and **`invalid_request` for `malformed`, `invalid_type` and
 * `replayed`**, which are not RFC 8935 codes. Never NULL.
 */
const char *axiam_ssf_push_error_code(axiam_ssf_reason_t reason);

/**
 * The replay store (§32.7 step 9), pluggable so a receiver running several instances can
 * share one. Record `jti` for `window_s` seconds and return 1, or return 0 without
 * recording when it is already held. MUST be atomic: two concurrent calls with one `jti`
 * must not both return 1. A negative return is a store failure, reported as
 * AXIAM_ERR_NETWORK rather than as a verdict on the SET.
 */
typedef int (*axiam_ssf_replay_check_fn)(void *ctx, const char *jti, long window_s);

/**
 * Supplies the bearer axiam_ssf_poll() presents: a client-credentials access token
 * carrying `ssf.manage` (for example from axiam_login_client_credentials()). Called once
 * per poll. On success return AXIAM_OK with `*out_token` a new Sensitive the helper frees;
 * otherwise return the failing kind with `err` filled.
 */
typedef axiam_error_kind_t (*axiam_ssf_token_fn)(void *ctx, axiam_sensitive_t **out_token,
                                                 axiam_error_t *err);

/** A receiver configuration (§32.7: `{ issuer, audience, jwks_uri | discovery_url,
 *  access_token_provider }`). Copied by axiam_ssf_receiver_new(); nothing is borrowed. */
typedef struct axiam_ssf_receiver_config {
    /** The transmitter's issuer — compared to `iss` exactly. Required. */
    const char *issuer;
    /** This receiver's audience — the stream's `audience`. Required. */
    const char *audience;
    /** The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`). Exactly one of this and
     *  `discovery_url`. */
    const char *jwks_uri;
    /** The transmitter's SSF configuration document (`/.well-known/ssf-configuration…`):
     *  its `issuer` must equal `issuer`, and its `jwks_uri` is used. */
    const char *discovery_url;
    /** The bearer for axiam_ssf_poll(); NULL for a push-only receiver. */
    axiam_ssf_token_fn access_token_provider;
    void *access_token_ctx; /**< Passed to `access_token_provider`. */
    /** How long a `jti` is remembered, seconds. 0 means the default; anything below
     *  AXIAM_SSF_MIN_REPLAY_WINDOW_S is refused. */
    long replay_window_s;
    /** Where accepted `jti`s are kept; NULL uses the in-memory store (one process, lost
     *  on restart, expired entries dropped as it goes). */
    axiam_ssf_replay_check_fn replay_store;
    void *replay_ctx; /**< Passed to `replay_store`. */
} axiam_ssf_receiver_config_t;

/** An opaque receiver. Free with axiam_ssf_receiver_free(). */
typedef struct axiam_ssf_receiver axiam_ssf_receiver_t;

/**
 * Build a receiver over `client`'s transport. `client` is BORROWED and must outlive the
 * receiver: its transport fetches the JWKS and its base URL is the transmitter root
 * axiam_ssf_poll() calls. No I/O happens here — the keys are fetched on first use.
 *
 * Returns NULL with `err` set to this SDK's local ValidationError (AXIAM_ERR_NETWORK,
 * transport_cause 400) when the issuer or audience is missing, when not exactly one of
 * `jwks_uri` and `discovery_url` is set, when that URL is not `https` (or `http` on
 * loopback), or when `replay_window_s` is below seven days.
 */
axiam_ssf_receiver_t *axiam_ssf_receiver_new(axiam_client_t *client,
                                             const axiam_ssf_receiver_config_t *config,
                                             axiam_error_t *err);

/** Free a receiver and its key cache and in-memory replay store. Safe on NULL. */
void axiam_ssf_receiver_free(axiam_ssf_receiver_t *receiver);

/** A verified Security Event Token (§32.7's result). Every member is owned; release with
 *  axiam_security_event_dispose(). */
typedef struct axiam_security_event {
    char *jti;        /**< The SET's unique id. */
    long iat;         /**< When it was issued, seconds since the epoch. */
    char *iss;        /**< The issuer, equal to the configured one. */
    char *aud;        /**< The audience AS SENT, as JSON text: a string or an array. */
    char *txn;        /**< The transaction id shared by one operation's SETs, or NULL. */
    char *event_type; /**< The single `events` key — an event-type URI. */
    char *event;      /**< That event's object, as JSON text; opaque to the helper. */
    char *sub_id;     /**< The RFC 9493 subject identifier, as JSON text; opaque. */
} axiam_security_event_t;

/** Release the members of an event (not the struct). Safe on NULL. */
void axiam_security_event_dispose(axiam_security_event_t *event);

/**
 * Verify one compact SET (§32.7), in this order, refusing at the first failure with
 * AXIAM_ERR_AUTH and the reason written to `*out_reason`:
 *
 * 1. three base64url parts that decode, a JSON object header and payload [malformed];
 * 2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case [invalid_type];
 * 3. `alg` exactly `EdDSA` — `none`, every `HS*` and every other value refused [invalid_key];
 * 4. the key named by `kid` in the configured JWKS; on an unknown `kid`, ONE refetch, at
 *    most once a minute, then refusal [invalid_key];
 * 5. the Ed25519 signature [invalid_key];
 * 6. `iss` equal to the configured issuer, exactly [invalid_issuer];
 * 7. `aud` equal to the configured audience, or an array containing it [invalid_audience];
 * 8. no `exp` and no `sub`; a non-empty string `jti`, a numeric `iat`, an object `sub_id`;
 *    `events` an object with exactly one member [invalid_request];
 * 9. a `jti` not seen within the replay window [replayed] — recorded only once 1–8 passed.
 *
 * **A SET that verifies has been recorded**: verifying it again is `replayed`. A polled
 * SET you processed must therefore be acknowledged on the next poll.
 *
 * A JWKS (or configuration document) that cannot be fetched is AXIAM_ERR_NETWORK with
 * `*out_reason` NONE — not a verdict on the SET. The keys are cached for
 * AXIAM_SSF_JWKS_CACHE_TTL_S; within AXIAM_SSF_JWKS_REFETCH_INTERVAL_S of a failed fetch
 * no fetch is made and the SET gets the same AXIAM_ERR_NETWORK (contract 1.60, P6), so a
 * JWKS outage is not one fetch per SET.
 *
 * @param out        Receives the event on AXIAM_OK; zeroed otherwise. Dispose with
 *                   axiam_security_event_dispose().
 * @param out_reason Receives the refusal reason (NONE on success or on a non-refusal
 *                   failure); may be NULL.
 */
axiam_error_kind_t axiam_ssf_verify_set(axiam_ssf_receiver_t *receiver, const char *set,
                                        axiam_security_event_t *out,
                                        axiam_ssf_reason_t *out_reason, axiam_error_t *err);

/** One RFC 8936 `setErrs` entry: the `jti` you refuse, the RFC 8935 `err`, and an optional
 *  description (AXIAM never stores it, §32.6). All three are borrowed. */
typedef struct axiam_ssf_set_err {
    const char *jti;
    const char *err;
    const char *description; /**< NULL omits it. */
} axiam_ssf_set_err_t;

/** The `setErrs` entry for a refusal: `err` is axiam_ssf_push_error_code(reason). */
axiam_ssf_set_err_t axiam_ssf_set_err_from_reason(const char *jti, axiam_ssf_reason_t reason);

/** Arguments to axiam_ssf_poll(). Every member is passed through as given; an unset one
 *  is not sent. All pointers are borrowed for the call. */
typedef struct axiam_ssf_poll_options {
    /** `maxEvents` — the server clamps it to 100; `0` acknowledges and returns nothing. */
    long max_events;
    int has_max_events; /**< 1 sends `max_events`. */
    /** `returnImmediately` — without it the server long-polls up to 30 s. */
    int return_immediately;
    int has_return_immediately; /**< 1 sends `return_immediately`. */
    /** `ack` — the `jti`s you PROCESSED since the last poll. Non-NULL sends the array
     *  (an empty one when `ack_count` is 0); NULL omits it. */
    const char *const *ack;
    size_t ack_count;
    /** `setErrs` — the `jti`s you refuse. Non-NULL sends the object (an empty one when
     *  `set_errs_count` is 0); NULL omits it. */
    const axiam_ssf_set_err_t *set_errs;
    size_t set_errs_count;
} axiam_ssf_poll_options_t;

/** A SET a poll returned and the helper refused. */
typedef struct axiam_ssf_refused_set {
    char *jti;                 /**< The key the transmitter returned it under. */
    axiam_ssf_reason_t reason; /**< Why; pass axiam_ssf_set_err_from_reason() of it next time. */
} axiam_ssf_refused_set_t;

/** What axiam_ssf_poll() returns. Release with axiam_ssf_poll_result_dispose(). */
typedef struct axiam_ssf_poll_result {
    axiam_security_event_t *events;   /**< The SETs that verified, in the map's order. */
    size_t events_count;
    int more_available;               /**< Whether the transmitter holds more. */
    axiam_ssf_refused_set_t *refused; /**< The SETs that did not verify. */
    size_t refused_count;
    /** The keys of the SETs this poll could NOT judge (contract 1.59, P1): a JWKS or
     *  configuration fetch, or the replay store, failed before a verdict. They are in
     *  neither `events` nor `refused`, and their `jti`s were not recorded — neither
     *  acknowledge nor refuse them, and the transmitter offers them again. */
    char **unjudged;
    size_t unjudged_count;
} axiam_ssf_poll_result_t;

/** Release the members of a poll result (not the struct). Safe on NULL. */
void axiam_ssf_poll_result_dispose(axiam_ssf_poll_result_t *result);

/**
 * Poll the stream's RFC 8936 endpoint, `POST {client base URL}/ssf/v1/poll/{stream_id}`,
 * with `Authorization: Bearer` from the configured `access_token_provider` (none
 * configured: a local AXIAM_ERR_AUTH and no request) and a JSON body carrying exactly the
 * members `options` sets (`{}` when it sets none, or is NULL).
 *
 * Every returned SET is verified with axiam_ssf_verify_set(); one whose verified `jti`
 * differs from the key it was returned under is refused `invalid_request`, and one that is
 * not a string `malformed`. The verified and the refused come back apart. **Nothing is
 * acknowledged on your behalf**: acknowledge, on the next call, the `jti`s you processed,
 * and pass each refused one in `set_errs` — except one refused `replayed`, which this
 * receiver accepted on an earlier poll: acknowledge that one (contract 1.59, P2). A SET
 * you neither acknowledge nor refuse is re-offered — and, having been recorded when it
 * verified, then reads as `replayed`.
 *
 * Retried per §16 on a transport failure, a `5xx`, `408` or `429` — never on another
 * `4xx`, which maps as on the management surface (`400` validation, `404` not found, …).
 *
 * **A poll never keeps a `jti` it does not return** (contract 1.59, P1). A failure that is
 * not a verdict on a SET — a JWKS or configuration fetch, a replay store that cannot
 * answer — stops the batch there: that SET and the ones after it are unjudged, not
 * recorded, and listed in `out->unjudged`; the transmitter offers them again. When SETs
 * before it were judged, the call returns AXIAM_OK with them in `events` and `refused`, so
 * every `jti` this poll recorded is returned to you; when the failure is on the first SET,
 * nothing was judged and the call raises it (AXIAM_ERR_NETWORK, no reason code).
 *
 * A poll that returns AXIAM_OK leaving SETs unjudged emits the §19.1 `ssf_unjudged`
 * telemetry event (AXIAM_TELEMETRY_SSF_UNJUDGED, contract 1.60): their number and the
 * failure category, `key_fetch` or `replay_store` -- never a `jti`.
 */
axiam_error_kind_t axiam_ssf_poll(axiam_ssf_receiver_t *receiver, const char *stream_id,
                                  const axiam_ssf_poll_options_t *options,
                                  axiam_ssf_poll_result_t *out, axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_SSF_H */
