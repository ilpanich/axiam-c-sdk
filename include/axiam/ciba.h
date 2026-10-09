/**
 * @file ciba.h
 * @brief CONTRACT.md §33 — CIBA, client-initiated backchannel authentication
 *        (contract 1.58), including the §33.2 signed request form.
 *
 * A CIBA client — a back-office system, a teller application, a kiosk — that already
 * knows whom it wants to authenticate asks AXIAM, over a client-authenticated call, to
 * authenticate that user ON ANOTHER DEVICE. AXIAM notifies the user; the user approves
 * or refuses on the console; the client collects the tokens by polling the token
 * endpoint, or is pinged and polls once.
 *
 * | Canonical          | C                          | I/O |
 * |--------------------|----------------------------|-----|
 * | `ciba_initiate`    | axiam_ciba_initiate()      | yes — `POST /oauth2/bc-authorize` |
 * | `ciba_poll`        | axiam_ciba_poll()          | yes — the CIBA grant at `/oauth2/token` |
 * | `ciba_await`       | axiam_ciba_await()         | yes — `ciba_poll` repeated under §33.7 |
 * | `ciba_handle_ping` | axiam_ciba_handle_ping()   | **none** |
 *
 * Both wire calls follow §12.1: form-encoded, `tenant_id` as a QUERY parameter (never a
 * body field), `X-Tenant-ID` sent per §5. **The client always authenticates**: with the
 * `client_secret_post` secret configured by axiam_client_config_set_oidc_client_secret(),
 * or — a client configured with a §6.1 certificate and no secret — by the certificate
 * itself (`tls_client_auth`), sending `client_id` only. A client with neither is refused
 * locally (AXIAM_ERR_AUTH, no request): a CIBA client is never public. This SDK has no
 * `private_key_jwt` client authentication.
 *
 * The endpoint is the discovery document's `backchannel_authentication_endpoint`, its
 * `mtls_endpoint_aliases` entry preferred on an mTLS call (§21.3 rule 2); a document
 * naming neither is AXIAM_ERR_AUTH ("this server does not support CIBA"). No alias is
 * ever synthesised.
 *
 * **A successful axiam_ciba_initiate() proves nothing about the user** (§33.3 rule 4):
 * AXIAM answers a hint that names nobody exactly like a real one, and only
 * `expired_token` tells a client that nobody answered.
 *
 * Errors (§33.4): a body with an `error` member is an OAuthProtocolError at ANY status —
 * AXIAM_ERR_AUTH with axiam_error_t::oauth_error set (e.g. `invalid_binding_message`,
 * with the server's `error_description` in the message) — and a `401` among them never
 * enters the §9 refresh guard. The one exception is a `5xx` on axiam_ciba_poll(), which is
 * AXIAM_ERR_NETWORK and transient whatever its body (contract 1.59, P8). axiam_error_is_access_denied() and
 * axiam_error_is_expired_token() tell the two terminal outcomes of a poll apart.
 *
 * Sensitive (§33.5): `auth_req_id` wherever it appears, `client_notification_token`, the
 * signing key and the signed `request` string. `binding_message` and `login_hint` are not
 * secrets but can be personal data; this SDK never logs them.
 */
#ifndef AXIAM_CIBA_H
#define AXIAM_CIBA_H

#include <stddef.h>
#include <time.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/oidc.h"
#include "axiam/sensitive.h"
#include "axiam/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The CIBA grant type at the token endpoint. */
#define AXIAM_CIBA_GRANT_TYPE "urn:openid:params:grant-type:ciba"
/** The first poll's wait when the initiate response carries no (or a zero) `interval`. */
#define AXIAM_CIBA_DEFAULT_INTERVAL_S 5L
/** What each `slow_down` adds to the interval, permanently (§33.7 rule 3). */
#define AXIAM_CIBA_SLOW_DOWN_INCREMENT_S 5L
/** The lifetime of a signed request this SDK mints: five minutes, inside the server's
 *  sixty-minute bound on `exp - nbf` (§33.2). */
#define AXIAM_CIBA_SIGNED_REQUEST_LIFETIME_S 300L

/** Which of the two hints names the user (§33.2). One kind and one value, so sending
 *  both — or a `login_hint_token`, which AXIAM refuses — cannot be written. */
typedef enum axiam_ciba_hint_kind {
    AXIAM_CIBA_LOGIN_HINT = 0, /**< `login_hint`: a username, then an e-mail address. */
    AXIAM_CIBA_ID_TOKEN_HINT   /**< `id_token_hint`: an ID token this deployment issued. */
} axiam_ciba_hint_kind_t;

/** How the client receives the outcome, as it registered. */
typedef enum axiam_ciba_delivery {
    AXIAM_CIBA_DELIVERY_POLL = 0, /**< The client polls the token endpoint. */
    AXIAM_CIBA_DELIVERY_PING      /**< AXIAM pings the client; the client then polls once. */
} axiam_ciba_delivery_t;

/** The algorithms a signed request may use (§33.2). There is deliberately no zero value:
 *  a zeroed field is "no algorithm", and that is refused rather than defaulted. */
typedef enum axiam_ciba_signing_alg {
    AXIAM_CIBA_SIGNING_PS256 = 1, /**< RSASSA-PSS, SHA-256, an RSA key of 2048 bits or more. */
    AXIAM_CIBA_SIGNING_ES256,     /**< ECDSA on P-256 with SHA-256. */
    AXIAM_CIBA_SIGNING_EDDSA      /**< Ed25519. */
} axiam_ciba_signing_alg_t;

/** The key and algorithm for the signed request form. Opaque; the key is never rendered. */
typedef struct axiam_ciba_request_signer axiam_ciba_request_signer_t;

/**
 * A signer from a PEM private key (PKCS#8 or the traditional form; unencrypted) and the
 * algorithm it signs under — the one the client registered as
 * `backchannel_authentication_request_signing_alg`. Both are the caller's: neither is
 * defaulted, and the SDK signs under exactly `alg`.
 *
 * Returns NULL with this SDK's local ValidationError (AXIAM_ERR_NETWORK, cause 400) for
 * no key, no or an unknown algorithm, a PEM that is not a private key, or a key that does
 * not sign under `alg` — proven by signing a probe before anything is returned. `kid`
 * (may be NULL) goes in the JWS header. The PEM is copied into the library's key object
 * and not retained as text.
 */
axiam_ciba_request_signer_t *axiam_ciba_request_signer_new(axiam_ciba_signing_alg_t alg,
                                                           const axiam_sensitive_t *private_key_pem,
                                                           const char *kid, axiam_error_t *err);

/** Free a signer and its key. Safe on NULL. */
void axiam_ciba_request_signer_free(axiam_ciba_request_signer_t *signer);

/** The algorithm a signer uses. */
axiam_ciba_signing_alg_t axiam_ciba_request_signer_alg(const axiam_ciba_request_signer_t *signer);

/**
 * Arguments to axiam_ciba_initiate() — `CibaInitiateRequest` (§33.2). Every pointer is
 * borrowed for the call. A member left NULL / unset is not sent.
 */
typedef struct axiam_ciba_initiate_params {
    /** Space-separated; must include `openid`. Required. */
    const char *scope;
    /** Which hint `hint` is. */
    axiam_ciba_hint_kind_t hint_kind;
    /** The one hint. Required. */
    const char *hint;
    /** Shown to the user on the approval page — what lets them tell the request they
     *  started from one an attacker did. Required for a `fapi2` client. */
    const char *binding_message;
    /** The requested lifetime, 30–600 s (absent: 300). Sent as a string on the form and
     *  as a number inside a signed request. */
    long requested_expiry;
    int has_requested_expiry; /**< 1 sends `requested_expiry`. */
    const char *acr_values;   /**< Space-separated authentication context classes. */
    const char *resource;     /**< RFC 8707 resource indicator. */
    /** Poll or ping, as registered. */
    axiam_ciba_delivery_t delivery;
    /** The bearer AXIAM presents at the ping — keep it to check the ping with
     *  axiam_ciba_handle_ping(). REQUIRED (non-empty) in ping mode, refused in poll mode. */
    const axiam_sensitive_t *client_notification_token;
    /** Non-NULL sends the request as ONE signed JWT (`request`), every member above
     *  inside it — required of a client that registered a signing algorithm, refused by
     *  the server from one that did not. */
    const axiam_ciba_request_signer_t *signer;
    /** Tenant UUID for the `tenant_id` query parameter, or NULL for the client's own. */
    const char *tenant_id;
    /** A pre-fetched discovery document, or NULL to use axiam_oidc_discover(). */
    const axiam_oidc_config_t *config;
} axiam_ciba_initiate_params_t;

/** `CibaInitiateResponse` (§33.2). Release with axiam_ciba_initiate_response_dispose(). */
typedef struct axiam_ciba_initiate_response {
    /** The request's id at the token endpoint — a bearer credential for the grant
     *  (§33.5). Never parse or length-check it. */
    axiam_sensitive_t *auth_req_id;
    /** The request's lifetime, seconds — authoritative (§33.7 rule 4). */
    long expires_in;
    /** The minimum seconds between token requests: the response's value, or
     *  AXIAM_CIBA_DEFAULT_INTERVAL_S when it was absent or zero. */
    long interval;
    /** When the response was received, by the client's clock; axiam_ciba_await()'s
     *  deadline is this plus `expires_in`. */
    time_t received_at;
} axiam_ciba_initiate_response_t;

/** Release the members of an initiate response, scrubbing `auth_req_id`. Safe on NULL. */
void axiam_ciba_initiate_response_dispose(axiam_ciba_initiate_response_t *response);

/**
 * `POST /oauth2/bc-authorize` (CIBA Core §7, CONTRACT.md §33.1) — ask AXIAM to
 * authenticate a user on another device.
 *
 * **Never retried** — not on a transport error, a `5xx` or a `429` (§33.7 rule 1): every
 * accepted call stores a request and may notify a person. On a lost answer, let it expire
 * and ask again deliberately.
 *
 * Refused locally, with no request: no client credential (AXIAM_ERR_AUTH); no scope, no
 * hint, a ping-mode request without a `client_notification_token` or a poll-mode request
 * with one (this SDK's ValidationError). A success proves nothing about the user.
 *
 * @param out Receives the response; dispose with axiam_ciba_initiate_response_dispose().
 */
axiam_error_kind_t axiam_ciba_initiate(axiam_client_t *client,
                                       const axiam_ciba_initiate_params_t *params,
                                       axiam_ciba_initiate_response_t *out, axiam_error_t *err);

/**
 * `POST /oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba` (CIBA Core
 * §10.1, CONTRACT.md §33.1) — ONE token request.
 *
 * The answers of §33.3 rule 6 surface as AXIAM_ERR_AUTH carrying `oauth_error`:
 * `authorization_pending` and `slow_down` (non-terminal), `access_denied` and
 * `expired_token` (terminal and distinct), `invalid_grant`. They are never retried. A
 * transport failure, a `5xx` — with or without an `error` member: AXIAM answers an
 * internal failure `500 {"error":"server_error"}` (contract 1.59, P8) — and a `408` or
 * `429` WITHOUT an `error` body are retried per §16 within the call; any other `4xx` is
 * not. A `5xx` that outlives §16 is AXIAM_ERR_NETWORK.
 *
 * A `200` is validated as every other grant's token set (§12.4, no nonce). **Store the
 * returned tokens before anything else**: a request is redeemed once, and a second
 * axiam_ciba_poll() for it is `invalid_grant` (§33.7 rule 7). The token set is RETURNED,
 * never adopted as this client's credential.
 *
 * @param config A pre-fetched discovery document, or NULL to discover.
 */
axiam_error_kind_t axiam_ciba_poll(axiam_client_t *client, const axiam_sensitive_t *auth_req_id,
                                   const char *tenant_id, const axiam_oidc_config_t *config,
                                   axiam_oidc_token_set_t *out, axiam_error_t *err);

/** The clock axiam_ciba_await() waits on — injectable so its schedule is testable
 *  without sleeping. `now` returns seconds; `sleep` waits that many seconds. */
typedef struct axiam_ciba_clock {
    time_t (*now)(void *ctx);
    void (*sleep)(void *ctx, long seconds);
    void *ctx;
} axiam_ciba_clock_t;

/**
 * Poll for `initiated`'s outcome until it is decided or expires (§33.1, §33.7). Surfaces
 * nothing to the user — AXIAM notified them.
 *
 * - The FIRST poll waits one `interval`: polling earlier only earns `slow_down` and a
 *   longer wait.
 * - `slow_down` adds AXIAM_CIBA_SLOW_DOWN_INCREMENT_S to the interval, cumulatively and
 *   permanently; `authorization_pending` never lowers it.
 * - A transport failure, a `5xx` (whatever its body, P8) or a `429` that outlived §16's
 *   retries — and the `rate_limit_exceeded` answer — is not terminal: the loop waits the
 *   interval and polls again.
 * - Polling stops at `received_at + expires_in`, even if the server has not said
 *   `expired_token`: when the next poll would not fall before the deadline, the same
 *   `expired_token` (AXIAM_ERR_AUTH, `oauth_error` "expired_token") is raised locally,
 *   with no request.
 * - Anything else (`access_denied`, `expired_token`, `invalid_grant`, an unknown code,
 *   a refused call) is returned as it came.
 *
 * The token set is returned, not adopted — the posture of axiam_device_login() and
 * axiam_login_client_credentials(). In **ping** mode do not call this: call
 * axiam_ciba_poll() once from the ping handler, and fall back to this loop only once half
 * of `expires_in` has passed without a ping (§33.7 rule 6).
 *
 * @param clock NULL waits on the client's own clock and sleep.
 */
axiam_error_kind_t axiam_ciba_await(axiam_client_t *client,
                                    const axiam_ciba_initiate_response_t *initiated,
                                    const char *tenant_id, const axiam_oidc_config_t *config,
                                    const axiam_ciba_clock_t *clock, axiam_oidc_token_set_t *out,
                                    axiam_error_t *err);

/**
 * Check a ping AXIAM delivered to your notification endpoint and return the `auth_req_id`
 * it names (CIBA Core §10.2, CONTRACT.md §33.1). **No I/O**, and no client: this function
 * has no way to make a request.
 *
 * 1. Exactly one `Authorization` header (name matched case-insensitively): the scheme
 *    `Bearer` in any case, exactly one space, and the token — compared to
 *    `expected_token` in constant time (OpenSSL's CRYPTO_memcmp). Anything else is
 *    AXIAM_ERR_AUTH, whose message names no value.
 * 2. `body` (of `body_len` bytes; need not be NUL-terminated) is a JSON object with a
 *    non-empty string `auth_req_id`; any other member is ignored. Anything else is this
 *    SDK's local ValidationError.
 *
 * It neither answers the HTTP request nor calls the token endpoint: answer `204` as soon
 * as this returns, THEN axiam_ciba_poll() — AXIAM retries a ping that is not answered
 * quickly. Nor does it check that the `auth_req_id` is one you issued: the token endpoint
 * answers `invalid_grant` for any other.
 *
 * @param headers        The request's headers, as the SDK's own header list.
 * @param out_auth_req_id Receives the id as a new Sensitive the caller frees; NULL on
 *                       failure.
 */
axiam_error_kind_t axiam_ciba_handle_ping(const axiam_kv_t *headers, const char *body,
                                          size_t body_len,
                                          const axiam_sensitive_t *expected_token,
                                          axiam_sensitive_t **out_auth_req_id,
                                          axiam_error_t *err);

/** 1 when `err` is the `access_denied` answer: at a CIBA or device poll, the user refused
 *  (§33.4). */
int axiam_error_is_access_denied(const axiam_error_t *err);

/** 1 when `err` is the `expired_token` answer: nobody decided in time — also raised
 *  locally when axiam_ciba_await() reaches its deadline (§33.4, §33.7 rule 4). */
int axiam_error_is_expired_token(const axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_CIBA_H */
