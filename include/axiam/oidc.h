/*
 * AXIAM C SDK — OIDC relying party, logout, device grant and token exchange
 * (CONTRACT.md §12, §12.7, §14, §15).
 *
 * WHY THIS FILE EXISTS AT ALL. Contract 1.10 and earlier deferred §12 in the
 * Swift, C and C++ SDKs: these are device- and IoT-oriented, and the
 * browser-redirect relying-party flow has no natural home in any of them.
 * Contract 1.11 (§12.6) reverses that, and the reason is worth keeping next to
 * the code. The persona argument only ever covered two of the nine operations —
 * `oidc_begin` and `oidc_exchange`, the pair that genuinely assumes a browser.
 * The other seven are exactly what an embedded consumer wants:
 * `login_client_credentials` is machine-to-machine login, `introspect` and
 * `revoke` are ordinary questions a device asks about its own credentials, and
 * `oidc_refresh` is the grant the §9 single-flight guard was built for.
 * Meanwhile §14 (device grant) exists *because* a device cannot show a browser,
 * and §20 (UMA) already gave this SDK a `/oauth2/token` call — so by 1.10 it was
 * speaking OAuth2 at the token endpoint anyway, without the shared discovery
 * cache and ID-token validation §12 specifies. This file removes a divergence
 * rather than adding one.
 *
 * THE FOUR THINGS THIS SURFACE WILL NOT DO FOR YOU:
 *
 *  1. It stores no `state`, `nonce` or `code_verifier` (§12.3 rule 1). They come
 *     back out of axiam_oidc_begin() and the caller hands them to
 *     axiam_oidc_exchange(). There is no implicit cache, and the caller must
 *     also remember its own `redirect_uri` — RFC 6749 §4.1.3 requires it
 *     replayed byte-identically and axiam_authorization_request_t deliberately
 *     does not carry it (§12.1).
 *  2. It never skips ID-token validation. There is no flag, no "insecure" entry
 *     point, and no partial result: §12.4 rule 7 is all-or-nothing, so a token
 *     set whose `id_token` fails any check is discarded whole — the access and
 *     refresh tokens from the same response never reach the caller.
 *  3. It adopts nothing. Every operation here returns tokens; none of them
 *     become this client's own credential. §15.2 rule 5 makes that a MUST NOT
 *     for the exchanged token specifically, and this SDK takes the same posture
 *     everywhere rather than having two.
 *  4. It does not retry a grant. §16.2 lists `oidc_exchange`, `device_authorize`,
 *     `device_login` and `token_exchange` as ineligible, because their
 *     credentials are single-use: retrying replays a spent authorization code or
 *     device code and turns a blip into a hard `invalid_grant`. Only the
 *     read-only calls here — discovery, introspection, a `device_poll` that hit
 *     a 5xx — go through §16.
 *
 * OWNERSHIP. Every out-parameter carrying heap memory has a matching _dispose,
 * and every one is safe on NULL and on a zeroed struct, so a caller can dispose
 * unconditionally on the error path.
 */
#ifndef AXIAM_OIDC_H
#define AXIAM_OIDC_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

/** §12.3 rule 6: the discovery cache TTL floor, seconds. A smaller configured
 *  value is raised to this, never honoured. */
#define AXIAM_OIDC_DISCOVERY_TTL_FLOOR_S 300L

/** §12.4 rule 5: the clock-skew ceiling, seconds. A larger configured value is
 *  clamped DOWN to this, not rejected. */
#define AXIAM_OIDC_MAX_CLOCK_SKEW_S 60L

/**
 * §12.4 rule 2: the unknown-`kid` re-fetch cooldown, seconds.
 *
 * "One re-fetch then fail" taken literally is unimplementable against a warm
 * cache without handing an attacker one JWKS fetch per forged `kid`. The rule
 * is per WINDOW: the first unknown `kid` triggers exactly one re-fetch and opens
 * the window; another unknown `kid` inside it re-consults the cached set with no
 * network call and fails immediately.
 */
#define AXIAM_OIDC_JWKS_REFETCH_COOLDOWN_S 60L

/** RFC 8628 §3.2 default poll interval when the response omits one (§14.2 rule 2). */
#define AXIAM_DEVICE_DEFAULT_INTERVAL_S 5L
/** §14.2 rule 1: seconds added to the CURRENT interval on every `slow_down`. */
#define AXIAM_DEVICE_SLOW_DOWN_INCREMENT_S 5L

/** grant_type of the RFC 8628 device authorization grant (§14.1). */
#define AXIAM_DEVICE_CODE_GRANT_TYPE "urn:ietf:params:oauth:grant-type:device_code"
/** grant_type of the RFC 8693 token exchange (§15.1). */
#define AXIAM_TOKEN_EXCHANGE_GRANT_TYPE "urn:ietf:params:oauth:grant-type:token-exchange"
/** The RFC 8693 token type this SDK sends and expects on both sides (§15.1). */
#define AXIAM_TOKEN_TYPE_ACCESS_TOKEN "urn:ietf:params:oauth:token-type:access_token"
/** The Back-Channel Logout 1.0 §2.4 event key §12.7.3 rule 3 requires. */
#define AXIAM_LOGOUT_EVENT_KEY "http://schemas.openid.net/event/backchannel-logout"

/**
 * @name §12.3 rule 3 ID-token validation reason codes
 *
 * A CLOSED vocabulary of exactly seven. No SDK may add an eighth, so several
 * distinct failures deliberately share one code and the sharing is normative,
 * not incidental:
 *
 *  - `token_expired` covers EVERY §12.4 rule 5 time failure — a past `exp`, an
 *    ABSENT `exp`, an absent or future `iat`, and a future `nbf`. There is no
 *    `token_not_yet_valid` and no `missing_exp`.
 *  - `unknown_kid` covers "the JOSE header carries no `kid` at all" as well as
 *    "no key matches it", and a JWKS transport failure during the rule-2
 *    re-fetch surfaces here rather than as `invalid_signature`.
 *  - `invalid_alg` covers a JOSE header that cannot be parsed at all, since the
 *    algorithm cannot then be established.
 *  - `invalid_signature` is the catch-all, so no unclassified case needs a code
 *    of its own.
 *
 * Read them from axiam_error_t::id_token_reason. A caller needing finer
 * granularity reads the message, not the code.
 * @{
 */
#define AXIAM_OIDC_REASON_INVALID_ALG       "invalid_alg"
#define AXIAM_OIDC_REASON_UNKNOWN_KID       "unknown_kid"
#define AXIAM_OIDC_REASON_INVALID_SIGNATURE "invalid_signature"
#define AXIAM_OIDC_REASON_INVALID_ISSUER    "invalid_issuer"
#define AXIAM_OIDC_REASON_INVALID_AUDIENCE  "invalid_audience"
#define AXIAM_OIDC_REASON_TOKEN_EXPIRED     "token_expired"
#define AXIAM_OIDC_REASON_NONCE_MISMATCH    "nonce_mismatch"
/** @} */

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

/**
 * The OIDC discovery document (§12.1), read from
 * `/.well-known/openid-configuration`. All members owned; NULL when the server
 * sent no such field.
 *
 * `issuer` is the AUTHORITATIVE issuer for the §12.4 rule 3 check. The server
 * derives it from its own configuration, so behind a proxy it may legitimately
 * differ from the base URL this document was fetched from — §12.3 rule 6
 * forbids rejecting a document over that mismatch. Endpoints are likewise read
 * from here rather than concatenated onto the issuer, including `jwks_uri`.
 */
typedef struct axiam_oidc_config {
    char *issuer;
    char *authorization_endpoint;
    char *token_endpoint;
    char *jwks_uri;
    char *userinfo_endpoint;
    char *introspection_endpoint;
    char *revocation_endpoint;
    /** §12.7.2 rule 1: where axiam_logout_url() sends the user agent. */
    char *end_session_endpoint;
    /** §14.1: where axiam_device_authorize() starts the grant. */
    char *device_authorization_endpoint;
    char **scopes_supported;
    size_t scopes_supported_count;
    char **response_types_supported;
    size_t response_types_supported_count;
    /**
     * Advertised ID-token algorithms. INFORMATIONAL ONLY: §12.4 rule 1 pins
     * verification to `EdDSA` regardless of what this list says, so a server
     * that additionally advertised `RS256` could not talk this SDK into it.
     */
    char **id_token_signing_alg_values_supported;
    size_t id_token_signing_alg_values_supported_count;
} axiam_oidc_config_t;

/**
 * What axiam_oidc_begin() returns (§12.1): everything needed to start the
 * redirect and, later, to finish it.
 *
 * THE CALLER OWNS ALL THREE CORRELATION VALUES (§12.3 rule 1). This SDK stores
 * none of them — not on the client, not in a global, not in an implicit cache —
 * so `state`, `nonce` and `code_verifier` must be persisted by the application
 * (typically in its own session) and handed back to axiam_oidc_exchange().
 *
 * THERE IS NO `redirect_uri` MEMBER, and that is the contract's shape rather
 * than an omission (§12.1). `oidc_exchange` must replay it byte-identically, so
 * the caller has to remember it alongside the three below. It is a real footgun
 * and §12.1 calls it out deliberately.
 */
typedef struct axiam_authorization_request {
    /** The URL to send the user agent to. */
    char *url;
    /** CSRF correlation value. NOT a secret (§12.3 rule 2) — the caller compares
     *  it on return, so it has to be readable. */
    char *state;
    /** Replay-protection value, checked into the ID token by the server and
     *  asserted by §12.4 rule 6. Not a secret, for the same reason. */
    char *nonce;
    /** The PKCE verifier whose S256 challenge went out in the URL. Secret for
     *  its WHOLE lifetime, including while it sits here (§12.5). */
    axiam_sensitive_t *code_verifier;
} axiam_authorization_request_t;

/**
 * The validated claims of an ID token (§12.4). Present on a token set only when
 * the response carried an `id_token` AND every §12.4 rule passed.
 */
typedef struct axiam_id_token_claims {
    char *subject;
    char *issuer;
    char **audience;
    size_t audience_count;
    long long expires_at;
    long long issued_at;
    char *nonce;            /**< NULL when the token carried none. */
    char *authorized_party; /**< `azp`; required by §12.4 rule 4 when `aud` is multi-valued. */
    char *email;
    char *preferred_username;
    char *tenant_id;
    char **roles;
    size_t roles_count;
    /**
     * The complete claim set as JSON, verbatim.
     *
     * §12.1 requires SDKs to PRESERVE claims beyond the named ones and forbids
     * rejecting unknown ones — the ID token's full claim set is not enumerated
     * by `openapi.json`. In a language with an open map this is a dictionary
     * member; in C it is the raw object, which a caller parses with whatever
     * JSON library it already has.
     */
    char *raw_claims_json;
} axiam_id_token_claims_t;

/**
 * The result of every §12 token-endpoint grant (§12.1).
 *
 * `id_claims` is non-NULL exactly when `id_token` is, because there is no path
 * that returns an unvalidated ID token: §12.4 rule 7 discards the whole set on
 * any validation failure.
 */
typedef struct axiam_oidc_token_set {
    axiam_sensitive_t *access_token;
    char *token_type;
    long expires_in;
    char *scope;                          /**< NULL when the server sent none. */
    axiam_sensitive_t *refresh_token;     /**< NULL when the grant issued none. */
    axiam_sensitive_t *id_token;          /**< NULL when the grant issued none. */
    axiam_id_token_claims_t *id_claims;   /**< Validated claims of `id_token`. */
} axiam_oidc_token_set_t;

/**
 * RFC 7662 introspection result (§12.1).
 *
 * `active` is the only field guaranteed present — an inactive token answers
 * `{"active":false}` and nothing else, which is the whole point of the endpoint.
 * Numeric members are 0 when the server sent none.
 */
typedef struct axiam_introspection_result {
    int active;
    char *scope;
    char *client_id;
    char *username;
    char *token_type;
    char *subject;
    char *audience;
    char *issuer;
    char *jwt_id;
    long long expires_at;
    long long issued_at;
} axiam_introspection_result_t;

/** `POST /api/v1/auth/federation/oidc/start` (§12.1) — where to send the user
 *  agent for upstream-IdP federation, and the single-use `state` tying the
 *  callback to it. There is no nonce here: the server keeps the federation
 *  nonce server-side (§12.1 note 7), so an SDK has nothing to check. */
typedef struct axiam_sso_start_result {
    char *authorize_url;
    char *state;
    long expires_in_secs;
} axiam_sso_start_result_t;

/**
 * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — the completed
 * federation login.
 *
 * CARRIES NO TOKEN MATERIAL. The session arrives as `Set-Cookie` and lands in
 * the §4 cookie jar (§12.1 note 6); a client without a persistent cookie store
 * silently loses it.
 */
typedef struct axiam_sso_complete_result {
    char *user_id;
    char *session_id;
    char *redirect_uri; /**< May be NULL. */
    long expires_in;
} axiam_sso_complete_result_t;

/**
 * A verified back-channel logout token (§12.7.3).
 *
 * NEVER COLLAPSED TO A BOOLEAN, per §12.7.3: the relying party has to know
 * WHICH session to end, and a verifier that only says "valid" forces the caller
 * to re-parse the token themselves with none of the checks applied.
 *
 * `jwt_id` is surfaced so the RP can deduplicate. This SDK deliberately does
 * NOT dedup internally: delivery is at-least-once, so a valid token legitimately
 * arrives twice, and a library with no durable store would silently drop a real
 * second logout after a restart.
 *
 * WHEN `sid` IS PRESENT, END THAT SESSION ONLY. Falling back to "every session
 * for `sub`" is an over-reach the server itself refuses to make.
 */
typedef struct axiam_verified_logout_token {
    char *sid;     /**< May be NULL — but not together with `subject`. */
    char *subject; /**< May be NULL — but not together with `sid`. */
    char *jwt_id;
    char *issuer;
    long long issued_at;
} axiam_verified_logout_token_t;

/**
 * `POST /oauth2/device_authorization` (§14.1) — the codes a device shows its
 * user.
 *
 * `verification_uri_complete` embeds the user code so a device that can render
 * a QR code does not make the user type anything. It is surfaced when the server
 * sends it and NEVER synthesised by concatenation when it does not (§14.3): its
 * format is the server's to choose.
 */
typedef struct axiam_device_authorization {
    /** A bearer credential for the life of the grant (§14.5), hence wrapped. */
    axiam_sensitive_t *device_code;
    /** The code the USER types. Not wrapped — §14.5 is explicit that wrapping it
     *  would defeat the one thing it exists for. It still must not be logged;
     *  displaying it is the caller's job. */
    char *user_code;
    char *verification_uri;
    char *verification_uri_complete; /**< NULL when the server sent none. */
    /** Seconds until the whole grant expires. Polling stops here (§14.2 rule 4). */
    long expires_in;
    /** Seconds between polls, from the RESPONSE (§14.2 rule 2). 5 when omitted. */
    long interval;
} axiam_device_authorization_t;

/**
 * `POST /oauth2/token` with the RFC 8693 grant (§15.1) — a NARROWER token.
 *
 * There is no refresh-token member, and §15.2 rule 4 makes that structural
 * rather than incidental: an exchange only ever narrows, and a refresh token
 * would let the holder re-widen later. Re-run the exchange for a fresh one.
 */
typedef struct axiam_exchanged_token {
    axiam_sensitive_t *access_token;
    /** §15.2 rule 6: surfaced, never dropped — a client that asked for one type
     *  and received another has to be able to tell. */
    char *issued_token_type;
    char *token_type;
    /** The scopes actually GRANTED, which §15.2 rule 7 permits to be narrower
     *  than the ones requested even on success. Read it. */
    char *scope;
    long expires_in;
} axiam_exchanged_token_t;

/* ------------------------------------------------------------------ */
/* §12 — the nine canonical operations                                */
/* ------------------------------------------------------------------ */

/**
 * `GET /.well-known/openid-configuration` (§12.1).
 *
 * Cached on the client for axiam_client_config_set_oidc_discovery_ttl() seconds
 * (default and floor: 300). §12.3 rule 6 governs the cache: it is
 * per-client-instance, which satisfies the origin rule by construction because a
 * client is bound to one base URL for its lifetime; it is NOT keyed on the
 * tenant, because the document is a per-origin protocol artifact with no
 * tenant-specific content. Concurrent callers share a single in-flight fetch.
 *
 * Every operation below calls this itself, so a caller normally never needs to —
 * except axiam_oidc_begin() and axiam_logout_url(), which take a document
 * because they perform no I/O of their own.
 *
 * @param out Filled on success; dispose with axiam_oidc_config_dispose().
 */
axiam_error_kind_t axiam_oidc_discover(axiam_client_t *client,
                                       axiam_oidc_config_t *out,
                                       axiam_error_t *err);

/**
 * Build the authorization-request URL (§12.1). PURE LOCAL COMPUTATION — no
 * network I/O, and it does not acquire the client's transport (§12.6).
 *
 * Constructs, per §12.1: a 32-byte CSPRNG `state` and `nonce`, base64url
 * without padding; a 43-character `code_verifier` from the RFC 7636 §4.1
 * unreserved set; `code_challenge = BASE64URL(SHA256(ASCII(verifier)))` with
 * `code_challenge_method=S256`; and a URL carrying exactly the eight permitted
 * query parameters and no others. `openid` is added to the scope when the caller
 * omits it.
 *
 * @param config       An already-fetched document (axiam_oidc_discover()). The
 *                     `authorization_endpoint` comes from it, never hardcoded.
 * @param redirect_uri Required, and the CALLER must remember it: §12.1 keeps it
 *                     off axiam_authorization_request_t, and axiam_oidc_exchange()
 *                     must replay it byte-identically.
 * @param scope        May be NULL, in which case "openid" is used.
 * @param out          Filled on success; dispose with
 *                     axiam_authorization_request_dispose().
 */
axiam_error_kind_t axiam_oidc_begin(axiam_client_t *client,
                                    const axiam_oidc_config_t *config,
                                    const char *redirect_uri,
                                    const char *scope,
                                    axiam_authorization_request_t *out,
                                    axiam_error_t *err);

/** Arguments to axiam_oidc_exchange(). All borrowed. */
typedef struct axiam_oidc_exchange_params {
    /** The authorization code from the redirect. Single-use — hence no retry. */
    const char *code;
    /** The verifier axiam_oidc_begin() produced, kept by the caller (§12.3 rule 1). */
    const axiam_sensitive_t *code_verifier;
    /** Replayed BYTE-IDENTICALLY from the authorization request (RFC 6749 §4.1.3). */
    const char *redirect_uri;
    /**
     * The nonce axiam_oidc_begin() produced. REQUIRED: §12.4 rule 6 makes the
     * check mandatory for this operation — the helper always requests `openid`,
     * so the server always issues a nonce, and a caller with nothing to compare
     * against is a caller who has lost replay protection.
     */
    const char *nonce;
    /** Tenant UUID for the mandatory `?tenant_id=` query parameter. NULL falls
     *  back to the client's configured tenant_id; a SLUG is never a substitute
     *  (§12.3 rule 4) and is refused client-side, with no wire call. */
    const char *tenant_id;
} axiam_oidc_exchange_params_t;

/**
 * `POST /oauth2/token` with `grant_type=authorization_code` (§12.1).
 *
 * Validates the returned `id_token` against every §12.4 rule before returning,
 * and discards the ENTIRE token set on any failure (rule 7) — the access and
 * refresh tokens from the same response are never handed back. The failing rule
 * is named in axiam_error_t::id_token_reason.
 *
 * NOT RETRIED, ever (§16.2): the authorization code is consumed by the attempt,
 * so a retry replays a spent credential and turns a transient blip into an
 * `invalid_grant` the caller cannot interpret.
 *
 * @param out Filled on success; dispose with axiam_oidc_token_set_dispose().
 */
axiam_error_kind_t axiam_oidc_exchange(axiam_client_t *client,
                                       const axiam_oidc_exchange_params_t *params,
                                       axiam_oidc_token_set_t *out,
                                       axiam_error_t *err);

/**
 * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1).
 *
 * A DISTINCT OPERATION from axiam_refresh(), which drives the cookie/opaque
 * session at `/api/v1/auth/refresh` (§5.1). The two must not be merged, aliased
 * or made to fall back to one another, and this SDK keeps them in separate
 * functions with separate guards for exactly that reason.
 *
 * SINGLE-FLIGHT (§12.1, §9 rule 2). Concurrent callers presenting the SAME
 * refresh token share ONE wire call and its one outcome; callers with different
 * tokens do not contend. That is not a performance tweak — AXIAM rotates refresh
 * tokens, so two threads racing on one token would spend it twice and the loser
 * would get an `invalid_grant` for a token that was perfectly good a millisecond
 * earlier. §9 rule 5 permits this dedicated guard rather than the §1 cookie
 * guard, whose API compares an access token's freshness — a comparison with no
 * meaning for a `refresh_token` grant.
 *
 * @param scope Optional; omitted rather than sent empty when NULL.
 * @param out   Filled on success; dispose with axiam_oidc_token_set_dispose().
 */
axiam_error_kind_t axiam_oidc_refresh(axiam_client_t *client,
                                      const axiam_sensitive_t *refresh_token,
                                      const char *scope,
                                      const char *tenant_id,
                                      axiam_oidc_token_set_t *out,
                                      axiam_error_t *err);

/**
 * `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) — the
 * machine-to-machine login.
 *
 * TWO KINDS OF PRINCIPAL USE THIS AND THE TOKEN DIFFERS (§12.1). The configured
 * `client_id` names either an OAuth2 client (`oa_…`) or a service account
 * (`sa_…`); the request is byte-identical, so nothing here changes. What
 * changes is the token: a service account's `sub` is its UUID rather than the
 * client id (check `sub_kind` before assuming either), and it carries NO `scope`
 * claim at all — a service account registers no scopes, so requesting one
 * answers `invalid_scope`, and its authorization comes from its assigned roles.
 * Both kinds get `aud: axiam:m2m`, so a §10 guard fronting a resource server
 * that accepts machine callers must be configured to expect that (§10.1 rule 6);
 * a guard expecting `axiam:user` rejects them, correctly.
 *
 * ADOPTION IS A MAY (§12.1) AND THIS SDK DOES NOT. The token is returned;
 * nothing is installed on the client. §14.3 rule 4 requires
 * axiam_device_login() to take the same posture, and it does.
 *
 * @param out Filled on success; dispose with axiam_oidc_token_set_dispose().
 */
axiam_error_kind_t axiam_login_client_credentials(axiam_client_t *client,
                                                  const char *scope,
                                                  const char *tenant_id,
                                                  axiam_oidc_token_set_t *out,
                                                  axiam_error_t *err);

/**
 * `POST /oauth2/introspect` (§12.1) — RFC 7662.
 *
 * CONFIDENTIAL CLIENTS ONLY (§12.1 rule 4): `token`, `client_id` and
 * `client_secret` are all required, so a client built without a secret is
 * refused here client-side rather than sending a request that cannot succeed.
 *
 * A `401` carrying an `OAuth2ErrorResponse` is a CLIENT-AUTHENTICATION failure,
 * not a session expiry: §12.3 rule 3 forbids it entering the §9 refresh guard,
 * because refreshing cannot fix a wrong client secret.
 *
 * @param token_type_hint Optional ("access_token", "refresh_token"); omitted
 *                        rather than sent empty when NULL.
 * @param out             Filled on success; dispose with
 *                        axiam_introspection_result_dispose().
 */
axiam_error_kind_t axiam_introspect(axiam_client_t *client,
                                    const axiam_sensitive_t *token,
                                    const char *token_type_hint,
                                    const char *tenant_id,
                                    axiam_introspection_result_t *out,
                                    axiam_error_t *err);

/**
 * `POST /oauth2/revoke` (§12.1) — RFC 7009. Returns no body.
 *
 * IDEMPOTENT BY DESIGN: per RFC 7009 the server answers `200` for an unknown,
 * expired or already-revoked token, and this function MUST report that as
 * success — that idempotence is the whole point of the endpoint. A `5xx` is
 * still a failure (§12.1 rule 5, corrected in contract 1.5: returning void does
 * not turn a server error into a success), and a `401` is a client-authentication
 * failure that does not enter the §9 guard.
 *
 * Confidential clients only, as for axiam_introspect().
 */
axiam_error_kind_t axiam_revoke(axiam_client_t *client,
                                const axiam_sensitive_t *token,
                                const char *token_type_hint,
                                const char *tenant_id,
                                axiam_error_t *err);

/**
 * `POST /api/v1/auth/federation/oidc/start` (§12.1) — begin SSO against an
 * upstream IdP.
 *
 * Carries org/tenant context in the JSON body per §5.1: one tenant form and one
 * org form, whichever this client was constructed with. Slug forms are valid
 * here — unlike the five `/oauth2/` operations, which need a UUID query
 * parameter.
 *
 * §12.4 DOES NOT APPLY to this pair: no ID token reaches the SDK, and the
 * federation nonce never leaves the server (§12.1 note 7). Round-trip `state`
 * unmodified into axiam_sso_complete() and do not synthesise a nonce.
 *
 * @param out Filled on success; dispose with axiam_sso_start_result_dispose().
 */
axiam_error_kind_t axiam_sso_start(axiam_client_t *client,
                                   const char *federation_config_id,
                                   const char *redirect_uri,
                                   axiam_sso_start_result_t *out,
                                   axiam_error_t *err);

/**
 * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — complete SSO.
 *
 * The session arrives as `Set-Cookie` (§12.1 note 6), so the §4 cookie-jar
 * requirement applies verbatim: the default libcurl transport keeps one, and a
 * caller who substituted a transport without cookie support loses the session
 * silently.
 *
 * @param out Filled on success; dispose with axiam_sso_complete_result_dispose().
 */
axiam_error_kind_t axiam_sso_complete(axiam_client_t *client,
                                      const char *code,
                                      const char *state,
                                      axiam_sso_complete_result_t *out,
                                      axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* §12.7 — logout                                                     */
/* ------------------------------------------------------------------ */

/**
 * Build the RP-Initiated Logout 1.0 URL (§12.7.1). PURE LOCAL COMPUTATION.
 *
 * @param config       An already-fetched document. `end_session_endpoint` comes
 *                     from it — §12.7.2 rule 1 forbids concatenating it onto the
 *                     issuer, which works against AXIAM and breaks against every
 *                     other OP the same code is pointed at.
 * @param id_token     Placed in `id_token_hint`. Passed as a plain string
 *                     because §12.7.5 is explicit: it is about to be embedded in
 *                     a URL handed to a browser, and a wrapper whose purpose is
 *                     to resist stringification is the wrong type for a value
 *                     that must be stringified. It still must never be logged.
 *                     There is deliberately NO hint-less mode that names the
 *                     user some other way — no such parameter exists on the wire.
 * @param post_logout_redirect_uri Optional. NOT pre-validated against a local
 *                     list (§12.7.2 rule 3): the allow-list lives in the client's
 *                     server-side registration, and a client-side copy would
 *                     drift and reject a URI an operator had just registered.
 * @param state        Optional, and the CALLER's to generate and check
 *                     (§12.7.2 rule 2) — the SDK passes it through and never
 *                     invents one, because the value only means something to the
 *                     application that will receive it back.
 *
 * @return A malloc'd URL the caller frees, or NULL on OOM / missing input.
 *
 * This does NOT end the SDK client's own session (§12.7.2 rule 4). Whether the
 * local session ends is the application's call — a backend holding a
 * service-account session must not lose it because a *user* logged out.
 */
char *axiam_logout_url(const axiam_oidc_config_t *config,
                       const char *id_token,
                       const char *post_logout_redirect_uri,
                       const char *state);

/**
 * Verify a back-channel logout token the OP POSTed to this RP (§12.7.1).
 *
 * No network I/O of its own: it verifies against the JWKS the client already
 * caches, through the same §12.4 verifier — there is no second key-fetching path
 * (§12.7.3 rule 1).
 *
 * THIS IS THE HALF THAT CARRIES SECURITY WEIGHT. The input arrives unsolicited,
 * from the network, and instructs the RP to terminate a session. Every §12.7.3
 * check is enforced, and each exists because skipping it has a name:
 *
 *  - `iss` must match the discovery issuer and `aud` this client's `client_id`,
 *    so a token minted for another RP is not accepted here.
 *  - `events` MUST carry the AXIAM_LOGOUT_EVENT_KEY key with an object value.
 *    This is what distinguishes a logout token from an ID token; skip it and a
 *    replayed ID token becomes a logout instruction.
 *  - `nonce` MUST BE ABSENT. Back-Channel Logout 1.0 §2.4 forbids it, and its
 *    presence is the documented signature of an ID token being replayed. This
 *    rejects rather than ignoring.
 *  - At least one of `sid` and `sub` must be present — a token naming neither
 *    identifies nothing.
 *  - `exp` must be in the future (AXIAM issues a 120 s lifetime).
 *
 * Verifying the SAME token twice succeeds both times, deliberately: delivery is
 * at-least-once, dedup is the RP's job through `jwt_id`, and an SDK that failed
 * the second delivery would break a legitimate retry.
 *
 * @param out Filled on success; dispose with
 *            axiam_verified_logout_token_dispose(). On failure it is zeroed and
 *            the error message never echoes the token (§12.7.3 rule 8).
 */
axiam_error_kind_t axiam_verify_logout_token(axiam_client_t *client,
                                             const char *logout_token,
                                             axiam_verified_logout_token_t *out,
                                             axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* §14 — device authorization grant (RFC 8628)                        */
/* ------------------------------------------------------------------ */

/**
 * `POST /oauth2/device_authorization` (§14.1) — start the grant.
 *
 * UNAUTHENTICATED. A device that cannot show a browser also cannot hold a client
 * secret, so §14.1 forbids sending one here AND forbids refusing to call this
 * from a client constructed without one. Only `client_id` goes out.
 *
 * @param out Filled on success; dispose with
 *            axiam_device_authorization_dispose().
 */
axiam_error_kind_t axiam_device_authorize(axiam_client_t *client,
                                          const char *scope,
                                          const char *tenant_id,
                                          axiam_device_authorization_t *out,
                                          axiam_error_t *err);

/**
 * One `POST /oauth2/token` with the device-code grant (§14.1) — a SINGLE poll.
 *
 * Returns AXIAM_OK with the token set once the user has approved. The five
 * RFC 8628 §3.5 answers all arrive as `400`, which §2 would map to a generic
 * error; §14.2 rule 5 overrides that and requires dispatching on the `error`
 * field first. This puts that field in axiam_error_t::oauth_error, so a caller
 * driving its own loop can tell `authorization_pending` and `slow_down` (keep
 * going) from `access_denied`, `expired_token` and `invalid_grant` (stop) —
 * §14.2 rule 3 keeps the first two of those terminal codes DISTINCT, because
 * "a human said no" and "nobody answered" are the only thing a device can act on.
 *
 * axiam_device_login() is the loop most callers want; this exists for one that
 * needs its own.
 */
axiam_error_kind_t axiam_device_poll(axiam_client_t *client,
                                     const axiam_sensitive_t *device_code,
                                     const char *tenant_id,
                                     axiam_oidc_token_set_t *out,
                                     axiam_error_t *err);

/**
 * Called once, BEFORE the first poll, with the codes the device must display
 * (§14.3 rule 2).
 *
 * The SDK does not print them on the caller's behalf and does not begin polling
 * until this has returned: a device shows them however it can — a screen, a QR
 * code, an e-ink panel — and only the application knows which.
 */
typedef void (*axiam_device_display_fn)(void *ctx,
                                        const axiam_device_authorization_t *authorization);

/**
 * The composed helper (§14.3): authorize, hand the caller the codes, poll to
 * completion.
 *
 * Polling follows §14.2 exactly. The interval starts at the SERVER's value (5 s
 * when it sent none — no faster floor may be hard-coded); `slow_down` adds 5 s
 * to the CURRENT interval permanently and never resets it, because an SDK that
 * backs off for one round and returns to the original rate will be told to slow
 * down again forever; and the loop stops at `expires_in` even if the server has
 * not yet said `expired_token`, because the deadline is authoritative and the
 * extra requests are pure load.
 *
 * A `5xx` or transport failure mid-poll is NOT terminal (§14.2 rule 6): it has
 * already been through the §16 bounded retry inside the poll, whose budget is
 * per attempt and separate from this loop, and a server restart mid-flow must
 * not lose a grant the user already approved.
 *
 * The token set is RETURNED, not adopted — the same posture
 * axiam_login_client_credentials() takes, which §14.3 rule 4 requires an SDK to
 * match rather than inventing a second one.
 *
 * @param display May be NULL only if the caller genuinely has no way to show the
 *                codes, in which case the grant cannot be approved; passing NULL
 *                is accepted rather than refused so a caller can drive
 *                axiam_device_poll() itself after an out-of-band display.
 * @param out     Filled on success; dispose with axiam_oidc_token_set_dispose().
 */
axiam_error_kind_t axiam_device_login(axiam_client_t *client,
                                      const char *scope,
                                      const char *tenant_id,
                                      axiam_device_display_fn display,
                                      void *display_ctx,
                                      axiam_oidc_token_set_t *out,
                                      axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* §15 — token exchange (RFC 8693)                                    */
/* ------------------------------------------------------------------ */

/** Arguments to axiam_token_exchange(). All borrowed. */
typedef struct axiam_token_exchange_params {
    /** The token being exchanged. Required. */
    const axiam_sensitive_t *subject_token;
    /**
     * ITS PRESENCE SELECTS DELEGATION; ITS ABSENCE SELECTS IMPERSONATION.
     *
     * Two different operations with different risk, and §15.2 rule 1 forbids
     * papering over the difference: this SDK supplies no default actor token and
     * never substitutes the client's own session for one. Passing NULL asks for
     * impersonation, and the server refuses unless this client holds that grant.
     */
    const axiam_sensitive_t *actor_token;
    /** Scope names. NULL/0 inherits the subject's, bounded by this client's
     *  registration — read the RESULT's `scope` for what was actually granted. */
    const char *const *scopes;
    size_t scope_count;
    const char *audience; /**< Optional. */
    const char *resource; /**< Optional. */
    /** Tenant UUID for `?tenant_id=`; NULL falls back to the client's. */
    const char *tenant_id;
} axiam_token_exchange_params_t;

/**
 * `POST /oauth2/token` with the RFC 8693 grant (§15.1).
 *
 * The exchanging client AUTHENTICATES (`client_secret_post`) — unlike §14's
 * device, this is a confidential service, and a client with no configured secret
 * is refused client-side.
 *
 * What this deliberately does NOT do:
 *
 *  - NO retry, downgrade or rewrite on `unauthorized_client` (§15.2 rule 2). It
 *    means either "this client may not exchange at all" or "this client may not
 *    impersonate"; both are registration facts an operator must fix, and
 *    reworking the request into a delegation would send one the caller did not
 *    write.
 *  - NO auto-narrowing on `invalid_scope` (§15.2 rule 3). The server refuses
 *    rather than silently narrowing precisely so the caller finds out here.
 *  - NO refresh token, ever (§15.2 rule 4) — axiam_exchanged_token_t has nowhere
 *    to put one, and this result never enters the §9 guard.
 *  - NO adoption (§15.2 rule 5). This is a MUST NOT where adoption elsewhere is
 *    a MAY: the exchanged token is one to hand onward in one outbound call, and
 *    adopting it would silently re-privilege every subsequent call this client
 *    makes.
 *
 * A cross-tenant subject token answers `invalid_grant`, and this SDK does not
 * try to tell "wrong tenant" from "bad token" (§15.3): the server collapses them
 * because distinguishing them is a tenant-enumeration signal, and re-deriving
 * the distinction client-side hands back what the server withheld. The code is
 * in axiam_error_t::oauth_error, verbatim.
 *
 * @param out Filled on success; dispose with axiam_exchanged_token_dispose().
 */
axiam_error_kind_t axiam_token_exchange(axiam_client_t *client,
                                        const axiam_token_exchange_params_t *params,
                                        axiam_exchanged_token_t *out,
                                        axiam_error_t *err);

/* ---- Disposal. Each is safe on NULL and on a zeroed struct. ---- */

void axiam_oidc_config_dispose(axiam_oidc_config_t *cfg);
void axiam_authorization_request_dispose(axiam_authorization_request_t *req);
void axiam_id_token_claims_free(axiam_id_token_claims_t *claims);
void axiam_oidc_token_set_dispose(axiam_oidc_token_set_t *set);
void axiam_introspection_result_dispose(axiam_introspection_result_t *r);
void axiam_sso_start_result_dispose(axiam_sso_start_result_t *r);
void axiam_sso_complete_result_dispose(axiam_sso_complete_result_t *r);
void axiam_verified_logout_token_dispose(axiam_verified_logout_token_t *t);
void axiam_device_authorization_dispose(axiam_device_authorization_t *d);
void axiam_exchanged_token_dispose(axiam_exchanged_token_t *t);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_OIDC_H */
