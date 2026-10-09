/**
 * @file registration.h
 * @brief CONTRACT.md §28.12 — RFC 7592 client configuration (contract 1.53).
 *
 * A client that registered itself through `POST /oauth2/register` (RFC 7591) receives,
 * once, a `registration_client_uri` and a `registration_access_token`. With those two it
 * can read, replace and delete **its own** registration:
 *
 * | Canonical                      | C                                    |
 * |--------------------------------|--------------------------------------|
 * | `read_client_registration`     | axiam_read_client_registration()     |
 * | `update_client_registration`   | axiam_update_client_registration()   |
 * | `delete_client_registration`   | axiam_delete_client_registration()   |
 * | type `ClientRegistration`      | axiam_client_registration_t          |
 *
 * Four rules shape all three (§28.12.2):
 *
 * 1. **The URI is used verbatim, and only at the configured AXIAM.** A URI whose scheme,
 *    host or port differs from the client's base URL — or an `http` URI when the base URL
 *    is not `http` on a loopback host — is refused locally, BEFORE any request: the token
 *    is a bearer, and a helper that followed a URI to another origin would hand it to
 *    whoever wrote the URI. The refusal is this SDK's local ValidationError:
 *    AXIAM_ERR_NETWORK with `transport_cause` 400 (so axiam_mgmt_error_class() answers
 *    AXIAM_MGMT_ERR_VALIDATION), and its message names no part of the URI or the token.
 *    A URI carrying userinfo (`user@host`) is refused the same way.
 * 2. **The token travels in `Authorization: Bearer` only** — never in the query, never in
 *    a body. `GET` and `DELETE` send no body.
 * 3. **It is not the SDK's session.** These requests carry no session cookie (the cookie
 *    jar is withheld for the request), no CSRF token, no device access token and no
 *    tenant header; the transport never follows a redirect; and a `401` from them never
 *    enters the §9 refresh guard.
 * 4. **Neither write is retried.** An update that reached the server and lost its
 *    response has already rotated the token; a delete whose `204` was lost would read
 *    `401` on a retry. Only the read follows §16 — and never on a `4xx` other than `408`
 *    and `429`.
 *
 * Errors (§28.12.3): a response whose body carries a non-empty `error` is an
 * OAuthProtocolError at ANY status — AXIAM_ERR_AUTH with axiam_error_t::oauth_error set
 * (`invalid_token`, `invalid_request`, `invalid_client_metadata`,
 * `invalid_redirect_uri`) and `error_description` optional. Otherwise §2's status rows
 * apply (`429` and `5xx` are AXIAM_ERR_NETWORK).
 */
#ifndef AXIAM_REGISTRATION_H
#define AXIAM_REGISTRATION_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An RFC 7591 §3.2.1 / RFC 7592 §3 client information response (§28.12.1).
 *
 * Decoded TOLERANTLY: every member the server sent that this struct does not name — and
 * a named member of an unexpected JSON type — is kept verbatim in `extra`. RFC 7591
 * §3.2.1 lets a server add members, and because an update is a FULL REPLACEMENT, a member
 * a read returned and an update left out is a member the server deletes. Passing a read
 * result straight to axiam_update_client_registration() therefore sends it back intact,
 * `jwks`, `jwks_uri` and the CIBA `backchannel_*` members included.
 *
 * `registration_access_token` and `client_secret` are Sensitive (§28.12.4): their only
 * rendering is "[SENSITIVE]", and the one way to read either is axiam_sensitive_reveal().
 *
 * Every pointer member is owned; release the whole value with
 * axiam_client_registration_free(). A caller may build one by hand (calloc it and fill
 * the members with malloc'd strings) to pass to the update.
 */
typedef struct axiam_client_registration {
    /** The client's `client_id`. Always set on a decoded value. */
    char *client_id;
    /** When the client id was issued, seconds since the epoch. Never sent on an update. */
    long client_id_issued_at;
    int has_client_id_issued_at; /**< 1 when `client_id_issued_at` is set. */
    /** The registered display name, or NULL. */
    char *client_name;
    char **redirect_uris;        /**< The registered redirect URIs. */
    size_t redirect_uris_count;  /**< Entries in `redirect_uris`. */
    char **grant_types;          /**< The registered grant types. */
    size_t grant_types_count;    /**< Entries in `grant_types`. */
    char **response_types;       /**< The registered response types. */
    size_t response_types_count; /**< Entries in `response_types`. */
    /** How the client authenticates at the token endpoint; the server refuses an update
     *  that changes it. NULL when absent. */
    char *token_endpoint_auth_method;
    /** The registered scope, space-separated, or NULL. */
    char *scope;
    /** Where this registration is read, replaced and deleted. Never sent on an update. */
    char *registration_client_uri;
    /** When the client secret expires (`0` = never). Never sent on an update. */
    long client_secret_expires_at;
    int has_client_secret_expires_at; /**< 1 when `client_secret_expires_at` is set. */
    /** The client's JWK Set, as raw JSON text, for a `private_key_jwt` client; or NULL. */
    char *jwks;
    /** Where the client's JWK Set is published, or NULL. */
    char *jwks_uri;
    /** The client secret: present only on the registration response itself, never on a
     *  read or an update. Never sent back. */
    axiam_sensitive_t *client_secret;
    /** The registration access token: present on the registration response and,
     *  ROTATED, on every update response; absent on a read. Never sent in a body. */
    axiam_sensitive_t *registration_access_token;
    /** Every other member of the response, verbatim, as a raw JSON object text; NULL
     *  when there was none. */
    char *extra;
} axiam_client_registration_t;

/**
 * Decode a client information response from JSON text, tolerating unknown members.
 *
 * Returns NULL, with `err` set to AXIAM_ERR_NETWORK, when `json` is not a JSON object or
 * carries no `client_id` string. The result is freed with axiam_client_registration_free().
 */
axiam_client_registration_t *axiam_client_registration_parse(const char *json,
                                                             axiam_error_t *err);

/** Free a registration and everything it owns, scrubbing both Sensitive members. Safe
 *  on NULL. */
void axiam_client_registration_free(axiam_client_registration_t *reg);

/**
 * `GET registration_client_uri` (RFC 7592 §2.1, CONTRACT.md §28.12) — read this client's
 * registration.
 *
 * The result carries neither the token nor the client secret: the server never returns
 * them on a read. It does carry every member an update needs, so the usual update is
 * "read, change a member, update".
 *
 * Retried per §16 on a transport failure, a `5xx`, `408` or `429` — never on another
 * `4xx`. A `401 invalid_token` (an unknown client, a wrong or rotated-away token, another
 * tenant's client, a client with no token: the server never says which) is
 * AXIAM_ERR_AUTH with `oauth_error` "invalid_token", and never refreshes the SDK's
 * session.
 *
 * @param c                          The client; its base URL is the only origin accepted.
 * @param registration_client_uri    The URI from the registration response, verbatim.
 * @param registration_access_token  The registration's bearer.
 * @param out                        Receives the registration; free with
 *                                   axiam_client_registration_free(). NULL on failure.
 * @param err                        Filled on failure; may be NULL.
 */
axiam_error_kind_t axiam_read_client_registration(axiam_client_t *c,
                                                  const char *registration_client_uri,
                                                  const axiam_sensitive_t *registration_access_token,
                                                  axiam_client_registration_t **out,
                                                  axiam_error_t *err);

/**
 * `PUT registration_client_uri` (RFC 7592 §2.2, CONTRACT.md §28.12) — REPLACE this
 * client's registration, and receive a ROTATED token.
 *
 * `metadata` is the **whole** registration: a member it omits is a member the server
 * deletes. Start from axiam_read_client_registration()'s result, which carries every
 * member (`jwks` / `jwks_uri` and the `extra` members included), and change what you mean
 * to change. The body is every member of `metadata` (its `extra` members first, the named
 * members over them) with `client_id` set to `metadata->client_id`, and WITHOUT
 * `registration_access_token`, `registration_client_uri`, `client_secret_expires_at`,
 * `client_id_issued_at` and `client_secret` — wherever they appear, `extra` included.
 *
 * **Persist the returned `registration_access_token` before doing anything else.** From
 * the moment the server answers, it is the only valid token: the one you presented is
 * dead for every operation.
 *
 * **Never retried** — not on a transport error, not on a `5xx`. An update that reached
 * the server and lost its response has already rotated the token; repeating it with the
 * old one is a `401` that locks you out of your own registration. On a lost answer, read
 * the registration with the token you hold: a `401` means the update landed.
 *
 * @param out Receives the updated registration (carrying the rotated token); free with
 *            axiam_client_registration_free(). NULL on failure.
 */
axiam_error_kind_t axiam_update_client_registration(axiam_client_t *c,
                                                    const char *registration_client_uri,
                                                    const axiam_sensitive_t *registration_access_token,
                                                    const axiam_client_registration_t *metadata,
                                                    axiam_client_registration_t **out,
                                                    axiam_error_t *err);

/**
 * `DELETE registration_client_uri` (RFC 7592 §2.3, CONTRACT.md §28.12) — delete this
 * client's registration. A `204` (any `2xx`) returns AXIAM_OK.
 *
 * **Never retried**: a retry after a lost `204` would read `401` and report a successful
 * deletion as a failure.
 */
axiam_error_kind_t axiam_delete_client_registration(axiam_client_t *c,
                                                    const char *registration_client_uri,
                                                    const axiam_sensitive_t *registration_access_token,
                                                    axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_REGISTRATION_H */
