/*
 * AXIAM C SDK — UMA 2.0 Protection API and ticket grant (CONTRACT.md §20).
 *
 * The resource-server side of User-Managed Access: a service that guards
 * resources on someone else's behalf registers them, asks the authorization
 * server what a caller would need, and exchanges the resulting ticket for a
 * Requesting Party Token.
 *
 * WHY THIS SHIPS WHILE §12 DOES NOT. The README records §12.7, §14 and §15 as
 * deferred because each needs an OIDC layer this SDK does not have — a
 * discovery cache, ID-token validation, PKCE. §20 needs none of that: UMA
 * carries its OWN discovery document (/.well-known/uma2-configuration, §20.1's
 * named wire reference), the Protection API is ordinary bearer-authenticated
 * REST, and the ticket grant returns an opaque RPT with no id_token to
 * validate. One GET and one POST. The parallel-stack objection genuinely does
 * not apply here, so the deferral would have been a habit rather than a reason.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE. A permission ticket is single-use and
 * is NOT retryable. Every other refusal in this SDK can be re-sent after the
 * caller fixes something; this one cannot — the ticket is spent whether or not
 * the exchange succeeded. See axiam_uma_exchange_ticket().
 *
 * OWNERSHIP. Every out-parameter that carries heap memory has a matching
 * _dispose/_free function, and every one of them is safe on a zeroed struct, so
 * a caller can dispose unconditionally on the error path.
 */
#ifndef AXIAM_UMA_H
#define AXIAM_UMA_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The scope a PAT must carry (§20.2 rule 1) — for callers minting one. */
#define AXIAM_UMA_PROTECTION_SCOPE "uma_protection"

/** grant_type of the UMA 2.0 ticket grant (§20.1). */
#define AXIAM_UMA_TICKET_GRANT_TYPE "urn:ietf:params:oauth:grant-type:uma-ticket"

/**
 * The only claim_token_format AXIAM implements. §20.2 rule 2 makes the
 * claim_token itself required rather than defaulted; the FORMAT has one value,
 * so the SDK supplies it.
 */
#define AXIAM_UMA_CLAIM_TOKEN_FORMAT "urn:ietf:params:oauth:token-type:access_token"

/** The UMA 2.0 discovery document (§20.1). All members owned. */
typedef struct axiam_uma_config {
    char *issuer;
    char *token_endpoint;
    char *permission_endpoint;
    char *resource_registration_endpoint;
    /** The ticket TTL the server advertises; -1 when it sent none. */
    long permission_ticket_lifetime;
} axiam_uma_config_t;

/**
 * A UMA resource set — an AXIAM resource seen through the Protection API
 * (§20.1). All members owned.
 *
 * `id` is THE AXIAM RESOURCE ID, not a parallel identifier: the same UUID is
 * directly usable as axiam_uma_permission_t::resource_id, and as the resource
 * id anywhere else in this SDK.
 */
typedef struct axiam_uma_resource_set {
    char *id;             /**< Assigned by the server; NULL on the way in. */
    char *name;           /**< Human-readable name. */
    char *type;           /**< Free-form type; NULL when the server sent none. */
    char **scopes;        /**< Declared scope names. */
    size_t scope_count;
} axiam_uma_resource_set_t;

/**
 * One (resource, scopes) pair a resource server requires (§20.1). Borrowed
 * pointers: the caller owns them and they must outlive the call.
 */
typedef struct axiam_uma_permission {
    const char *resource_id;       /**< The AXIAM resource id. */
    const char *const *scopes;     /**< Scope names, matched exactly. */
    size_t scope_count;
} axiam_uma_permission_t;

/**
 * The result of the ticket grant (§20.1).
 *
 * THERE IS NO refresh_token MEMBER, AND THAT IS DELIBERATE (§20.2 rule 5). The
 * grant issues none, so an RPT cannot outlive the ticket that authorised it; an
 * application that wants a fresh one re-runs the grant.
 */
typedef struct axiam_uma_rpt {
    axiam_sensitive_t *access_token; /**< The RPT itself (§20.6 secret). */
    char *token_type;                /**< Always "Bearer". */
    long expires_in;                 /**< min(claim token life, ceiling, 300s). */
} axiam_uma_rpt_t;

/** A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2, §20.3). */
typedef struct axiam_uma_challenge {
    char *realm;                 /**< May be NULL. */
    char *as_uri;                /**< The nominated AS. NOT automatically trusted. */
    axiam_sensitive_t *ticket;   /**< §20.6 secret. May be NULL. */
} axiam_uma_challenge_t;

/**
 * GET /.well-known/uma2-configuration (§20.1) — fetch the UMA discovery
 * document.
 *
 * Cached on the client for five minutes, the floor §12.3 rule 6 sets for the
 * OIDC document: an endpoint map is not a credential, and re-fetching it on
 * every guarded request is a self-inflicted round trip. Every operation below
 * calls this itself, so a caller normally never needs to.
 *
 * @param out Filled on success; dispose with axiam_uma_config_dispose().
 */
axiam_error_kind_t axiam_uma_discover(axiam_client_t *client,
                                      axiam_uma_config_t *out,
                                      axiam_error_t *err);

/**
 * POST /uma2/rreg/resource_set (§20.1) — register a resource set.
 *
 * @param pat    A Protection API Token: a CLIENT-credentials token carrying the
 *               `uma_protection` scope (§20.2 rule 1). This SDK never
 *               substitutes its own session for it; a NULL or empty PAT is
 *               refused client-side, with no wire call.
 * @param type   May be NULL, in which case the field is omitted rather than
 *               sent empty and the server applies its `uma_resource` default.
 * @param out    Filled on success; dispose with axiam_uma_resource_set_dispose().
 */
axiam_error_kind_t axiam_uma_register_resource(axiam_client_t *client,
                                               const axiam_sensitive_t *pat,
                                               const char *name,
                                               const char *type,
                                               const char *const *scopes,
                                               size_t scope_count,
                                               axiam_uma_resource_set_t *out,
                                               axiam_error_t *err);

/** GET /uma2/rreg/resource_set/{id} (§20.1) — read a registered resource set. */
axiam_error_kind_t axiam_uma_read_resource(axiam_client_t *client,
                                           const axiam_sensitive_t *pat,
                                           const char *id,
                                           axiam_uma_resource_set_t *out,
                                           axiam_error_t *err);

/**
 * PUT /uma2/rreg/resource_set/{id} (§20.1) — replace a resource set's state.
 *
 * `scopes` REPLACES the declared list; it does not merge with it (§20.2 rule 8).
 * This function performs no read-modify-write: folding the current scopes into
 * the payload as a convenience would make removing a scope impossible through
 * this SDK.
 */
axiam_error_kind_t axiam_uma_update_resource(axiam_client_t *client,
                                             const axiam_sensitive_t *pat,
                                             const char *id,
                                             const char *name,
                                             const char *type,
                                             const char *const *scopes,
                                             size_t scope_count,
                                             axiam_uma_resource_set_t *out,
                                             axiam_error_t *err);

/** DELETE /uma2/rreg/resource_set/{id} (§20.1) — deregister a resource set. */
axiam_error_kind_t axiam_uma_delete_resource(axiam_client_t *client,
                                             const axiam_sensitive_t *pat,
                                             const char *id,
                                             axiam_error_t *err);

/**
 * GET /uma2/rreg/resource_set (§20.1) — the ids THIS client registered.
 *
 * Not the tenant's resource tree: the server scopes the listing to the
 * registering client, so a PAT is not an enumeration handle.
 *
 * @param out_ids   Receives a malloc'd array of malloc'd strings; free with
 *                  axiam_uma_string_array_free().
 * @param out_count Receives the element count.
 */
axiam_error_kind_t axiam_uma_list_resources(axiam_client_t *client,
                                            const axiam_sensitive_t *pat,
                                            char ***out_ids,
                                            size_t *out_count,
                                            axiam_error_t *err);

/**
 * POST /uma2/perm (§20.1) — mint a permission ticket for the pairs a caller
 * lacks.
 *
 * The ticket comes back wrapped: for its 60-second life it is the credential
 * that converts into an RPT, and a short lifetime is not the same as a harmless
 * one (§20.6).
 *
 * @param out_ticket Receives an owned handle; free with axiam_sensitive_free().
 */
axiam_error_kind_t axiam_uma_request_ticket(axiam_client_t *client,
                                            const axiam_sensitive_t *pat,
                                            const axiam_uma_permission_t *permissions,
                                            size_t permission_count,
                                            axiam_sensitive_t **out_ticket,
                                            axiam_error_t *err);

/** Arguments to axiam_uma_exchange_ticket(). All borrowed. */
typedef struct axiam_uma_exchange_params {
    /**
     * The permission ticket to redeem (§20.6 secret). Required.
     *
     * SINGLE-USE AND NOT RETRYABLE: it is spent whether or not the exchange
     * succeeds. A failure means "request a NEW ticket", never "send this one
     * again" (§20.2 rule 6).
     */
    const axiam_sensitive_t *ticket;
    /**
     * The requesting party's access token (§20.6 secret). Required, and never
     * defaulted (§20.2 rule 2) — it is the only channel that names the
     * requesting party.
     */
    const axiam_sensitive_t *claim_token;
    /** The confidential client's id (client_secret_post, §20.1). Required. */
    const char *client_id;
    /** The confidential client's secret. Required. */
    const axiam_sensitive_t *client_secret;
    /**
     * Tenant UUID for the mandatory `?tenant_id=` query parameter (§12.1
     * note 2). NULL falls back to the client's configured tenant_id; a tenant
     * SLUG is never a valid substitute (§12.3 rule 4).
     */
    const char *tenant_id;
} axiam_uma_exchange_params_t;

/**
 * POST /oauth2/token with the UMA ticket grant (§20.1) — redeem a permission
 * ticket for a Requesting Party Token.
 *
 * What this function deliberately does NOT do:
 *
 *  - NO RETRY, EVER (§20.2 rule 6) — not on 5xx, not on a transport failure,
 *    not on invalid_grant. This is the one documented exception to §16, and it
 *    is a security rule rather than a performance one: the ticket is consumed
 *    BEFORE the request is evaluated, so a failed exchange has already spent
 *    it, and a retry is a second redemption — exactly the concurrent redemption
 *    a server whose storage engine this SDK cannot attest may admit twice
 *    (ilpanich/axiam#302). The property holds structurally: this call never
 *    enters the §16 retry loop.
 *  - No defaulted claim_token (rule 2). Defaulting it to the resource server's
 *    own PAT would mint an RPT for the resource server rather than for the
 *    user. An absent one is refused client-side, with no wire call, so a
 *    request that could not have succeeded never spends a ticket.
 *  - No auto-narrowing on access_denied (rule 3). A partial grant is refused
 *    whole, and whether two-of-three permissions is useful is the calling
 *    application's judgement, not this SDK's.
 *  - No adoption (rule 4). The RPT is the REQUESTING PARTY's token; it is
 *    returned to the caller and never becomes this client's own credential.
 *  - No refresh token (rule 5) — axiam_uma_rpt_t has nowhere to put one.
 *
 * §20.4: the four ticket refusals — unknown, expired, already used, minted by
 * another client — all arrive as one `invalid_grant`, and this SDK does not
 * guess which; the server collapses them because telling them apart lets a
 * caller probe for live ticket handles. The machine-readable code is placed in
 * axiam_error_t::oauth_error, which is dispatched on the body's `error` field
 * at ANY status: access_denied answers HTTP 403 here where RFC 8628's answers
 * 400, and the field is what stays correct if either moves.
 *
 * @param out Filled on success; dispose with axiam_uma_rpt_dispose().
 */
axiam_error_kind_t axiam_uma_exchange_ticket(axiam_client_t *client,
                                             const axiam_uma_exchange_params_t *params,
                                             axiam_uma_rpt_t *out,
                                             axiam_error_t *err);

/**
 * Parse a `WWW-Authenticate: UMA …` header value (§20.3). Returns 1 when the
 * header is a UMA challenge and `out` was filled, 0 otherwise (`out` is zeroed).
 *
 * PURE LOCAL COMPUTATION — it performs NO exchange of the ticket it finds, and
 * that is the point. Parsing a challenge and acting on it are separate
 * decisions: the as_uri names an authorization server the client has not
 * necessarily chosen to trust, and auto-exchanging would send the requesting
 * party's claim_token to whatever host answered the 401. The parsed challenge
 * is returned; the caller decides.
 *
 * Dispose with axiam_uma_challenge_dispose().
 */
int axiam_uma_parse_challenge(const char *header, axiam_uma_challenge_t *out);

/**
 * Format a `WWW-Authenticate: UMA` header value (§20.3, emit half) — for a
 * resource server that has just minted a ticket and wants to tell the caller
 * where to redeem it.
 *
 * @return A malloc'd string the caller frees, or NULL on OOM/invalid input.
 */
char *axiam_uma_challenge_header(const char *realm, const char *as_uri,
                                 const axiam_sensitive_t *ticket);

/* ---- Disposal. Each is safe on NULL and on a zeroed struct. ---- */

void axiam_uma_config_dispose(axiam_uma_config_t *cfg);
void axiam_uma_resource_set_dispose(axiam_uma_resource_set_t *rs);
void axiam_uma_rpt_dispose(axiam_uma_rpt_t *rpt);
void axiam_uma_challenge_dispose(axiam_uma_challenge_t *ch);
void axiam_uma_string_array_free(char **items, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_UMA_H */
