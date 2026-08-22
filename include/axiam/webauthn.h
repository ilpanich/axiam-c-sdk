/*
 * AXIAM C SDK — WebAuthn / passkeys (CONTRACT.md §24).
 *
 * WHAT IS HERE, AND WHAT DELIBERATELY IS NOT.
 *
 * The six relying-party wire operations, plus §24.6a's JSON bridge. What is not
 * here is §24.6b's linked-API ceremony helper: a C program has no authenticator
 * — there is no platform API to link on the targets this SDK serves — and
 * §24.6b rule 2 forbids emulating one in software, because a "credential" held
 * in process memory is not a second factor.
 *
 * That is a statement about convenience, not about capability. §24.6a is the
 * seam that makes it so: axiam_webauthn_request_json() hands out the challenge
 * in the exact JSON form every platform authenticator API takes, and every
 * *_finish takes the platform's response JSON back as a string, byte for byte.
 * An embedded gateway that fronts a browser, a mobile app talking to a C
 * service, or a test harness driving a virtual authenticator all use the same
 * two seams.
 *
 * THE SERVER OWNS THE OPTIONS (§24.0). Nothing in this file defaults a field,
 * validates one, or re-encodes a buffer. The challenge arrives as JSON text and
 * leaves as JSON text; the authenticator's response is spliced into the request
 * body without being parsed into a model and printed back out. A signed buffer
 * that makes a round trip through a JSON model is a signed buffer that can come
 * out different.
 *
 * OWNERSHIP. Every out-parameter carrying heap memory has a matching _dispose,
 * and every one is safe on NULL and on a zeroed struct, so a caller can dispose
 * unconditionally on the error path.
 */
#ifndef AXIAM_WEBAUTHN_H
#define AXIAM_WEBAUTHN_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

/**
 * A started ceremony: the server's options plus the token binding a response to
 * them (§24.1).
 */
typedef struct axiam_webauthn_challenge {
    /**
     * The server's options as JSON TEXT, exactly as they arrived — a
     * `{"publicKey": {…}}` object carrying base64url buffers. Owned; freed by
     * axiam_webauthn_challenge_dispose().
     *
     * Hand it to the authenticator unchanged (§24.0), or call
     * axiam_webauthn_request_json() for the string a platform API takes.
     */
    char *challenge_json;
    /**
     * Binds the authenticator's answer to this challenge.
     *
     * A bearer credential for the length of the ceremony — one that leaks
     * inside that window is a ceremony an attacker can try to complete — so it
     * is held behind a Sensitive handle (§24.5). It is OPAQUE: this SDK never
     * decodes it, and neither should a caller.
     */
    axiam_sensitive_t *state_token;
} axiam_webauthn_challenge_t;

/** Release the heap members of a challenge (not the struct itself). */
void axiam_webauthn_challenge_dispose(axiam_webauthn_challenge_t *c);

/** A credential the user just enrolled — the `201` body of register/finish. */
typedef struct axiam_webauthn_credential {
    char *id;              /**< This credential's AXIAM id, for a later delete. */
    char *credential_id;   /**< The authenticator's own base64url credential id. */
    char *name;            /**< The label it was stored under. */
    char *credential_type; /**< "passkey" or "security_key". */
    char *created_at;      /**< RFC 3339 timestamp. */
    char *last_used_at;    /**< RFC 3339 timestamp, or NULL for a credential never used. */
} axiam_webauthn_credential_t;

/** Release the heap members of a credential (not the struct itself). */
void axiam_webauthn_credential_dispose(axiam_webauthn_credential_t *c);

/**
 * A completed authentication ceremony (§24.3).
 *
 * The tokens are also adopted by the client that produced this value — the
 * server sets the axiam_access / axiam_refresh / axiam_csrf cookie triple
 * alongside them — so a caller who only wants to be signed in can dispose this
 * immediately.
 */
typedef struct axiam_webauthn_login {
    axiam_sensitive_t *access_token;  /**< §24.5. */
    axiam_sensitive_t *refresh_token; /**< §24.5. */
    char *session_id;                 /**< The session this ceremony established. */
    long expires_in;                  /**< Access token TTL, seconds. */
} axiam_webauthn_login_t;

/** Release the heap members of a login result. The tokens are zeroized (§7). */
void axiam_webauthn_login_dispose(axiam_webauthn_login_t *l);

/**
 * The workspace a usernameless ceremony runs in (§24.1).
 *
 * `discoverable/start` is the one WebAuthn endpoint that carries the workspace
 * explicitly, because a usernameless ceremony has no prior step to have minted
 * a token that names it. Unlike the five /oauth2 operations of §12.1 rule 2 it
 * ACCEPTS SLUGS, so a slug-only client can run it.
 *
 * Pass NULL to axiam_webauthn_discoverable_start() to have it filled from the
 * client's own configured identity, which is what almost every caller wants.
 * Every member is borrowed, not owned: nothing here is freed by this SDK.
 */
typedef struct axiam_webauthn_workspace {
    const char *org_id;
    const char *org_slug;
    const char *tenant_id;
    const char *tenant_slug;
} axiam_webauthn_workspace_t;

/**
 * A ceremony failure a caller can say something useful about (§24.6b rule 5).
 *
 * This SDK ships no linked-API helper, but the classification is still required
 * of it: whatever DID run the ceremony — a browser, a phone — reports the
 * failure as one opaque type whose only machine-readable part is a name, and
 * translating that once beats translating it in every caller.
 */
typedef enum axiam_webauthn_failure {
    /**
     * Covers BOTH an explicit refusal and a silent timeout.
     *
     * The WebAuthn spec deliberately refuses to distinguish them, because
     * telling a website which one happened leaks whether an authenticator was
     * present. It must not be recovered by timing the call, and user-facing
     * copy must not accuse the user of cancelling.
     */
    AXIAM_WEBAUTHN_CANCELLED = 0,
    /**
     * The authenticator already holds a credential for this account and refused
     * to silently mint a second — the exclusion list working, not a failure.
     * The only classification whose remedy is "use a different device".
     */
    AXIAM_WEBAUTHN_ALREADY_REGISTERED = 1,
    /** An explicitly aborted ceremony. */
    AXIAM_WEBAUTHN_TIMEOUT = 2,
    /** This device or browser cannot run the ceremony. */
    AXIAM_WEBAUTHN_UNSUPPORTED = 3,
    /** Everything else. */
    AXIAM_WEBAUTHN_UNKNOWN = 4
} axiam_webauthn_failure_t;

/**
 * Map a platform ceremony error name to its canonical classification.
 *
 * Anything unrecognised — including NULL — is AXIAM_WEBAUTHN_UNKNOWN rather
 * than an error: a classifier that can fail is one more thing for an error
 * handler to handle. Case-insensitive.
 */
axiam_webauthn_failure_t axiam_webauthn_classify(const char *platform_error_name);

/**
 * Copy for a failure, safe to show a user. Returns a static string; never NULL.
 *
 * The AXIAM_WEBAUTHN_CANCELLED string deliberately does not accuse anyone of
 * cancelling: the same classification covers a silent timeout, and the spec will
 * not say which happened.
 */
const char *axiam_webauthn_failure_message(axiam_webauthn_failure_t f);

/* ------------------------------------------------------------------ */
/* §24.6a — the JSON bridge                                           */
/* ------------------------------------------------------------------ */

/**
 * The challenge in the JSON form every platform authenticator API takes
 * (§24.6a rule 1).
 *
 * This is the string a browser passes to
 * `PublicKeyCredential.parseCreationOptionsFromJSON()` and an Android app
 * passes to `CreatePublicKeyCredentialRequest`. It is the INNER options object:
 * the `publicKey` wrapper belongs to the DOM's `CredentialCreationOptions`, and
 * the platform JSON APIs do not want it.
 *
 * Pure local computation, no I/O. Nothing is defaulted, dropped or reordered on
 * the way through (§24.0).
 *
 * @return a malloc'd string the caller frees, or NULL on OOM. When the
 *         challenge carries no `publicKey` wrapper the whole object is returned
 *         — a server that sent the bare options is not wrong for every
 *         consumer, and this call has one job.
 */
char *axiam_webauthn_request_json(const axiam_webauthn_challenge_t *c);

/* ------------------------------------------------------------------ */
/* §24.1 — the six wire operations                                    */
/* ------------------------------------------------------------------ */

/**
 * POST /api/v1/auth/webauthn/register/start (§24.1) — begin enrolling a passkey
 * for the signed-in user.
 *
 * Requires a session, and refuses CLIENT-SIDE WITH NO WIRE CALL when there is
 * none — the shape §1.1 rule 3 requires of get_user_info.
 *
 * A `503` here means the tenant's attestation policy needs FIDO metadata the
 * server cannot reach: a configuration state, not a transient one, and §24.4
 * rule 2 deliberately does not retry it.
 */
axiam_error_kind_t axiam_webauthn_register_start(axiam_client_t *client,
                                                 axiam_webauthn_challenge_t *out,
                                                 axiam_error_t *err);

/**
 * POST /api/v1/auth/webauthn/register/finish (§24.1) — hand the authenticator's
 * answer back and store the credential.
 *
 * @param response the platform's own response JSON, VERBATIM (§24.6a rule 2).
 *        It reaches the wire byte for byte, because re-encoding a signed buffer
 *        is three chances to corrupt it in service of nothing. A string that is
 *        not a JSON object is refused client-side, with no wire call.
 */
axiam_error_kind_t axiam_webauthn_register_finish(axiam_client_t *client,
                                                  const axiam_sensitive_t *state_token,
                                                  const char *credential_name,
                                                  const char *response,
                                                  axiam_webauthn_credential_t *out,
                                                  axiam_error_t *err);

/**
 * POST /api/v1/auth/webauthn/authenticate/start (§24.1) — begin the
 * SECOND-FACTOR ceremony.
 *
 * Continues an axiam_login() that answered mfa_required with "webauthn" among
 * its available methods; `challenge_token` is that login's token. A different
 * flow from axiam_webauthn_discoverable_start(), not the same one with a flag
 * (§24.2) — which is why the token is required here and absent there.
 */
axiam_error_kind_t axiam_webauthn_authenticate_start(axiam_client_t *client,
                                                     const axiam_sensitive_t *challenge_token,
                                                     axiam_webauthn_challenge_t *out,
                                                     axiam_error_t *err);

/**
 * POST /api/v1/auth/webauthn/authenticate/finish (§24.1).
 *
 * On success the client is signed in: the server sets the same cookie triple
 * POST /api/v1/auth/login sets, and the §17 decision memo is cleared because
 * the subject changed (§24.3).
 */
axiam_error_kind_t axiam_webauthn_authenticate_finish(axiam_client_t *client,
                                                      const axiam_sensitive_t *state_token,
                                                      const char *response,
                                                      axiam_webauthn_login_t *out,
                                                      axiam_error_t *err);

/**
 * POST /api/v1/auth/webauthn/authenticate/discoverable/start (§24.1) — begin
 * the usernameless ceremony.
 *
 * A PRIMARY FACTOR: nothing precedes it, `allowCredentials` comes back empty,
 * and the assertion itself identifies the user. Pass NULL for `workspace` to
 * have it filled from this client's own configured identity.
 *
 * Unlike authenticate/finish, discoverable/finish fires the `login.post_auth`
 * reactor hook (§22.5) — the former continues a login already gated at its
 * password step, and this one has no such step.
 */
axiam_error_kind_t axiam_webauthn_discoverable_start(axiam_client_t *client,
                                                     const axiam_webauthn_workspace_t *workspace,
                                                     axiam_webauthn_challenge_t *out,
                                                     axiam_error_t *err);

/**
 * POST /api/v1/auth/webauthn/authenticate/discoverable/finish (§24.1). Adopts
 * credentials exactly as axiam_webauthn_authenticate_finish() does.
 */
axiam_error_kind_t axiam_webauthn_discoverable_finish(axiam_client_t *client,
                                                      const axiam_sensitive_t *state_token,
                                                      const char *response,
                                                      axiam_webauthn_login_t *out,
                                                      axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_WEBAUTHN_H */
