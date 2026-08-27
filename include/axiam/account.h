/*
 * AXIAM C SDK — account lifecycle and MFA enrolment (CONTRACT.md §25).
 *
 * The calls a user makes about their own account, none of which is
 * administration: voluntary and forced TOTP enrolment, email verification, and
 * the password-reset triple. All nine have been live server surface since
 * before §1 was written; what they lacked was an SDK, which is exactly the
 * divergence §1 exists to prevent, arrived at through omission.
 *
 * SIX OF THE NINE ARE DELIBERATELY UNAUTHENTICATED. A user who cannot log in is
 * the entire audience for a password reset, and a user whose email is
 * unverified may have no session at all.
 *
 * WHERE THE TENANT GOES. `verify_email`, `resend_verification` and
 * `confirm_password_reset` take it as a BODY field — these are not /oauth2
 * endpoints, so §12.1 rule 2's query-parameter convention does not reach them.
 * `request_password_reset` accepts the workspace in slug form as well, like
 * login.
 */
#ifndef AXIAM_ACCOUNT_H
#define AXIAM_ACCOUNT_H

#include "axiam/client.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A TOTP factor offered but not yet active (§25.1).
 *
 * BOTH HALVES ARE SENSITIVE, AND THE SECOND ONE IS WHY. The otpauth:// URI
 * CONTAINS the secret: wrapping the bare secret and leaving the URI as a plain
 * string has wrapped nothing, because the URI is the field that actually gets
 * logged — it is the one the caller passes to a QR renderer (§25.3).
 */
typedef struct axiam_mfa_enrollment {
    /** The shared TOTP secret. Anyone holding it can generate valid codes forever. */
    axiam_sensitive_t *secret_base32;
    /** `otpauth://totp/…?secret=<secret_base32>` — the string an app scans. */
    axiam_sensitive_t *totp_uri;
} axiam_mfa_enrollment_t;

/** Release the heap members of an enrolment. Both secrets are zeroized (§7). */
void axiam_mfa_enrollment_dispose(axiam_mfa_enrollment_t *e);

/**
 * The OPAQUE policy for the account a reset token belongs to (§25.1).
 */
typedef struct axiam_password_reset_context {
    /**
     * The tenant's §23 parameters as JSON TEXT when it has OPAQUE enabled, and
     * NULL when it does not — in which case the plaintext path is allowed.
     *
     * Forwarded to the §23 helpers untouched: this SDK does not model, validate
     * or re-encode the block. Owned; freed by the dispose below.
     */
    char *opaque_json;
} axiam_password_reset_context_t;

/** Release the heap members of a reset context. */
void axiam_password_reset_context_dispose(axiam_password_reset_context_t *c);

/**
 * Arguments to axiam_request_password_reset() (§25.1).
 *
 * The workspace members are all optional: left NULL, they are filled from the
 * client's own configured identity, which is what almost every caller wants.
 * Every member is borrowed, not owned.
 */
typedef struct axiam_password_reset_request {
    const char *email;       /**< The address to send the reset mail to. Required. */
    const char *org_slug;    /**< An organization override. */
    const char *tenant_id;   /**< A tenant override, in UUID form. */
    const char *tenant_slug; /**< A tenant override, in slug form. */
} axiam_password_reset_request_t;

/**
 * Arguments to axiam_confirm_password_reset() (§25.1).
 *
 * `opaque_json`, when non-NULL, is the §23 registration record as JSON text —
 * spliced into the request body verbatim, exactly as the §23 helpers produced
 * it. Every member is borrowed, not owned.
 */
typedef struct axiam_password_reset_confirmation {
    const axiam_sensitive_t *token;        /**< The single-use token from the reset mail. */
    const axiam_sensitive_t *new_password; /**< The replacement password. */
    const char *tenant_id;                 /**< A BODY field; see the file header. */
    const char *opaque_json;               /**< The §23 record, or NULL on the plaintext path. */
} axiam_password_reset_confirmation_t;

/* ------------------------------------------------------------------ */
/* Voluntary enrolment (§25.2)                                        */
/* ------------------------------------------------------------------ */

/**
 * POST /api/v1/auth/mfa/enroll (§25.1) — start voluntary TOTP enrolment for the
 * signed-in user.
 *
 * Changes nothing about the current session. In particular it does NOT clear
 * the §17 decision memo: the subject has not changed, and discarding a warm
 * memo on an unrelated profile action costs a round trip on every check that
 * follows (§25.2 rule 3).
 *
 * ENROLMENT IS TWO CALLS AND THIS IS ONLY THE FIRST. The factor is not active
 * until axiam_mfa_confirm() accepts a code derived from the returned secret,
 * and §25.2 rule 4 forbids a composed one-call helper here — the human step in
 * the middle is not something a helper can wait for.
 */
axiam_error_kind_t axiam_mfa_enroll(axiam_client_t *client,
                                    axiam_mfa_enrollment_t *out,
                                    axiam_error_t *err);

/**
 * POST /api/v1/auth/mfa/confirm (§25.1) — activate the factor axiam_mfa_enroll()
 * offered.
 *
 * @param out_enabled receives 1 when MFA is now on. May be NULL.
 */
axiam_error_kind_t axiam_mfa_confirm(axiam_client_t *client,
                                     const char *totp_code,
                                     int *out_enabled,
                                     axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* Forced enrolment (§25.2 rule 2)                                    */
/* ------------------------------------------------------------------ */

/**
 * POST /api/v1/auth/mfa/setup/enroll (§25.1) — start the enrolment an
 * axiam_login() demanded.
 *
 * Reached when login returns `mfa_setup_required` with a `setup_token`: the
 * tenant requires MFA and this account has none. There is no session yet — the
 * setup token IS the credential.
 */
axiam_error_kind_t axiam_mfa_setup_enroll(axiam_client_t *client,
                                          const axiam_sensitive_t *setup_token,
                                          axiam_mfa_enrollment_t *out,
                                          axiam_error_t *err);

/**
 * POST /api/v1/auth/mfa/setup/confirm (§25.1) — finish forced enrolment and,
 * with it, the login that was interrupted.
 *
 * Adopts credentials exactly as axiam_login() does, because it IS the
 * completion of a login (§25.2 rule 2) — including clearing the §17 memo. `out`
 * is filled as axiam_login() fills it.
 */
axiam_error_kind_t axiam_mfa_setup_confirm(axiam_client_t *client,
                                           const axiam_sensitive_t *setup_token,
                                           const char *totp_code,
                                           axiam_login_result_t *out,
                                           axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* Email verification (§25.1)                                         */
/* ------------------------------------------------------------------ */

/** POST /api/v1/auth/verify-email (§25.1). Unauthenticated. */
axiam_error_kind_t axiam_verify_email(axiam_client_t *client,
                                      const axiam_sensitive_t *token,
                                      const char *tenant_id,
                                      axiam_error_t *err);

/**
 * POST /api/v1/auth/resend-verification (§25.1) — the UNAUTHENTICATED resend, for a
 * caller with no session.
 *
 * RETURNS AXIAM_OK WHATEVER THE OUTCOME. The address may not exist, may already be
 * verified, or may be over the daily limit, and the server answers identically in every
 * case because it takes an address from an anonymous caller: anything else is an oracle
 * for which addresses have accounts (§25.4).
 *
 * A caller that IS signed in wants axiam_resend_own_verification(), which says what
 * happened. §25.7 rule 2 forbids routing either of these to the other, and this SDK does
 * not.
 */
axiam_error_kind_t axiam_resend_verification(axiam_client_t *client,
                                             const char *email,
                                             const char *tenant_id,
                                             axiam_error_t *err);

/**
 * POST /api/v1/users/me/resend-verification (§25.1, §25.7) — resend the SIGNED-IN
 * caller's own verification mail, and say what happened.
 *
 * Takes no address. The server reads it off the caller's own record, and this signature
 * deliberately offers no way to name a different one: a parameter here would let an
 * authenticated session mail an arbitrary address.
 *
 * Unlike axiam_resend_verification() this reports the outcome, because the caller is
 * signed in to the account it is asking about and none of the outcomes tells it anything
 * it did not already bring with it:
 *
 *  - AXIAM_OK          — a token was minted and the mail ENQUEUED. Delivery is
 *                        asynchronous and can still fail at the provider; a queue that
 *                        accepts everything in front of a provider that rejects it looks
 *                        exactly like this succeeding (§25.7 rule 3).
 *  - AXIAM_ERR_AUTHZ   — from 409: already verified, or an account state that must not be
 *                        sent a live token.
 *  - AXIAM_ERR_NETWORK — from 429: the daily resend limit.
 *  - AXIAM_ERR_AUTH    — there is no session. Raised client-side, with NO wire call.
 *
 * §25.7 rule 2 forbids falling back to the unauthenticated endpoint on either failure,
 * and this SDK does not: that fallback turns both back into a silent success and restores
 * the bug this operation exists to fix, with an extra round trip.
 */
axiam_error_kind_t axiam_resend_own_verification(axiam_client_t *client,
                                                 axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* Password reset (§25.4)                                             */
/* ------------------------------------------------------------------ */

/**
 * POST /api/v1/auth/reset (§25.1) — ask for a reset mail.
 *
 * RETURNS AXIAM_OK WHETHER OR NOT THE ADDRESS EXISTS, and this SDK exposes no
 * way to tell the two apart. That is not an omission to improve on: a client
 * that surfaced a "no such user" state — even one inferred from timing — would
 * turn the endpoint into the account-enumeration oracle its uniform response
 * exists to prevent (§25.4).
 */
axiam_error_kind_t axiam_request_password_reset(axiam_client_t *client,
                                                const axiam_password_reset_request_t *request,
                                                axiam_error_t *err);

/**
 * GET /api/v1/auth/reset/context?token=… (§25.1) — the OPAQUE policy for the
 * account a reset token belongs to.
 *
 * Call this before axiam_confirm_password_reset() on any tenant that might have
 * §23 enabled: the client has to build a registration record, and building one
 * needs parameters it cannot know before it has a token to ask with. Sending a
 * plaintext password to a tenant in `opaque_mode: required` is refused, and
 * refused late (§25.4 rule 1).
 *
 * A `404` means unknown, expired OR already-consumed, deliberately without
 * distinguishing them; this SDK does not distinguish them either (§25.4 rule 3).
 */
axiam_error_kind_t axiam_password_reset_context(axiam_client_t *client,
                                                const axiam_sensitive_t *token,
                                                axiam_password_reset_context_t *out,
                                                axiam_error_t *err);

/** POST /api/v1/auth/reset/confirm (§25.1) — set the new password. */
axiam_error_kind_t axiam_confirm_password_reset(
    axiam_client_t *client,
    const axiam_password_reset_confirmation_t *confirmation,
    axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_ACCOUNT_H */
