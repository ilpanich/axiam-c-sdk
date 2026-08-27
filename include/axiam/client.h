/*
 * AXIAM C SDK — Client operations (CONTRACT.md §1).
 *
 * All symbols are prefixed axiam_, snake_case. The canonical operations are:
 * login, verify_mfa, refresh, logout, check_access, can, batch_check.
 * check_access / can take (action, resource[, scope]) — action before object.
 */
#ifndef AXIAM_CLIENT_H
#define AXIAM_CLIENT_H

#include <stddef.h>
#include "axiam/config.h"
#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque client handle. Not thread-hostile: the single-flight refresh guard
 *  (§9) is internally synchronized; concurrent calls are supported. */
typedef struct axiam_client axiam_client_t;

/**
 * Construct a client from a config (§5 validation applied). On failure returns
 * NULL and fills err. The config may be freed after this call returns.
 */
axiam_client_t *axiam_client_new(const axiam_client_config_t *cfg, axiam_error_t *err);

/**
 * Deterministic shutdown (CONTRACT.md §18). Releases the transport, the cookie
 * jar, the JWKS cache and every OS handle the client holds, and zeroizes §7
 * Sensitive material — while leaving the handle itself valid so a later
 * axiam_client_free() is safe.
 *
 * - **Idempotent** (§18.1 rule 2): calling it twice is a no-op the second time,
 *   never a double free. Cleanup runs from error paths, and an error path that
 *   itself faults hides the original failure.
 * - **Does not log out** (§18.1 rule 5): it issues no request. The server-side
 *   session deliberately outlives the client object — that is what lets a
 *   process restart and resume — so a close() that logged out would silently
 *   end every user's session on each deploy.
 * - **Use after close is an error, not undefined** (§18.1 rule 4): every
 *   operation on a closed client returns AXIAM_ERR_NETWORK with a message
 *   naming the cause, rather than reconnecting or reading freed memory.
 *
 * Safe on NULL.
 */
void axiam_client_close(axiam_client_t *client);

/**
 * Destroy a client and free the handle. Calls axiam_client_close() first if the
 * caller has not, so `free` alone remains a complete shutdown (§18.1 rule 1
 * names axiam_client_free as this SDK's canonical form). Safe on NULL.
 */
void axiam_client_free(axiam_client_t *client);

/** Number of refresh transport round-trips performed (test/observability). */
unsigned long axiam_client_refresh_count(const axiam_client_t *client);

/* ------------------------------------------------------------------ */
/* Auth                                                               */
/* ------------------------------------------------------------------ */

/** Result of a login / verify_mfa call. Free with axiam_login_result_dispose. */
typedef struct axiam_login_result {
    int authenticated;      /**< 1 when a session was established. */
    int mfa_required;       /**< 1 when MFA verification is required next. */
    int mfa_setup_required; /**< 1 when MFA enrollment is required. */
    /**
     * For axiam_verify_mfa_sensitive (when mfa_required). CONTRACT §7 classes
     * the MFA challenge token as a secret, so it is held behind an opaque
     * Sensitive handle: it renders as "[SENSITIVE]" and its backing memory is
     * zeroized by axiam_login_result_dispose(). May be NULL.
     */
    axiam_sensitive_t *challenge_token;
    /** MFA-setup token (when mfa_setup_required); Sensitive, as above. */
    axiam_sensitive_t *setup_token;
    char *session_id;       /**< Established session id (when authenticated). */
    long  expires_in;       /**< Access token TTL seconds (when authenticated). */
    char *user_id;
    char *username;
    char *email;
    char *tenant_id;
    /**
     * 1 when the account that just signed in is an ORGANIZATION-LEVEL principal
     * (CONTRACT.md §5.2) — one whose record lives in its organization's reserved tenant,
     * so its global grants apply in every tenant of that organization and it can act on a
     * different one by sending a different `X-Tenant-ID` on the next request, with no
     * re-login.
     *
     * An ordinary tenant principal is a principal of exactly one tenant; the same header
     * change produces a 403 for it. This flag is therefore what an application checks
     * BEFORE offering a tenant switch, rather than discovering the answer from a failed
     * request.
     *
     * Derived from the login response, never asserted by the caller (§5.2 rule 2): it is
     * resolved server-side from the caller's own tenant record and is never sent. 0 when
     * the response omits it — which is what a server older than contract 1.31 answers —
     * and 0 on the two pending outcomes, where no principal has been established yet.
     * Both are the safe direction.
     *
     * Appended LAST so every existing designated or positional initializer of this struct
     * still compiles, and so `{0}` still means "no claim".
     */
    int organization_level;
} axiam_login_result_t;

/** Release heap members of a login result (not the struct itself). The
 *  Sensitive MFA tokens are zeroized before release (§7). */
void axiam_login_result_dispose(axiam_login_result_t *r);

/** POST /api/v1/auth/login. */
axiam_error_kind_t axiam_login(axiam_client_t *client,
                               const char *username_or_email,
                               const char *password,
                               axiam_login_result_t *out,
                               axiam_error_t *err);

/** POST /api/v1/auth/mfa/verify, with the challenge token as a raw string.
 *  Prefer axiam_verify_mfa_sensitive() when the token came from a
 *  axiam_login_result_t — it keeps the secret behind its Sensitive handle. */
axiam_error_kind_t axiam_verify_mfa(axiam_client_t *client,
                                    const char *challenge_token,
                                    const char *totp_code,
                                    axiam_login_result_t *out,
                                    axiam_error_t *err);

/**
 * POST /api/v1/auth/mfa/verify using the Sensitive challenge token returned by
 * axiam_login() (§7). The secret is never rendered or copied into a plain
 * caller-visible string.
 */
axiam_error_kind_t axiam_verify_mfa_sensitive(axiam_client_t *client,
                                              const axiam_sensitive_t *challenge_token,
                                              const char *totp_code,
                                              axiam_login_result_t *out,
                                              axiam_error_t *err);

/** POST /api/v1/auth/refresh (also used internally by the single-flight guard). */
axiam_error_kind_t axiam_refresh(axiam_client_t *client, axiam_error_t *err);

/** POST /api/v1/auth/logout. Clears local session state on success. */
axiam_error_kind_t axiam_logout(axiam_client_t *client, axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* Authorization                                                      */
/* ------------------------------------------------------------------ */

/**
 * @name Decision reason codes (§11 rule 9)
 *
 * The three codes the server currently emits. They are provided as string
 * constants rather than an enum on purpose: §11 rule 9 requires an unrecognised
 * code be surfaced *verbatim*, so a server that adds a fourth code must not
 * become a parse failure in every deployed client. Compare with `strcmp`, and
 * treat anything else as "some code this build does not know about".
 * @{
 */
/** An allow grant matched and no deny did. */
#define AXIAM_REASON_CODE_ALLOWED        "allowed"
/** Nothing matched — default deny. Tells the user to *ask an admin for access*. */
#define AXIAM_REASON_CODE_NO_GRANT       "no_grant"
/** An explicit deny rule matched and overrode any allow. *An admin already decided.* */
#define AXIAM_REASON_CODE_DENIED_BY_RULE "denied_by_rule"
/** @} */

/**
 * Single check result. reason and reason_code are owned; free with
 * axiam_check_result_dispose.
 */
typedef struct axiam_check_result {
    int allowed;    /**< 1 = permitted. */
    char *reason;   /**< Optional generic deny reason (may be NULL). */
    /**
     * §11 rule 9 machine-readable decision reason (may be NULL when the server
     * is older than the clause). One of the AXIAM_REASON_CODE_* constants, or
     * an unrecognised code passed through untouched. The allow/deny outcome is
     * carried by `allowed` alone — never re-derive it from this field.
     */
    char *reason_code;
} axiam_check_result_t;

void axiam_check_result_dispose(axiam_check_result_t *r);

/** One input row for a batch check. */
typedef struct axiam_check_input {
    const char *action;
    const char *resource_id;
    const char *scope;      /**< May be NULL. */
    const char *subject_id; /**< May be NULL (checks the authenticated caller). */
} axiam_check_input_t;

/**
 * POST /api/v1/authz/check. Argument order is (action, resource[, scope]) per §1.
 * scope and subject_id may be NULL. On 401 with an active session, a single
 * refresh (§9) is attempted and the request retried once.
 */
axiam_error_kind_t axiam_check_access(axiam_client_t *client,
                                      const char *action,
                                      const char *resource_id,
                                      const char *scope,
                                      const char *subject_id,
                                      axiam_check_result_t *out,
                                      axiam_error_t *err);

/** Alias of check_access for browser/UI page-gating scenarios (§1). */
axiam_error_kind_t axiam_can(axiam_client_t *client,
                             const char *action,
                             const char *resource_id,
                             const char *scope,
                             axiam_check_result_t *out,
                             axiam_error_t *err);

/**
 * POST /api/v1/authz/check/batch. Results are written to out_results (caller
 * provides an array of at least n entries) in the SAME order as the input.
 * *out_count is set to the number of results returned.
 */
axiam_error_kind_t axiam_batch_check(axiam_client_t *client,
                                     const axiam_check_input_t *checks,
                                     size_t n,
                                     axiam_check_result_t *out_results,
                                     size_t *out_count,
                                     axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_CLIENT_H */
