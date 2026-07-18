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

/** Destroy a client and release its cookie jar / TLS material. Safe on NULL. */
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
    char *challenge_token;  /**< For verify_mfa (when mfa_required). */
    char *setup_token;      /**< For MFA setup (when mfa_setup_required). */
    char *session_id;       /**< Established session id (when authenticated). */
    long  expires_in;       /**< Access token TTL seconds (when authenticated). */
    char *user_id;
    char *username;
    char *email;
    char *tenant_id;
} axiam_login_result_t;

/** Release heap members of a login result (not the struct itself). */
void axiam_login_result_dispose(axiam_login_result_t *r);

/** POST /api/v1/auth/login. */
axiam_error_kind_t axiam_login(axiam_client_t *client,
                               const char *username_or_email,
                               const char *password,
                               axiam_login_result_t *out,
                               axiam_error_t *err);

/** POST /api/v1/auth/mfa/verify. */
axiam_error_kind_t axiam_verify_mfa(axiam_client_t *client,
                                    const char *challenge_token,
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

/** Single check result. reason is owned; free with axiam_check_result_dispose. */
typedef struct axiam_check_result {
    int allowed;    /**< 1 = permitted. */
    char *reason;   /**< Optional generic deny reason (may be NULL). */
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
