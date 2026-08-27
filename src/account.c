/*
 * AXIAM C SDK — account lifecycle and MFA enrolment (CONTRACT.md §25).
 *
 * Nine operations, six of them deliberately unauthenticated: a user who cannot
 * log in is the entire audience for a password reset, and a user whose email is
 * unverified may have no session at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "axiam/account.h"
#include "internal.h"

#define PATH_MFA_ENROLL         "/api/v1/auth/mfa/enroll"
#define PATH_MFA_CONFIRM        "/api/v1/auth/mfa/confirm"
#define PATH_MFA_SETUP_ENROLL   "/api/v1/auth/mfa/setup/enroll"
#define PATH_MFA_SETUP_CONFIRM  "/api/v1/auth/mfa/setup/confirm"
#define PATH_VERIFY_EMAIL       "/api/v1/auth/verify-email"
#define PATH_RESEND_VERIFY      "/api/v1/auth/resend-verification"
#define PATH_RESEND_OWN_VERIFY  "/api/v1/users/me/resend-verification"
#define PATH_RESET              "/api/v1/auth/reset"
#define PATH_RESET_CONTEXT      "/api/v1/auth/reset/context"
#define PATH_RESET_CONFIRM      "/api/v1/auth/reset/confirm"

/* ------------------------------------------------------------------ */
/* Disposal                                                           */
/* ------------------------------------------------------------------ */

void axiam_mfa_enrollment_dispose(axiam_mfa_enrollment_t *e) {
    if (!e) return;
    axiam_sensitive_free(e->secret_base32);
    axiam_sensitive_free(e->totp_uri);
    memset(e, 0, sizeof(*e));
}

void axiam_password_reset_context_dispose(axiam_password_reset_context_t *c) {
    if (!c) return;
    free(c->opaque_json);
    memset(c, 0, sizeof(*c));
}

/* ------------------------------------------------------------------ */
/* Shared mechanics                                                   */
/* ------------------------------------------------------------------ */

static axiam_error_kind_t map_status(axiam_http_response_t *resp, const char *context,
                                     axiam_error_t *err) {
    axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp->status);
    if (kind == AXIAM_OK) kind = AXIAM_ERR_NETWORK;
    axiam_error_set(err, kind, resp->status, context);
    return kind;
}

static axiam_error_kind_t transport_failed(axiam_http_response_t *resp, axiam_error_t *err) {
    axiam_error_set(err, AXIAM_ERR_NETWORK, resp->transport_err,
                    resp->transport_msg ? resp->transport_msg : "network failure");
    return AXIAM_ERR_NETWORK;
}

/** POST a JSON body and accept 200/202/204 as success. */
static axiam_error_kind_t post_no_content(axiam_client_t *client, const char *path,
                                          char *body, int body_is_secret,
                                          const char *context, axiam_error_t *err) {
    if (!body) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", path, body, &resp);
    if (body_is_secret) axiam_secure_zero(body, strlen(body)); /* §7 */
    free(body);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = transport_failed(&resp, err);
    } else if (resp.status == 200 || resp.status == 202 || resp.status == 204) {
        kind = AXIAM_OK;
    } else {
        kind = map_status(&resp, context, err);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/** Read a `MfaEnrollResponse` into `out`, wrapping both halves (§25.3). */
static axiam_error_kind_t read_enrollment(axiam_http_response_t *resp, const char *context,
                                          axiam_mfa_enrollment_t *out, axiam_error_t *err) {
    if (resp->status != 200) return map_status(resp, context, err);

    cJSON *root = resp->body ? cJSON_Parse(resp->body) : NULL;
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp->status,
                        "mfa enrolment: response body is not a JSON object");
        return AXIAM_ERR_NETWORK;
    }
    if (out) {
        const cJSON *secret = cJSON_GetObjectItemCaseSensitive(root, "secret_base32");
        const cJSON *uri = cJSON_GetObjectItemCaseSensitive(root, "totp_uri");
        out->secret_base32 = axiam_sensitive_new(
            cJSON_IsString(secret) && secret->valuestring ? secret->valuestring : "");
        /* §25.3: the URI CONTAINS the secret, so it is wrapped too. Wrapping the
         * bare secret and leaving this one a plain string wraps nothing — the
         * URI is the field that actually gets logged, because it is the one the
         * caller passes to a QR renderer. */
        out->totp_uri = axiam_sensitive_new(
            cJSON_IsString(uri) && uri->valuestring ? uri->valuestring : "");

        /* ALL-OR-NOTHING. An enrolment missing either half is not a partial
         * success: a caller handed a NULL `totp_uri` renders no QR code, and a
         * caller handed a NULL `secret_base32` cannot generate the code that
         * would confirm the factor. Reporting the allocation failure is the
         * only outcome that leaves the account where it was. */
        if (!out->secret_base32 || !out->totp_uri) {
            axiam_mfa_enrollment_dispose(out);
            cJSON_Delete(root);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(root);
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* Voluntary enrolment                                                */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_mfa_enroll(axiam_client_t *client, axiam_mfa_enrollment_t *out,
                                    axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    /* §25.2 rule 3: the memo is NOT cleared. The subject has not changed, and
     * discarding a warm memo on an unrelated profile action is a needless round
     * trip for every check that follows. */
    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", PATH_MFA_ENROLL, "{}", &resp);
    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = transport_failed(&resp, err);
    } else {
        kind = read_enrollment(&resp, "axiam_mfa_enroll failed", out, err);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_mfa_confirm(axiam_client_t *client, const char *totp_code,
                                     int *out_enabled, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out_enabled) *out_enabled = 0;
    if (!client || !totp_code) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "totp_code", totp_code);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", PATH_MFA_CONFIRM, body, &resp);
    axiam_secure_zero(body, strlen(body)); /* §25.3: a code in a log is a code in a log. */
    free(body);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = transport_failed(&resp, err);
    } else if (resp.status != 200) {
        kind = map_status(&resp, "axiam_mfa_confirm failed", err);
    } else {
        kind = AXIAM_OK;
        cJSON *body_root = resp.body ? cJSON_Parse(resp.body) : NULL;
        if (body_root && out_enabled) {
            const cJSON *enabled = cJSON_GetObjectItemCaseSensitive(body_root, "mfa_enabled");
            *out_enabled = cJSON_IsTrue(enabled) ? 1 : 0;
        }
        if (body_root) cJSON_Delete(body_root);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

/* ------------------------------------------------------------------ */
/* Forced enrolment                                                   */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_mfa_setup_enroll(axiam_client_t *client,
                                          const axiam_sensitive_t *setup_token,
                                          axiam_mfa_enrollment_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !setup_token) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    /* There is no session yet — the setup token IS the credential. */
    cJSON_AddStringToObject(root, "setup_token", axiam_sensitive_reveal(setup_token));
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", PATH_MFA_SETUP_ENROLL, body, &resp);
    axiam_secure_zero(body, strlen(body));
    free(body);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = transport_failed(&resp, err);
    } else {
        kind = read_enrollment(&resp, "axiam_mfa_setup_enroll failed", out, err);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_mfa_setup_confirm(axiam_client_t *client,
                                           const axiam_sensitive_t *setup_token,
                                           const char *totp_code,
                                           axiam_login_result_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !setup_token || !totp_code) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    /* §25.2 rule 2: this IS the completion of a login, so §24.3's adoption rules
     * apply verbatim — including clearing the §17 memo, on the caller's intent,
     * before the wire. */
    axiam_client_drop_memo(client);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "setup_token", axiam_sensitive_reveal(setup_token));
    cJSON_AddStringToObject(root, "totp_code", totp_code);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", PATH_MFA_SETUP_CONFIRM, body, &resp);
    axiam_secure_zero(body, strlen(body));
    free(body);

    if (rc != 0 || resp.status == 0) {
        axiam_error_kind_t kind = transport_failed(&resp, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }
    /* Through the SAME parser login() uses, rather than a second one that could
     * drift on what "adopted" means. */
    axiam_error_kind_t kind = axiam_client_parse_login(client, &resp, out, err);
    axiam_http_response_dispose(&resp);
    return kind;
}

/* ------------------------------------------------------------------ */
/* Email verification                                                 */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_verify_email(axiam_client_t *client, const axiam_sensitive_t *token,
                                      const char *tenant_id, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client || !token || !tenant_id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "token", axiam_sensitive_reveal(token));
    /* A BODY field: this is not an /oauth2 endpoint, so §12.1 rule 2's
     * query-parameter convention does not reach it. */
    cJSON_AddStringToObject(root, "tenant_id", tenant_id);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return post_no_content(client, PATH_VERIFY_EMAIL, body, 1,
                           "axiam_verify_email failed", err);
}

axiam_error_kind_t axiam_resend_verification(axiam_client_t *client, const char *email,
                                             const char *tenant_id, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client || !email || !tenant_id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "email", email);
    cJSON_AddStringToObject(root, "tenant_id", tenant_id);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return post_no_content(client, PATH_RESEND_VERIFY, body, 0,
                           "axiam_resend_verification failed", err);
}

axiam_error_kind_t axiam_resend_own_verification(axiam_client_t *client, axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    /* §25.7: session-authenticated, and the refusal is raised HERE, with no wire call.
     * Sending it anyway would leave a rejected request in the audit log for what is a
     * programming error on this side. */
    if (!axiam_client_has_session(client)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_resend_own_verification requires an authenticated session: it "
                        "resends the mail for the account you are signed in to, and names no "
                        "address (CONTRACT.md §25.7). Use axiam_resend_verification() when "
                        "there is no session.");
        return AXIAM_ERR_AUTH;
    }

    /* The empty object, exactly as axiam_mfa_enroll sends: the server takes the address
     * off the caller's own record, and §25.6 asks for a request carrying NO address
     * field. Duplicated rather than shared with a literal so the body is heap-owned,
     * which is what post_no_content() frees. */
    char *body = axiam_strdup0("{}");
    return post_no_content(client, PATH_RESEND_OWN_VERIFY, body, 0,
                           "axiam_resend_own_verification failed", err);
}

/* ------------------------------------------------------------------ */
/* Password reset                                                     */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_request_password_reset(axiam_client_t *client,
                                                const axiam_password_reset_request_t *request,
                                                axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client || !request || !request->email) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    const axiam_client_config_t *cfg = axiam_client_config_of(client);
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "email", request->email);

    const char *org_slug = request->org_slug;
    if (!org_slug && cfg && cfg->org_slug && cfg->org_slug[0]) org_slug = cfg->org_slug;
    if (org_slug) {
        cJSON_AddStringToObject(root, "org_slug", org_slug);
    } else if (cfg && cfg->org_id && cfg->org_id[0]) {
        cJSON_AddStringToObject(root, "org_id", cfg->org_id);
    }

    if (request->tenant_id) {
        cJSON_AddStringToObject(root, "tenant_id", request->tenant_id);
    } else if (request->tenant_slug) {
        cJSON_AddStringToObject(root, "tenant_slug", request->tenant_slug);
    } else if (cfg && cfg->tenant_id && cfg->tenant_id[0]) {
        cJSON_AddStringToObject(root, "tenant_id", cfg->tenant_id);
    } else if (cfg && cfg->tenant_slug && cfg->tenant_slug[0]) {
        /* §25.1: this endpoint accepts the workspace in slug form as well. */
        cJSON_AddStringToObject(root, "tenant_slug", cfg->tenant_slug);
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    /* Returns AXIAM_OK whether or not the address exists, and this SDK exposes
     * no way to tell the two apart (§25.4). */
    return post_no_content(client, PATH_RESET, body, 0,
                           "axiam_request_password_reset failed", err);
}

axiam_error_kind_t axiam_password_reset_context(axiam_client_t *client,
                                                const axiam_sensitive_t *token,
                                                axiam_password_reset_context_t *out,
                                                axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !token) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    /* The token travels as a query PARAMETER, percent-encoded. A token spliced
     * in raw can end the query early or land in the path, and the 404 that
     * produces reads exactly like an expired token. */
    const char *raw = axiam_sensitive_reveal(token);
    char *encoded = axiam_url_encode(raw);
    if (!encoded) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    size_t path_len = strlen(PATH_RESET_CONTEXT) + strlen("?token=") + strlen(encoded) + 1;
    char *path = malloc(path_len);
    if (!path) {
        free(encoded);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    snprintf(path, path_len, "%s?token=%s", PATH_RESET_CONTEXT, encoded);
    free(encoded);

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "GET", path, NULL, &resp);
    axiam_secure_zero(path, strlen(path)); /* the path carried the token. */
    free(path);

    axiam_error_kind_t kind;
    if (rc != 0 || resp.status == 0) {
        kind = transport_failed(&resp, err);
    } else if (resp.status != 200) {
        /* §25.4 rule 3: a 404 means unknown, expired OR already-consumed, and
         * this SDK does not distinguish them either. */
        kind = map_status(&resp, "axiam_password_reset_context failed", err);
    } else {
        kind = AXIAM_OK;
        cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
        if (!root) {
            /* A 200 whose body did not parse is not "this tenant has no
             * OPAQUE". Reporting it as one is the same silent downgrade the
             * check below guards against, arrived at one step earlier. */
            axiam_http_response_dispose(&resp);
            axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status,
                            "reset context: response body is not a JSON object");
            return AXIAM_ERR_NETWORK;
        }
        if (out) {
            cJSON *opaque = cJSON_GetObjectItemCaseSensitive(root, "opaque");
            if (opaque && cJSON_IsObject(opaque)) {
                out->opaque_json = cJSON_PrintUnformatted(opaque);
                /* A NULL here would be indistinguishable from "this tenant does
                 * not use OPAQUE", and the caller reads that as permission to
                 * send a plaintext password — to a tenant that may be in
                 * `opaque_mode: required`. An allocation failure must not
                 * silently downgrade the password path. */
                if (!out->opaque_json) {
                    cJSON_Delete(root);
                    axiam_http_response_dispose(&resp);
                    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
                    return AXIAM_ERR_NETWORK;
                }
            }
        }
        if (root) cJSON_Delete(root);
    }
    axiam_http_response_dispose(&resp);
    return kind;
}

axiam_error_kind_t axiam_confirm_password_reset(
    axiam_client_t *client, const axiam_password_reset_confirmation_t *confirmation,
    axiam_error_t *err) {
    axiam_error_reset(err);
    if (!client || !confirmation || !confirmation->token || !confirmation->new_password ||
        !confirmation->tenant_id) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "token", axiam_sensitive_reveal(confirmation->token));
    cJSON_AddStringToObject(root, "new_password",
                            axiam_sensitive_reveal(confirmation->new_password));
    cJSON_AddStringToObject(root, "tenant_id", confirmation->tenant_id);
    if (confirmation->opaque_json && confirmation->opaque_json[0]) {
        /* The §23 registration record, parsed only to attach it — this SDK does
         * not model, validate or reshape the block (§25.4 rule 1). */
        cJSON *opaque = cJSON_Parse(confirmation->opaque_json);
        if (!opaque) {
            cJSON_Delete(root);
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "axiam_confirm_password_reset: opaque_json is not valid JSON");
            return AXIAM_ERR_AUTH;
        }
        /* The return value matters here and nowhere else in this file: this is
         * the one AddItem* call whose item was built separately, so a failure
         * to attach leaves `opaque` owned by nobody. */
        if (!cJSON_AddItemToObject(root, "opaque", opaque)) {
            cJSON_Delete(opaque);
            cJSON_Delete(root);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return post_no_content(client, PATH_RESET_CONFIRM, body, 1,
                           "axiam_confirm_password_reset failed", err);
}
