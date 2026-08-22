/*
 * AXIAM C SDK — WebAuthn / passkeys, the relying-party layer (CONTRACT.md §24).
 *
 * The six wire operations plus §24.6a's JSON bridge. §24.6b's linked-API
 * ceremony helper is deliberately absent: a C program has no authenticator, and
 * rule 2 forbids emulating one in software.
 *
 * THE ONE THING THIS FILE IS CAREFUL ABOUT. Both *_finish bodies are assembled
 * as TEXT, with the caller's response JSON spliced in unmodified. Parsing it
 * into cJSON and printing it back out would reorder members, round every number
 * through a double, and hand the server a byte sequence the authenticator never
 * signed. The only thing this file checks about that string is that it IS a
 * JSON object — the SDK will not POST a body it already knows the server cannot
 * verify.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "axiam/webauthn.h"
#include "internal.h"

#define PATH_REGISTER_START   "/api/v1/auth/webauthn/register/start"
#define PATH_REGISTER_FINISH  "/api/v1/auth/webauthn/register/finish"
#define PATH_AUTH_START       "/api/v1/auth/webauthn/authenticate/start"
#define PATH_AUTH_FINISH      "/api/v1/auth/webauthn/authenticate/finish"
#define PATH_DISC_START       "/api/v1/auth/webauthn/authenticate/discoverable/start"
#define PATH_DISC_FINISH      "/api/v1/auth/webauthn/authenticate/discoverable/finish"

/* ------------------------------------------------------------------ */
/* Disposal                                                           */
/* ------------------------------------------------------------------ */

void axiam_webauthn_challenge_dispose(axiam_webauthn_challenge_t *c) {
    if (!c) return;
    free(c->challenge_json);
    axiam_sensitive_free(c->state_token);
    memset(c, 0, sizeof(*c));
}

void axiam_webauthn_credential_dispose(axiam_webauthn_credential_t *c) {
    if (!c) return;
    free(c->id);
    free(c->credential_id);
    free(c->name);
    free(c->credential_type);
    free(c->created_at);
    free(c->last_used_at);
    memset(c, 0, sizeof(*c));
}

void axiam_webauthn_login_dispose(axiam_webauthn_login_t *l) {
    if (!l) return;
    axiam_sensitive_free(l->access_token);
    axiam_sensitive_free(l->refresh_token);
    free(l->session_id);
    memset(l, 0, sizeof(*l));
}

/* ------------------------------------------------------------------ */
/* §24.6b rule 5 — the failure classification                         */
/* ------------------------------------------------------------------ */

axiam_webauthn_failure_t axiam_webauthn_classify(const char *name) {
    if (!name) return AXIAM_WEBAUTHN_UNKNOWN;
    /* Skip leading whitespace, so a name relayed with a stray space still
     * classifies. A classifier that can be defeated by formatting is one that
     * silently degrades to "unknown" in production. */
    while (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r') name++;

    if (axiam_str_ieq(name, "NotAllowedError") ||
        axiam_str_ieq(name, "canceled") ||
        axiam_str_ieq(name, "cancelled")) {
        return AXIAM_WEBAUTHN_CANCELLED;
    }
    if (axiam_str_ieq(name, "InvalidStateError")) return AXIAM_WEBAUTHN_ALREADY_REGISTERED;
    if (axiam_str_ieq(name, "AbortError") || axiam_str_ieq(name, "timeout")) {
        return AXIAM_WEBAUTHN_TIMEOUT;
    }
    if (axiam_str_ieq(name, "NotSupportedError") || axiam_str_ieq(name, "SecurityError")) {
        return AXIAM_WEBAUTHN_UNSUPPORTED;
    }
    return AXIAM_WEBAUTHN_UNKNOWN;
}

const char *axiam_webauthn_failure_message(axiam_webauthn_failure_t f) {
    switch (f) {
    case AXIAM_WEBAUTHN_CANCELLED:
        return "The request was cancelled or timed out. You can try again.";
    case AXIAM_WEBAUTHN_ALREADY_REGISTERED:
        return "This device is already registered on your account. "
               "Try a different device, or remove the existing one first.";
    case AXIAM_WEBAUTHN_TIMEOUT:
        return "The request timed out before it completed. Please try again.";
    case AXIAM_WEBAUTHN_UNSUPPORTED:
        return "This browser or device cannot be used for passkeys. "
               "Try a different browser, or use another sign-in method.";
    case AXIAM_WEBAUTHN_UNKNOWN:
    default:
        return "Something went wrong. Please try again.";
    }
}

/* ------------------------------------------------------------------ */
/* §24.6a — the JSON bridge                                           */
/* ------------------------------------------------------------------ */

char *axiam_webauthn_request_json(const axiam_webauthn_challenge_t *c) {
    if (!c || !c->challenge_json) return NULL;

    cJSON *root = cJSON_Parse(c->challenge_json);
    if (!root) return NULL;

    cJSON *options = cJSON_GetObjectItemCaseSensitive(root, "publicKey");
    /* A server that sent the bare options rather than the wrapper is not wrong
     * for every consumer, and this call has one job: hand a caller something a
     * platform API accepts. */
    char *out = cJSON_PrintUnformatted(options ? options : root);
    cJSON_Delete(root);
    return out;
}

/* ------------------------------------------------------------------ */
/* Shared mechanics                                                   */
/* ------------------------------------------------------------------ */

/** The §2 mapping applied to a response the caller already has. */
static axiam_error_kind_t map_status(axiam_http_response_t *resp, const char *context,
                                     axiam_error_t *err) {
    axiam_error_kind_t kind = axiam_error_kind_from_http_status(resp->status);
    if (kind == AXIAM_OK) kind = AXIAM_ERR_NETWORK;
    axiam_error_set(err, kind, resp->status, context);
    return kind;
}

/** Transport failure, with the same message shape every other call uses. */
static axiam_error_kind_t transport_failed(axiam_http_response_t *resp, axiam_error_t *err) {
    axiam_error_set(err, AXIAM_ERR_NETWORK, resp->transport_err,
                    resp->transport_msg ? resp->transport_msg : "network failure");
    return AXIAM_ERR_NETWORK;
}

/**
 * §24.1: register/… needs a session, and the refusal is raised client-side with
 * NO WIRE CALL — the shape §1.1 rule 3 requires of get_user_info.
 */
static int require_session(axiam_client_t *c, const char *operation, axiam_error_t *err) {
    if (axiam_client_has_session(c)) return 1;
    char msg[256];
    snprintf(msg, sizeof(msg),
             "%s requires an authenticated session: enrol a passkey while signed in "
             "(CONTRACT.md §24.1)",
             operation);
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
    return 0;
}

/** Append a JSON string literal (quotes and escaping included) to `sb`. */
static int append_json_string(char **sb, size_t *len, size_t *cap, const char *value) {
    cJSON *tmp = cJSON_CreateString(value ? value : "");
    if (!tmp) return 0;
    char *printed = cJSON_PrintUnformatted(tmp);
    cJSON_Delete(tmp);
    if (!printed) return 0;

    size_t n = strlen(printed);
    if (*len + n + 1 > *cap) {
        size_t next = (*cap ? *cap : 256);
        while (next < *len + n + 1) next *= 2;
        char *grown = realloc(*sb, next);
        if (!grown) { free(printed); return 0; }
        *sb = grown;
        *cap = next;
    }
    memcpy(*sb + *len, printed, n);
    *len += n;
    (*sb)[*len] = '\0';
    free(printed);
    return 1;
}

/** Append raw text to `sb`. */
static int append_raw(char **sb, size_t *len, size_t *cap, const char *text) {
    size_t n = strlen(text);
    if (*len + n + 1 > *cap) {
        size_t next = (*cap ? *cap : 256);
        while (next < *len + n + 1) next *= 2;
        char *grown = realloc(*sb, next);
        if (!grown) return 0;
        *sb = grown;
        *cap = next;
    }
    memcpy(*sb + *len, text, n);
    *len += n;
    (*sb)[*len] = '\0';
    return 1;
}

/**
 * Build a *_finish body as TEXT, splicing `response` in verbatim (§24.0,
 * §24.6a rule 2).
 *
 * `credential_name` is NULL for the two authentication ceremonies.
 * Returns NULL and sets `err` when the response string is not a JSON object —
 * the one thing checked, and checked client-side so no unverifiable body is
 * ever POSTed.
 */
static char *build_finish_body(const axiam_sensitive_t *state_token,
                               const char *credential_name,
                               const char *response,
                               const char *operation,
                               axiam_error_t *err) {
    if (!response) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, "the authenticator response is NULL");
        return NULL;
    }

    /* Trim leading whitespace so the object check sees the first real byte; the
     * spliced text keeps whatever the platform produced from there on. */
    const char *trimmed = response;
    while (*trimmed == ' ' || *trimmed == '\t' || *trimmed == '\n' || *trimmed == '\r') trimmed++;

    cJSON *parsed = cJSON_Parse(trimmed);
    if (!parsed) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%s: the authenticator response string is not valid JSON. Pass the "
                 "platform's response JSON verbatim (CONTRACT.md §24.6a)",
                 operation);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return NULL;
    }
    int is_object = cJSON_IsObject(parsed);
    cJSON_Delete(parsed);
    if (!is_object) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%s: the authenticator response must be a JSON object (CONTRACT.md §24.6a)",
                 operation);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return NULL;
    }

    char *sb = NULL;
    size_t len = 0, cap = 0;
    const char *token = state_token ? axiam_sensitive_reveal(state_token) : "";

    if (!append_raw(&sb, &len, &cap, "{\"state_token\":")) goto oom;
    if (!append_json_string(&sb, &len, &cap, token)) goto oom;
    if (credential_name) {
        if (!append_raw(&sb, &len, &cap, ",\"credential_name\":")) goto oom;
        if (!append_json_string(&sb, &len, &cap, credential_name)) goto oom;
    }
    if (!append_raw(&sb, &len, &cap, ",\"response\":")) goto oom;
    if (!append_raw(&sb, &len, &cap, trimmed)) goto oom;
    if (!append_raw(&sb, &len, &cap, "}")) goto oom;
    return sb;

oom:
    free(sb);
    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    return NULL;
}

/** Run either *_start call and return the options untouched. */
static axiam_error_kind_t webauthn_start(axiam_client_t *client, const char *path,
                                         const char *body,
                                         axiam_webauthn_challenge_t *out,
                                         axiam_error_t *err) {
    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", path, body, &resp);
    if (rc != 0 || resp.status == 0) {
        axiam_error_kind_t kind = transport_failed(&resp, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }
    if (resp.status != 200) {
        axiam_error_kind_t kind = map_status(&resp, "webauthn start failed", err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status,
                        "webauthn start: response body is not a JSON object");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }

    cJSON *challenge = cJSON_GetObjectItemCaseSensitive(root, "challenge");
    const cJSON *state = cJSON_GetObjectItemCaseSensitive(root, "state_token");
    if (out) {
        out->challenge_json = challenge ? cJSON_PrintUnformatted(challenge)
                                        : axiam_strdup0("{}");
        out->state_token = axiam_sensitive_new(cJSON_IsString(state) && state->valuestring
                                                   ? state->valuestring
                                                   : "");
        /* All-or-nothing: a challenge with no options is nothing to hand an
         * authenticator, and one with no state token is a ceremony whose answer
         * the server cannot bind. Either way the caller must not proceed. */
        if (!out->challenge_json || !out->state_token) {
            axiam_webauthn_challenge_dispose(out);
            cJSON_Delete(root);
            axiam_http_response_dispose(&resp);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(root);
    axiam_http_response_dispose(&resp);
    return AXIAM_OK;
}

/** The shared tail of both authentication ceremonies. */
static axiam_error_kind_t webauthn_finish_login(axiam_client_t *client, const char *path,
                                                const axiam_sensitive_t *state_token,
                                                const char *response, const char *operation,
                                                axiam_webauthn_login_t *out,
                                                axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    char *body = build_finish_body(state_token, NULL, response, operation, err);
    if (!body) return err && err->kind != AXIAM_OK ? err->kind : AXIAM_ERR_AUTH;

    /* §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this
     * call changes the subject. Cleared before the wire, on the caller's INTENT,
     * exactly as login() does it. */
    axiam_client_drop_memo(client);

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", path, body, &resp);
    free(body);
    if (rc != 0 || resp.status == 0) {
        axiam_error_kind_t kind = transport_failed(&resp, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }
    if (resp.status != 200) {
        char context[128];
        snprintf(context, sizeof(context), "%s failed", operation);
        axiam_error_kind_t kind = map_status(&resp, context, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    if (!root) {
        /* A 200 whose body did not parse is not a ceremony that half-succeeded.
         * Returning AXIAM_OK with an empty result would tell the caller they
         * are signed in while handing them no tokens to prove it. */
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status,
                        "webauthn finish: response body is not a JSON object");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (out) {
        const cJSON *access = cJSON_GetObjectItemCaseSensitive(root, "access_token");
        const cJSON *refresh = cJSON_GetObjectItemCaseSensitive(root, "refresh_token");
        const cJSON *session = cJSON_GetObjectItemCaseSensitive(root, "session_id");
        const cJSON *expires = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
        out->access_token = axiam_sensitive_new(
            cJSON_IsString(access) && access->valuestring ? access->valuestring : "");
        out->refresh_token = axiam_sensitive_new(
            cJSON_IsString(refresh) && refresh->valuestring ? refresh->valuestring : "");
        out->session_id = axiam_strdup0(
            cJSON_IsString(session) && session->valuestring ? session->valuestring : "");
        out->expires_in = cJSON_IsNumber(expires) ? (long)expires->valuedouble : 0L;

        /* All-or-nothing, and the session is NOT adopted on this path. The
         * ceremony did succeed server-side, but a caller holding a result whose
         * tokens could not be allocated has no way to act on it, and adopting
         * the session anyway would leave the client signed in as someone the
         * caller was never told about. */
        if (!out->access_token || !out->refresh_token || !out->session_id) {
            axiam_webauthn_login_dispose(out);
            cJSON_Delete(root);
            axiam_http_response_dispose(&resp);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(root);

    /* §24.3: the cookie triple arrived on this response and the transport stored
     * it; this is the in-memory half. */
    axiam_client_adopt_session(client, &resp);
    axiam_http_response_dispose(&resp);
    return AXIAM_OK;
}

/**
 * Fill the discoverable ceremony's workspace from the client's own
 * configuration when the caller passed none.
 *
 * Only fields that actually have a value are emitted: the server takes either
 * form at either level, and sending null for the ones it does not have is
 * indistinguishable from asking it to resolve nothing.
 */
static char *build_workspace_body(const axiam_client_t *client,
                                  const axiam_webauthn_workspace_t *ws,
                                  axiam_error_t *err) {
    const axiam_client_config_t *cfg = axiam_client_config_of(client);
    const char *org_id = ws ? ws->org_id : NULL;
    const char *org_slug = ws ? ws->org_slug : NULL;
    if (!org_id && !org_slug && cfg) {
        org_id = (cfg->org_id && cfg->org_id[0]) ? cfg->org_id : NULL;
        org_slug = (cfg->org_slug && cfg->org_slug[0]) ? cfg->org_slug : NULL;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return NULL;
    }

    if (org_id) {
        cJSON_AddStringToObject(root, "org_id", org_id);
    } else if (org_slug) {
        cJSON_AddStringToObject(root, "org_slug", org_slug);
    } else {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_webauthn_discoverable_start needs an organization: construct "
                        "the client with one, or pass it in the workspace argument "
                        "(CONTRACT.md §24.1)");
        return NULL;
    }

    const char *tenant_id = ws ? ws->tenant_id : NULL;
    const char *tenant_slug = ws ? ws->tenant_slug : NULL;
    if (tenant_id) {
        cJSON_AddStringToObject(root, "tenant_id", tenant_id);
    } else if (tenant_slug) {
        cJSON_AddStringToObject(root, "tenant_slug", tenant_slug);
    } else if (cfg && cfg->tenant_id && cfg->tenant_id[0]) {
        cJSON_AddStringToObject(root, "tenant_id", cfg->tenant_id);
    } else {
        /* §5 makes one of the two mandatory at construction — there is no
         * default tenant — so this arm always has a slug to fall back on. No
         * "needs a tenant" refusal is written here for that reason: it would be
         * a branch no caller can reach, and an unreachable guard is a guard
         * nobody maintains. The ORGANIZATION guard above is different, and
         * stays: an org is optional at construction. */
        cJSON_AddStringToObject(root, "tenant_slug", cfg->tenant_slug);
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
    return body;
}

/* ------------------------------------------------------------------ */
/* §24.1 — the six wire operations                                    */
/* ------------------------------------------------------------------ */

axiam_error_kind_t axiam_webauthn_register_start(axiam_client_t *client,
                                                 axiam_webauthn_challenge_t *out,
                                                 axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);
    if (!require_session(client, "axiam_webauthn_register_start", err)) return AXIAM_ERR_AUTH;

    return webauthn_start(client, PATH_REGISTER_START, "{}", out, err);
}

axiam_error_kind_t axiam_webauthn_register_finish(axiam_client_t *client,
                                                  const axiam_sensitive_t *state_token,
                                                  const char *credential_name,
                                                  const char *response,
                                                  axiam_webauthn_credential_t *out,
                                                  axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !credential_name) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);
    if (!require_session(client, "axiam_webauthn_register_finish", err)) return AXIAM_ERR_AUTH;

    char *body = build_finish_body(state_token, credential_name, response,
                                   "axiam_webauthn_register_finish", err);
    if (!body) return err && err->kind != AXIAM_OK ? err->kind : AXIAM_ERR_AUTH;

    axiam_http_response_t resp;
    int rc = axiam_client_send_raw(client, "POST", PATH_REGISTER_FINISH, body, &resp);
    free(body);
    if (rc != 0 || resp.status == 0) {
        axiam_error_kind_t kind = transport_failed(&resp, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    if (resp.status != 200 && resp.status != 201) {
        /* §24.4 rule 1: the 403 from register/finish is the one whose BODY
         * matters. The generic §2 mapping would say "register/finish failed",
         * which tells the person holding the key nothing they can act on: the
         * tenant's attestation policy rejected THIS authenticator, and the
         * server's message is the only place that says which one would be
         * accepted. Only the named `message` field is read; the rest of the
         * body is still discarded. */
        char context[512];
        snprintf(context, sizeof(context), "axiam_webauthn_register_finish failed");
        if (resp.status == 403 && resp.body) {
            cJSON *body_root = cJSON_Parse(resp.body);
            if (body_root) {
                const cJSON *message = cJSON_GetObjectItemCaseSensitive(body_root, "message");
                if (cJSON_IsString(message) && message->valuestring && message->valuestring[0]) {
                    snprintf(context, sizeof(context),
                             "axiam_webauthn_register_finish failed: %s", message->valuestring);
                }
                cJSON_Delete(body_root);
            }
        }
        axiam_error_kind_t kind = map_status(&resp, context, err);
        axiam_http_response_dispose(&resp);
        return kind;
    }

    cJSON *root = resp.body ? cJSON_Parse(resp.body) : NULL;
    if (!root) {
        /* Same reasoning as the login path: a credential the caller cannot name
         * is one they can never find again to remove. */
        axiam_error_set(err, AXIAM_ERR_NETWORK, resp.status,
                        "webauthn register/finish: response body is not a JSON object");
        axiam_http_response_dispose(&resp);
        return AXIAM_ERR_NETWORK;
    }
    if (out) {
        const cJSON *last_used = cJSON_GetObjectItemCaseSensitive(root, "last_used_at");
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "id");
        const cJSON *cred = cJSON_GetObjectItemCaseSensitive(root, "credential_id");
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(root, "name");
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "credential_type");
        const cJSON *created = cJSON_GetObjectItemCaseSensitive(root, "created_at");
        out->id = axiam_strdup0(cJSON_IsString(id) ? id->valuestring : "");
        out->credential_id = axiam_strdup0(cJSON_IsString(cred) ? cred->valuestring : "");
        out->name = axiam_strdup0(cJSON_IsString(name) ? name->valuestring : "");
        out->credential_type = axiam_strdup0(cJSON_IsString(type) ? type->valuestring : "");
        out->created_at = axiam_strdup0(cJSON_IsString(created) ? created->valuestring : "");
        out->last_used_at = (cJSON_IsString(last_used) && last_used->valuestring &&
                             last_used->valuestring[0])
                                ? axiam_strdup0(last_used->valuestring)
                                : NULL;
        /* `last_used_at` is legitimately absent on a credential never used, so
         * it is not in this check; the other five always arrive. */
        if (!out->id || !out->credential_id || !out->name || !out->credential_type ||
            !out->created_at) {
            axiam_webauthn_credential_dispose(out);
            cJSON_Delete(root);
            axiam_http_response_dispose(&resp);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(root);
    axiam_http_response_dispose(&resp);
    return AXIAM_OK;
}

axiam_error_kind_t axiam_webauthn_authenticate_start(axiam_client_t *client,
                                                     const axiam_sensitive_t *challenge_token,
                                                     axiam_webauthn_challenge_t *out,
                                                     axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client || !challenge_token) {
        /* §24.2: the second-factor ceremony cannot run without the token that
         * names the user. Merging it with the discoverable one behind a
         * nullable argument reproduces a bug the server already fixed. */
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_webauthn_authenticate_start needs the challenge token from a "
                        "login that answered mfa_required (CONTRACT.md §24.2)");
        return AXIAM_ERR_AUTH;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(root, "challenge_token", axiam_sensitive_reveal(challenge_token));
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    axiam_error_kind_t kind = webauthn_start(client, PATH_AUTH_START, body, out, err);
    /* §7: the body carried the challenge token. */
    axiam_secure_zero(body, strlen(body));
    free(body);
    return kind;
}

axiam_error_kind_t axiam_webauthn_authenticate_finish(axiam_client_t *client,
                                                      const axiam_sensitive_t *state_token,
                                                      const char *response,
                                                      axiam_webauthn_login_t *out,
                                                      axiam_error_t *err) {
    return webauthn_finish_login(client, PATH_AUTH_FINISH, state_token, response,
                                 "axiam_webauthn_authenticate_finish", out, err);
}

axiam_error_kind_t axiam_webauthn_discoverable_start(axiam_client_t *client,
                                                     const axiam_webauthn_workspace_t *workspace,
                                                     axiam_webauthn_challenge_t *out,
                                                     axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!client) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (axiam_client_is_shut(client)) return axiam_client_shut_error(err);

    char *body = build_workspace_body(client, workspace, err);
    if (!body) return err && err->kind != AXIAM_OK ? err->kind : AXIAM_ERR_AUTH;

    axiam_error_kind_t kind = webauthn_start(client, PATH_DISC_START, body, out, err);
    free(body);
    return kind;
}

axiam_error_kind_t axiam_webauthn_discoverable_finish(axiam_client_t *client,
                                                      const axiam_sensitive_t *state_token,
                                                      const char *response,
                                                      axiam_webauthn_login_t *out,
                                                      axiam_error_t *err) {
    return webauthn_finish_login(client, PATH_DISC_FINISH, state_token, response,
                                 "axiam_webauthn_discoverable_finish", out, err);
}
