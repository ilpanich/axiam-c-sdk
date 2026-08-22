/*
 * AXIAM C SDK — §12.4 ID-token validation, and the disposal functions for every
 * §12/§12.7/§14/§15 result type.
 *
 * §12.4 is a checklist of seven, and the reason it is written as a checklist
 * rather than a paragraph is that each item, skipped, has a name. `alg` unpinned
 * is algorithm confusion. `iss` matched loosely is a different OP's token.
 * `aud` unchecked is another RP's token. `nonce` unchecked is a replay. And rule
 * 7 — all-or-nothing — is what stops the tempting shortcut of returning the
 * access token anyway because "only the ID token was bad": the two came out of
 * one response, and a response you do not trust is one you do not keep half of.
 *
 * The signature half is NOT re-implemented here. §12.4 says to extend the
 * existing JWKS verifier rather than fork it, so this calls
 * axiam_jwt_verify_reasoned() — the same key cache, the same EdDSA pin, the same
 * unknown-`kid` cooldown the §10 guards use — and layers rules 3 to 6 on top.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "oidc_internal.h"

/* ------------------------------------------------------------------ */
/* Disposal                                                           */
/* ------------------------------------------------------------------ */

static void string_array_free(char **items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

void axiam_oidc_config_dispose(axiam_oidc_config_t *cfg) {
    if (!cfg) return;
    free(cfg->issuer);
    free(cfg->authorization_endpoint);
    free(cfg->token_endpoint);
    free(cfg->jwks_uri);
    free(cfg->userinfo_endpoint);
    free(cfg->introspection_endpoint);
    free(cfg->revocation_endpoint);
    free(cfg->end_session_endpoint);
    free(cfg->device_authorization_endpoint);
    free(cfg->pushed_authorization_request_endpoint);
    string_array_free(cfg->scopes_supported, cfg->scopes_supported_count);
    string_array_free(cfg->response_types_supported, cfg->response_types_supported_count);
    string_array_free(cfg->id_token_signing_alg_values_supported,
                      cfg->id_token_signing_alg_values_supported_count);
    memset(cfg, 0, sizeof(*cfg));
}

void axiam_authorization_request_dispose(axiam_authorization_request_t *req) {
    if (!req) return;
    free(req->url);
    free(req->state);
    free(req->nonce);
    /* The verifier is secret for its WHOLE lifetime (§12.5), so it goes through
     * the scrubbing free rather than plain free(). */
    axiam_sensitive_free(req->code_verifier);
    memset(req, 0, sizeof(*req));
}

void axiam_id_token_claims_free(axiam_id_token_claims_t *claims) {
    if (!claims) return;
    free(claims->subject);
    free(claims->issuer);
    string_array_free(claims->audience, claims->audience_count);
    free(claims->nonce);
    free(claims->authorized_party);
    free(claims->email);
    free(claims->preferred_username);
    free(claims->tenant_id);
    string_array_free(claims->roles, claims->roles_count);
    free(claims->raw_claims_json);
    free(claims);
}

void axiam_oidc_token_set_dispose(axiam_oidc_token_set_t *set) {
    if (!set) return;
    axiam_sensitive_free(set->access_token);
    axiam_sensitive_free(set->refresh_token);
    axiam_sensitive_free(set->id_token);
    free(set->token_type);
    free(set->scope);
    axiam_id_token_claims_free(set->id_claims);
    memset(set, 0, sizeof(*set));
}

void axiam_introspection_result_dispose(axiam_introspection_result_t *r) {
    if (!r) return;
    free(r->scope);
    free(r->client_id);
    free(r->username);
    free(r->token_type);
    free(r->subject);
    free(r->audience);
    free(r->issuer);
    free(r->jwt_id);
    memset(r, 0, sizeof(*r));
}

void axiam_sso_start_result_dispose(axiam_sso_start_result_t *r) {
    if (!r) return;
    free(r->authorize_url);
    free(r->state);
    memset(r, 0, sizeof(*r));
}

void axiam_sso_complete_result_dispose(axiam_sso_complete_result_t *r) {
    if (!r) return;
    free(r->user_id);
    free(r->session_id);
    free(r->redirect_uri);
    memset(r, 0, sizeof(*r));
}

void axiam_verified_logout_token_dispose(axiam_verified_logout_token_t *t) {
    if (!t) return;
    free(t->sid);
    free(t->subject);
    free(t->jwt_id);
    free(t->issuer);
    memset(t, 0, sizeof(*t));
}

void axiam_device_authorization_dispose(axiam_device_authorization_t *d) {
    if (!d) return;
    axiam_sensitive_free(d->device_code);
    free(d->user_code);
    free(d->verification_uri);
    free(d->verification_uri_complete);
    memset(d, 0, sizeof(*d));
}

void axiam_exchanged_token_dispose(axiam_exchanged_token_t *t) {
    if (!t) return;
    axiam_sensitive_free(t->access_token);
    free(t->issued_token_type);
    free(t->token_type);
    free(t->scope);
    memset(t, 0, sizeof(*t));
}

/* ------------------------------------------------------------------ */
/* Shared JSON helpers                                                */
/* ------------------------------------------------------------------ */

/* A string member, copied, or NULL when absent/empty/wrong-typed. */
static char *json_str(const cJSON *root, const char *name) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0]) return NULL;
    return axiam_strdup0(v->valuestring);
}

static long long json_int(const cJSON *root, const char *name, long long fallback) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    return cJSON_IsNumber(v) ? (long long)v->valuedouble : fallback;
}

/* Copy a JSON array of strings. Also accepts a bare string, which is how `aud`
 * arrives for a single audience (RFC 7519 §4.1.3 permits both). */
static char **json_str_array(const cJSON *root, const char *name, size_t *out_count) {
    *out_count = 0;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (cJSON_IsString(v) && v->valuestring) {
        char **one = calloc(1, sizeof(char *));
        if (!one) return NULL;
        one[0] = axiam_strdup0(v->valuestring);
        if (!one[0]) { free(one); return NULL; }
        *out_count = 1;
        return one;
    }
    if (!cJSON_IsArray(v)) return NULL;
    int n = cJSON_GetArraySize(v);
    if (n <= 0) return NULL;
    char **items = calloc((size_t)n, sizeof(char *));
    if (!items) return NULL;
    for (int i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(v, i);
        if (cJSON_IsString(e) && e->valuestring) items[(*out_count)++] = axiam_strdup0(e->valuestring);
    }
    return items;
}

/* ------------------------------------------------------------------ */
/* §12.4                                                              */
/* ------------------------------------------------------------------ */

/* Fill an error with one of the seven §12.3 rule 3 reason codes. The kind is
 * always AXIAM_ERR_AUTH: the contract models these as an AuthError sub-type,
 * and C has no subtyping, so the code lands in a field rather than a type. */
static axiam_error_kind_t id_token_fail(axiam_error_t *err, const char *reason,
                                        const char *message) {
    axiam_error_set(err, AXIAM_ERR_AUTH, 0, message);
    if (err) snprintf(err->id_token_reason, sizeof(err->id_token_reason), "%s", reason);
    return AXIAM_ERR_AUTH;
}

/*
 * Constant-time string equality, for the §12.4 rule 6 nonce comparison.
 *
 * The nonce is not a secret in the §7 sense — it is returned to the caller as a
 * plain string — but rule 6 names constant-time comparison explicitly, and the
 * reason is timing: a variable-time compare against an attacker-chosen nonce
 * leaks a prefix oracle, and recovering the expected nonce byte by byte is
 * enough to forge the one check standing between a replayed ID token and
 * acceptance. Lengths are compared first and that is not a leak — the nonce
 * length is fixed by this SDK's own generator.
 */
static int ct_streq(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* The client's §12.4 rule 5 skew, honouring the configured clamp. */
static long oidc_clock_skew(const axiam_client_t *c) {
    long s = (c && c->cfg) ? c->cfg->oidc_clock_skew_s : -1;
    if (s < 0) return AXIAM_OIDC_MAX_CLOCK_SKEW_S;
    return s > AXIAM_OIDC_MAX_CLOCK_SKEW_S ? AXIAM_OIDC_MAX_CLOCK_SKEW_S : s;
}

/* §12.4 rule 4. `aud` must contain the RP's client_id; when it holds MORE THAN
 * ONE audience, `azp` must be present and equal to that client_id. */
static int audience_ok(char **audience, size_t count, const char *azp,
                       const char *client_id) {
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (audience[i] && strcmp(audience[i], client_id) == 0) { found = 1; break; }
    }
    if (!found) return 0;
    if (count > 1) return azp && strcmp(azp, client_id) == 0;
    return 1;
}

/*
 * Rules 3 to 6 against an already-signature-verified claim set.
 *
 * `expected_nonce` NULL means rule 6 is skipped, which is correct for
 * `oidc_refresh`, `login_client_credentials` and `device_poll`: OIDC Core §12.2
 * does not require a nonce in a refresh-issued ID token, and those flows had no
 * authorization request to carry one. It is NEVER NULL for `oidc_exchange`,
 * where §12.4 rule 6 is mandatory.
 */
static axiam_error_kind_t check_id_claims(axiam_client_t *c, cJSON *root,
                                          const axiam_oidc_config_t *config,
                                          const char *expected_nonce,
                                          axiam_error_t *err) {
    const char *client_id = c->cfg->oidc_client_id;

    /* Rule 3: EXACT string comparison against the discovery document's issuer.
     * No normalization, no trailing-slash tolerance, no prefix matching — every
     * one of those has been an OP-confusion CVE somewhere. */
    char *iss = json_str(root, "iss");
    int iss_ok = iss && config->issuer && strcmp(iss, config->issuer) == 0;
    free(iss);
    if (!iss_ok) {
        return id_token_fail(err, AXIAM_OIDC_REASON_INVALID_ISSUER,
                             "id_token iss does not equal the discovery document's issuer");
    }

    /* Rule 4. */
    size_t aud_count = 0;
    char **aud = json_str_array(root, "aud", &aud_count);
    char *azp = json_str(root, "azp");
    int aud_ok = client_id && aud && audience_ok(aud, aud_count, azp, client_id);
    string_array_free(aud, aud_count);
    free(azp);
    if (!aud_ok) {
        return id_token_fail(err, AXIAM_OIDC_REASON_INVALID_AUDIENCE,
                             "id_token aud does not name this client (or azp is "
                             "missing on a multi-audience token)");
    }

    /* Rule 5. `exp` and `iat` are BOTH required (contract 1.5 clarified that an
     * ID token missing either is rejected), and every failure here — past exp,
     * absent exp, absent or future iat, future nbf — reports the single code
     * `token_expired`. The vocabulary is closed at seven; there is no
     * `missing_exp` and no `token_not_yet_valid` to reach for. */
    long long now = (long long)time(NULL);
    long skew = oidc_clock_skew(c);
    long long exp = json_int(root, "exp", -1);
    long long iat = json_int(root, "iat", -1);
    if (exp < 0) {
        return id_token_fail(err, AXIAM_OIDC_REASON_TOKEN_EXPIRED,
                             "id_token has no usable exp claim");
    }
    if (now > exp + skew) {
        return id_token_fail(err, AXIAM_OIDC_REASON_TOKEN_EXPIRED, "id_token has expired");
    }
    if (iat < 0) {
        return id_token_fail(err, AXIAM_OIDC_REASON_TOKEN_EXPIRED,
                             "id_token has no usable iat claim");
    }
    if (iat > now + skew) {
        return id_token_fail(err, AXIAM_OIDC_REASON_TOKEN_EXPIRED,
                             "id_token was issued in the future");
    }
    const cJSON *nbf = cJSON_GetObjectItemCaseSensitive(root, "nbf");
    if (nbf) {
        if (!cJSON_IsNumber(nbf) || (long long)nbf->valuedouble > now + skew) {
            return id_token_fail(err, AXIAM_OIDC_REASON_TOKEN_EXPIRED,
                                 "id_token is not yet valid");
        }
    }

    /* Rule 6. */
    if (expected_nonce) {
        char *nonce = json_str(root, "nonce");
        int ok = nonce && ct_streq(nonce, expected_nonce);
        free(nonce);
        if (!ok) {
            return id_token_fail(err, AXIAM_OIDC_REASON_NONCE_MISMATCH,
                                 "id_token nonce is absent or does not match the "
                                 "one oidc_begin produced");
        }
    }
    return AXIAM_OK;
}

/* Build the caller-visible claim struct from a validated payload. */
static axiam_id_token_claims_t *build_claims(cJSON *root, const char *raw) {
    axiam_id_token_claims_t *out = calloc(1, sizeof(*out));
    if (!out) return NULL;
    out->subject = json_str(root, "sub");
    out->issuer = json_str(root, "iss");
    out->audience = json_str_array(root, "aud", &out->audience_count);
    out->expires_at = json_int(root, "exp", 0);
    out->issued_at = json_int(root, "iat", 0);
    out->nonce = json_str(root, "nonce");
    out->authorized_party = json_str(root, "azp");
    out->email = json_str(root, "email");
    out->preferred_username = json_str(root, "preferred_username");
    out->tenant_id = json_str(root, "tenant_id");
    out->roles = json_str_array(root, "roles", &out->roles_count);
    /* §12.1: preserve every further claim the server sent. `openapi.json` types
     * the ID token as an opaque string, so the claim set is not enumerable and
     * an SDK MUST NOT reject what it does not recognise. In a language with an
     * open map this is a dictionary; here it is the object, verbatim. */
    out->raw_claims_json = axiam_strdup0(raw);
    if (!out->raw_claims_json) {
        axiam_id_token_claims_free(out);
        return NULL;
    }
    return out;
}

/*
 * The full §12.4 pass over one ID token: signature (through the shared
 * verifier), then rules 3 to 6, then the claim struct.
 */
static axiam_error_kind_t validate_id_token(axiam_client_t *c, const char *id_token,
                                            const axiam_oidc_config_t *config,
                                            const char *expected_nonce,
                                            axiam_id_token_claims_t **out_claims,
                                            axiam_error_t *err) {
    *out_claims = NULL;

    /* Rules 1 and 2, in the verifier the §10 guards already use. */
    char *payload = NULL;
    char reason[32] = {0};
    axiam_error_kind_t kind =
        axiam_jwt_verify_reasoned(c, id_token, &payload, reason, sizeof(reason), err);
    if (kind != AXIAM_OK) {
        if (err && reason[0]) {
            snprintf(err->id_token_reason, sizeof(err->id_token_reason), "%s", reason);
        }
        free(payload);
        return kind;
    }

    cJSON *root = payload ? cJSON_Parse(payload) : NULL;
    if (!root) {
        free(payload);
        return id_token_fail(err, AXIAM_OIDC_REASON_INVALID_SIGNATURE,
                             "id_token payload is not a JSON object");
    }

    kind = check_id_claims(c, root, config, expected_nonce, err);
    if (kind == AXIAM_OK) {
        *out_claims = build_claims(root, payload);
        if (!*out_claims) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            kind = AXIAM_ERR_NETWORK;
        }
    }
    cJSON_Delete(root);
    free(payload);
    return kind;
}

/* ------------------------------------------------------------------ */
/* TokenResponse                                                      */
/* ------------------------------------------------------------------ */

axiam_error_kind_t oidc_parse_token_set(axiam_client_t *c, const char *json,
                                        const axiam_oidc_config_t *config,
                                        const char *expected_nonce,
                                        axiam_oidc_token_set_t *out,
                                        axiam_error_t *err) {
    memset(out, 0, sizeof(*out));
    cJSON *root = json ? cJSON_Parse(json) : NULL;
    const cJSON *access = root ? cJSON_GetObjectItemCaseSensitive(root, "access_token") : NULL;
    if (!cJSON_IsString(access) || !access->valuestring[0]) {
        cJSON_Delete(root);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "malformed TokenResponse (missing access_token)");
        return AXIAM_ERR_NETWORK;
    }

    const cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "id_token");
    if (cJSON_IsString(id) && id->valuestring[0]) {
        axiam_id_token_claims_t *claims = NULL;
        axiam_error_kind_t kind =
            validate_id_token(c, id->valuestring, config, expected_nonce, &claims, err);
        if (kind != AXIAM_OK) {
            /*
             * §12.4 rule 7, and the whole reason this branch runs BEFORE
             * anything is written to `out`. The access and refresh tokens in
             * this same response are discarded with the ID token: there is no
             * partial success, and "the access token was probably fine" is
             * exactly the reasoning that turns a failed audience check into a
             * live session for the wrong relying party.
             */
            cJSON_Delete(root);
            memset(out, 0, sizeof(*out));
            return kind;
        }
        out->id_claims = claims;
        out->id_token = axiam_sensitive_new(id->valuestring);
    }

    out->access_token = axiam_sensitive_new(access->valuestring);
    out->token_type = json_str(root, "token_type");
    if (!out->token_type) out->token_type = axiam_strdup0("Bearer");
    out->expires_in = (long)json_int(root, "expires_in", 0);
    out->scope = json_str(root, "scope");
    const cJSON *refresh = cJSON_GetObjectItemCaseSensitive(root, "refresh_token");
    if (cJSON_IsString(refresh) && refresh->valuestring[0]) {
        out->refresh_token = axiam_sensitive_new(refresh->valuestring);
    }
    cJSON_Delete(root);

    if (!out->access_token || !out->token_type ||
        (out->id_claims && !out->id_token)) {
        axiam_oidc_token_set_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* Copies                                                             */
/* ------------------------------------------------------------------ */

static axiam_sensitive_t *sensitive_copy(const axiam_sensitive_t *src) {
    if (!src) return NULL;
    return axiam_sensitive_new_bytes(axiam_sensitive_bytes(src), axiam_sensitive_len(src));
}

static char **string_array_copy(char *const *src, size_t count) {
    if (!src || count == 0) return NULL;
    char **out = calloc(count, sizeof(char *));
    if (!out) return NULL;
    for (size_t i = 0; i < count; i++) out[i] = axiam_strdup0(src[i]);
    return out;
}

static axiam_id_token_claims_t *claims_copy(const axiam_id_token_claims_t *src) {
    if (!src) return NULL;
    axiam_id_token_claims_t *out = calloc(1, sizeof(*out));
    if (!out) return NULL;
    out->subject = axiam_strdup0(src->subject);
    out->issuer = axiam_strdup0(src->issuer);
    out->audience = string_array_copy(src->audience, src->audience_count);
    out->audience_count = out->audience ? src->audience_count : 0;
    out->expires_at = src->expires_at;
    out->issued_at = src->issued_at;
    out->nonce = axiam_strdup0(src->nonce);
    out->authorized_party = axiam_strdup0(src->authorized_party);
    out->email = axiam_strdup0(src->email);
    out->preferred_username = axiam_strdup0(src->preferred_username);
    out->tenant_id = axiam_strdup0(src->tenant_id);
    out->roles = string_array_copy(src->roles, src->roles_count);
    out->roles_count = out->roles ? src->roles_count : 0;
    out->raw_claims_json = axiam_strdup0(src->raw_claims_json);
    return out;
}

int oidc_token_set_copy(const axiam_oidc_token_set_t *src, axiam_oidc_token_set_t *dst) {
    memset(dst, 0, sizeof(*dst));
    dst->access_token = sensitive_copy(src->access_token);
    dst->refresh_token = sensitive_copy(src->refresh_token);
    dst->id_token = sensitive_copy(src->id_token);
    dst->token_type = axiam_strdup0(src->token_type);
    dst->scope = axiam_strdup0(src->scope);
    dst->expires_in = src->expires_in;
    dst->id_claims = claims_copy(src->id_claims);
    if (!dst->access_token || !dst->token_type ||
        (src->refresh_token && !dst->refresh_token) ||
        (src->id_token && !dst->id_token) ||
        (src->id_claims && !dst->id_claims)) {
        axiam_oidc_token_set_dispose(dst);
        return 0;
    }
    return 1;
}

axiam_error_kind_t oidc_config_copy(const axiam_oidc_config_t *src, axiam_oidc_config_t *dst) {
    memset(dst, 0, sizeof(*dst));
    dst->issuer = axiam_strdup0(src->issuer);
    dst->authorization_endpoint = axiam_strdup0(src->authorization_endpoint);
    dst->token_endpoint = axiam_strdup0(src->token_endpoint);
    dst->jwks_uri = axiam_strdup0(src->jwks_uri);
    dst->userinfo_endpoint = axiam_strdup0(src->userinfo_endpoint);
    dst->introspection_endpoint = axiam_strdup0(src->introspection_endpoint);
    dst->revocation_endpoint = axiam_strdup0(src->revocation_endpoint);
    dst->end_session_endpoint = axiam_strdup0(src->end_session_endpoint);
    dst->device_authorization_endpoint = axiam_strdup0(src->device_authorization_endpoint);
    dst->pushed_authorization_request_endpoint =
        axiam_strdup0(src->pushed_authorization_request_endpoint);
    dst->scopes_supported = string_array_copy(src->scopes_supported, src->scopes_supported_count);
    dst->scopes_supported_count = dst->scopes_supported ? src->scopes_supported_count : 0;
    dst->response_types_supported =
        string_array_copy(src->response_types_supported, src->response_types_supported_count);
    dst->response_types_supported_count =
        dst->response_types_supported ? src->response_types_supported_count : 0;
    dst->id_token_signing_alg_values_supported =
        string_array_copy(src->id_token_signing_alg_values_supported,
                          src->id_token_signing_alg_values_supported_count);
    dst->id_token_signing_alg_values_supported_count =
        dst->id_token_signing_alg_values_supported
            ? src->id_token_signing_alg_values_supported_count
            : 0;
    if (!dst->issuer || !dst->authorization_endpoint || !dst->token_endpoint || !dst->jwks_uri) {
        axiam_oidc_config_dispose(dst);
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

void axiam_pushed_authorization_request_dispose(axiam_pushed_authorization_request_t *p) {
    if (!p) return;
    free(p->url);
    free(p->state);
    free(p->nonce);
    /* Both secrets go through the scrubbing free: the handle is a bearer
     * credential for the length of the redirect window (§26.5), and the verifier
     * is secret for its whole lifetime (§12.5). */
    axiam_sensitive_free(p->request_uri);
    axiam_sensitive_free(p->code_verifier);
    memset(p, 0, sizeof(*p));
}
