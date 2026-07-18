#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "internal.h"

static char *print_and_free(cJSON *root) {
    if (!root) return NULL;
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return s;
}

char *axiam_build_login_body(const char *user, const char *password,
                             const axiam_client_config_t *cfg) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddStringToObject(root, "username_or_email", user ? user : "");
    cJSON_AddStringToObject(root, "password", password ? password : "");
    if (cfg) {
        if (cfg->tenant_id && cfg->tenant_id[0])
            cJSON_AddStringToObject(root, "tenant_id", cfg->tenant_id);
        else if (cfg->tenant_slug && cfg->tenant_slug[0])
            cJSON_AddStringToObject(root, "tenant_slug", cfg->tenant_slug);
        if (cfg->org_id && cfg->org_id[0])
            cJSON_AddStringToObject(root, "org_id", cfg->org_id);
        else if (cfg->org_slug && cfg->org_slug[0])
            cJSON_AddStringToObject(root, "org_slug", cfg->org_slug);
    }
    return print_and_free(root);
}

char *axiam_build_mfa_body(const char *challenge_token, const char *totp_code) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddStringToObject(root, "challenge_token", challenge_token ? challenge_token : "");
    cJSON_AddStringToObject(root, "totp_code", totp_code ? totp_code : "");
    return print_and_free(root);
}

char *axiam_build_refresh_body(const char *tenant_id, const char *org_id) {
    /* RefreshRequest requires tenant_id + org_id UUIDs. Callers pass the values
     * resolved from the access-token claims (falling back to UUID-form config);
     * a slug is never a valid substitute here. */
    if (!tenant_id || !tenant_id[0] || !org_id || !org_id[0]) {
        return NULL;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddStringToObject(root, "tenant_id", tenant_id);
    cJSON_AddStringToObject(root, "org_id", org_id);
    return print_and_free(root);
}

static void add_check_fields(cJSON *obj, const char *action, const char *resource_id,
                             const char *scope, const char *subject_id) {
    cJSON_AddStringToObject(obj, "action", action ? action : "");
    cJSON_AddStringToObject(obj, "resource_id", resource_id ? resource_id : "");
    if (scope) cJSON_AddStringToObject(obj, "scope", scope);
    if (subject_id) cJSON_AddStringToObject(obj, "subject_id", subject_id);
}

char *axiam_build_check_body(const char *action, const char *resource_id,
                             const char *scope, const char *subject_id) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    add_check_fields(root, action, resource_id, scope, subject_id);
    return print_and_free(root);
}

char *axiam_build_batch_body(const axiam_check_input_t *checks, size_t n) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON *arr = cJSON_AddArrayToObject(root, "checks");
    if (!arr) { cJSON_Delete(root); return NULL; }
    for (size_t i = 0; i < n; i++) {
        cJSON *obj = cJSON_CreateObject();
        if (!obj) { cJSON_Delete(root); return NULL; }
        add_check_fields(obj, checks[i].action, checks[i].resource_id,
                         checks[i].scope, checks[i].subject_id);
        cJSON_AddItemToArray(arr, obj);
    }
    return print_and_free(root);
}
