/*
 * Hand-written conveniences around the generated §27 models (CONTRACT.md §29 – §32), and
 * the local checks the generated operations call (PRECHECKS in scripts/gen_management.py).
 * See include/axiam/management_helpers.h.
 *
 * The read-modify-write conversions go THROUGH THE WIRE SHAPE: the read result is built
 * into its JSON object by the generated `_build`, and that object is parsed as the input
 * type by the generated `_parse`. The field names of a read type and its replacement are
 * the server's and identical, so this carries every shared member over — including ones
 * a later re-vendor adds to both — and drops the read-only ones (`id`, `created_at`,
 * `state`, ...) because the input parser does not know them. Nothing here hand-copies a
 * member, so nothing here can forget one.
 */

#include <stdlib.h>
#include <string.h>

#include "axiam/management_helpers.h"
#include "cJSON.h"
#include "internal.h"
#include "management_internal.h"

/* The generated parse/build pair, internal to the generated sources. */
cJSON *axiam_mgmt_saml_service_provider_build(const axiam_mgmt_saml_service_provider_t *value);
axiam_mgmt_saml_service_provider_input_t *axiam_mgmt_saml_service_provider_input_parse(const cJSON *src);
cJSON *axiam_mgmt_ssf_stream_build(const axiam_mgmt_ssf_stream_t *value);
axiam_mgmt_ssf_stream_input_t *axiam_mgmt_ssf_stream_input_parse(const cJSON *src);
cJSON *axiam_mgmt_scim_target_response_build(const axiam_mgmt_scim_target_response_t *value);
axiam_mgmt_scim_target_input_t *axiam_mgmt_scim_target_input_parse(const cJSON *src);
cJSON *axiam_mgmt_directory_config_build(const axiam_mgmt_directory_config_t *value);
axiam_mgmt_set_directory_config_t *axiam_mgmt_set_directory_config_parse(const cJSON *src);

/* ---- read-modify-write ---------------------------------------------------------- */

axiam_mgmt_saml_service_provider_input_t *
axiam_mgmt_saml_service_provider_to_input(const axiam_mgmt_saml_service_provider_t *sp) {
    cJSON *wire = sp ? axiam_mgmt_saml_service_provider_build(sp) : NULL;
    axiam_mgmt_saml_service_provider_input_t *out =
        wire ? axiam_mgmt_saml_service_provider_input_parse(wire) : NULL;
    cJSON_Delete(wire);
    return out;
}

axiam_mgmt_ssf_stream_input_t *axiam_mgmt_ssf_stream_to_input(const axiam_mgmt_ssf_stream_t *stream) {
    cJSON *wire = stream ? axiam_mgmt_ssf_stream_build(stream) : NULL;
    axiam_mgmt_ssf_stream_input_t *out = wire ? axiam_mgmt_ssf_stream_input_parse(wire) : NULL;
    cJSON_Delete(wire);
    return out;
}

axiam_mgmt_scim_target_input_t *
axiam_mgmt_scim_target_response_to_input(const axiam_mgmt_scim_target_response_t *target) {
    cJSON *wire = target ? axiam_mgmt_scim_target_response_build(target) : NULL;
    axiam_mgmt_scim_target_input_t *out = wire ? axiam_mgmt_scim_target_input_parse(wire) : NULL;
    cJSON_Delete(wire);
    return out;
}

axiam_mgmt_set_directory_config_t *
axiam_mgmt_directory_config_to_set(const axiam_mgmt_directory_config_t *config) {
    cJSON *wire = config ? axiam_mgmt_directory_config_build(config) : NULL;
    axiam_mgmt_set_directory_config_t *out =
        wire ? axiam_mgmt_set_directory_config_parse(wire) : NULL;
    cJSON_Delete(wire);
    return out;
}

/* ---- saml.parse_sp_metadata ------------------------------------------------------- */

static axiam_mgmt_parse_saml_sp_metadata_t *parse_metadata_body(const char *url, const char *xml) {
    axiam_mgmt_parse_saml_sp_metadata_t *out = calloc(1, sizeof(*out));
    if (!out) return NULL;
    out->metadata_url = axiam_strdup0(url);
    out->metadata_xml = axiam_strdup0(xml);
    if (!out->metadata_url && !out->metadata_xml) {
        free(out);
        return NULL;
    }
    return out;
}

axiam_mgmt_parse_saml_sp_metadata_t *axiam_mgmt_parse_saml_sp_metadata_from_url(const char *url) {
    return url ? parse_metadata_body(url, NULL) : NULL;
}

axiam_mgmt_parse_saml_sp_metadata_t *axiam_mgmt_parse_saml_sp_metadata_from_xml(const char *xml) {
    return xml ? parse_metadata_body(NULL, xml) : NULL;
}

axiam_error_kind_t axiam_mgmt_check_parse_sp_metadata(const axiam_mgmt_parse_saml_sp_metadata_t *body,
                                                      axiam_error_t *err) {
    int has_url = body && body->metadata_url;
    int has_xml = body && body->metadata_xml;
    if (has_url && has_xml) {
        axiam_local_refusal(err, "saml.parse_sp_metadata", "metadata_xml",
                            "set exactly one of metadata_xml and metadata_url, not both "
                            "(CONTRACT.md \xc2\xa7" "29.2)");
        return AXIAM_ERR_NETWORK;
    }
    if (!has_url && !has_xml) {
        axiam_local_refusal(err, "saml.parse_sp_metadata", "metadata_url",
                            "set exactly one of metadata_xml and metadata_url "
                            "(CONTRACT.md \xc2\xa7" "29.2)");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ---- §31.2 tagged unions ---------------------------------------------------------- */

/* A tag plus its raw object, both owned; `obj` is consumed. 0 on any failure. */
static int tagged(cJSON *obj, char **type, char **raw, const char *tag) {
    *type = NULL;
    *raw = obj ? cJSON_PrintUnformatted(obj) : NULL;
    cJSON_Delete(obj);
    *type = *raw ? axiam_strdup0(tag) : NULL;
    if (!*type) {
        free(*raw);
        *raw = NULL;
        return 0;
    }
    return 1;
}

/* `{"type": tag}` -- the discriminator first, as §31.2 writes the shapes. */
static cJSON *typed_object(const char *tag) {
    cJSON *obj = cJSON_CreateObject();
    if (obj && !cJSON_AddStringToObject(obj, "type", tag)) {
        cJSON_Delete(obj);
        return NULL;
    }
    return obj;
}

static axiam_mgmt_scim_target_auth_t *auth_from(cJSON *obj, const char *tag) {
    axiam_mgmt_scim_target_auth_t *out = calloc(1, sizeof(*out));
    if (!out) {
        cJSON_Delete(obj);
        return NULL;
    }
    if (!tagged(obj, &out->type, &out->raw, tag)) {
        free(out);
        return NULL;
    }
    return out;
}

static axiam_mgmt_scim_target_scope_t *scope_from(cJSON *obj, const char *tag) {
    axiam_mgmt_scim_target_scope_t *out = calloc(1, sizeof(*out));
    if (!out) {
        cJSON_Delete(obj);
        return NULL;
    }
    if (!tagged(obj, &out->type, &out->raw, tag)) {
        free(out);
        return NULL;
    }
    return out;
}

axiam_mgmt_scim_target_auth_t *axiam_mgmt_scim_target_auth_bearer(void) {
    return auth_from(typed_object("bearer"), "bearer");
}

axiam_mgmt_scim_target_auth_t *axiam_mgmt_scim_target_auth_client_credentials(const char *token_url,
                                                                              const char *client_id,
                                                                              const char *scope) {
    if (!token_url || !client_id) return NULL;
    cJSON *obj = typed_object("oauth2_client_credentials");
    if (!obj) return NULL;
    if (!cJSON_AddStringToObject(obj, "token_url", token_url) ||
        !cJSON_AddStringToObject(obj, "client_id", client_id) ||
        (scope && !cJSON_AddStringToObject(obj, "scope", scope))) {
        cJSON_Delete(obj);
        return NULL;
    }
    return auth_from(obj, "oauth2_client_credentials");
}

axiam_mgmt_scim_target_scope_t *axiam_mgmt_scim_target_scope_all_users(void) {
    return scope_from(typed_object("all_users"), "all_users");
}

axiam_mgmt_scim_target_scope_t *axiam_mgmt_scim_target_scope_groups(const char *const *group_ids,
                                                                    size_t count) {
    if (!group_ids && count > 0) return NULL;
    cJSON *obj = typed_object("groups");
    cJSON *ids = obj ? cJSON_AddArrayToObject(obj, "group_ids") : NULL;
    if (!ids) {
        cJSON_Delete(obj);
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *id = group_ids[i] ? cJSON_CreateString(group_ids[i]) : NULL;
        if (!id) {
            cJSON_Delete(obj);
            return NULL;
        }
        cJSON_AddItemToArray(ids, id);
    }
    return scope_from(obj, "groups");
}
