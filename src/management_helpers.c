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
    /* Contract 1.61, §32.2: the edit is conditional on the version it read. `updated_at` is
     * not a member of the replacement body, so the wire shape cannot carry it; it is sent
     * back as the very string the response held (never re-formatted). `events_requested` --
     * an absent one, a `[]` and a list alike -- does cross the wire shape above, so `[]`
     * stays `[]` and an unset one stays absent. */
    if (out && stream->updated_at) {
        out->expected_updated_at = axiam_strdup0(stream->updated_at);
        if (!out->expected_updated_at) {
            axiam_mgmt_ssf_stream_input_free(out);
            return NULL;
        }
    }
    return out;
}

/* Replace an owned string with a copy of `value`; 0 on allocation failure. NULL leaves it. */
static int replace_str(char **slot, const char *value) {
    if (!value) return 1;
    char *copy = axiam_strdup0(value);
    if (!copy) return 0;
    free(*slot);
    *slot = copy;
    return 1;
}

/* `requested` (a JSON array text) cut to the entries that are in `ceiling` (another), in
 * the requested order; a malloc'd array text. NULL when either is not a JSON array of
 * strings or on allocation failure, in which case the caller keeps what it had and the
 * server judges. */
static char *cut_to_ceiling(const char *requested, const char *ceiling) {
    cJSON *req = cJSON_Parse(requested);
    cJSON *top = cJSON_Parse(ceiling);
    cJSON *kept = NULL;
    char *text = NULL;
    if (cJSON_IsArray(req) && cJSON_IsArray(top) && (kept = cJSON_CreateArray())) {
        const cJSON *r;
        cJSON_ArrayForEach(r, req) {
            if (!cJSON_IsString(r)) continue;
            const cJSON *c;
            cJSON_ArrayForEach(c, top) {
                if (cJSON_IsString(c) && strcmp(c->valuestring, r->valuestring) == 0) {
                    cJSON *copy = cJSON_CreateString(r->valuestring);
                    if (!copy || !cJSON_AddItemToArray(kept, copy)) {
                        cJSON_Delete(copy);
                        cJSON_Delete(kept);
                        kept = NULL;
                    }
                    break;
                }
            }
            if (!kept) break;
        }
        if (kept) text = cJSON_PrintUnformatted(kept);
    }
    cJSON_Delete(kept);
    cJSON_Delete(req);
    cJSON_Delete(top);
    return text;
}

axiam_mgmt_ssf_stream_input_t *
axiam_mgmt_ssf_stream_apply_changes(const axiam_mgmt_ssf_stream_t *stream,
                                    const axiam_mgmt_ssf_stream_changes_t *changes) {
    /* The read, carried: `events_requested` as read (an `[]` stays `[]`) and
     * `expected_updated_at` as the response's own string. */
    axiam_mgmt_ssf_stream_input_t *out = axiam_mgmt_ssf_stream_to_input(stream);
    if (!out || !changes) return out;

    int ok = replace_str(&out->receiver_client_id, changes->receiver_client_id) &&
             replace_str(&out->audience, changes->audience) &&
             replace_str(&out->description, changes->description) &&
             replace_str(&out->endpoint_url, changes->endpoint_url) &&
             replace_str(&out->status_reason, changes->status_reason) &&
             replace_str(&out->events_allowed, changes->events_allowed) &&
             replace_str(&out->events_requested, changes->events_requested);

    if (ok && changes->events_allowed && !changes->events_requested && out->events_requested) {
        /* The ceiling was named and the caller named no list of their own: cut the one
         * read to it (a requested entry outside the ceiling is `400`). */
        char *cut = cut_to_ceiling(out->events_requested, changes->events_allowed);
        if (cut) {
            free(out->events_requested);
            out->events_requested = cut;
        }
    }
    if (ok && changes->has_delivery_method) out->delivery_method = changes->delivery_method;
    if (ok && changes->has_status) { out->status = changes->status; out->has_status = 1; }
    if (ok && changes->has_subject_format) {
        out->subject_format = changes->subject_format;
        out->has_subject_format = 1;
    }
    if (ok && changes->authorization_header) {
        axiam_sensitive_t *header = axiam_sensitive_new(changes->authorization_header);
        if (header) {
            axiam_sensitive_free(out->authorization_header);
            out->authorization_header = header;
        } else {
            ok = 0;
        }
    }
    if (ok && changes->clear_authorization_header) {
        out->clear_authorization_header = 1;
        out->has_clear_authorization_header = 1;
    }
    if (ok && changes->no_expected_updated_at) {
        /* "none": the key is left out and `null` is never sent (§27.11 rule 5). */
        free(out->expected_updated_at);
        out->expected_updated_at = NULL;
    } else if (ok) {
        ok = replace_str(&out->expected_updated_at, changes->expected_updated_at);
    }

    if (!ok) {
        axiam_mgmt_ssf_stream_input_free(out);
        return NULL;
    }
    return out;
}

axiam_mgmt_scim_target_input_t *
axiam_mgmt_scim_target_response_to_input(const axiam_mgmt_scim_target_response_t *target) {
    cJSON *wire = target ? axiam_mgmt_scim_target_response_build(target) : NULL;
    axiam_mgmt_scim_target_input_t *out = wire ? axiam_mgmt_scim_target_input_parse(wire) : NULL;
    cJSON_Delete(wire);
    /* §31.3 rule 4: the update is conditional on the version read, which is the response's own
     * `updated_at` string, byte for byte (the read-only member the conversion above drops). */
    if (out && target->updated_at && !replace_str(&out->expected_updated_at, target->updated_at)) {
        axiam_mgmt_scim_target_input_free(out);
        return NULL;
    }
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
