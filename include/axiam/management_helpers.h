/**
 * @file management_helpers.h
 * @brief Hand-written conveniences around the generated §27 models for §29 – §32.
 *
 * Nothing here performs I/O. Three kinds of helper, each one the contract asks for:
 *
 * - **Read-modify-write** (§27.4 rule 5, SHOULD; §29.2, §30.2, §31.2, §32.2). Every
 *   update in these namespaces is a REPLACEMENT: a member left out takes its default, not
 *   its stored value. The `_to_input()` functions turn a read result into the replacement
 *   body with every member carried over, so changing one field and sending it back keeps
 *   the rest. The write-only secret (`bind_secret`, `authorization_header`,
 *   `credential`) is never on a read and so is ABSENT from the result — which on these
 *   updates means "keep the stored one", subject to each section's moved-connection rule.
 * - **The one-of body of `saml.parse_sp_metadata`** (§29.2: exactly one of `metadata_xml`
 *   and `metadata_url`). Building it through these two functions cannot produce both or
 *   neither; a hand-built value that does is refused locally by the operation.
 * - **The tagged unions of §31.2** (`ScimTargetAuth`, `ScimTargetScope`). The generated
 *   type carries the tag and the raw object; these build both, with exactly §31.2's keys.
 *
 * Every function returns a newly allocated value the caller frees with the model's own
 * `_free()`, or NULL on an allocation failure (or a NULL argument).
 */
#ifndef AXIAM_MANAGEMENT_HELPERS_H
#define AXIAM_MANAGEMENT_HELPERS_H

#include <stddef.h>

#include "axiam/management_models.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- read-modify-write ---------------------------------------------------------- */

/** A `SamlServiceProvider` read as the `update_service_provider` replacement body. */
axiam_mgmt_saml_service_provider_input_t *
axiam_mgmt_saml_service_provider_to_input(const axiam_mgmt_saml_service_provider_t *sp);

/** An `SsfStream` read as the `update_stream` replacement body; `authorization_header`
 *  absent (keeps the stored header unless the endpoint moves — §32.3 rule 5). */
axiam_mgmt_ssf_stream_input_t *axiam_mgmt_ssf_stream_to_input(const axiam_mgmt_ssf_stream_t *stream);

/** A `ScimTargetResponse` read as the `update` replacement body; `credential` absent
 *  (keeps the stored one unless the URL moves — §31.3 rule 2). */
axiam_mgmt_scim_target_input_t *
axiam_mgmt_scim_target_response_to_input(const axiam_mgmt_scim_target_response_t *target);

/** A `DirectoryConfig` read as the `directory.set` replacement body; `bind_secret` absent
 *  (keeps the stored secret unless the connection moves — §30.3 rule 2). */
axiam_mgmt_set_directory_config_t *
axiam_mgmt_directory_config_to_set(const axiam_mgmt_directory_config_t *config);

/* ---- saml.parse_sp_metadata ------------------------------------------------------- */

/** `{"metadata_url": url}` — the server fetches the document (`https` only, through its
 *  SSRF guard). */
axiam_mgmt_parse_saml_sp_metadata_t *axiam_mgmt_parse_saml_sp_metadata_from_url(const char *url);

/** `{"metadata_xml": xml}` — the document itself (at most 512 KiB). */
axiam_mgmt_parse_saml_sp_metadata_t *axiam_mgmt_parse_saml_sp_metadata_from_xml(const char *xml);

/* ---- §31.2 tagged unions ---------------------------------------------------------- */

/** `{"type": "bearer"}`. The bearer itself is `ScimTargetInput.credential`. */
axiam_mgmt_scim_target_auth_t *axiam_mgmt_scim_target_auth_bearer(void);

/** `{"type": "oauth2_client_credentials", "token_url", "client_id", "scope"}`; `scope`
 *  NULL omits it. The client secret is `ScimTargetInput.credential`, never a member here. */
axiam_mgmt_scim_target_auth_t *axiam_mgmt_scim_target_auth_client_credentials(const char *token_url,
                                                                              const char *client_id,
                                                                              const char *scope);

/** `{"type": "all_users"}`. */
axiam_mgmt_scim_target_scope_t *axiam_mgmt_scim_target_scope_all_users(void);

/** `{"type": "groups", "group_ids": [...]}` — users who are DIRECT members of any listed
 *  group. */
axiam_mgmt_scim_target_scope_t *axiam_mgmt_scim_target_scope_groups(const char *const *group_ids,
                                                                    size_t count);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_MANAGEMENT_HELPERS_H */
