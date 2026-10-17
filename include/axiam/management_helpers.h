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

/**
 * An `SsfStream` read as the `update_stream` replacement body -- the PLAIN converter;
 * `authorization_header` absent (keeps the stored header unless the endpoint moves, §32.3
 * rule 5).
 *
 * Contract 1.61 (§32.2): `expected_updated_at` is the stream's `updated_at`, verbatim -- the
 * very string the response held, never parsed or re-formatted -- so the update is a `409` if
 * the stream was written since, and `events_requested` is the one read: `[]` stays `[]`
 * (the receiver's "none"), and an absent one stays absent.
 *
 * **Cutting `events_requested` to the new `events_allowed` is the caller's duty.** This
 * function cannot know that you are about to lower the ceiling, so when you do, a requested
 * list left outside the new `events_allowed` is `400`, and one you drop altogether
 * *resets* the stream to every allowed event, widening what the receiver narrowed (the
 * three meanings of `events_requested`, §32.2: absent resets, `[]` is none, a list is
 * stored as given). An edit built from a read is conditional on that read: it is a `409`,
 * never retried, once the stream changes under it -- read again and decide again. To have
 * the cut made for you, use axiam_mgmt_ssf_stream_apply_changes().
 */
axiam_mgmt_ssf_stream_input_t *axiam_mgmt_ssf_stream_to_input(const axiam_mgmt_ssf_stream_t *stream);

/**
 * The changes axiam_mgmt_ssf_stream_apply_changes() applies over a stream that was read.
 *
 * A member left NULL (or with its `has_` flag 0) is **unchanged**: the read's value goes
 * back. Every string is borrowed for the call. Zero-initialise it (`= {0}`) and set what you
 * change. To drop an optional member (`description`, `endpoint_url`, `status_reason`),
 * edit the result: free the member and set it NULL.
 */
typedef struct axiam_mgmt_ssf_stream_changes {
    const char *receiver_client_id; /**< The new receiver client, or NULL. */
    const char *audience;           /**< The new audience, or NULL. */
    int has_delivery_method;        /**< 1 when `delivery_method` is set. */
    axiam_mgmt_ssf_delivery_method_t delivery_method;
    const char *description;        /**< The new description, or NULL. */
    const char *endpoint_url;       /**< The new push endpoint, or NULL. */
    /**
     * The new `events_allowed`: a JSON array of event-type URIs (`["...","..."]`), or NULL.
     * When set and `events_requested` below is NULL, the read `events_requested` is **cut to
     * this ceiling**: the entries of the read list that are in it, in their order.
     */
    const char *events_allowed;
    /**
     * An `events_requested` of your own, a JSON array: sent as given, never cut -- the server
     * judges it (`400` outside `events_allowed`). NULL: the read's, as read.
     */
    const char *events_requested;
    int has_status;                 /**< 1 when `status` is set. */
    axiam_mgmt_ssf_stream_status_t status;
    const char *status_reason;      /**< The new status reason, or NULL. */
    int has_subject_format;         /**< 1 when `subject_format` is set. */
    axiam_mgmt_ssf_subject_format_t subject_format;
    /** A new push `Authorization` header value (write-only, §32.5), or NULL to keep the stored one. */
    const char *authorization_header;
    int clear_authorization_header; /**< 1 sends `clear_authorization_header: true`. */
    /**
     * An `expected_updated_at` of your own, sent as given, or NULL: the read's `updated_at`,
     * verbatim.
     */
    const char *expected_updated_at;
    /**
     * 1 states `expected_updated_at` as **none** (§27.11 rule 5, contract 1.62): the key is
     * left out of the body, `null` is never sent, and the replacement is no longer
     * conditional on the version read. Takes precedence over `expected_updated_at`.
     */
    int no_expected_updated_at;
} axiam_mgmt_ssf_stream_changes_t;

/**
 * The CHANGE-TAKING read-modify-write form of §32.2 (contract 1.62): the `update_stream` body
 * for `stream` with `changes` applied over it -- `(stream, changes) -> body`.
 *
 * It sends **`events_requested` and `expected_updated_at` as read** (the string, byte for
 * byte; an `[]` stays `[]`, never omitted, because omitting it would reset the stream to
 * every allowed event and widen what the receiver narrowed), and **cuts `events_requested`
 * to the new `events_allowed`** when `changes` names one and no `events_requested` of its
 * own: the read list's entries that are in the new ceiling, in their order. An
 * `events_requested` named in `changes` is sent as given. `authorization_header` is left
 * absent unless `changes` carries one (absent keeps the stored header). The result is
 * conditional on the version read: a `409` if the stream was written since, never retried.
 *
 * `changes` may be NULL, which is the plain converter axiam_mgmt_ssf_stream_to_input().
 * Returns a newly allocated body (free with axiam_mgmt_ssf_stream_input_free()), or NULL on
 * allocation failure or a NULL `stream`.
 */
axiam_mgmt_ssf_stream_input_t *
axiam_mgmt_ssf_stream_apply_changes(const axiam_mgmt_ssf_stream_t *stream,
                                    const axiam_mgmt_ssf_stream_changes_t *changes);

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
