/**
 * @file management_manifest.h
 * @brief CONTRACT.md §27.6/§27.7 declarative layer — describe a tenant, plan, apply.
 *
 * The imperative surface is fine for one change. It is a poor way to describe a TENANT,
 * because re-running it either fails on the second run or makes the caller hand-write
 * "does this exist already?" for every object. A manifest is re-runnable by
 * construction: apply it twice and the second run sends nothing.
 *
 * Four properties constrain everything here, and are worth knowing before running one
 * against production:
 *
 * - **Plan writes nothing.** ::axiam_mgmt_plan issues reads and reports the difference.
 *   Safe against production, safe in CI, safe on a schedule.
 * - **Apply stops at the first failure and does NOT roll back** (§27.7). The report says
 *   what landed, what failed, and what was never attempted — a partial apply is a state
 *   an operator resumes from, and an automatic rollback would fire a second wave of
 *   writes exactly when the server is saying something is wrong.
 * - **Ordering is derived, not declared.** By kind, then by dependency, then by key. The
 *   tie-break on key is what makes a plan stable across runs.
 * - **Omission is never deletion.** There is no delete action at all, so an incomplete
 *   manifest cannot become a destructive one.
 *
 * Entities are addressed by a manifest-local `key`, never by a server-assigned UUID —
 * that is what lets the same manifest mean the same thing against a fresh tenant and an
 * existing one, since a UUID does not exist until the first apply.
 */

#ifndef AXIAM_MANAGEMENT_MANIFEST_H
#define AXIAM_MANAGEMENT_MANIFEST_H

#include <stddef.h>

#include "axiam/management.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The entity kinds a manifest can declare.
 *
 * The order of these constants IS the order an apply runs them in — the dependency order
 * §27.6 requires be derived rather than written down by the caller. A role cannot be
 * granted a permission that does not exist yet, and a group cannot be assigned a role
 * that does not exist yet. AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT (contract 1.51, §27.6.1)
 * sorts LAST because §27.6 rule 5's full order puts "service accounts" and their
 * bindings after "groups" and group bindings; group role bindings are applied between
 * the GROUP and SERVICE_ACCOUNT phases (see axiam_mgmt_apply()'s doc comment), and
 * service-account role bindings after the SERVICE_ACCOUNT phase.
 */
typedef enum axiam_mgmt_manifest_kind {
    AXIAM_MGMT_MANIFEST_RESOURCE = 0, /**< Hierarchical resource; parents before children. */
    AXIAM_MGMT_MANIFEST_PERMISSION,   /**< A permission (an action). Depends on nothing. */
    AXIAM_MGMT_MANIFEST_ROLE,         /**< A role. Depends on permissions. */
    AXIAM_MGMT_MANIFEST_GROUP,        /**< A group. Depends on roles. */
    AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT /**< A service account (contract 1.51, §27.6.1). */
} axiam_mgmt_manifest_kind_t;

/**
 * One role-binding declaration inside a `groups[]` or `service_accounts[]` entity's
 * `roles[]` list (CONTRACT.md §27.6.1 item 2). Every `roles[]` entry is one of two
 * shapes on the wire: a bare role key (no resource, no inheritance question), or this
 * object naming a resource scope and, only when `false`, `inherit`.
 */
typedef struct axiam_mgmt_role_binding {
    const char *role_key;     /**< Manifest-local key of the role this binds. */
    /**
     * Manifest-local key of the resource this binding is scoped to, or NULL for the
     * PLAIN shape (no resource, reaches wherever the role does).
     */
    const char *resource_key;
    /**
     * 1 sends `inherit: false` on the wire (server T22.11's non-inheritable
     * assignment). 0 OMITS the `inherit` key entirely — CONTRACT.md §27.6.1 item 2 is
     * explicit that an SDK MUST NOT send `inherit: true` explicitly, so that an
     * inheritable binding's body stays byte-for-byte a pre-1.51 body. There is
     * therefore no third state: a binding either asks to stop inheritance, or it says
     * nothing about it.
     */
    int inherit_false;
} axiam_mgmt_role_binding_t;

/**
 * What a plan intends to do to one declared entity.
 *
 * There is deliberately no DELETE. §27.6 is explicit that omission is never deletion: a
 * manifest describes what must exist, not everything that may exist, and a tenant almost
 * always holds objects no manifest mentions. Leaving the action out of the enum makes
 * that structural rather than a matter of discipline.
 */
typedef enum axiam_mgmt_change_action {
    AXIAM_MGMT_CHANGE_UNCHANGED = 0, /**< Already matches; nothing will be sent. */
    AXIAM_MGMT_CHANGE_CREATE,        /**< Does not exist; will be created. */
    AXIAM_MGMT_CHANGE_UPDATE         /**< Exists but differs; updated in place. */
} axiam_mgmt_change_action_t;

/** One entity a manifest declares must exist. */
typedef struct axiam_mgmt_manifest_entity {
    axiam_mgmt_manifest_kind_t kind; /**< What sort of object this is. */
    const char *key;                 /**< Manifest-local identity, unique within its kind. */
    const char *name;                /**< The name the server knows it by; also the match key. */
    const char *description;         /**< Human-readable description; may be NULL. */
    const char *resource_type;       /**< For a resource: its `resource_type`. */
    const char *action;              /**< For a permission: the action it names. */
    int is_global;                   /**< For a role: whether it applies tenant-wide. */
    /**
     * For a resource: its `metadata`, as a JSON OBJECT string (e.g. `"{}"` or
     * `"{\"env\":\"prod\"}"`), or NULL when not stated (CONTRACT.md §27.6.1 item 1).
     * Sent on Create and, when stated, on Update; drift is JSON value equality of the
     * WHOLE object, with a stated `"{}"` equal to what the server returns for none —
     * never a key-by-key merge.
     */
    const char *metadata_json;
    /**
     * For a group or service account: its role bindings (CONTRACT.md §27.6.1 item 2).
     * NULL/0 declares no bindings for this subject — existing bindings on it are left
     * alone either way (§27.6 rule 4: deletion is opt-in and this manifest form has
     * none at all for bindings), never removed.
     */
    const axiam_mgmt_role_binding_t *roles;
    size_t roles_count;
    /**
     * Key of the entity this one must be applied after, beyond what `kind` already
     * orders — a parent resource, or a permission a role grants. NULL for none.
     *
     * A KEY, never a UUID: a manifest describes a tenant that may not exist yet.
     */
    const char *depends_on;
} axiam_mgmt_manifest_entity_t;

/** A declarative description of the state a tenant must be in. */
typedef struct axiam_mgmt_manifest {
    const axiam_mgmt_manifest_entity_t *entities; /**< Everything declared. */
    size_t count;                                 /**< How many. */
} axiam_mgmt_manifest_t;

/** One entry in a plan: what would happen to one entity, and why. */
typedef struct axiam_mgmt_planned_change {
    const axiam_mgmt_manifest_entity_t *entity; /**< The declaration this is for. */
    axiam_mgmt_change_action_t action;          /**< What would be done. */
    char *id;                                   /**< Server id when it already exists, else NULL. */
} axiam_mgmt_planned_change_t;

/**
 * What a plan intends to do to one declared role binding (CONTRACT.md §27.6.1).
 *
 * There is no DELETE here either. `AXIAM_MGMT_BINDING_UPDATE` is the ONE case §27.6.1
 * gives a binding that is not create-or-leave-alone: the natural key is
 * `(subject, role)`, and its resource/inherit are fields, so a binding whose resource
 * or inherit flag differs from the server's is an UPDATE — applied as unassign then
 * assign, never a PATCH (there is no update endpoint for an assignment).
 */
typedef enum axiam_mgmt_binding_action {
    AXIAM_MGMT_BINDING_NOCHANGE = 0, /**< The server's assignment already matches. */
    AXIAM_MGMT_BINDING_CREATE,       /**< No assignment of this role to this subject exists. */
    AXIAM_MGMT_BINDING_UPDATE        /**< Exists but its resource/inherit differs: rebind. */
} axiam_mgmt_binding_change_action_t;

/**
 * One entry in a plan: what would happen to one declared role binding.
 *
 * `old_resource_id`/`old_inherit`/`old_tenant_scope` are the SERVER's current
 * assignment, captured at plan time, for an `AXIAM_MGMT_BINDING_UPDATE`: an apply
 * that unassigns the old binding and then fails to assign the new one restores
 * exactly this — CONTRACT.md §27.6.1's "if the assign fails, the SDK MUST attempt to
 * assign the previous binding again (same resource, same inherit)", with
 * `tenant_scope` carried across per the same rule. Meaningless (and NULL/0) for
 * `AXIAM_MGMT_BINDING_CREATE` and `AXIAM_MGMT_BINDING_NOCHANGE`, since there is
 * nothing to restore.
 */
typedef struct axiam_mgmt_planned_binding {
    const axiam_mgmt_manifest_entity_t *subject; /**< The group or service_account entity. */
    const axiam_mgmt_role_binding_t *binding;    /**< Which of `subject->roles[]`. */
    axiam_mgmt_binding_change_action_t action;
    char *old_resource_id;          /**< The server's CURRENT resource_id, or NULL (plain). */
    int old_inherit;                /**< The server's CURRENT inherit, when old_resource_id set. */
    char **old_tenant_scope;        /**< The server's CURRENT tenant_scope, or NULL. */
    size_t old_tenant_scope_count;
} axiam_mgmt_planned_binding_t;

/**
 * What ::axiam_mgmt_plan produced: the ordered changes an apply would make.
 *
 * Includes the UNCHANGED entries as well, so a reader sees what was considered and not
 * only what moved. `bindings` is a SEPARATE ordered list (role bindings are relationships
 * between two entities, not entities themselves — see axiam_mgmt_apply()'s doc comment
 * for exactly where each bindings entry runs relative to `changes`).
 */
typedef struct axiam_mgmt_plan {
    axiam_mgmt_planned_change_t *changes; /**< Every declared entity, in apply order. */
    size_t count;                         /**< How many. */
    size_t pending;                        /**< How many would actually send a request. */
    axiam_mgmt_planned_binding_t *bindings; /**< Every declared role binding, in apply order. */
    size_t binding_count;
    size_t binding_pending;                 /**< How many bindings would actually send a request. */
} axiam_mgmt_plan_t;

/** Free a plan and everything it owns. Safe to pass NULL. */
void axiam_mgmt_plan_free(axiam_mgmt_plan_t *plan);

/**
 * The one-time secret an `apply`'s `Create` of one `service_accounts[]` entry
 * returned (CONTRACT.md §27.5 rule 5). `key` is the entity's manifest-local key, so a
 * caller matches it back to the spec it declared; `client_secret` is exactly what
 * `service_accounts.create` returned, `Sensitive<T>` as always.
 */
typedef struct axiam_mgmt_created_secret {
    char *key;                        /**< Manifest-local key of the service_accounts[] entry. */
    axiam_sensitive_t *client_secret; /**< Returned ONCE; §27.5 rule 3. */
} axiam_mgmt_created_secret_t;

/**
 * What ::axiam_mgmt_apply actually did — including, when it stopped early, what it had
 * already done.
 *
 * This is the recovery tool. `applied` is how many entity changes landed, in order;
 * `failed` is the index of the one that did not (or -1); `remaining` is how many were
 * never attempted. `bindings_applied`/`failed_binding`/`bindings_remaining` are the
 * same three, for the binding phase — entity changes and binding changes are reported
 * separately because they are two different arrays in the plan (see
 * axiam_mgmt_plan_t), not because they run at unrelated times; axiam_mgmt_apply()'s doc
 * comment gives the exact interleaving.
 *
 * `created_secrets` is filled incrementally as each service-account `Create` lands —
 * CONTRACT.md §27.5 rule 5's "the outcome MUST be returned even when a later action of
 * the same apply fails": a caller reads it however apply() returns, success or not.
 * Free with ::axiam_mgmt_apply_report_dispose.
 */
typedef struct axiam_mgmt_apply_report {
    size_t applied;   /**< How many entity changes landed. */
    long failed;      /**< Index into `changes` of the failing one, or -1 when none failed. */
    size_t remaining; /**< How many entity changes were never attempted because of the failure. */

    size_t bindings_applied;   /**< How many binding changes landed. */
    long failed_binding;       /**< Index into `bindings` of the failing one, or -1. */
    size_t bindings_remaining; /**< How many binding changes were never attempted. */
    /**
     * For an `AXIAM_MGMT_BINDING_UPDATE` whose ASSIGN half failed (the unassign
     * having already landed): 1 once a restore of the previous binding was attempted,
     * and, of those, 1 again if it succeeded. Both 0 when no rebind failed this way.
     */
    int restore_attempted;
    int restore_succeeded;

    axiam_mgmt_created_secret_t *created_secrets; /**< One per service-account Create. */
    size_t created_secrets_count;
} axiam_mgmt_apply_report_t;

/**
 * Release everything an apply report owns (the created-secrets list, each one
 * Sensitive and zeroized on release). Does NOT reset the scalar fields — call this once
 * you are done reading them. Safe to pass NULL, and safe on a report axiam_mgmt_apply()
 * never touched (all-zero).
 */
void axiam_mgmt_apply_report_dispose(axiam_mgmt_apply_report_t *report);

/**
 * Compute what an apply would do. Sends only reads (§27.6).
 *
 * Validates the manifest BEFORE the first request: a dangling `depends_on`, a cycle, or a
 * duplicate key is refused up front, because §27.7 gives apply no rollback and
 * discovering it halfway through leaves a tenant in a state nobody described.
 *
 * @param c        The client. Must have an active session.
 * @param manifest The desired state.
 * @param out      Receives the plan; free with ::axiam_mgmt_plan_free.
 * @param err      Filled on failure; may be NULL.
 * @return AXIAM_OK on success, or the failing kind.
 */
axiam_error_kind_t axiam_mgmt_plan(axiam_client_t *c,
                                   const axiam_mgmt_manifest_t *manifest,
                                   axiam_mgmt_plan_t **out,
                                   axiam_error_t *err);

/**
 * Apply a manifest, stopping at the first failure and NOT rolling back (§27.7).
 *
 * Re-plans internally rather than taking a plan, so what is applied is computed against
 * the tenant's state NOW. A plan from an earlier run describes a tenant that may have
 * moved since, and applying it would either duplicate work or fail on a conflict.
 *
 * Ordering (CONTRACT.md §27.6 rule 5's full order, restricted to what this port's
 * manifest covers): `resources` → `permissions` → `roles` → `groups` →
 * `group role bindings` → `service_accounts` → `service-account role bindings`. Both
 * binding phases run between the entity phases on either side of them — a group's
 * bindings are applied once every declared group exists (so a binding naming a
 * just-created group has an id to bind), and before any service account is created, and
 * likewise for service-account bindings after every declared service account exists.
 *
 * Returns AXIAM_OK only when every planned change (entity AND binding) landed; on a
 * partial apply it returns the failing kind AND fills `report`, which is what tells you
 * where to resume — dispose it with ::axiam_mgmt_apply_report_dispose once you are done
 * reading it, whether or not this call succeeded.
 *
 * @param c        The client. Must have an active session.
 * @param manifest The desired state.
 * @param report   Filled with what happened; may be NULL.
 * @param err      Filled on failure; may be NULL.
 */
axiam_error_kind_t axiam_mgmt_apply(axiam_client_t *c,
                                    const axiam_mgmt_manifest_t *manifest,
                                    axiam_mgmt_apply_report_t *report,
                                    axiam_error_t *err);

/**
 * Validate a manifest without contacting the server.
 *
 * Every check here can be made from the manifest alone: a duplicate key, a `depends_on`
 * naming an entity nobody declares, or a dependency cycle. Exposed separately so a
 * caller can check a manifest at start-up rather than at apply time.
 */
axiam_error_kind_t axiam_mgmt_manifest_validate(const axiam_mgmt_manifest_t *manifest,
                                                axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_MANAGEMENT_MANIFEST_H */
