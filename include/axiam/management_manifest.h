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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The entity kinds a manifest can declare.
 *
 * The order of these constants IS the order an apply runs them in — the dependency order
 * §27.6 requires be derived rather than written down by the caller. A role cannot be
 * granted a permission that does not exist yet, and a group cannot be assigned a role
 * that does not exist yet.
 */
typedef enum axiam_mgmt_manifest_kind {
    AXIAM_MGMT_MANIFEST_RESOURCE = 0, /**< Hierarchical resource; parents before children. */
    AXIAM_MGMT_MANIFEST_PERMISSION,   /**< A permission (an action). Depends on nothing. */
    AXIAM_MGMT_MANIFEST_ROLE,         /**< A role. Depends on permissions. */
    AXIAM_MGMT_MANIFEST_GROUP         /**< A group. Depends on roles. */
} axiam_mgmt_manifest_kind_t;

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
 * What ::axiam_mgmt_plan produced: the ordered changes an apply would make.
 *
 * Includes the UNCHANGED entries as well, so a reader sees what was considered and not
 * only what moved.
 */
typedef struct axiam_mgmt_plan {
    axiam_mgmt_planned_change_t *changes; /**< Every declared entity, in apply order. */
    size_t count;                         /**< How many. */
    size_t pending;                        /**< How many would actually send a request. */
} axiam_mgmt_plan_t;

/** Free a plan and everything it owns. Safe to pass NULL. */
void axiam_mgmt_plan_free(axiam_mgmt_plan_t *plan);

/**
 * What ::axiam_mgmt_apply actually did — including, when it stopped early, what it had
 * already done.
 *
 * This is the recovery tool. `applied` is how many changes landed, in order; `failed` is
 * the index of the one that did not (or -1); `remaining` is how many were never
 * attempted.
 */
typedef struct axiam_mgmt_apply_report {
    size_t applied;   /**< How many changes landed. */
    long failed;      /**< Index of the failing change, or -1 when none failed. */
    size_t remaining; /**< How many were never attempted because of the failure. */
} axiam_mgmt_apply_report_t;

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
 * Returns AXIAM_OK only when every planned change landed; on a partial apply it returns
 * the failing kind AND fills `report`, which is what tells you where to resume.
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
