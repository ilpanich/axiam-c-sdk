/*
 * CONTRACT.md §27.6/§27.7 declarative layer. See axiam/management_manifest.h for the
 * four properties that constrain everything below.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/management_manifest.h"
#include "axiam/management_ops.h"
#include "internal.h"
#include "management_internal.h"

/* Page size used when reading existing state; large enough to make one call usual. */
#define SCAN_LIMIT 200L

/* ---------------------------------------------------------------- */
/* Validation -- BEFORE any request                                 */
/* ---------------------------------------------------------------- */

static const axiam_mgmt_manifest_entity_t *find_key(const axiam_mgmt_manifest_t *m,
                                                    const char *key) {
    if (!key) return NULL;
    for (size_t i = 0; i < m->count; i++) {
        if (m->entities[i].key && strcmp(m->entities[i].key, key) == 0) return &m->entities[i];
    }
    return NULL;
}

axiam_error_kind_t axiam_mgmt_manifest_validate(const axiam_mgmt_manifest_t *manifest,
                                                axiam_error_t *err) {
    if (!manifest || (manifest->count && !manifest->entities)) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: invalid arguments");
        return AXIAM_ERR_NETWORK;
    }

    char msg[256];

    /* A duplicate key does not merge -- one silently wins, and which one is an accident
     * of ordering. Since the key is also how an entity is referenced, the loser takes
     * every reference to it along. */
    for (size_t i = 0; i < manifest->count; i++) {
        const axiam_mgmt_manifest_entity_t *a = &manifest->entities[i];
        if (!a->key || !*a->key) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: every entity needs a key");
            return AXIAM_ERR_NETWORK;
        }
        for (size_t j = i + 1; j < manifest->count; j++) {
            const axiam_mgmt_manifest_entity_t *b = &manifest->entities[j];
            if (a->kind == b->kind && b->key && strcmp(a->key, b->key) == 0) {
                snprintf(msg, sizeof msg,
                         "manifest declares \"%s\" twice -- a key must be unique within "
                         "its kind", a->key);
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                return AXIAM_ERR_NETWORK;
            }
        }
    }

    /* A dangling reference is invisible until apply reaches the entity that needs it, by
     * which point the objects before it are already created. */
    for (size_t i = 0; i < manifest->count; i++) {
        const char *dep = manifest->entities[i].depends_on;
        if (dep && !find_key(manifest, dep)) {
            snprintf(msg, sizeof msg,
                     "\"%s\" depends on \"%s\", which this manifest does not declare",
                     manifest->entities[i].key, dep);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
            return AXIAM_ERR_NETWORK;
        }
    }

    /* Resources are the realistic source of a cycle: parent_id makes them a tree, and a
     * manifest can describe a shape that is not one. No ordering satisfies a cycle, so
     * the only correct response is to refuse. Walk each chain; a chain longer than the
     * manifest must have revisited something. */
    for (size_t i = 0; i < manifest->count; i++) {
        const axiam_mgmt_manifest_entity_t *e = &manifest->entities[i];
        size_t steps = 0;
        while (e && e->depends_on) {
            if (++steps > manifest->count) {
                snprintf(msg, sizeof msg,
                         "manifest has a dependency cycle reachable from \"%s\"",
                         manifest->entities[i].key);
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                return AXIAM_ERR_NETWORK;
            }
            e = find_key(manifest, e->depends_on);
        }
    }

    /* §27.6.1 role bindings: every check here needs no server state, so all of it runs
     * before the first request, exactly like the checks above. */
    for (size_t i = 0; i < manifest->count; i++) {
        const axiam_mgmt_manifest_entity_t *subj = &manifest->entities[i];
        if (subj->kind != AXIAM_MGMT_MANIFEST_GROUP &&
            subj->kind != AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT)
            continue;

        for (size_t b = 0; b < subj->roles_count; b++) {
            const axiam_mgmt_role_binding_t *rb = &subj->roles[b];
            const axiam_mgmt_manifest_entity_t *role = find_key(manifest, rb->role_key);
            if (!role || role->kind != AXIAM_MGMT_MANIFEST_ROLE) {
                snprintf(msg, sizeof msg,
                         "\"%s\" binds role \"%s\", which this manifest does not declare "
                         "as a role", subj->key, rb->role_key ? rb->role_key : "(null)");
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                return AXIAM_ERR_NETWORK;
            }
            if (rb->resource_key) {
                const axiam_mgmt_manifest_entity_t *res = find_key(manifest, rb->resource_key);
                if (!res || res->kind != AXIAM_MGMT_MANIFEST_RESOURCE) {
                    snprintf(msg, sizeof msg,
                             "\"%s\" binds role \"%s\" to resource \"%s\", which this "
                             "manifest does not declare as a resource",
                             subj->key, rb->role_key, rb->resource_key);
                    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                    return AXIAM_ERR_NETWORK;
                }
            }

            /* A subject holds a role AT MOST ONCE (server: has_role UNIQUE(in, out), a
             * repeat is 409). A manifest binding one role to one subject twice -- plain
             * and scoped, or twice scoped -- describes a state the server cannot hold. */
            for (size_t b2 = b + 1; b2 < subj->roles_count; b2++) {
                if (subj->roles[b2].role_key && rb->role_key &&
                    strcmp(subj->roles[b2].role_key, rb->role_key) == 0) {
                    snprintf(msg, sizeof msg,
                             "\"%s\" binds role \"%s\" twice -- a subject holds a role at "
                             "most once (CONTRACT.md \xc2\xa7""27.6.1)", subj->key, rb->role_key);
                    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                    return AXIAM_ERR_NETWORK;
                }
            }

            /* §27.13 S-10 rule 2's two 400s, pre-empted client-side because both need no
             * server state: inherit:false with no resource_id, and inherit:false on a
             * global role -- checkable because the role is (now confirmed) in this
             * manifest. */
            if (rb->inherit_false && !rb->resource_key) {
                snprintf(msg, sizeof msg,
                         "\"%s\" binds role \"%s\" with inherit:false and no resource -- "
                         "there is no resource to stop at", subj->key, rb->role_key);
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                return AXIAM_ERR_NETWORK;
            }
            if (rb->inherit_false && role->is_global) {
                snprintf(msg, sizeof msg,
                         "\"%s\" binds global role \"%s\" with inherit:false -- a global "
                         "role applies everywhere by definition", subj->key, rb->role_key);
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                return AXIAM_ERR_NETWORK;
            }
        }
    }

    axiam_error_reset(err);
    return AXIAM_OK;
}

/* ---------------------------------------------------------------- */
/* Derived ordering                                                 */
/* ---------------------------------------------------------------- */

/* Depth of an entity's dependency chain -- a parent sorts before its child. */
static int depth_of(const axiam_mgmt_manifest_t *m, const axiam_mgmt_manifest_entity_t *e) {
    int depth = 0;
    size_t guard = 0;
    while (e && e->depends_on && guard++ <= m->count) {
        const axiam_mgmt_manifest_entity_t *parent = find_key(m, e->depends_on);
        if (!parent || parent->kind != e->kind) break;
        depth++;
        e = parent;
    }
    return depth;
}

/*
 * Order: by kind, then by dependency depth, then by KEY.
 *
 * The final tie-break on key is what makes a plan STABLE ACROSS RUNS (§27.6). Two
 * entities of the same kind with no dependency between them have no natural order, and
 * without a deterministic tie-break they would come out in whatever order the caller
 * happened to declare them -- making every plan diff unreadable.
 */
static void order_entities(const axiam_mgmt_manifest_t *m, const axiam_mgmt_manifest_entity_t **out) {
    for (size_t i = 0; i < m->count; i++) out[i] = &m->entities[i];

    for (size_t i = 1; i < m->count; i++) {
        const axiam_mgmt_manifest_entity_t *key = out[i];
        int key_depth = depth_of(m, key);
        size_t j = i;
        while (j > 0) {
            const axiam_mgmt_manifest_entity_t *prev = out[j - 1];
            int prev_depth = depth_of(m, prev);
            int after = (prev->kind > key->kind)
                        || (prev->kind == key->kind && prev_depth > key_depth)
                        || (prev->kind == key->kind && prev_depth == key_depth
                            && strcmp(prev->key, key->key) > 0);
            if (!after) break;
            out[j] = out[j - 1];
            j--;
        }
        out[j] = key;
    }
}

/* ---------------------------------------------------------------- */
/* Reading current state                                            */
/* ---------------------------------------------------------------- */

/* One existing object: the name the manifest matches on, and the id an update needs.
 * `metadata` is populated for a RESOURCE row only (its wire `metadata`, raw JSON text);
 * NULL for every other kind. */
typedef struct {
    char *name;
    char *id;
    char *description;
    char *metadata;
} existing_t;

typedef struct {
    existing_t *rows;
    size_t count;
} existing_set_t;

static void existing_free(existing_set_t *set) {
    if (!set) return;
    for (size_t i = 0; i < set->count; i++) {
        free(set->rows[i].name);
        free(set->rows[i].id);
        free(set->rows[i].description);
        free(set->rows[i].metadata);
    }
    free(set->rows);
    set->rows = NULL;
    set->count = 0;
}

static const existing_t *existing_find(const existing_set_t *set, const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < set->count; i++) {
        if (set->rows[i].name && strcmp(set->rows[i].name, name) == 0) return &set->rows[i];
    }
    return NULL;
}

/* As existing_find(), but also reports whether MORE THAN ONE row matches --
 * CONTRACT.md §27.6.1 item 3: a service account's only unique index is `client_id`, so
 * a tenant can hold two accounts with one name, and plan() MUST fail before any write
 * rather than pick one. */
static const existing_t *existing_find_checked(const existing_set_t *set, const char *name,
                                               int *out_ambiguous) {
    const existing_t *found = NULL;
    size_t matches = 0;
    if (name) {
        for (size_t i = 0; i < set->count; i++) {
            if (set->rows[i].name && strcmp(set->rows[i].name, name) == 0) {
                if (!found) found = &set->rows[i];
                matches++;
            }
        }
    }
    if (out_ambiguous) *out_ambiguous = matches > 1;
    return found;
}

static int existing_push(existing_set_t *set, const char *name, const char *id,
                         const char *description, const char *metadata) {
    existing_t *grown = (existing_t *) realloc(set->rows, (set->count + 1) * sizeof(existing_t));
    if (!grown) return -1;
    set->rows = grown;
    set->rows[set->count].name = axiam_strdup0(name);
    set->rows[set->count].id = axiam_strdup0(id);
    set->rows[set->count].description = axiam_strdup0(description);
    set->rows[set->count].metadata = axiam_strdup0(metadata);
    set->count++;
    return 0;
}

/* Read the tenant's current state for one kind. Only the kinds a manifest mentions are
 * scanned: a manifest declaring two permissions has no business listing every group in
 * the tenant, and on a large tenant that is one request instead of dozens. */
static axiam_error_kind_t read_existing(axiam_client_t *c, axiam_mgmt_manifest_kind_t kind,
                                        existing_set_t *out, axiam_error_t *err) {
    axiam_mgmt_page_req_t page = { 0, SCAN_LIMIT };
    axiam_error_kind_t rc = AXIAM_OK;

    memset(out, 0, sizeof *out);

    if (kind == AXIAM_MGMT_MANIFEST_RESOURCE) {
        axiam_mgmt_resource_page_t *p = NULL;
        rc = axiam_resources_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id, NULL,
                                  p->items[i]->metadata);
        }
        axiam_mgmt_resource_page_free(p);
    } else if (kind == AXIAM_MGMT_MANIFEST_PERMISSION) {
        axiam_mgmt_permission_page_t *p = NULL;
        rc = axiam_permissions_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->action, p->items[i]->id,
                                  p->items[i]->description, NULL);
        }
        axiam_mgmt_permission_page_free(p);
    } else if (kind == AXIAM_MGMT_MANIFEST_ROLE) {
        axiam_mgmt_role_page_t *p = NULL;
        rc = axiam_roles_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id,
                                  p->items[i]->description, NULL);
        }
        axiam_mgmt_role_page_free(p);
    } else if (kind == AXIAM_MGMT_MANIFEST_GROUP) {
        axiam_mgmt_group_page_t *p = NULL;
        rc = axiam_groups_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id,
                                  p->items[i]->description, NULL);
        }
        axiam_mgmt_group_page_free(p);
    } else {
        /* AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT (contract 1.51, §27.6.1). `name` is NOT
         * unique server-side (only `client_id` is indexed), so this set can legitimately
         * hold more than one row with the same name -- existing_find_checked() is what
         * plan() uses to detect that rather than existing_find(), which would silently
         * pick the first. */
        axiam_mgmt_service_account_response_page_t *p = NULL;
        rc = axiam_service_accounts_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id,
                                  p->items[i]->description, NULL);
        }
        axiam_mgmt_service_account_response_page_free(p);
    }

    if (rc != AXIAM_OK) existing_free(out);
    return rc;
}

/* The name a declaration is matched against: a permission is known by its action, and
 * everything else by its name. */
static const char *match_name(const axiam_mgmt_manifest_entity_t *e) {
    return e->kind == AXIAM_MGMT_MANIFEST_PERMISSION ? e->action : e->name;
}

/* ---------------------------------------------------------------- */
/* Plan                                                             */
/* ---------------------------------------------------------------- */

void axiam_mgmt_plan_free(axiam_mgmt_plan_t *plan) {
    if (!plan) return;
    for (size_t i = 0; i < plan->count; i++) free(plan->changes[i].id);
    free(plan->changes);
    for (size_t i = 0; i < plan->binding_count; i++) {
        free(plan->bindings[i].old_resource_id);
        if (plan->bindings[i].old_tenant_scope) {
            for (size_t t = 0; t < plan->bindings[i].old_tenant_scope_count; t++)
                free(plan->bindings[i].old_tenant_scope[t]);
            free(plan->bindings[i].old_tenant_scope);
        }
    }
    free(plan->bindings);
    free(plan);
}

void axiam_mgmt_apply_report_dispose(axiam_mgmt_apply_report_t *report) {
    if (!report) return;
    for (size_t i = 0; i < report->created_secrets_count; i++) {
        free(report->created_secrets[i].key);
        axiam_sensitive_free(report->created_secrets[i].client_secret);
    }
    free(report->created_secrets);
    report->created_secrets = NULL;
    report->created_secrets_count = 0;
}

/* Manifest-local key -> resolved server id, read from an in-progress plan/apply.
 * Returns NULL when the entity was not found (a validation bug, since every reference
 * is checked before plan() runs) OR when it is about to be CREATED and has no id yet. */
static const char *resolved_id_for_key(const axiam_mgmt_plan_t *plan, const char *key) {
    if (!key) return NULL;
    for (size_t i = 0; i < plan->count; i++) {
        if (plan->changes[i].entity->key && strcmp(plan->changes[i].entity->key, key) == 0)
            return plan->changes[i].id;
    }
    return NULL;
}

static axiam_error_kind_t read_subject_bindings(axiam_client_t *c,
                                                axiam_mgmt_manifest_kind_t kind,
                                                const char *subject_id,
                                                axiam_mgmt_role_assignment_list_t **out,
                                                axiam_error_t *err) {
    if (kind == AXIAM_MGMT_MANIFEST_GROUP) return axiam_groups_list_roles(c, subject_id, out, err);
    return axiam_service_accounts_list_roles(c, subject_id, out, err);
}

static const axiam_mgmt_role_assignment_t *find_binding_by_role_name(
        const axiam_mgmt_role_assignment_list_t *list, const char *role_name) {
    if (!list || !role_name) return NULL;
    for (size_t i = 0; i < list->count; i++) {
        const axiam_mgmt_role_assignment_t *a = list->items[i];
        if (a && a->role && a->role->name && strcmp(a->role->name, role_name) == 0) return a;
    }
    return NULL;
}

/* JSON value equality of a resource's metadata (§27.6.1 item 1): `declared == NULL`
 * means the manifest is silent about it, which is never drift (rule 3). Anything that
 * fails to parse on either side is treated as drift rather than silently skipped --
 * fail toward reporting a change, not toward missing one. */
static int metadata_differs(const char *declared, const char *server) {
    if (!declared) return 0;
    cJSON *a = cJSON_Parse(declared);
    cJSON *b = server ? cJSON_Parse(server) : NULL;
    int eq = a && b && cJSON_Compare(a, b, 1);
    cJSON_Delete(a);
    cJSON_Delete(b);
    return !eq;
}

axiam_error_kind_t axiam_mgmt_plan(axiam_client_t *c, const axiam_mgmt_manifest_t *manifest,
                                   axiam_mgmt_plan_t **out, axiam_error_t *err) {
    if (out) *out = NULL;

    axiam_error_kind_t rc = axiam_mgmt_manifest_validate(manifest, err);
    if (rc != AXIAM_OK) return rc;

    const axiam_mgmt_manifest_entity_t **ordered =
        (const axiam_mgmt_manifest_entity_t **) calloc(manifest->count ? manifest->count : 1,
                                                       sizeof(*ordered));
    if (!ordered) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: out of memory");
        return AXIAM_ERR_NETWORK;
    }
    order_entities(manifest, ordered);

    axiam_mgmt_plan_t *plan = (axiam_mgmt_plan_t *) calloc(1, sizeof(*plan));
    if (!plan) { free(ordered); axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: out of memory"); return AXIAM_ERR_NETWORK; }
    plan->changes = (axiam_mgmt_planned_change_t *) calloc(manifest->count ? manifest->count : 1,
                                                           sizeof(*plan->changes));
    if (!plan->changes) { free(plan); free(ordered); axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: out of memory"); return AXIAM_ERR_NETWORK; }

    /* Cache one read per KIND, not one per entity: ten roles is one list call. Five
     * kinds since contract 1.51's AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT. */
    #define AXIAM_MGMT_MANIFEST_KIND_COUNT 5
    existing_set_t cache[AXIAM_MGMT_MANIFEST_KIND_COUNT];
    int loaded[AXIAM_MGMT_MANIFEST_KIND_COUNT] = { 0 };
    memset(cache, 0, sizeof cache);

    for (size_t i = 0; i < manifest->count; i++) {
        const axiam_mgmt_manifest_entity_t *e = ordered[i];
        if (!loaded[e->kind]) {
            rc = read_existing(c, e->kind, &cache[e->kind], err);
            if (rc != AXIAM_OK) {
                for (int k = 0; k < AXIAM_MGMT_MANIFEST_KIND_COUNT; k++)
                    if (loaded[k]) existing_free(&cache[k]);
                axiam_mgmt_plan_free(plan);
                free(ordered);
                return rc;
            }
            loaded[e->kind] = 1;
        }

        const existing_t *found;
        if (e->kind == AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT) {
            int ambiguous = 0;
            found = existing_find_checked(&cache[e->kind], match_name(e), &ambiguous);
            if (ambiguous) {
                char msg[256];
                snprintf(msg, sizeof msg,
                         "\"%s\": more than one existing service account is named \"%s\" "
                         "-- name is not unique server-side (CONTRACT.md \xc2\xa7""27.6.1 "
                         "item 3); plan cannot pick one", e->key, match_name(e));
                axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
                for (int k = 0; k < AXIAM_MGMT_MANIFEST_KIND_COUNT; k++)
                    if (loaded[k]) existing_free(&cache[k]);
                axiam_mgmt_plan_free(plan);
                free(ordered);
                return AXIAM_ERR_NETWORK;
            }
        } else {
            found = existing_find(&cache[e->kind], match_name(e));
        }

        plan->changes[i].entity = e;
        if (!found) {
            plan->changes[i].action = AXIAM_MGMT_CHANGE_CREATE;
            plan->pending++;
        } else {
            /* Compare ONLY what the manifest names. A server object carries plenty a
             * manifest says nothing about, and treating that as drift would make every
             * plan report a change and every apply overwrite work nobody claimed.
             * §27.6.1 item 1: a resource's metadata drifts on JSON VALUE equality of
             * the whole object, never a key-by-key merge. */
            int drifted = (e->description && (!found->description
                                              || strcmp(e->description, found->description) != 0))
                        || (e->kind == AXIAM_MGMT_MANIFEST_RESOURCE
                            && metadata_differs(e->metadata_json, found->metadata));
            plan->changes[i].action = drifted ? AXIAM_MGMT_CHANGE_UPDATE
                                              : AXIAM_MGMT_CHANGE_UNCHANGED;
            plan->changes[i].id = axiam_strdup0(found->id);
            if (drifted) plan->pending++;
        }
        plan->count++;
    }

    /*
     * §27.6.1 role bindings, planned in TWO passes (groups, then service accounts) so
     * plan->bindings[] comes out grouped by subject kind -- axiam_mgmt_apply() finds the
     * group/service-account split with one linear scan rather than needing bindings
     * sorted some other way. Each binding needs the SUBJECT's id, which a just-planned
     * CREATE does not have yet (resolved_id_for_key() returns NULL for one): such a
     * subject has no existing bindings to diff against either, so every one of its
     * declared bindings is simply a CREATE.
     */
    size_t binding_total = 0;
    for (size_t i = 0; i < manifest->count; i++) binding_total += manifest->entities[i].roles_count;

    if (binding_total > 0) {
        plan->bindings = (axiam_mgmt_planned_binding_t *)
                calloc(binding_total, sizeof(*plan->bindings));
        if (!plan->bindings) {
            for (int k = 0; k < AXIAM_MGMT_MANIFEST_KIND_COUNT; k++)
                if (loaded[k]) existing_free(&cache[k]);
            free(ordered);
            axiam_mgmt_plan_free(plan);
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: out of memory");
            return AXIAM_ERR_NETWORK;
        }

        const axiam_mgmt_manifest_kind_t subject_kinds[2] = {
            AXIAM_MGMT_MANIFEST_GROUP, AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT
        };
        for (int sk = 0; sk < 2; sk++) {
            for (size_t i = 0; i < manifest->count; i++) {
                const axiam_mgmt_manifest_entity_t *subj = &manifest->entities[i];
                if (subj->kind != subject_kinds[sk] || subj->roles_count == 0) continue;

                const char *subject_id = resolved_id_for_key(plan, subj->key);
                axiam_mgmt_role_assignment_list_t *existing_bindings = NULL;
                if (subject_id) {
                    rc = read_subject_bindings(c, subj->kind, subject_id, &existing_bindings, err);
                    if (rc != AXIAM_OK) {
                        for (int k = 0; k < AXIAM_MGMT_MANIFEST_KIND_COUNT; k++)
                            if (loaded[k]) existing_free(&cache[k]);
                        free(ordered);
                        axiam_mgmt_plan_free(plan);
                        return rc;
                    }
                }

                for (size_t b = 0; b < subj->roles_count; b++) {
                    const axiam_mgmt_role_binding_t *rb = &subj->roles[b];
                    const axiam_mgmt_manifest_entity_t *role_entity = find_key(manifest, rb->role_key);
                    const char *resolved_resource_id =
                            rb->resource_key ? resolved_id_for_key(plan, rb->resource_key) : NULL;

                    axiam_mgmt_planned_binding_t *pb = &plan->bindings[plan->binding_count];
                    pb->subject = subj;
                    pb->binding = rb;

                    const axiam_mgmt_role_assignment_t *existing =
                            role_entity ? find_binding_by_role_name(existing_bindings, role_entity->name)
                                        : NULL;

                    if (!existing) {
                        pb->action = AXIAM_MGMT_BINDING_CREATE;
                        plan->binding_pending++;
                    } else {
                        int existing_has_resource = existing->resource_id && existing->resource_id[0];
                        int declared_has_resource = rb->resource_key != NULL;
                        int declared_inherit = !rb->inherit_false;
                        int existing_inherit = existing->inherit;
                        int resource_matches = 0;
                        if (!existing_has_resource && !declared_has_resource) {
                            resource_matches = 1;
                        } else if (existing_has_resource && declared_has_resource &&
                                  resolved_resource_id &&
                                  strcmp(existing->resource_id, resolved_resource_id) == 0) {
                            resource_matches = 1;
                        }
                        /* Note: a PLAIN declared binding (no resource_key) over an
                         * EXISTING resource-scoped assignment falls through to
                         * resource_matches == 0 above (existing_has_resource=1,
                         * declared_has_resource=0) -- an UPDATE, per C-1's EXECUTED
                         * item 5: "a plain binding over a resource-scoped server
                         * assignment is now an Update." */
                        if (resource_matches && existing_inherit == declared_inherit) {
                            pb->action = AXIAM_MGMT_BINDING_NOCHANGE;
                        } else {
                            pb->action = AXIAM_MGMT_BINDING_UPDATE;
                            plan->binding_pending++;
                            if (existing_has_resource)
                                pb->old_resource_id = axiam_strdup0(existing->resource_id);
                            pb->old_inherit = existing_inherit;
                            if (existing->tenant_scope_count > 0) {
                                pb->old_tenant_scope = (char **)
                                        calloc(existing->tenant_scope_count, sizeof(char *));
                                if (pb->old_tenant_scope) {
                                    for (size_t t = 0; t < existing->tenant_scope_count; t++)
                                        pb->old_tenant_scope[t] =
                                                axiam_strdup0(existing->tenant_scope[t]);
                                    pb->old_tenant_scope_count = existing->tenant_scope_count;
                                }
                            }
                        }
                    }
                    plan->binding_count++;
                }
                axiam_mgmt_role_assignment_list_free(existing_bindings);
            }
        }
    }

    for (int k = 0; k < AXIAM_MGMT_MANIFEST_KIND_COUNT; k++)
        if (loaded[k]) existing_free(&cache[k]);
    free(ordered);
    #undef AXIAM_MGMT_MANIFEST_KIND_COUNT

    if (out) *out = plan;
    else axiam_mgmt_plan_free(plan);
    return AXIAM_OK;
}

/* ---------------------------------------------------------------- */
/* Apply                                                            */
/* ---------------------------------------------------------------- */

/*
 * Perform one entity change. Writes the entity's id back into `ch->id` on a
 * successful CREATE (it arrives with none) so a binding planned/applied against a
 * subject or resource created in THIS SAME apply can resolve it.
 *
 * `out_secret` is non-NULL only when the caller is prepared to receive a
 * service-account Create's one-time client_secret (CONTRACT.md §27.5 rule 5); every
 * other path leaves `*out_secret` untouched (NULL, from the caller's own init).
 */
static axiam_error_kind_t perform(axiam_client_t *c, axiam_mgmt_planned_change_t *ch,
                                  axiam_sensitive_t **out_secret, axiam_error_t *err) {
    const axiam_mgmt_manifest_entity_t *e = ch->entity;
    int create = ch->action == AXIAM_MGMT_CHANGE_CREATE;

    if (e->kind == AXIAM_MGMT_MANIFEST_RESOURCE) {
        if (create) {
            axiam_mgmt_create_resource_request_t body;
            memset(&body, 0, sizeof body);
            body.name = (char *) e->name;
            body.resource_type = (char *) (e->resource_type ? e->resource_type : "folder");
            body.metadata = (char *) e->metadata_json;
            axiam_mgmt_resource_t *out = NULL;
            axiam_error_kind_t rc = axiam_resources_create(c, &body, &out, err);
            if (rc == AXIAM_OK && out) ch->id = axiam_strdup0(out->id);
            axiam_mgmt_resource_free(out);
            return rc;
        }
        axiam_mgmt_update_resource_request_t body;
        memset(&body, 0, sizeof body);
        body.name = (char *) e->name;
        body.metadata = (char *) e->metadata_json;
        axiam_mgmt_resource_t *out = NULL;
        axiam_error_kind_t rc = axiam_resources_update(c, ch->id, &body, &out, err);
        axiam_mgmt_resource_free(out);
        return rc;
    }

    if (e->kind == AXIAM_MGMT_MANIFEST_PERMISSION) {
        if (create) {
            axiam_mgmt_create_permission_request_t body;
            memset(&body, 0, sizeof body);
            body.action = (char *) e->action;
            body.description = (char *) (e->description ? e->description : "");
            axiam_mgmt_permission_t *out = NULL;
            axiam_error_kind_t rc = axiam_permissions_create(c, &body, &out, err);
            if (rc == AXIAM_OK && out) ch->id = axiam_strdup0(out->id);
            axiam_mgmt_permission_free(out);
            return rc;
        }
        axiam_mgmt_update_permission_request_t body;
        memset(&body, 0, sizeof body);
        body.description = (char *) e->description;
        axiam_mgmt_permission_t *out = NULL;
        axiam_error_kind_t rc = axiam_permissions_update(c, ch->id, &body, &out, err);
        axiam_mgmt_permission_free(out);
        return rc;
    }

    if (e->kind == AXIAM_MGMT_MANIFEST_ROLE) {
        if (create) {
            axiam_mgmt_create_role_request_t body;
            memset(&body, 0, sizeof body);
            body.name = (char *) e->name;
            body.description = (char *) (e->description ? e->description : "");
            body.is_global = e->is_global;
            axiam_mgmt_role_t *out = NULL;
            axiam_error_kind_t rc = axiam_roles_create(c, &body, &out, err);
            if (rc == AXIAM_OK && out) ch->id = axiam_strdup0(out->id);
            axiam_mgmt_role_free(out);
            return rc;
        }
        axiam_mgmt_update_role_t body;
        memset(&body, 0, sizeof body);
        body.description = (char *) e->description;
        axiam_mgmt_role_t *out = NULL;
        axiam_error_kind_t rc = axiam_roles_update(c, ch->id, &body, &out, err);
        axiam_mgmt_role_free(out);
        return rc;
    }

    if (e->kind == AXIAM_MGMT_MANIFEST_GROUP) {
        if (create) {
            axiam_mgmt_create_group_request_t body;
            memset(&body, 0, sizeof body);
            body.name = (char *) e->name;
            body.description = (char *) (e->description ? e->description : "");
            axiam_mgmt_group_t *out = NULL;
            axiam_error_kind_t rc = axiam_groups_create(c, &body, &out, err);
            if (rc == AXIAM_OK && out) ch->id = axiam_strdup0(out->id);
            axiam_mgmt_group_free(out);
            return rc;
        }
        axiam_mgmt_update_group_t body;
        memset(&body, 0, sizeof body);
        body.description = (char *) e->description;
        axiam_mgmt_group_t *out = NULL;
        axiam_error_kind_t rc = axiam_groups_update(c, ch->id, &body, &out, err);
        axiam_mgmt_group_free(out);
        return rc;
    }

    /* AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT (contract 1.51, §27.6.1 item 3). `status` is
     * not a manifest field in 1.51; `description` is the only field UPDATE reconciles. */
    if (create) {
        axiam_mgmt_create_service_account_request_t body;
        memset(&body, 0, sizeof body);
        body.name = (char *) e->name;
        body.description = (char *) (e->description ? e->description : "");
        axiam_mgmt_service_account_created_response_t *out = NULL;
        axiam_error_kind_t rc = axiam_service_accounts_create(c, &body, &out, err);
        if (rc == AXIAM_OK && out) {
            ch->id = axiam_strdup0(out->id);
            /* §27.5 rule 5: the outcome carries the one-time secret, Sensitive<T>,
             * exactly as the imperative `create` returns it. Handed to the caller
             * (never rotated to reconcile, never dropped) -- ownership transfers: the
             * response struct's OWN copy is freed below without touching this one. */
            if (out_secret && out->client_secret) {
                *out_secret = axiam_sensitive_new(axiam_sensitive_reveal(out->client_secret));
            }
        }
        axiam_mgmt_service_account_created_response_free(out);
        return rc;
    }
    axiam_mgmt_update_service_account_t body;
    memset(&body, 0, sizeof body);
    body.description = (char *) e->description;
    axiam_mgmt_service_account_response_t *out = NULL;
    axiam_error_kind_t rc = axiam_service_accounts_update(c, ch->id, &body, &out, err);
    axiam_mgmt_service_account_response_free(out);
    return rc;
}

/*
 * Perform one role-binding change. Resolves subject/role/resource ids from the plan's
 * OWN entity changes (post their own perform(), so a subject/role/resource created
 * earlier in this same apply has an id by now).
 *
 * For an UPDATE (rebind): unassign the OLD binding first (there is no update
 * endpoint), then assign the new one, carrying `tenant_scope` across unchanged
 * (§27.6.1: dropping it would silently widen an organization-level account). If the
 * ASSIGN half fails, attempt to reassign the PREVIOUS binding (same resource, same
 * inherit, same tenant_scope) and record whether that restore itself succeeded --
 * CONTRACT.md §27.6.1's own words, and C-1's EXECUTED choice for what a failed rebind
 * leaves behind (BindingUpdateFailed carrying both outcomes; this port's C shape is
 * the `restore_attempted`/`restore_succeeded` pair on the report).
 */
static axiam_error_kind_t perform_binding(axiam_client_t *c, const axiam_mgmt_plan_t *plan,
                                          axiam_mgmt_planned_binding_t *pb,
                                          axiam_mgmt_apply_report_t *report,
                                          axiam_error_t *err) {
    const axiam_mgmt_manifest_entity_t *subj = pb->subject;
    const axiam_mgmt_role_binding_t *rb = pb->binding;
    int is_group = subj->kind == AXIAM_MGMT_MANIFEST_GROUP;

    const char *subject_id = resolved_id_for_key(plan, subj->key);
    const char *role_id = resolved_id_for_key(plan, rb->role_key);
    const char *resource_id = rb->resource_key ? resolved_id_for_key(plan, rb->resource_key) : NULL;
    if (!subject_id || !role_id || (rb->resource_key && !resource_id)) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "manifest: could not resolve a role binding's subject, role or "
                        "resource id (an earlier action must have failed)");
        return AXIAM_ERR_NETWORK;
    }

    if (pb->action == AXIAM_MGMT_BINDING_UPDATE) {
        axiam_error_kind_t urc = is_group
                ? axiam_roles_unassign_from_group(c, role_id, subject_id, pb->old_resource_id, err)
                : axiam_roles_unassign_from_service_account(c, role_id, subject_id,
                                                            pb->old_resource_id, err);
        if (urc != AXIAM_OK) return urc; /* the OLD binding is still intact; nothing to restore */
    }

    axiam_error_kind_t rc;
    if (is_group) {
        axiam_mgmt_assign_role_to_group_request_t body;
        memset(&body, 0, sizeof body);
        body.group_id = (char *) subject_id;
        body.resource_id = (char *) resource_id;
        if (rb->inherit_false) { body.inherit = 0; body.has_inherit = 1; }
        body.tenant_scope = pb->old_tenant_scope; /* NULL/0 unless this is an UPDATE */
        body.tenant_scope_count = pb->old_tenant_scope_count;
        rc = axiam_roles_assign_to_group(c, role_id, &body, err);
    } else {
        axiam_mgmt_assign_role_to_service_account_request_t body;
        memset(&body, 0, sizeof body);
        body.service_account_id = (char *) subject_id;
        body.resource_id = (char *) resource_id;
        if (rb->inherit_false) { body.inherit = 0; body.has_inherit = 1; }
        body.tenant_scope = pb->old_tenant_scope;
        body.tenant_scope_count = pb->old_tenant_scope_count;
        rc = axiam_roles_assign_to_service_account(c, role_id, &body, err);
    }

    if (rc != AXIAM_OK && pb->action == AXIAM_MGMT_BINDING_UPDATE) {
        if (report) report->restore_attempted = 1;
        axiam_error_t restore_err;
        axiam_error_kind_t rrc;
        if (is_group) {
            axiam_mgmt_assign_role_to_group_request_t restore;
            memset(&restore, 0, sizeof restore);
            restore.group_id = (char *) subject_id;
            restore.resource_id = pb->old_resource_id;
            if (!pb->old_inherit) { restore.inherit = 0; restore.has_inherit = 1; }
            restore.tenant_scope = pb->old_tenant_scope;
            restore.tenant_scope_count = pb->old_tenant_scope_count;
            rrc = axiam_roles_assign_to_group(c, role_id, &restore, &restore_err);
        } else {
            axiam_mgmt_assign_role_to_service_account_request_t restore;
            memset(&restore, 0, sizeof restore);
            restore.service_account_id = (char *) subject_id;
            restore.resource_id = pb->old_resource_id;
            if (!pb->old_inherit) { restore.inherit = 0; restore.has_inherit = 1; }
            restore.tenant_scope = pb->old_tenant_scope;
            restore.tenant_scope_count = pb->old_tenant_scope_count;
            rrc = axiam_roles_assign_to_service_account(c, role_id, &restore, &restore_err);
        }
        if (report) report->restore_succeeded = (rrc == AXIAM_OK) ? 1 : 0;
    }
    return rc;
}

static void report_entity_failure(axiam_mgmt_apply_report_t *report,
                                  const axiam_mgmt_plan_t *plan,
                                  size_t done, size_t failed_index) {
    if (!report) return;
    report->applied = done;
    report->failed = (long) failed_index;
    size_t left = 0;
    for (size_t j = failed_index + 1; j < plan->count; j++)
        if (plan->changes[j].action != AXIAM_MGMT_CHANGE_UNCHANGED) left++;
    report->remaining = left;
}

static void report_binding_failure(axiam_mgmt_apply_report_t *report,
                                   const axiam_mgmt_plan_t *plan,
                                   size_t done, size_t failed_index) {
    if (!report) return;
    report->bindings_applied = done;
    report->failed_binding = (long) failed_index;
    size_t left = 0;
    for (size_t j = failed_index + 1; j < plan->binding_count; j++)
        if (plan->bindings[j].action != AXIAM_MGMT_BINDING_NOCHANGE) left++;
    report->bindings_remaining = left;
}

/* Takes ownership of `secret` on success; returns 0 (leaving it to the caller to free)
 * only on allocation failure. */
static int record_created_secret(axiam_mgmt_apply_report_t *report, const char *key,
                                 axiam_sensitive_t *secret) {
    if (!report) return 0;
    axiam_mgmt_created_secret_t *grown = (axiam_mgmt_created_secret_t *) realloc(
            report->created_secrets, (report->created_secrets_count + 1) * sizeof(*grown));
    if (!grown) return 0;
    report->created_secrets = grown;
    report->created_secrets[report->created_secrets_count].key = axiam_strdup0(key);
    report->created_secrets[report->created_secrets_count].client_secret = secret;
    report->created_secrets_count++;
    return 1;
}

/*
 * §27.6 rule 5's order, restricted to what this port's manifest covers: resources,
 * permissions, roles, groups, GROUP BINDINGS, service accounts, SERVICE-ACCOUNT
 * BINDINGS. plan->changes[] is already sorted by kind (order_entities()), and
 * plan->bindings[] is already grouped group-then-service-account (axiam_mgmt_plan()'s
 * two-pass binding loop) -- so each phase boundary is one linear scan for the first
 * index of the next kind, and this function just walks the four phases in order,
 * stopping at the first failure exactly as §27.7 requires.
 */
axiam_error_kind_t axiam_mgmt_apply(axiam_client_t *c, const axiam_mgmt_manifest_t *manifest,
                                    axiam_mgmt_apply_report_t *report, axiam_error_t *err) {
    if (report) {
        memset(report, 0, sizeof(*report));
        report->failed = -1;
        report->failed_binding = -1;
    }

    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, manifest, &plan, err);
    if (rc != AXIAM_OK) return rc;

    size_t sa_entity_start = plan->count;
    for (size_t i = 0; i < plan->count; i++) {
        if (plan->changes[i].entity->kind == AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT) {
            sa_entity_start = i;
            break;
        }
    }
    size_t sa_binding_start = plan->binding_count;
    for (size_t i = 0; i < plan->binding_count; i++) {
        if (plan->bindings[i].subject->kind == AXIAM_MGMT_MANIFEST_SERVICE_ACCOUNT) {
            sa_binding_start = i;
            break;
        }
    }

    size_t done_entities = 0;
    size_t done_bindings = 0;

    /* Phase 1: resources, permissions, roles, groups. */
    for (size_t i = 0; i < sa_entity_start; i++) {
        if (plan->changes[i].action == AXIAM_MGMT_CHANGE_UNCHANGED) continue;
        rc = perform(c, &plan->changes[i], NULL, err);
        if (rc != AXIAM_OK) {
            /* §27.7: stop here, do not undo what landed. A partial apply against a live
             * IAM tenant is a state an operator inspects and resumes from; an automatic
             * rollback would issue a second wave of writes at exactly the moment the
             * server is already saying something is wrong. */
            report_entity_failure(report, plan, done_entities, i);
            axiam_mgmt_plan_free(plan);
            return rc;
        }
        done_entities++;
    }

    /* Phase 2: group role bindings -- every declared group now exists. */
    for (size_t i = 0; i < sa_binding_start; i++) {
        if (plan->bindings[i].action == AXIAM_MGMT_BINDING_NOCHANGE) continue;
        rc = perform_binding(c, plan, &plan->bindings[i], report, err);
        if (rc != AXIAM_OK) {
            report_binding_failure(report, plan, done_bindings, i);
            if (report) report->applied = done_entities;
            axiam_mgmt_plan_free(plan);
            return rc;
        }
        done_bindings++;
    }

    /* Phase 3: service accounts. */
    for (size_t i = sa_entity_start; i < plan->count; i++) {
        if (plan->changes[i].action == AXIAM_MGMT_CHANGE_UNCHANGED) continue;
        axiam_sensitive_t *secret = NULL;
        rc = perform(c, &plan->changes[i], &secret, err);
        if (secret) {
            /* §27.5 rule 5: recorded even when a LATER action of this same apply
             * fails -- this happens BEFORE the failure check below, not after. */
            if (!record_created_secret(report, plan->changes[i].entity->key, secret))
                axiam_sensitive_free(secret); /* OOM recording it; the secret itself is lost */
        }
        if (rc != AXIAM_OK) {
            report_entity_failure(report, plan, done_entities, i);
            if (report) report->bindings_applied = done_bindings;
            axiam_mgmt_plan_free(plan);
            return rc;
        }
        done_entities++;
    }

    /* Phase 4: service-account role bindings. */
    for (size_t i = sa_binding_start; i < plan->binding_count; i++) {
        if (plan->bindings[i].action == AXIAM_MGMT_BINDING_NOCHANGE) continue;
        rc = perform_binding(c, plan, &plan->bindings[i], report, err);
        if (rc != AXIAM_OK) {
            report_binding_failure(report, plan, done_bindings, i);
            if (report) report->applied = done_entities;
            axiam_mgmt_plan_free(plan);
            return rc;
        }
        done_bindings++;
    }

    if (report) {
        report->applied = done_entities;
        report->bindings_applied = done_bindings;
    }
    axiam_mgmt_plan_free(plan);
    axiam_error_reset(err);
    return AXIAM_OK;
}
