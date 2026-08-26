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

/* One existing object: the name the manifest matches on, and the id an update needs. */
typedef struct {
    char *name;
    char *id;
    char *description;
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

static int existing_push(existing_set_t *set, const char *name, const char *id,
                         const char *description) {
    existing_t *grown = (existing_t *) realloc(set->rows, (set->count + 1) * sizeof(existing_t));
    if (!grown) return -1;
    set->rows = grown;
    set->rows[set->count].name = axiam_strdup0(name);
    set->rows[set->count].id = axiam_strdup0(id);
    set->rows[set->count].description = axiam_strdup0(description);
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
        rc = axiam_mgmt_resources_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i]) existing_push(out, p->items[i]->name, p->items[i]->id, NULL);
        }
        axiam_mgmt_resource_page_free(p);
    } else if (kind == AXIAM_MGMT_MANIFEST_PERMISSION) {
        axiam_mgmt_permission_page_t *p = NULL;
        rc = axiam_mgmt_permissions_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->action, p->items[i]->id,
                                  p->items[i]->description);
        }
        axiam_mgmt_permission_page_free(p);
    } else if (kind == AXIAM_MGMT_MANIFEST_ROLE) {
        axiam_mgmt_role_page_t *p = NULL;
        rc = axiam_mgmt_roles_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id,
                                  p->items[i]->description);
        }
        axiam_mgmt_role_page_free(p);
    } else {
        axiam_mgmt_group_page_t *p = NULL;
        rc = axiam_mgmt_groups_list(c, &page, &p, err);
        if (rc == AXIAM_OK && p) {
            for (size_t i = 0; i < p->count; i++)
                if (p->items[i])
                    existing_push(out, p->items[i]->name, p->items[i]->id,
                                  p->items[i]->description);
        }
        axiam_mgmt_group_page_free(p);
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
    free(plan);
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

    /* Cache one read per KIND, not one per entity: ten roles is one list call. */
    existing_set_t cache[4];
    int loaded[4] = { 0, 0, 0, 0 };
    memset(cache, 0, sizeof cache);

    for (size_t i = 0; i < manifest->count; i++) {
        const axiam_mgmt_manifest_entity_t *e = ordered[i];
        if (!loaded[e->kind]) {
            rc = read_existing(c, e->kind, &cache[e->kind], err);
            if (rc != AXIAM_OK) {
                for (int k = 0; k < 4; k++) if (loaded[k]) existing_free(&cache[k]);
                axiam_mgmt_plan_free(plan);
                free(ordered);
                return rc;
            }
            loaded[e->kind] = 1;
        }

        const existing_t *found = existing_find(&cache[e->kind], match_name(e));
        plan->changes[i].entity = e;
        if (!found) {
            plan->changes[i].action = AXIAM_MGMT_CHANGE_CREATE;
            plan->pending++;
        } else {
            /* Compare ONLY what the manifest names. A server object carries plenty a
             * manifest says nothing about, and treating that as drift would make every
             * plan report a change and every apply overwrite work nobody claimed. */
            int drifted = e->description && (!found->description
                                             || strcmp(e->description, found->description) != 0);
            plan->changes[i].action = drifted ? AXIAM_MGMT_CHANGE_UPDATE
                                              : AXIAM_MGMT_CHANGE_UNCHANGED;
            plan->changes[i].id = axiam_strdup0(found->id);
            if (drifted) plan->pending++;
        }
        plan->count++;
    }

    for (int k = 0; k < 4; k++) if (loaded[k]) existing_free(&cache[k]);
    free(ordered);

    if (out) *out = plan;
    else axiam_mgmt_plan_free(plan);
    return AXIAM_OK;
}

/* ---------------------------------------------------------------- */
/* Apply                                                            */
/* ---------------------------------------------------------------- */

static axiam_error_kind_t perform(axiam_client_t *c, const axiam_mgmt_planned_change_t *ch,
                                  axiam_error_t *err) {
    const axiam_mgmt_manifest_entity_t *e = ch->entity;
    int create = ch->action == AXIAM_MGMT_CHANGE_CREATE;

    if (e->kind == AXIAM_MGMT_MANIFEST_RESOURCE) {
        if (create) {
            axiam_mgmt_create_resource_request_t body;
            memset(&body, 0, sizeof body);
            body.name = (char *) e->name;
            body.resource_type = (char *) (e->resource_type ? e->resource_type : "folder");
            axiam_mgmt_resource_t *out = NULL;
            axiam_error_kind_t rc = axiam_mgmt_resources_create(c, &body, &out, err);
            axiam_mgmt_resource_free(out);
            return rc;
        }
        axiam_mgmt_update_resource_request_t body;
        memset(&body, 0, sizeof body);
        body.name = (char *) e->name;
        axiam_mgmt_resource_t *out = NULL;
        axiam_error_kind_t rc = axiam_mgmt_resources_update(c, ch->id, &body, &out, err);
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
            axiam_error_kind_t rc = axiam_mgmt_permissions_create(c, &body, &out, err);
            axiam_mgmt_permission_free(out);
            return rc;
        }
        axiam_mgmt_update_permission_request_t body;
        memset(&body, 0, sizeof body);
        body.description = (char *) e->description;
        axiam_mgmt_permission_t *out = NULL;
        axiam_error_kind_t rc = axiam_mgmt_permissions_update(c, ch->id, &body, &out, err);
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
            axiam_error_kind_t rc = axiam_mgmt_roles_create(c, &body, &out, err);
            axiam_mgmt_role_free(out);
            return rc;
        }
        axiam_mgmt_update_role_t body;
        memset(&body, 0, sizeof body);
        body.description = (char *) e->description;
        axiam_mgmt_role_t *out = NULL;
        axiam_error_kind_t rc = axiam_mgmt_roles_update(c, ch->id, &body, &out, err);
        axiam_mgmt_role_free(out);
        return rc;
    }

    if (create) {
        axiam_mgmt_create_group_request_t body;
        memset(&body, 0, sizeof body);
        body.name = (char *) e->name;
        body.description = (char *) (e->description ? e->description : "");
        axiam_mgmt_group_t *out = NULL;
        axiam_error_kind_t rc = axiam_mgmt_groups_create(c, &body, &out, err);
        axiam_mgmt_group_free(out);
        return rc;
    }
    axiam_mgmt_update_group_t body;
    memset(&body, 0, sizeof body);
    body.description = (char *) e->description;
    axiam_mgmt_group_t *out = NULL;
    axiam_error_kind_t rc = axiam_mgmt_groups_update(c, ch->id, &body, &out, err);
    axiam_mgmt_group_free(out);
    return rc;
}

axiam_error_kind_t axiam_mgmt_apply(axiam_client_t *c, const axiam_mgmt_manifest_t *manifest,
                                    axiam_mgmt_apply_report_t *report, axiam_error_t *err) {
    if (report) { report->applied = 0; report->failed = -1; report->remaining = 0; }

    axiam_mgmt_plan_t *plan = NULL;
    axiam_error_kind_t rc = axiam_mgmt_plan(c, manifest, &plan, err);
    if (rc != AXIAM_OK) return rc;

    size_t done = 0;
    for (size_t i = 0; i < plan->count; i++) {
        if (plan->changes[i].action == AXIAM_MGMT_CHANGE_UNCHANGED) continue;

        rc = perform(c, &plan->changes[i], err);
        if (rc != AXIAM_OK) {
            /* §27.7: stop here, do not undo what landed. A partial apply against a live
             * IAM tenant is a state an operator inspects and resumes from; an automatic
             * rollback would issue a second wave of writes at exactly the moment the
             * server is already saying something is wrong. */
            if (report) {
                report->applied = done;
                report->failed = (long) i;
                size_t left = 0;
                for (size_t j = i + 1; j < plan->count; j++)
                    if (plan->changes[j].action != AXIAM_MGMT_CHANGE_UNCHANGED) left++;
                report->remaining = left;
            }
            axiam_mgmt_plan_free(plan);
            return rc;
        }
        done++;
    }

    if (report) report->applied = done;
    axiam_mgmt_plan_free(plan);
    axiam_error_reset(err);
    return AXIAM_OK;
}
