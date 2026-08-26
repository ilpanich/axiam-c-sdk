/*
 * examples/management_manifest.c — the CONTRACT.md §27.6/§27.7 declarative layer.
 *
 * Describe the tenant you want; let the SDK work out the difference. The imperative
 * surface is fine for one change, but a poor way to describe a TENANT: re-running it
 * either fails on the second run or makes you hand-write "does this exist already?" for
 * every object. A manifest is re-runnable by construction — apply it twice and the second
 * run sends nothing.
 *
 * Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"
#include "axiam/management_manifest.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

static const char *action_name(axiam_mgmt_change_action_t a) {
    switch (a) {
        case AXIAM_MGMT_CHANGE_CREATE:    return "create";
        case AXIAM_MGMT_CHANGE_UPDATE:    return "update";
        case AXIAM_MGMT_CHANGE_UNCHANGED: return "unchanged";
    }
    return "?";
}

int main(void) {
    /*
     * The desired shape of the tenant. Nothing here contacts a server: this is a
     * description, and describing a tenant is not the same act as changing one.
     *
     * Declaration order is irrelevant — §27.6 requires the apply order to be DERIVED, and
     * it is: resources (parents before children), then permissions, then roles, then
     * groups. Group these however reads best.
     */
    axiam_mgmt_manifest_entity_t entities[] = {
        { AXIAM_MGMT_MANIFEST_GROUP,      "auditors", "auditors",       "Internal audit",   NULL,     NULL,             0, "auditor" },
        { AXIAM_MGMT_MANIFEST_ROLE,       "auditor",  "auditor",        "Read-only audit",  NULL,     NULL,             0, "docs.read" },
        { AXIAM_MGMT_MANIFEST_PERMISSION, "docs.read", "documents:read", "Read documents",  NULL,     "documents:read", 0, NULL },
        { AXIAM_MGMT_MANIFEST_RESOURCE,   "payroll",  "payroll",        "Payroll folder",   "folder", NULL,             0, "root" },
        { AXIAM_MGMT_MANIFEST_RESOURCE,   "root",     "acme",           "Org root",         "organization", NULL,       0, NULL },
    };
    axiam_mgmt_manifest_t manifest = { entities, sizeof entities / sizeof entities[0] };

    /*
     * Validate up front. Every check here can be made from the manifest alone — a
     * dangling reference, a cycle, a duplicate key — and §27.7 gives apply no rollback,
     * so discovering one halfway through leaves a tenant in a state nobody described.
     */
    axiam_error_t err;
    if (axiam_mgmt_manifest_validate(&manifest, &err) != AXIAM_OK) {
        fprintf(stderr, "manifest is not applicable: %s\n", err.message);
        return 2;
    }

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://axiam.example.com"));
    axiam_client_config_set_tenant_id(cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-4111-8111-111111111111"));
    axiam_client_config_set_org_id(cfg, env_or("AXIAM_ORG_ID", "11111111-1111-4111-8111-111111111111"));

    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!c) { fprintf(stderr, "client: %s\n", err.message); return 1; }

    axiam_login_result_t login;
    if (axiam_login(c, env_or("AXIAM_ADMIN", "admin@example.com"),
                    env_or("AXIAM_PASSWORD", "secret"), &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login: %s\n", err.message);
        axiam_client_free(c);
        return 1;
    }
    axiam_login_result_dispose(&login);

    /* ---- plan -----------------------------------------------------------
     *
     * §27.6: plan() WRITES NOTHING. It reads the tenant and reports the difference, so it
     * is safe against production, safe in CI and safe on a schedule. Print it and let a
     * human approve before anything changes.
     */
    axiam_mgmt_plan_t *plan = NULL;
    if (axiam_mgmt_plan(c, &manifest, &plan, &err) != AXIAM_OK) {
        fprintf(stderr, "plan: %s\n", err.message);
        axiam_client_free(c);
        return 2;
    }

    if (plan->pending == 0) {
        printf("tenant already matches the manifest; nothing to do\n");
        axiam_mgmt_plan_free(plan);
        axiam_client_free(c);
        return 0;
    }

    printf("planned changes:\n");
    for (size_t i = 0; i < plan->count; i++) {
        if (plan->changes[i].action == AXIAM_MGMT_CHANGE_UNCHANGED) continue;
        printf("  %-9s %s\n", action_name(plan->changes[i].action), plan->changes[i].entity->key);
    }
    axiam_mgmt_plan_free(plan);

    if (strcmp(env_or("AXIAM_APPLY", "no"), "yes") != 0) {
        printf("\n(set AXIAM_APPLY=yes to apply)\n");
        axiam_client_free(c);
        return 0;
    }

    /* ---- apply ----------------------------------------------------------
     *
     * §27.7: apply STOPS AT THE FIRST FAILURE and DOES NOT ROLL BACK. That is a feature.
     * A partial apply against a live IAM tenant is a state an operator must be able to
     * inspect and resume from, and an automatic rollback would fire a second wave of
     * writes at exactly the moment the server is saying something is wrong.
     *
     * The report is the recovery tool: what landed, which change failed, what was never
     * attempted. Fix the cause and re-run — the changes that already landed will plan as
     * Unchanged next time, so a resumed apply picks up where this one stopped.
     */
    axiam_mgmt_apply_report_t report;
    axiam_error_kind_t rc = axiam_mgmt_apply(c, &manifest, &report, &err);

    printf("\napplied %zu change(s)\n", report.applied);
    if (rc != AXIAM_OK) {
        printf("FAILED at change %ld: %s\n", report.failed, err.message);
        printf("%zu change(s) never attempted\n", report.remaining);
        axiam_client_free(c);
        return 1;
    }

    axiam_client_free(c);
    return 0;
}
