/*
 * examples/management_basics.c — the CONTRACT.md §27 management API in C.
 *
 * §27.3's FLAT-SYMBOL accommodation: `axiam_users_list()` rather than
 * `client.management().users().list()`. The namespace lives in the name, so a completion
 * list sorted alphabetically groups exactly the way handles would in the other SDKs.
 *
 * Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:   ./build/examples/management_basics
 * (needs a reachable AXIAM server and an administrator account — a failure here is
 * expected with no live server; this example is illustrative and compile-checked.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"
#include "axiam/management_ops.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

int main(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://axiam.example.com"));
    axiam_client_config_set_tenant_id(cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-4111-8111-111111111111"));
    axiam_client_config_set_org_id(cfg, env_or("AXIAM_ORG_ID", "11111111-1111-4111-8111-111111111111"));

    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!c) {
        fprintf(stderr, "client: %s\n", err.message);
        return 1;
    }

    /* §27.4 rule 1: without a session, a management call never reaches the server. */
    axiam_login_result_t login;
    if (axiam_login(c, env_or("AXIAM_ADMIN", "admin@example.com"),
                    env_or("AXIAM_PASSWORD", "secret"), &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login: %s\n", err.message);
        axiam_client_free(c);
        return 1;
    }
    axiam_login_result_dispose(&login);

    /* ---- one page -------------------------------------------------------
     *
     * §27.4 rule 4: `total` is the SERVER's count across all pages. It is NOT `count`,
     * and treating them as interchangeable is how a management tool silently processes
     * the first fifty of four hundred users. They are separate members here for exactly
     * that reason.
     */
    axiam_mgmt_page_req_t page = { 0, 50 };
    axiam_mgmt_user_response_page_t *users = NULL;
    if (axiam_users_list(c, &page, &users, &err) == AXIAM_OK && users) {
        printf("users on this page: %zu, users in total: %ld\n", users->count, users->total);
        axiam_mgmt_user_response_page_free(users);
    }

    /* ---- every page -----------------------------------------------------
     *
     * The walk stops on the first EMPTY page, never on a short one: a server may return
     * fewer rows than asked for without the collection having ended.
     */
    axiam_mgmt_page_req_t cursor = { 0, 50 };
    for (;;) {
        axiam_mgmt_user_response_page_t *p = NULL;
        if (axiam_users_list(c, &cursor, &p, &err) != AXIAM_OK || !p) break;
        if (p->count == 0) { axiam_mgmt_user_response_page_free(p); break; }
        for (size_t i = 0; i < p->count; i++)
            printf("  %s\n", p->items[i]->id ? p->items[i]->id : "(no id)");
        axiam_mgmt_user_response_page_free(p);
        cursor = axiam_mgmt_page_next(cursor);
    }

    /* ---- a sparse update -------------------------------------------------
     *
     * §27.4 rule 5: set only the fields you mean to change. What you leave zeroed is
     * OMITTED from the request, not sent as null — on a sparse update those say opposite
     * things, and only omission means "leave it alone".
     *
     * memset first: a stack struct with uninitialised members would send whatever
     * happened to be on the stack.
     */
    axiam_mgmt_update_user_request_t update;
    memset(&update, 0, sizeof update);
    update.status = AXIAM_MGMT_USER_STATUS_LOCKED;
    update.has_status = 1;   /* an optional SCALAR needs its presence flag */

    axiam_mgmt_user_response_t *updated = NULL;
    axiam_error_kind_t rc = axiam_users_update(
        c, env_or("AXIAM_USER_ID", "33333333-3333-4333-8333-333333333333"),
        &update, &updated, &err);

    /* ---- §27.4 rule 7 ----------------------------------------------------
     *
     * C has no subtyping, so the sub-type is a classification beside the error rather
     * than a hierarchy inside it. `kind` keeps the §2 parent rule 7 names; the class says
     * which sub-type it would have been.
     */
    if (rc != AXIAM_OK) {
        switch (axiam_mgmt_error_class(&err)) {
            case AXIAM_MGMT_ERR_NOT_FOUND:
                /* Deliberately an AUTHZ outcome: on a multi-tenant surface the server
                 * answers 404 for another tenant's object PRECISELY SO a probing caller
                 * cannot tell "does not exist" from "exists, not yours". */
                fprintf(stderr, "not found (or not visible to you)\n");
                break;
            case AXIAM_MGMT_ERR_CONFLICT:
                fprintf(stderr, "conflict: %s\n", err.message);
                break;
            case AXIAM_MGMT_ERR_VALIDATION:
                fprintf(stderr, "rejected: %s\n", err.message);
                break;
            default:
                fprintf(stderr, "failed: %s\n", err.message);
                break;
        }
    }
    axiam_mgmt_user_response_free(updated);

    /* ---- scoping one call ------------------------------------------------
     *
     * §27.4 rule 3: `{org_id}`/`{tenant_id}` come from the client. A per-call scope
     * overrides them — and because it is an ARGUMENT rather than state on a handle, one
     * call's override cannot leak into the next.
     */
    axiam_mgmt_call_scope_t other = { env_or("AXIAM_OTHER_ORG", NULL), NULL };
    axiam_mgmt_ca_certificate_page_t *cas = NULL;
    if (axiam_ca_certificates_list(c, other.org_id ? &other : NULL, NULL, &cas, &err)
        == AXIAM_OK && cas) {
        printf("CA certificates visible: %zu\n", cas->count);
        axiam_mgmt_ca_certificate_page_free(cas);
    }

    axiam_client_free(c);
    return 0;
}
