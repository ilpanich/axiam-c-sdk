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

    /* ---- searching a list ------------------------------------------------
     *
     * §27.4 rule 4: the term rides on the PAGE REQUEST, beside offset and limit, not as
     * an extra argument on each of the twenty paginated operations. That is what lets
     * axiam_mgmt_page_next() carry it: an argument has nowhere to live between one
     * request and the next, and a walk that filtered only its first request would return
     * the matches followed by the unfiltered tail.
     *
     * The server does the matching, case-insensitively, against the identifying fields of
     * whatever is being listed — a name or username, plus the record id, so a UUID pasted
     * out of a log line finds its row. `total` then counts MATCHES, not rows.
     *
     * `search` is BORROWED, never copied: it must outlive every request derived from it,
     * which is why the term below is declared outside the loop rather than inside it.
     */
    const char *term = env_or("AXIAM_SEARCH", "ada");
    axiam_mgmt_page_req_t filtered = { 0, 50, term };
    axiam_mgmt_user_response_page_t *matches = NULL;
    if (axiam_users_list(c, &filtered, &matches, &err) == AXIAM_OK && matches) {
        printf("matching users on this page: %zu, matches in total: %ld\n",
               matches->count, matches->total);
        axiam_mgmt_user_response_page_free(matches);
    }

    /* The whole filtered set: the term travels with the walk, so every request asks the
     * same question. */
    for (;;) {
        axiam_mgmt_user_response_page_t *p = NULL;
        if (axiam_users_list(c, &filtered, &p, &err) != AXIAM_OK || !p) break;
        if (p->count == 0) { axiam_mgmt_user_response_page_free(p); break; }
        for (size_t i = 0; i < p->count; i++)
            printf("  match: %s\n", p->items[i]->id ? p->items[i]->id : "(no id)");
        axiam_mgmt_user_response_page_free(p);
        filtered = axiam_mgmt_page_next(filtered);
    }

    /* A NULL, empty or all-whitespace term is the SAME request as none: no `search`
     * parameter is sent at all. A search box that fires on every keystroke sends one the
     * moment it is cleared, and "rows containing the empty string" is a different
     * question from "all rows". */
    axiam_mgmt_page_req_t cleared = { 0, 50, "   " };
    axiam_mgmt_user_response_page_t *everyone = NULL;
    if (axiam_users_list(c, &cleared, &everyone, &err) == AXIAM_OK && everyone) {
        printf("after clearing the box: %ld users\n", everyone->total);
        axiam_mgmt_user_response_page_free(everyone);
    }

    /* ---- open enums, and the list-only projection (§27.11) ----------------
     *
     * Rule 1: a value this SDK's copy of the spec does not list decodes to the enum's
     * _UNKNOWN constant rather than failing. Failing here would make the caller drop the
     * whole record — or the whole page — over one field it did not ask about. It is
     * never read as one of the KNOWN constants, which would turn a new server state into
     * a wrong one, and _UNKNOWN is deliberately not the zero value either.
     */
    axiam_mgmt_tenant_page_t *tenants = NULL;
    if (axiam_tenants_list(c, NULL, NULL, &tenants, &err) == AXIAM_OK && tenants) {
        for (size_t i = 0; i < tenants->count; i++) {
            const axiam_mgmt_tenant_t *t = tenants->items[i];
            const char *what = "an ordinary tenant";
            if (t->has_kind) {
                switch (t->kind) {
                    case AXIAM_MGMT_TENANT_KIND_ORGANIZATION:
                        what = "the organization's own scope"; break;
                    case AXIAM_MGMT_TENANT_KIND_UNKNOWN:
                        what = "a kind this SDK predates — upgrade to name it"; break;
                    default:
                        break;
                }
            }
            printf("  %s: %s\n", t->slug ? t->slug : "(no slug)", what);
        }
        axiam_mgmt_tenant_page_free(tenants);
    }

    /* Rule 4: `bound_service_account_id` is a PROJECTION, not a member of the
     * certificate. The server resolves it for a whole page in one query, so `list`
     * populates it and `get` leaves it NULL. NULL there means "this read does not carry
     * it", not "there is nothing bound" — and this SDK does not go and fetch it, because
     * a `get` that silently costs two round trips is what §27.4 rule 3 forbids elsewhere.
     */
    axiam_mgmt_certificate_page_t *certs = NULL;
    if (axiam_certificates_list(c, NULL, &certs, &err) == AXIAM_OK && certs) {
        for (size_t i = 0; i < certs->count; i++) {
            const axiam_mgmt_certificate_t *cert = certs->items[i];
            printf("  %s -> %s\n",
                   cert->subject ? cert->subject : "(no subject)",
                   cert->bound_service_account_id ? cert->bound_service_account_id
                                                  : "not bound to a service account");
        }
        axiam_mgmt_certificate_page_free(certs);
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
