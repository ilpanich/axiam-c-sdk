/*
 * rest_authz.c — demonstrates the REST authorization surface: check_access,
 * can (the browser/UI alias), and batch_check (CONTRACT.md §1).
 *
 * It logs in first (see examples/login_mfa.c for the full MFA-aware flow),
 * supplying organization context (§5.1) alongside tenant context (§5), then
 * exercises POST /api/v1/authz/check and POST /api/v1/authz/check/batch.
 *
 * This example is illustrative — connection details come from environment
 * variables and it compiles/links without a live AXIAM server. Argument order
 * for the authorization calls is (action, resource[, scope]) per §1.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/rest_authz
 */
#include <axiam/axiam.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

/*
 * Turn a §11 rule 9 reason code into something worth showing a person. This is
 * the entire reason the code exists: `no_grant` and `denied_by_rule` are both
 * `allowed == 0`, but one of them means "ask an admin" and the other means "an
 * admin has already said no". Sending a user to raise a ticket that will be
 * refused is the bug the clause prevents.
 *
 * Note what this function does NOT do: it never decides the outcome. That is
 * `allowed`, and a code this build has never seen falls through to the default
 * without changing anything.
 */
static const char *explain(const axiam_check_result_t *r) {
    if (!r->reason_code) return "(server predates reason codes)";
    if (strcmp(r->reason_code, AXIAM_REASON_CODE_ALLOWED) == 0)
        return "a grant matched";
    if (strcmp(r->reason_code, AXIAM_REASON_CODE_NO_GRANT) == 0)
        return "nothing grants this — you can request access";
    if (strcmp(r->reason_code, AXIAM_REASON_CODE_DENIED_BY_RULE) == 0)
        return "an explicit deny rule applies — requesting access will not help";
    return "an unrecognised reason code — treat it as opaque";
}

int main(void) {
    const char *base_url    = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const char *tenant_slug = getenv_or("AXIAM_TENANT_SLUG", "acme");
    const char *org_slug    = getenv_or("AXIAM_ORG_SLUG", "acme");
    const char *email       = getenv_or("AXIAM_EMAIL", "user@example.com");
    const char *password    = getenv_or("AXIAM_PASSWORD", "changeme");
    const char *resource_id = getenv_or("AXIAM_RESOURCE_ID",
                                        "00000000-0000-0000-0000-000000000000");

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, tenant_slug); /* §5: required */
    axiam_client_config_set_org_slug(cfg, org_slug);       /* §5.1: required for login/refresh */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    axiam_login_result_t login = {0};
    if (axiam_login(client, email, password, &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login failed: %s\n", err.message);
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 1;
    }
    if (login.mfa_required) {
        printf("MFA is required for this account — see examples/login_mfa.c first.\n");
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        return 0;
    }
    axiam_login_result_dispose(&login);

    /* POST /api/v1/authz/check — single access check (action, resource, scope). */
    axiam_check_result_t res = {0};
    if (axiam_check_access(client, "resource:read", resource_id, NULL, NULL, &res, &err) == AXIAM_OK) {
        printf("check_access -> allowed: %d, reason: %s\n",
               res.allowed, res.reason ? res.reason : "(none)");
        /* §11 rule 9 — the machine-readable half of the decision. */
        printf("  reason_code: %s (%s)\n",
               res.reason_code ? res.reason_code : "(absent)", explain(&res));
    } else {
        fprintf(stderr, "check_access error: %s\n", err.message);
    }
    axiam_check_result_dispose(&res);

    /* axiam_can — the browser/UI-facing alias for check_access (§1). */
    axiam_check_result_t can = {0};
    if (axiam_can(client, "resource:write", resource_id, NULL, &can, &err) == AXIAM_OK) {
        printf("can(resource:write) -> allowed: %d\n", can.allowed);
    } else {
        fprintf(stderr, "can error: %s\n", err.message);
    }
    axiam_check_result_dispose(&can);

    /* POST /api/v1/authz/check/batch — ordered batch; results preserve order. */
    axiam_check_input_t checks[2] = {
        { .action = "resource:read",   .resource_id = resource_id, .scope = NULL,    .subject_id = NULL },
        { .action = "resource:delete", .resource_id = resource_id, .scope = "admin", .subject_id = NULL },
    };
    axiam_check_result_t batch[2] = {0};
    size_t count = 0;
    if (axiam_batch_check(client, checks, 2, batch, &count, &err) == AXIAM_OK) {
        for (size_t i = 0; i < count; i++) {
            printf("batch_check[%zu] -> allowed: %d, reason_code: %s (%s)\n",
                   i, batch[i].allowed,
                   batch[i].reason_code ? batch[i].reason_code : "(absent)",
                   explain(&batch[i]));
        }
    } else {
        fprintf(stderr, "batch_check error: %s\n", err.message);
    }
    for (size_t i = 0; i < count; i++) {
        axiam_check_result_dispose(&batch[i]);
    }

    axiam_logout(client, &err);
    axiam_client_free(client);
    return 0;
}
