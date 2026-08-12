/*
 * uma_resource_server — UMA 2.0 (CONTRACT.md §20), the RESOURCE-SERVER half of
 * the example pair.
 *
 * The situation: this service holds invoices that belong to *users*, not to
 * itself. When someone asks for one, the useful answer is not just "no" — it is
 * "not with what you're carrying, and here is where to go and get better". That
 * actionable refusal is what UMA adds over plain RBAC.
 *
 * What this shows, in order:
 *
 *   1. The PAT — a client-credentials token carrying `uma_protection`. §20.2
 *      rule 1 requires a *client* token: a minted ticket is bound to the
 *      client_id that minted it, so a user token cannot stand in. This SDK
 *      mints no tokens of its own, so the PAT arrives from the environment.
 *   2. Register the resource this service guards. The returned id IS the AXIAM
 *      resource id — there is no parallel resource store to keep in sync.
 *   3. Guard a request with axiam_require_access_uma(), so a denial hands back
 *      a `WWW-Authenticate: UMA` value carrying a fresh ticket.
 *
 * Its counterpart is examples/uma_client.c, which consumes that header.
 *
 * Illustrative and self-contained: it compiles without a live server, and reads
 * every connection detail from the environment.
 *
 * Build: cmake -DAXIAM_BUILD_EXAMPLES=ON && make uma_resource_server
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

int main(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://localhost:8443"));
    axiam_client_config_set_tenant_id(cfg, env_or("AXIAM_TENANT_ID", "acme"));

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "client construction failed\n");
        return 1;
    }

    /* ---- 1. The PAT ----
     *
     * §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a
     * user token, and not this client's ambient session — the SDK will not
     * substitute either, and the Protection API would refuse them anyway.
     */
    axiam_sensitive_t *pat = axiam_sensitive_new(
        env_or("AXIAM_PAT", "a-protection-api-token"));

    /* ---- 2. Registration ----
     *
     * Registering the same name twice creates two resources, so a real service
     * registers once at provisioning time and stores the id, or reconciles by
     * listing. Inline here because it is the step that shows the returned id is
     * the AXIAM resource id.
     *
     * The declared scopes are the allow-list the permission endpoint validates a
     * ticket request against: a resource registered with none can never appear
     * in a ticket.
     */
    const char *scopes[] = { "invoices:read", "invoices:approve" };
    axiam_uma_resource_set_t registered;
    memset(&registered, 0, sizeof(registered));
    if (axiam_uma_register_resource(client, pat, "invoice-7", "invoice",
                                    scopes, 2, &registered, &err) != AXIAM_OK) {
        fprintf(stderr, "registration failed: %s\n", err.message);
        axiam_sensitive_free(pat);
        axiam_client_free(client);
        return 1;
    }
    printf("registered invoice-7 as %s\n", registered.id ? registered.id : "(none)");

    /* ---- 3. The challenger ----
     *
     * as_uri names where the caller should redeem the ticket. Read it from the
     * discovery document rather than assembling it by hand — a deployment is
     * free to move its endpoints, which is why UMA ships a discovery document.
     */
    axiam_uma_config_t uma_cfg;
    memset(&uma_cfg, 0, sizeof(uma_cfg));
    if (axiam_uma_discover(client, &uma_cfg, &err) != AXIAM_OK) {
        fprintf(stderr, "uma discovery failed: %s\n", err.message);
        axiam_uma_resource_set_dispose(&registered);
        axiam_sensitive_free(pat);
        axiam_client_free(client);
        return 1;
    }

    axiam_uma_challenger_t challenger;
    challenger.realm = "invoices";
    challenger.as_uri = uma_cfg.issuer;
    challenger.pat = pat;

    /* What a guarded route does. A framework adapter builds `headers` from the
     * real request and turns the status into a response; the only new part is
     * the challenge it now has to put on a 403.
     */
    char bearer[2048];
    snprintf(bearer, sizeof(bearer), "Bearer %s",
             env_or("AXIAM_USER_TOKEN", "the-callers-access-token"));
    axiam_headers_t *headers = axiam_kv_append(NULL, "Authorization", bearer);

    char *challenge = NULL;
    axiam_guard_status_t status = axiam_require_access_uma(
        client, headers, "invoices:read",
        registered.id ? registered.id : "00000000-0000-0000-0000-000000000000",
        NULL, &challenger, &challenge);

    switch (status) {
    case AXIAM_GUARD_ALLOW:
        /* Reached only when the engine allowed it — including honouring any deny
         * rule, which UMA does not bypass: the ticket minted on a refusal asks
         * for the same action this check just evaluated, so the same grants and
         * denies apply to whatever RPT comes back. */
        printf("allowed: the caller may read invoice-7\n");
        break;
    case AXIAM_GUARD_DENIED:
        printf("refused with 403\n");
        /* The header itself is NOT printed: it carries a live ticket (§20.6),
         * and a credential in a log line is a credential in a log line,
         * 60-second life or not. A real adapter sends it, and nothing else. */
        printf("challenge present: %s\n", challenge ? "yes" : "no");
        break;
    default:
        printf("guard returned %d\n", (int)status);
        break;
    }

    free(challenge);
    axiam_kv_free(headers);
    axiam_uma_config_dispose(&uma_cfg);
    axiam_uma_resource_set_dispose(&registered);
    axiam_sensitive_free(pat);
    axiam_client_free(client);
    return 0;
}
