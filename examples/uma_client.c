/*
 * uma_client — UMA 2.0 (CONTRACT.md §20), the CLIENT half of the example pair.
 *
 * Run examples/uma_resource_server first; this program consumes the challenge
 * that one emits.
 *
 * The flow, which is the whole reason UMA exists:
 *
 *   1. Ask for the invoice with the user's ordinary token. The resource server
 *      refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket
 *      and an authorization server.
 *   2. PARSE the challenge. Note what happens next, and what does not: parsing
 *      performs no exchange (§20.3). The as_uri in that header is a host the
 *      *server we just failed against* chose; auto-redeeming would send the
 *      user's token wherever a 403 pointed.
 *   3. Decide to trust it, then EXCHANGE the ticket for an RPT.
 *   4. Retry with the RPT.
 *
 * Step 3 is a decision, not a formality — this example makes it explicitly, by
 * comparing the nominated as_uri against the issuer this client already trusts,
 * and refusing when they differ.
 *
 * The refusal in step 1 arrives here as a header string from the environment
 * rather than from a live HTTP call: this SDK is an AXIAM client, not a general
 * HTTP client, and an example that shipped its own socket code would be
 * demonstrating that instead of §20. Feed it the header your resource server
 * returned.
 *
 * Build: cmake -DAXIAM_BUILD_EXAMPLES=ON && make uma_client
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axiam/axiam.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

/* Compares issuers without letting a trailing slash decide a security question. */
static int same_issuer(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    while (la > 0 && a[la - 1] == '/') la--;
    while (lb > 0 && b[lb - 1] == '/') lb--;
    return la == lb && strncmp(a, b, la) == 0;
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

    int rc = 0;

    /* ---- 1. The refusal ---- */
    const char *header = getenv("AXIAM_WWW_AUTHENTICATE");
    if (!header || !*header) {
        /* A resource server that refuses without a challenge is telling you it
         * has nothing to offer — there is no ticket to redeem, and retrying the
         * same request would be pointless. */
        printf("no WWW-Authenticate header: this refusal is not actionable.\n");
        printf("set AXIAM_WWW_AUTHENTICATE to the header your resource server returned.\n");
        axiam_client_free(client);
        return 0;
    }

    /* ---- 2. Parse, and only parse ---- */
    axiam_uma_challenge_t challenge;
    if (!axiam_uma_parse_challenge(header, &challenge) || !challenge.ticket) {
        printf("the challenge names no ticket; nothing to redeem.\n");
        axiam_uma_challenge_dispose(&challenge);
        axiam_client_free(client);
        return 0;
    }

    /* Nothing from the challenge is echoed, and there are two separate reasons.
     *
     * The ticket, because §20.6 says so: its 60-second life does not make it
     * harmless — for those 60 seconds it IS the credential that converts into an
     * RPT, so a header in a log line is a live credential in a log line.
     *
     * The realm and as_uri, because they are strings a *remote* server chose.
     * They are not secrets, but echoing attacker-controlled text into a terminal
     * or a log file is its own small hazard (escape sequences, log forging), and
     * an example is the last place to teach the habit. What matters here is the
     * shape of the challenge, not its contents.
     */
    printf("challenge parsed: as_uri present=%s, ticket present=yes\n",
           challenge.as_uri ? "yes" : "no");

    /* ---- 3. The trust decision ----
     *
     * This is the step §20.3 exists to keep in the caller's hands. The SDK
     * parsed the header and stopped; deciding whether to send the user's token
     * to the host it names is this program's call, and it is a real one — a
     * compromised or merely misconfigured resource server could nominate
     * anything here.
     */
    axiam_uma_config_t uma_cfg;
    memset(&uma_cfg, 0, sizeof(uma_cfg));
    if (axiam_uma_discover(client, &uma_cfg, &err) != AXIAM_OK) {
        printf("discovery failed; cannot make the trust decision, so not redeeming.\n");
        rc = 1;
        goto done;
    }

    if (challenge.as_uri && uma_cfg.issuer && !same_issuer(challenge.as_uri, uma_cfg.issuer)) {
        /* Neither side of the comparison is echoed. The nominated value for the
         * reasons above; our own issuer because printing values read back off a
         * configured client is a habit that is fine here and wrong three
         * refactors later. The decision and its outcome are what a reader needs;
         * the values are two lines away in a debugger. */
        printf("refusing to redeem: the challenge nominates an authorization server\n");
        printf("that is not the issuer this client already trusts.\n");
        printf("this is the auto-exchange §20.3 forbids, and why it forbids it.\n");
        goto done;
    }
    printf("as_uri matches the issuer we already trust; redeeming.\n");

    /* ---- 4. Exchange ----
     *
     * One request. A ticket is spent whether or not this succeeds (§20.2 rule
     * 6), so on failure the next step is a *new* ticket — which means going back
     * to step 1, not resending this one.
     */
    {
        axiam_sensitive_t *claim_token = axiam_sensitive_new(
            env_or("AXIAM_USER_TOKEN", "the-requesting-partys-access-token"));
        axiam_sensitive_t *client_secret = axiam_sensitive_new(
            env_or("AXIAM_OIDC_CLIENT_SECRET", "client-secret"));

        axiam_uma_exchange_params_t params;
        memset(&params, 0, sizeof(params));
        params.ticket = challenge.ticket;
        params.claim_token = claim_token;
        params.client_id = env_or("AXIAM_OIDC_CLIENT_ID", "invoices-client");
        params.client_secret = client_secret;

        axiam_uma_rpt_t rpt;
        memset(&rpt, 0, sizeof(rpt));
        if (axiam_uma_exchange_ticket(client, &params, &rpt, &err) != AXIAM_OK) {
            /* err.oauth_error carries the machine-readable code (§20.4). It is
             * safe to print: it is one of a fixed set of protocol constants, not
             * anything a remote server composed. */
            printf("exchange failed (%s); the ticket is spent either way —\n",
                   err.oauth_error[0] ? err.oauth_error : "no oauth error code");
            printf("request a new one by retrying the call from step 1.\n");
        } else {
            printf("got an RPT, valid for %lds\n", rpt.expires_in);
            /* Step 4 in a real program: send rpt.access_token as the bearer on
             * the retried request. It is not printed here, for the reason above. */
        }
        axiam_uma_rpt_dispose(&rpt);
        axiam_sensitive_free(client_secret);
        axiam_sensitive_free(claim_token);
    }

done:
    axiam_uma_config_dispose(&uma_cfg);
    axiam_uma_challenge_dispose(&challenge);
    axiam_client_free(client);
    return rc;
}
