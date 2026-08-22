/*
 * par_login.c — Pushed Authorization Requests, RFC 9126 (CONTRACT.md §26).
 *
 * PAR moves the authorization request off the browser. Instead of putting
 * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
 * agent carries, the client POSTs them straight to AXIAM over an authenticated
 * back channel and puts an opaque handle in the redirect. What travels through
 * the browser is then a random string that cannot be edited into meaning
 * something else — no `redirect_uri` to swap, no `scope` to widen, nothing for
 * a referrer header or a shoulder to leak.
 *
 * TWO THINGS TO NOTICE, because both are easy to get wrong:
 *
 *  1. The server answers 201, not 200 — RFC 9126 §2.2 specifies Created. Code
 *     written `if (status == 200)` treats every successful push as a failure.
 *  2. The redirect carries EXACTLY `client_id` and `request_uri`. AXIAM refuses
 *     a request that mixes a request_uri with inline authorization parameters
 *     rather than merging them, because merging is where parameter confusion
 *     lives: an attacker supplies the inline value they want and lets the
 *     pushed copy satisfy whichever check reads the other one. Re-adding
 *     `scope` "for compatibility" restores the attack.
 *
 * REQUIRED FOR A FAPI 2.0 CLIENT: `profile: "fapi2"` refuses a registration
 * that does not set `require_par`, so such a client cannot authorize any other
 * way (§21.1).
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/par_login
 */
#include <axiam/axiam.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

int main(void) {
    const char *base_url      = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const char *tenant_id     = getenv_or("AXIAM_TENANT_ID",
                                          "00000000-0000-0000-0000-000000000000");
    const char *client_id     = getenv_or("AXIAM_OIDC_CLIENT_ID", "example-rp");
    const char *client_secret = getenv_or("AXIAM_OIDC_CLIENT_SECRET", "example-secret");
    const char *redirect_uri  = getenv_or("AXIAM_REDIRECT_URI",
                                          "https://app.example.com/callback");

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    /* §12.1 rule 2: the /oauth2 family takes the tenant as a query parameter in
     * UUID form. A slug is never a substitute here and is refused client-side. */
    axiam_client_config_set_tenant_id(cfg, tenant_id);
    axiam_client_config_set_oidc_client_id(cfg, client_id);
    axiam_client_config_set_oidc_client_secret(cfg, client_secret);

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    /* Discovery is what says whether this server supports PAR at all. §26.1
     * forbids synthesising the endpoint from the issuer — a server that does
     * not advertise it does not have it, and guessing `/oauth2/par` produces a
     * 404 that reads like a broken request. */
    axiam_oidc_config_t config;
    if (axiam_oidc_discover(client, &config, &err) != AXIAM_OK) {
        fprintf(stderr, "discovery failed: %s\n", err.message);
        axiam_client_free(client);
        return 1;
    }
    if (!config.pushed_authorization_request_endpoint) {
        printf("this server does not advertise a PAR endpoint — "
               "use examples/oidc_login.c instead\n");
        axiam_oidc_config_dispose(&config);
        axiam_client_free(client);
        return 0;
    }

    /* §26.2 rule 1: everything the push sends was computed HERE. There is no
     * second generator inside oidc_par, and there must not be — two sources for
     * `state` or the PKCE pair are two things that can disagree, and when they
     * do the failure surfaces at the exchange as an opaque `invalid_grant` a
     * long way from the code that caused it. */
    axiam_authorization_request_t request;
    if (axiam_oidc_begin(client, &config, redirect_uri, "openid profile", &request, &err)
        != AXIAM_OK) {
        fprintf(stderr, "oidc_begin failed: %s\n", err.message);
        axiam_oidc_config_dispose(&config);
        axiam_client_free(client);
        return 1;
    }

    /* The push itself. NOT RETRIED on a 5xx or a transport failure (§26.2 rule
     * 4): it is a POST that creates server state, so it falls outside §16.2's
     * read-only eligibility exactly as oidc_exchange does. The safe recovery is
     * a fresh push — one round trip, and it cannot double-consume anything. */
    axiam_pushed_authorization_request_t pushed;
    if (axiam_oidc_par(client, &config, &request, redirect_uri, "openid profile",
                       NULL, &pushed, &err) != AXIAM_OK) {
        fprintf(stderr, "pushed authorization request failed: %s\n", err.message);
        axiam_authorization_request_dispose(&request);
        axiam_oidc_config_dispose(&config);
        axiam_client_free(client);
        return 1;
    }

    /*
     * Exactly two parameters, and the handle is single-use with a short life
     * (§26.2 rule 3 — `expires_in` is not advisory). It is Sensitive because
     * between this line and the redirect it is a bearer handle to a
     * fully-formed authorization request; `state` and `nonce` stay readable
     * because the caller has to compare them when the IdP comes back.
     */
    printf("send the user agent to:\n  %s\n", pushed.url);
    printf("the handle expires in %ld s (rendered in a log: %s)\n",
           pushed.expires_in, axiam_sensitive_to_string(pushed.request_uri));

    /*
     * §12.3 rule 1: the SDK stores none of this. Persist `state`, `nonce` and
     * the PKCE verifier in your own session — plus the redirect_uri, which
     * RFC 6749 §4.1.3 requires replayed byte-identically and which §12.1
     * deliberately does not carry for you.
     */
    printf("persist across the redirect: state=%s nonce=%s (+ the code_verifier)\n",
           pushed.state, pushed.nonce);

    const char *code = getenv_or("AXIAM_AUTH_CODE", "");
    if (code[0]) {
        /* The exchange is unchanged by PAR — same code, same verifier, same
         * nonce. PAR protected the request on its way to the IdP; it does not
         * change what comes back. */
        axiam_oidc_exchange_params_t params = {code, pushed.code_verifier, redirect_uri,
                                               pushed.nonce, NULL};
        axiam_oidc_token_set_t tokens;
        if (axiam_oidc_exchange(client, &params, &tokens, &err) == AXIAM_OK) {
            printf("exchanged: token_type=%s expires_in=%ld\n",
                   tokens.token_type ? tokens.token_type : "(none)", tokens.expires_in);
            axiam_oidc_token_set_dispose(&tokens);
        } else {
            fprintf(stderr, "exchange failed: %s\n", err.message);
        }
    } else {
        printf("(set AXIAM_AUTH_CODE to run the exchange)\n");
    }

    axiam_pushed_authorization_request_dispose(&pushed);
    axiam_authorization_request_dispose(&request);
    axiam_oidc_config_dispose(&config);
    axiam_client_free(client);
    return 0;
}
