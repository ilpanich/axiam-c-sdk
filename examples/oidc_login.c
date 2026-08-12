/*
 * oidc_login — the OIDC relying-party flow (CONTRACT.md §12), plus §12.7 logout.
 *
 * A browser redirect has an awkward home in a C program, and that is exactly
 * why this example is worth reading: the SDK does the two halves the redirect
 * sits between, and it deliberately does NOT do the middle.
 *
 *   1. `axiam_oidc_discover`   — fetch the document once; the client caches it.
 *   2. `axiam_oidc_begin`      — build the authorization URL. NO NETWORK I/O.
 *   3. …your application sends the user agent there and receives the callback…
 *   4. `axiam_oidc_exchange`   — trade the code for a validated token set.
 *   5. `axiam_logout_url`      — build the end-session URL when they leave.
 *
 * THE PART THIS EXAMPLE EXISTS TO MAKE UNMISSABLE (§12.3 rule 1): the SDK
 * stores NOTHING between steps 2 and 4. `state`, `nonce` and `code_verifier`
 * come out of `axiam_oidc_begin` and the application has to keep them — and so
 * does the `redirect_uri`, which `axiam_authorization_request_t` deliberately
 * does not carry, because RFC 6749 §4.1.3 requires it replayed byte-identically.
 * A web application parks all four in its own session. A CLI writes them to a
 * temporary file. Either way it is the caller's storage, and there is no
 * SDK-side cache that will quietly cover for losing them.
 *
 * Step 3 is not shown because this SDK is an AXIAM client, not an HTTP server:
 * an example that shipped its own listener would be demonstrating that instead
 * of §12. Feed the code and state your callback received through the
 * environment.
 *
 * Note also what is NOT printed below. `state` and `nonce` are correlation
 * values and are safe to display; the access token, the refresh token, the ID
 * token and the code verifier are not, and none of them reaches stdout here.
 *
 * Build: cmake -DAXIAM_BUILD_EXAMPLES=ON && make oidc_login
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
    const char *redirect_uri = env_or("AXIAM_REDIRECT_URI", "https://app.example.com/callback");

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://localhost:8443"));
    /* §12.3 rule 4: five of the nine operations put the tenant in a `?tenant_id=`
     * query parameter, which requires a UUID. A slug-only client is refused
     * client-side rather than sent to fail on the server. */
    axiam_client_config_set_tenant_id(
        cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"));
    /* §12.1: the client_id is CONFIGURATION, not a per-call argument, because
     * §12.4 rule 4 compares an ID token's `aud` against the same value. */
    axiam_client_config_set_oidc_client_id(cfg, env_or("AXIAM_OIDC_CLIENT_ID", "example-rp"));
    /* Optional. A public client omits it and no `client_secret` field goes out. */
    const char *secret = getenv("AXIAM_OIDC_CLIENT_SECRET");
    if (secret && *secret) axiam_client_config_set_oidc_client_secret(cfg, secret);

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "client construction failed: %s\n", err.message);
        return 1;
    }

    /* --- 1. discovery ------------------------------------------------ */
    axiam_oidc_config_t doc;
    if (axiam_oidc_discover(client, &doc, &err) != AXIAM_OK) {
        fprintf(stderr, "discovery failed: %s\n", err.message);
        axiam_client_free(client);
        return 1;
    }
    printf("issuer:               %s\n", doc.issuer);
    printf("authorization:        %s\n", doc.authorization_endpoint);
    printf("end_session:          %s\n",
           doc.end_session_endpoint ? doc.end_session_endpoint : "(not advertised)");

    /* --- 2. begin (no network I/O) ----------------------------------- */
    axiam_authorization_request_t request;
    if (axiam_oidc_begin(client, &doc, redirect_uri, "openid profile", &request, &err) != AXIAM_OK) {
        fprintf(stderr, "oidc_begin failed: %s\n", err.message);
        axiam_oidc_config_dispose(&doc);
        axiam_client_free(client);
        return 1;
    }

    printf("\nSend the user agent to:\n  %s\n", request.url);
    /* Safe to print: §12.3 rule 2 classes these as correlation values rather
     * than secrets, and the caller has to be able to compare them on return. */
    printf("\nKeep these until the callback arrives — the SDK does not:\n");
    printf("  state         %s\n", request.state);
    printf("  nonce         %s\n", request.nonce);
    printf("  code_verifier [SENSITIVE — %zu bytes, keep it, never log it]\n",
           axiam_sensitive_len(request.code_verifier));
    printf("  redirect_uri  %s\n", redirect_uri);

    /* --- 4. exchange, once the callback has happened ------------------ */
    const char *code = getenv("AXIAM_AUTH_CODE");
    const char *returned_state = getenv("AXIAM_RETURNED_STATE");
    if (!code || !*code) {
        printf("\nSet AXIAM_AUTH_CODE (and AXIAM_RETURNED_STATE) to continue past the "
               "redirect.\n");
        axiam_authorization_request_dispose(&request);
        axiam_oidc_config_dispose(&doc);
        axiam_client_free(client);
        return 0;
    }
    /*
     * The CSRF check is the application's, not the SDK's — the SDK never saw
     * the callback. Comparing the returned `state` against the one from step 2
     * is what stops an attacker's authorization code being exchanged inside
     * this user's session.
     */
    if (returned_state && strcmp(returned_state, request.state) != 0) {
        fprintf(stderr, "state mismatch — refusing to exchange\n");
        axiam_authorization_request_dispose(&request);
        axiam_oidc_config_dispose(&doc);
        axiam_client_free(client);
        return 1;
    }

    axiam_oidc_exchange_params_t params = {0};
    params.code = code;
    params.code_verifier = request.code_verifier;
    params.redirect_uri = redirect_uri; /* byte-identical to step 2 */
    params.nonce = request.nonce;       /* §12.4 rule 6 is mandatory here */

    axiam_oidc_token_set_t tokens;
    if (axiam_oidc_exchange(client, &params, &tokens, &err) != AXIAM_OK) {
        /* An OAuth2 refusal names itself in err.oauth_error; an ID-token
         * validation failure names the §12.4 rule that failed in
         * err.id_token_reason. They are separate vocabularies on purpose. */
        fprintf(stderr, "exchange failed: %s (oauth=%s id_token=%s)\n",
                err.message, err.oauth_error, err.id_token_reason);
        axiam_authorization_request_dispose(&request);
        axiam_oidc_config_dispose(&doc);
        axiam_client_free(client);
        return 1;
    }

    /* §12.4 rule 7 already ran: if any rule had failed there would be no token
     * set at all, not a token set with unvalidated claims. */
    printf("\nSigned in.\n");
    printf("  token_type    %s (expires in %lds)\n", tokens.token_type, tokens.expires_in);
    printf("  access_token  %s\n", axiam_sensitive_to_string(tokens.access_token));
    if (tokens.id_claims) {
        printf("  sub           %s\n", tokens.id_claims->subject);
        printf("  iss           %s\n", tokens.id_claims->issuer);
        if (tokens.id_claims->email) printf("  email         %s\n", tokens.id_claims->email);
        /* §12.3 rule 5: a relying party's claims come from HERE. There is no
         * userinfo operation in this SDK and calling GET /oauth2/userinfo is
         * forbidden. */
    }

    /* --- 5. logout (§12.7, no network I/O) ---------------------------- */
    if (doc.end_session_endpoint) {
        /* The ID token goes in whole, as a plain string: §12.7.5 is explicit
         * that a wrapper whose purpose is to resist stringification is the
         * wrong type for a value about to be embedded in a URL. It still must
         * not be logged, which is why the URL below is not printed in full. */
        char *logout = axiam_logout_url(&doc, axiam_sensitive_reveal(tokens.id_token),
                                        env_or("AXIAM_POST_LOGOUT_URI", NULL),
                                        env_or("AXIAM_LOGOUT_STATE", NULL));
        if (logout) {
            printf("\nOn sign-out, redirect to the end-session endpoint "
                   "(URL withheld — it embeds the ID token).\n");
            free(logout);
        }
    }

    axiam_oidc_token_set_dispose(&tokens);
    axiam_authorization_request_dispose(&request);
    axiam_oidc_config_dispose(&doc);
    axiam_client_free(client);
    return 0;
}
