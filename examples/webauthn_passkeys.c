/*
 * webauthn_passkeys.c — enrolling and using a passkey from C (CONTRACT.md §24).
 *
 * THE THING THIS EXAMPLE IS REALLY ABOUT. A C program has no authenticator.
 * There is no platform API to link on the targets this SDK serves, and §24.6b
 * rule 2 forbids emulating one in software — a "credential" held in process
 * memory is not a second factor. So this SDK ships the six wire operations and
 * §24.6a's JSON bridge, and nothing else.
 *
 * That is a statement about convenience, not capability. The bridge is the
 * whole interface: axiam_webauthn_request_json() hands out the challenge in the
 * exact JSON form every platform authenticator API takes, and every *_finish
 * takes the platform's response JSON back as a string, byte for byte. An
 * embedded gateway fronting a browser, a native app talking to a C service, or
 * a test harness driving a virtual authenticator all use the same two seams —
 * and the bytes the authenticator signed reach the server unchanged, which is
 * the only reason any of it verifies.
 *
 * Where the ceremony actually happens is marked below. In a real program those
 * two blocks are an IPC round trip, a WebSocket message, or a local HTTP
 * endpoint your front end calls.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/webauthn_passkeys
 */
#include <axiam/axiam.h>
#include <axiam/webauthn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

/*
 * Stand-in for the platform. In a real program this is where the challenge
 * crosses into something that owns an authenticator, and what comes back is
 * that platform's response JSON — returned here verbatim, exactly as it must
 * be forwarded.
 *
 * The SDK will not touch these bytes: it splices the string into the request
 * body without parsing it into a model and printing it back out, because a
 * signed buffer that makes a round trip through a JSON model is a signed buffer
 * that can come out different. Member order, unmodelled fields and large
 * integers all survive, and the server's signature check is the reason that
 * matters.
 */
static char *run_ceremony_on_the_platform(const char *request_json) {
    printf("  → hand this to the authenticator, unchanged:\n    %s\n", request_json);
    printf("  ← the platform answers with its response JSON; forward it verbatim\n");
    return NULL; /* no authenticator here — see the header comment */
}

static void enrol_a_passkey(axiam_client_t *client) {
    axiam_error_t err;
    axiam_webauthn_challenge_t challenge;

    /*
     * register/start requires a session and refuses CLIENT-SIDE with no wire
     * call when there is none: a passkey is enrolled BY a signed-in user, for
     * themselves. A 503 here is a configuration state, not a transient one —
     * the tenant's attestation policy needs FIDO metadata the server cannot
     * reach — and §24.4 rule 2 deliberately does not retry it.
     */
    if (axiam_webauthn_register_start(client, &challenge, &err) != AXIAM_OK) {
        fprintf(stderr, "register/start failed: %s\n", err.message);
        axiam_webauthn_challenge_dispose(&challenge);
        return;
    }

    /*
     * §24.6a rule 1: the INNER options object. The `publicKey` wrapper the
     * server sends belongs to the DOM's CredentialCreationOptions, and the
     * platform JSON APIs — parseCreationOptionsFromJSON() in a browser,
     * CreatePublicKeyCredentialRequest on Android — do not want it.
     */
    char *request_json = axiam_webauthn_request_json(&challenge);
    char *response = request_json ? run_ceremony_on_the_platform(request_json) : NULL;
    free(request_json);

    if (!response) {
        printf("  (no authenticator in this process — stopping here)\n");
        axiam_webauthn_challenge_dispose(&challenge);
        return;
    }

    axiam_webauthn_credential_t credential;
    axiam_error_kind_t kind = axiam_webauthn_register_finish(
        client, challenge.state_token, "Ada's laptop", response, &credential, &err);
    free(response);

    if (kind == AXIAM_OK) {
        printf("  enrolled %s (%s), created %s\n", credential.name,
               credential.credential_type, credential.created_at);
    } else {
        /*
         * The one error whose BODY matters (§24.4 rule 1). A 403 here means the
         * tenant's attestation policy rejected THIS authenticator, and the
         * server's message is the only place that says which one would be
         * accepted — "register/finish failed" tells the person holding the key
         * nothing they can act on.
         */
        fprintf(stderr, "register/finish failed: %s\n", err.message);
    }
    axiam_webauthn_credential_dispose(&credential);
    axiam_webauthn_challenge_dispose(&challenge);
}

static void sign_in_with_a_discoverable_credential(axiam_client_t *client) {
    axiam_error_t err;
    axiam_webauthn_challenge_t challenge;

    /*
     * A PRIMARY factor, and a different flow from the second-factor ceremony
     * rather than the same one with a flag (§24.2). Nothing precedes it, so
     * there is no challenge token to carry the workspace — which is why this is
     * the one WebAuthn endpoint that names the workspace explicitly. Passing
     * NULL fills it from the client's own configuration.
     */
    if (axiam_webauthn_discoverable_start(client, NULL, &challenge, &err) != AXIAM_OK) {
        fprintf(stderr, "discoverable/start failed: %s\n", err.message);
        axiam_webauthn_challenge_dispose(&challenge);
        return;
    }

    char *request_json = axiam_webauthn_request_json(&challenge);
    char *response = request_json ? run_ceremony_on_the_platform(request_json) : NULL;
    free(request_json);

    if (!response) {
        printf("  (no authenticator in this process — stopping here)\n");
        axiam_webauthn_challenge_dispose(&challenge);
        return;
    }

    axiam_webauthn_login_t login;
    axiam_error_kind_t kind = axiam_webauthn_discoverable_finish(
        client, challenge.state_token, response, &login, &err);
    free(response);

    if (kind == AXIAM_OK) {
        /*
         * §24.3: the client is now signed in. The server set the same cookie
         * triple POST /api/v1/auth/login sets, the §17 decision memo was
         * cleared because the subject changed, and a caller who only wanted a
         * session can dispose this result immediately.
         */
        printf("  signed in, session %s (%ld s)\n", login.session_id, login.expires_in);
    } else {
        fprintf(stderr, "discoverable/finish failed: %s\n", err.message);
    }
    axiam_webauthn_login_dispose(&login);
    axiam_webauthn_challenge_dispose(&challenge);
}

/*
 * §24.6b rule 5, and required of every SDK claiming §24 even where no ceremony
 * helper exists. Whatever DID run the ceremony reports its failure as one
 * opaque type whose only machine-readable part is a name; translating that once
 * beats translating it in every caller.
 *
 * Note what AXIAM_WEBAUTHN_CANCELLED covers: both an explicit refusal AND a
 * silent timeout. The spec deliberately refuses to distinguish them, because
 * telling a website which one happened leaks whether an authenticator was
 * present — so copy that says "you cancelled" is wrong half the time it shows.
 */
static void explain_a_ceremony_failure(const char *platform_error_name) {
    axiam_webauthn_failure_t failure = axiam_webauthn_classify(platform_error_name);
    printf("  %-20s → %s\n", platform_error_name,
           axiam_webauthn_failure_message(failure));
}

int main(void) {
    const char *base_url    = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const char *tenant_slug = getenv_or("AXIAM_TENANT_SLUG", "acme");
    const char *org_slug    = getenv_or("AXIAM_ORG_SLUG", "acme");
    const char *email       = getenv_or("AXIAM_EMAIL", "user@example.com");
    const char *password    = getenv_or("AXIAM_PASSWORD", "changeme");

    axiam_client_config_t *cfg = axiam_client_config_new();
    if (!cfg) {
        fprintf(stderr, "out of memory allocating config\n");
        return 1;
    }
    axiam_client_config_set_base_url(cfg, base_url);
    axiam_client_config_set_tenant_slug(cfg, tenant_slug); /* §5   */
    axiam_client_config_set_org_slug(cfg, org_slug);       /* §5.1 */

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!client) {
        fprintf(stderr, "config error: %s\n", err.message);
        return 1;
    }

    printf("failure classification (§24.6b rule 5):\n");
    explain_a_ceremony_failure("NotAllowedError");
    explain_a_ceremony_failure("InvalidStateError");
    explain_a_ceremony_failure("NotSupportedError");
    explain_a_ceremony_failure("SomeFutureError");

    printf("\nusernameless sign-in (§24.2):\n");
    sign_in_with_a_discoverable_credential(client);

    axiam_login_result_t login = {0};
    if (axiam_login(client, email, password, &login, &err) == AXIAM_OK &&
        login.authenticated) {
        printf("\nenrolling a passkey for the signed-in user (§24.1):\n");
        enrol_a_passkey(client);
    } else {
        printf("\n(sign in to enrol a passkey — register/* requires a session)\n");
    }
    axiam_login_result_dispose(&login);

    axiam_client_free(client);
    return 0;
}
