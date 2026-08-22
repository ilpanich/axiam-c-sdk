/*
 * reactor.c — an AXIAM Reactor on the SDK's §22 protocol core, driven by a
 * transport you supply (CONTRACT.md §22, §22.11).
 *
 * A REACTOR is an external service AXIAM consults synchronously at five points
 * in its own flows: it may veto a login, enrich a token, or adjust a user before
 * creation. §22.1–§22.8 and §22.14 are in the library — verification, canonical
 * signing, the registry and its allow-lists, the runtime, the binder.
 *
 * WHAT THIS SDK DOES NOT SHIP IS A CONNECTION. §22.11 defers the transport, and
 * only the transport: there is no maintained AMQP client for these targets this
 * project is willing to vendor, which is the same reason §8 has never listed C
 * among the SDKs that speak AMQP. `rabbitmq-c` is the usual choice here; wire it
 * behind the two function pointers below and nothing else moves.
 *
 * Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 * Run:    ./build/examples/reactor
 */
#include <axiam/axiam.h>
#include <axiam/reactor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

/* ------------------------------------------------------------------ */
/* The transport seam — the part this project does not fill for you   */
/*                                                                    */
/* Its obligations are §22.1's and §8b's, not the runtime's:          */
/*                                                                    */
/*  * connect over `amqps://` with a supplied CA bundle —             */
/*    axiam_amqps_endpoint() below is the check, and §22.11 rule 3 is */
/*    why it is a FUNCTION rather than a paragraph;                   */
/*  * consume axiam_reactor_queue_name(tenant, reactor), the queue    */
/*    the SERVER declared, with manual acknowledgement;               */
/*  * DECLARE NOTHING. No exchange, no queue, no binding. §22.1 is a  */
/*    MUST NOT, and note that this struct gives you no member with    */
/*    which to;                                                       */
/*  * publish the reply to the delivery's `reply_to` through the      */
/*    default exchange, echoing its `correlation_id` property.        */
/*                                                                    */
/* Everything above the transport — verify, dispatch, sign,           */
/* publish-or-abstain — is axiam_reactor_serve()'s, including the     */
/* rule that a failure of its own publishes NOTHING.                  */
/* ------------------------------------------------------------------ */

typedef struct {
    const char **bodies;
    int n;
    int at;
    int published;
} demo_transport_t;

static int demo_next(void *ctx, axiam_reactor_delivery_t *out) {
    demo_transport_t *t = ctx;
    if (t->at >= t->n) return 0;
    out->body = t->bodies[t->at++];
    out->reply_to = "amq.rabbitmq.reply-to.example";
    out->correlation_id = NULL;
    return 1;
}

static void demo_publish(void *ctx, const char *destination, const char *correlation_id,
                         const char *body) {
    demo_transport_t *t = ctx;
    t->published++;
    printf("  → publish to %s (correlation %s)\n    %s\n", destination, correlation_id, body);
}

/* ------------------------------------------------------------------ */
/* The handlers an integrator writes                                  */
/* ------------------------------------------------------------------ */

static axiam_reactor_decision_t on_login(const axiam_reactor_event_t *event, void *ctx) {
    (void)ctx;
    /* The payload arrives as JSON TEXT — parse it with whatever your service
     * already uses. Do NOT log it at info level by default (§22.12): it is
     * tenant business data, even though it is not a §7 secret. */
    if (strstr(event->payload_json, "203.0.113.")) {
        /* `allow` + require_mfa on login.post_auth means "proceed only after
         * step-up". It is not a fourth decision value, and on the federated paths
         * (SAML ACS, OIDC callback) there is no step-up branch — answer deny there
         * and drive enrolment out of band (§22.5). */
        return axiam_reactor_allow_with_step_up();
    }
    return axiam_reactor_allow();
}

static axiam_reactor_decision_t on_token(const axiam_reactor_event_t *event, void *ctx) {
    (void)event;
    (void)ctx;
    /* `ext.` is the complete allow-list for this event: no standard claim begins
     * with it, so `sub`, `aud` and the rest are unreachable — a hook that could
     * rewrite `sub` is a hook that could mint a token for anyone.
     *
     * The entries are borrowed for the length of the reply, so `static` here; a
     * stack array would be gone by the time the runtime signed it. */
    static const axiam_reactor_patch_entry_t patch[] = {{"ext.department", "engineering"}};
    return axiam_reactor_mutate(patch, 1);
}

int main(void) {
    printf("AXIAM reactor sample — CONTRACT.md §22.\n"
           "The protocol core is the SDK's; the transport below is yours (§22.11).\n\n");

    /* -----------------------------------------------------------------
     * §8b rules 1–5, BEFORE anything opens a socket.
     *
     * This is the constructor §8b rule 7's second clause names: where an SDK
     * takes a caller-supplied connection, it must still ship the guard, and that
     * guard is what its README and examples show. Documenting the requirement
     * instead is precisely the failure contract 1.23 was written to stop.
     * ----------------------------------------------------------------- */
    axiam_error_t err;
    axiam_amqps_endpoint_t endpoint;
    printf("§8b — the broker URL, checked before a socket exists\n");
    if (axiam_amqps_endpoint(getenv_or("AXIAM_AMQP_URL", "amqps://broker.internal:5671/prod"),
                             getenv_or("AXIAM_AMQP_CA_PEM", NULL), NULL, NULL, &endpoint,
                             &err) != AXIAM_OK) {
        fprintf(stderr, "  refused: %s\n", err.message);
        axiam_amqps_endpoint_dispose(&endpoint);
        return 1;
    }
    printf("  ok   %s:%d vhost %s\n", endpoint.host, endpoint.port, endpoint.virtual_host);
    axiam_amqps_endpoint_dispose(&endpoint);

    /* There is NO loopback exception (§8b rule 8): §6's `http://localhost` dev
     * carve-out does not extend to the broker, and the server has no plaintext
     * listener for such an exception to reach. */
    const char *plaintext = "amqp://localhost:5672"; /* refused below — §8b rules 1 and 8 */
    if (axiam_amqps_endpoint(plaintext, NULL, NULL, NULL, &endpoint, &err) == AXIAM_OK) {
        fprintf(stderr, "  plaintext localhost must be refused\n");
        axiam_amqps_endpoint_dispose(&endpoint);
        return 1;
    }
    axiam_amqps_endpoint_dispose(&endpoint);
    printf("  ok   amqp://localhost is refused — no loopback exception\n");

    /* -----------------------------------------------------------------
     * §22.14 — bind one handler per event.
     *
     * The alternative is a switch on event->event with a `default:` arm, and that
     * arm is where §22.14's second defect lives: it answers on behalf of code
     * that never ran, defeating an operator's `fail_closed` from a file they
     * never read. Here an unbound event ABSTAINS.
     * ----------------------------------------------------------------- */
    axiam_reactor_router_t *router = axiam_reactor_router_new();
    if (!router) return 1;
    if (axiam_reactor_router_on(router, AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH, on_login, NULL,
                                &err) != AXIAM_OK ||
        axiam_reactor_router_on(router, AXIAM_REACTOR_EVENT_TOKEN_PRE_ISSUE, on_token, NULL,
                                &err) != AXIAM_OK) {
        fprintf(stderr, "binding failed: %s\n", err.message);
        axiam_reactor_router_free(router);
        return 1;
    }

    size_t bound_count = 0;
    const char *const *bound = axiam_reactor_router_bound_events(router, &bound_count);
    printf("\n§22.8 — this reactor's strictest-wins default: %s\n",
           axiam_reactor_default_failure_policy(bound, bound_count));

    const char *tenant = getenv_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111");
    const char *reactor_id =
        getenv_or("AXIAM_REACTOR_ID", "99999999-9999-9999-9999-999999999999");
    char *queue = axiam_reactor_queue_name(tenant, reactor_id);
    printf("§22.1 — the queue the SERVER declared and this reactor consumes: %s\n", queue);
    free(queue);

    /* -----------------------------------------------------------------
     * §22.10 — the runtime, over the transport above.
     *
     * The signing key is the tenant's HKDF-derived AMQP subkey (§8.1) as RAW
     * BYTES. §22.12 makes it a credential: it must not appear at any log level,
     * nor in a reconnect diagnostic, which is why it is Sensitive.
     * ----------------------------------------------------------------- */
    axiam_sensitive_t *signing_key =
        axiam_sensitive_new(getenv_or("AXIAM_REACTOR_SIGNING_KEY", "not-a-real-key"));
    printf("§22.12 — the signing key renders as %s\n", axiam_sensitive_to_string(signing_key));

    const char *bodies[] = {"{\"not\":\"a signed event\"}"};
    demo_transport_t demo = {bodies, 1, 0, 0};
    axiam_reactor_transport_t transport;
    transport.ctx = &demo;
    transport.next_delivery = demo_next;
    transport.publish_reply = demo_publish;

    axiam_reactor_config_t config;
    memset(&config, 0, sizeof(config));
    config.tenant_id = tenant;
    config.reactor_id = reactor_id;
    config.signing_key = signing_key;

    printf("\n§22.3/§22.10 — verify, dispatch, sign, publish\n");
    axiam_reactor_serve(&config, &transport, axiam_reactor_router_handler(), router, &err);
    /* The delivery above is unsigned, so it is refused — and a refusal publishes
     * NOTHING rather than a synthesized allow (§22.10 rule 2). Point the
     * transport at a real broker and this is where replies start flowing. */
    printf("  %d replies published (an unsigned delivery is never answered)\n", demo.published);

    axiam_sensitive_free(signing_key);
    axiam_reactor_router_free(router);
    return 0;
}
