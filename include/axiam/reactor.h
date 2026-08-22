/*
 * AXIAM C SDK — Reactor (CONTRACT.md §22), the protocol core over a
 * caller-supplied transport.
 *
 * WHAT THIS SHIPS, AND WHAT IT DOES NOT.
 *
 * §22.1–§22.8 and §22.14 in full: the §8 v2 verification set on the event, the
 * canonical serialization and MAC in both directions, the §22.5 registry and its
 * mutable-field allow-lists, §22.8's strictest-wins default, and the declarative
 * binding table. What it does NOT do is open a connection. §22.11 defers only
 * the transport, because there is no maintained AMQP client for the targets this
 * SDK serves that this project is willing to vendor.
 *
 * That split is the newer one, and it is worth stating. Until contract 1.28 this
 * SDK shipped nothing from §22 while the section still bound an integrator to
 * §22.1–§22.8 — so the half deferred for want of a *dependency* was the
 * transport, and the half left to hand-roll from prose was the **protocol**: v2
 * HMAC over a canonical serialization with a `null` signature placeholder,
 * freshness in both directions, nonce and correlation binding, the allow-lists.
 * That is the half with the sharp edges, none of them AMQP-shaped, and asking
 * every integrator to reimplement it is how a signing bug ships.
 *
 * THE TRANSPORT SEAM HAS EXACTLY TWO CAPABILITIES (§22.11 rule 1): take the next
 * delivery, and publish a reply to a named destination. It is not wider than that
 * on purpose — a seam that also exposed declare, bind or queue-name derivation
 * would hand an integrator the tools §22.1 forbids using.
 */
#ifndef AXIAM_REACTOR_H
#define AXIAM_REACTOR_H

#include <stddef.h>
#include <stdint.h>

#include "axiam/error.h"
#include "axiam/sensitive.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* §22.5 — the event registry                                         */
/*                                                                    */
/* WHAT IS ABSENT IS LOAD-BEARING. §22.7 is a normative MUST NOT: the  */
/* three hot-path decision operations are not hookable, and no SDK may */
/* present them as such. They are in no constant here and in no list   */
/* here — §22.13 asserts on the constants, not on a comment. A reactor */
/* round trip is milliseconds; the check path's budget is microseconds.*/
/* An application needing external input on an authorization decision  */
/* writes a DENY GRANT, evaluated in the hot path at hot-path cost.    */
/* ------------------------------------------------------------------ */

#define AXIAM_REACTOR_EVENT_TOKEN_PRE_ISSUE  "token.pre_issue"
#define AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH  "login.post_auth"
#define AXIAM_REACTOR_EVENT_USER_PRE_CREATE  "user.pre_create"
#define AXIAM_REACTOR_EVENT_USER_PRE_UPDATE  "user.pre_update"
#define AXIAM_REACTOR_EVENT_GRANT_PRE_ASSIGN "grant.pre_assign"

/**
 * Every hookable event, in registry order — the COMPLETE list. An event absent
 * from it is not hookable, and that includes §22.7's three.
 *
 * @param out_count receives the length. The array is static; do not free it.
 */
const char *const *axiam_reactor_event_names(size_t *out_count);

/**
 * Whether `field` may appear in a patch for `event` (§22.5).
 *
 * A registry entry ending in `.` names a NAMESPACE: `ext.` admits
 * `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`, `extra`,
 * `external_id` (a prefix match on the string is not a match on the namespace)
 * and `evil.ext.department`.
 *
 * A QUERY, not a filter. §22.4 rule 1 sends a patch unfiltered, and nothing in
 * this SDK calls this to prune one.
 */
int axiam_reactor_patch_field_allowed(const char *event, const char *field);

/**
 * §22.8's strictest-wins default, in either array order. Returns a static
 * "fail_open" or "fail_closed"; never NULL.
 *
 * A reactor registered for both `token.pre_issue` (open) and `login.post_auth`
 * (closed) can veto a login, so it inherits fail_closed. Reducing this to "take
 * the first event's default" would let the order of a JSON array decide whether
 * an unreachable fraud check passes.
 */
const char *axiam_reactor_default_failure_policy(const char *const *events, size_t count);

/**
 * §22.1 topology names. RENDERING THESE IS NOT DECLARING THEM: a reactor
 * consumes the queue the server declared and never declares or binds anything.
 * Both return a malloc'd string the caller frees, or NULL on OOM.
 */
char *axiam_reactor_routing_key(const char *tenant_id, const char *event);
char *axiam_reactor_queue_name(const char *tenant_id, const char *reactor_id);

/* ------------------------------------------------------------------ */
/* §22.3 — the event, after verification                              */
/* ------------------------------------------------------------------ */

/**
 * A delivery that passed every §22.3 check. A handler never sees anything else:
 * a runtime that hands unverified bytes to user code has already lost, because
 * the handler will act on them and "we checked afterwards" is not a check.
 *
 * Every member is BORROWED from the runtime for the length of the handler call.
 * Copy anything that must outlive it.
 */
typedef struct axiam_reactor_event {
    const char *tenant_id;
    const char *event;
    const char *correlation_id;
    /**
     * The server's payload as JSON TEXT. Not a parsed model: parse it with
     * whatever your service already uses.
     *
     * `_reactor_patch`, when present, is the patch accumulated by earlier
     * reactors in the chain — READ-ONLY context. Echoing it back inside your own
     * patch is not how a field is preserved; the server merges (§22.6).
     */
    const char *payload_json;
    /** The window the server will wait (§22.10 rule 4). */
    long timeout_ms;
    const char *nonce;
} axiam_reactor_event_t;

/* ------------------------------------------------------------------ */
/* §22.4 — the reply                                                  */
/* ------------------------------------------------------------------ */

/** One patch entry. Both members are borrowed. */
typedef struct axiam_reactor_patch_entry {
    const char *key;
    const char *value;
} axiam_reactor_patch_entry_t;

/** The three answers, plus ABSTENTION. */
typedef enum axiam_reactor_answer_kind {
    /**
     * Publish no reply, and let the registration's `failure_policy` resolve the
     * event exactly as §22.8 resolves a timeout.
     *
     * What §22.14 rule 4 requires of an unbound event, and expressible by a plain
     * handler too: a handler that cannot decide must be able to say so rather
     * than pick one of the three answers on the operator's behalf. It is the ZERO
     * value, so a zeroed decision abstains — the safe default for a handler that
     * returned without filling one in.
     */
    AXIAM_REACTOR_ABSTAIN = 0,
    AXIAM_REACTOR_ALLOW = 1,
    AXIAM_REACTOR_DENY = 2,
    AXIAM_REACTOR_MUTATE = 3
} axiam_reactor_answer_kind_t;

/**
 * A handler's answer.
 *
 * There is deliberately no way to spell `allow` + `patch`: a patch travels only
 * on AXIAM_REACTOR_MUTATE (§22.4 rule 2).
 */
typedef struct axiam_reactor_decision {
    axiam_reactor_answer_kind_t kind;
    /**
     * DENY only. A deny with no reason still denies; the server substitutes
     * "denied by reactor". An empty or NULL reason is OMITTED, not sent as `""` —
     * the omission changes the canonical bytes and therefore the MAC.
     */
    const char *reason;
    /**
     * MUTATE only, and sent UNFILTERED (§22.4 rule 1). One forbidden key rejects
     * the WHOLE patch server-side, including the fields that would have been fine
     * — and dropping the offender to rescue the rest would leave the author
     * believing a field was set when it was dropped, which is exactly the failure
     * the server refuses to produce.
     *
     * Order does not matter: the entries are sorted into byte order before
     * signing, because that is what the server's BTreeMap emits.
     */
    const axiam_reactor_patch_entry_t *patch;
    size_t patch_count;
    /**
     * ALLOW only, and `login.post_auth` only. `allow` + require_mfa means
     * "proceed only after step-up"; it is NOT a fourth decision value.
     *
     * On the federated paths (SAML ACS, OIDC callback) there is no step-up
     * branch, so it FAILS the sign-in rather than being quietly dropped — answer
     * deny there and drive enrolment out of band (§22.5).
     */
    int require_mfa;
} axiam_reactor_decision_t;

/** Convenience constructors. Every one returns a value, never an allocation. */
axiam_reactor_decision_t axiam_reactor_allow(void);
axiam_reactor_decision_t axiam_reactor_allow_with_step_up(void);
axiam_reactor_decision_t axiam_reactor_deny(const char *reason);
axiam_reactor_decision_t axiam_reactor_mutate(const axiam_reactor_patch_entry_t *patch,
                                              size_t count);
axiam_reactor_decision_t axiam_reactor_abstain(void);

/* ------------------------------------------------------------------ */
/* §22.11 — the transport seam                                        */
/* ------------------------------------------------------------------ */

/** One inbound message, as the broker hands it over. */
typedef struct axiam_reactor_delivery {
    /** The raw message body. Verified by the runtime, never by the transport. */
    const char *body;
    /** The `reply_to` basic property — where the reply is published. */
    const char *reply_to;
    /** The `correlation_id` basic property. */
    const char *correlation_id;
} axiam_reactor_delivery_t;

/**
 * EXACTLY TWO CAPABILITIES (§22.11 rule 1). Deliberately not wider: a seam that
 * also exposed declare, bind or queue-name derivation would hand the integrator
 * the tools §22.1 forbids using.
 */
typedef struct axiam_reactor_transport {
    void *ctx;
    /**
     * Fill `out` with the next delivery and return 1, or return 0 when the
     * consumer is done — which is how axiam_reactor_serve() returns. The strings
     * must stay valid until the next call.
     */
    int (*next_delivery)(void *ctx, axiam_reactor_delivery_t *out);
    /** Publish a signed reply. `destination` is the delivery's `reply_to`. */
    void (*publish_reply)(void *ctx, const char *destination, const char *correlation_id,
                          const char *body);
} axiam_reactor_transport_t;

/* ------------------------------------------------------------------ */
/* §22.10 — the runtime                                               */
/* ------------------------------------------------------------------ */

/** One function from a verified event to one answer (§22.10). */
typedef axiam_reactor_decision_t (*axiam_reactor_handler_fn)(const axiam_reactor_event_t *event,
                                                             void *ctx);

typedef struct axiam_reactor_config {
    /**
     * The tenant this reactor is registered for. An event naming another tenant
     * is refused AFTER the MAC — identity is not cryptography, and spending it on
     * unauthenticated bytes tells an unauthenticated party what this reactor
     * accepts.
     */
    const char *tenant_id;
    const char *reactor_id;
    /**
     * The tenant's HKDF-derived AMQP subkey (§8.1) as RAW BYTES — the same key in
     * both directions. §22.12 makes it a credential: it MUST NOT be logged at any
     * level, and MUST NOT appear in a reconnect diagnostic.
     */
    const axiam_sensitive_t *signing_key;

    /**
     * Test seams. §22.13's sign-direction vectors pin an exact `issued_at` and
     * `nonce`, and a runtime whose values are unreachable can only be tested
     * through a reimplementation of the thing under test. Leave both NULL in
     * production, where they default to the real clock and a CSPRNG.
     */
    long (*clock_fn)(void *ctx);      /**< Unix seconds. */
    void *clock_ctx;
    /** Writes a NUL-terminated nonce into `out` (at least 64 bytes). */
    void (*nonce_fn)(void *ctx, char *out, size_t n);
    void *nonce_ctx;
} axiam_reactor_config_t;

/**
 * Consume, verify, dispatch, sign, publish — until the transport is done.
 *
 * For each delivery, in this order (§22.3): refuse `key_version` below 2; verify
 * the MAC; check freshness in BOTH directions; check the nonce against a seen-set
 * held for this call's whole lifetime. Only then is the handler invoked.
 *
 * Four rules from §22.10, all of them observable:
 *
 *  1. It declares no topology (§22.1). The transport is not even given the
 *     vocabulary to.
 *  2. It FAILS CLOSED on its own errors. A body it cannot verify, or a decision
 *     it cannot serialize, produces NO REPLY — letting the server's
 *     `failure_policy` decide. A runtime that answered `allow` on behalf of a
 *     handler that did not would have overridden the operator's `fail_closed`
 *     setting from inside the library.
 *  3. It does not filter a patch (§22.4 rule 1).
 *  4. It honours `timeout_ms` by abandoning work whose window has closed rather
 *     than replying late.
 *
 * @return AXIAM_OK when the transport ran dry, or an error for a configuration
 *         problem raised before the first delivery.
 */
axiam_error_kind_t axiam_reactor_serve(const axiam_reactor_config_t *config,
                                       const axiam_reactor_transport_t *transport,
                                       axiam_reactor_handler_fn handler, void *handler_ctx,
                                       axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* §22.14 — declarative handler binding                               */
/* ------------------------------------------------------------------ */

/**
 * A binding table: one handler per event, composed into the single handler
 * axiam_reactor_serve() takes.
 *
 * §22.10's handler is ONE function from an event to one answer, which is the
 * right shape for the wire and the wrong shape for the code. A reactor registered
 * for three events opens with a dispatch on `event->event`, and that dispatch is
 * where two defects live. The first is cheap: a misspelled event name compiles,
 * binds nothing, and is discovered as an event that never fires. The second is
 * not — it is the catch-all arm that returns `allow` on behalf of code that never
 * ran, which is §22.10 rule 2's defect relocated into user code where the rule
 * does not reach it.
 *
 * A TABLE rather than an attribute, for the same reason Go's is: C has no
 * metadata mechanism to reach for (§22.14).
 *
 * PURE SUGAR. It opens no connection, consumes no queue, verifies no event, signs
 * no reply and interprets no `timeout_ms`; its output is exactly the handler
 * axiam_reactor_serve() takes (rule 1).
 */
typedef struct axiam_reactor_router axiam_reactor_router_t;

/** Create an empty router, or NULL on OOM. */
axiam_reactor_router_t *axiam_reactor_router_new(void);
void axiam_reactor_router_free(axiam_reactor_router_t *router);

/**
 * Bind `handler` to `event`.
 *
 * @return AXIAM_ERR_AUTH when `event` is not in the §22.5 registry — AT BIND
 *         TIME, not at dispatch time. Failing when the binding is written is the
 *         entire point: a typo that survives to production is discovered as
 *         silence, and silence on a `fail_open` event is indistinguishable from a
 *         healthy reactor with nothing to say. This is also how §22.7's three
 *         hot-path operations are refused — they are in no registry row, so they
 *         fail like any other unknown name, and the message names the registry
 *         rather than naming what is absent from it.
 *
 *         Also AXIAM_ERR_AUTH on a second binding for an already-bound event
 *         (rule 3). Never a silent overwrite: which of two handlers runs is not
 *         something the author of either can see from their own file.
 */
axiam_error_kind_t axiam_reactor_router_on(axiam_reactor_router_t *router, const char *event,
                                           axiam_reactor_handler_fn handler, void *ctx,
                                           axiam_error_t *err);

/**
 * An explicit fallback for unbound events.
 *
 * OPTIONAL, and it has no default (rule 4). Without one an unbound event
 * ABSTAINS — no reply, and the registration's `failure_policy` resolves it. It is
 * not answered `allow`, and not answered `deny` either: the binder does not know
 * what the registration was for, and the operator's policy does.
 */
axiam_error_kind_t axiam_reactor_router_fallback(axiam_reactor_router_t *router,
                                                 axiam_reactor_handler_fn handler, void *ctx,
                                                 axiam_error_t *err);

/**
 * The bound event names, so a reactor author can compute §22.8's strictest-wins
 * default from the code that actually handles the events rather than from a
 * restatement of the registration. Borrowed; valid until the router is freed.
 */
const char *const *axiam_reactor_router_bound_events(const axiam_reactor_router_t *router,
                                                     size_t *out_count);

/**
 * The composed handler, to pass to axiam_reactor_serve() with the router itself
 * as `handler_ctx`.
 *
 * A handler's own behaviour reaches the runtime UNCHANGED (rule 5): nothing here
 * converts an answer into another one, because §22.10 rule 2 puts the fail-closed
 * obligation on the runtime and a binder that intercepted first would satisfy the
 * letter of that rule while defeating it.
 */
axiam_reactor_handler_fn axiam_reactor_router_handler(void);

/* ------------------------------------------------------------------ */
/* §8b rules 1–5 — the broker URL guard                               */
/* ------------------------------------------------------------------ */

/**
 * A validated broker endpoint: everything a caller needs to open an `amqps://`
 * connection, and nothing that could open a plaintext one.
 *
 * Dispose with axiam_amqps_endpoint_dispose(); safe on NULL and on a zeroed
 * struct, so a caller may dispose unconditionally on the error path.
 */
typedef struct axiam_amqps_endpoint {
    char *url;          /**< The validated `amqps://` URL, unchanged. */
    char *host;
    int port;           /**< The broker TLS port, defaulted when the URL omits it. */
    char *virtual_host; /**< "/" when the URL carries no path. */
    char *ca_pem;       /**< A privately-issued broker certificate's CA. */
    char *client_cert_pem;
    char *client_key_pem;
} axiam_amqps_endpoint_t;

void axiam_amqps_endpoint_dispose(axiam_amqps_endpoint_t *endpoint);

/**
 * Validate a broker URL and its TLS material against §8b rules 1–5.
 *
 * §22.11 rule 3 is why this is a PUBLIC, TESTED FUNCTION rather than a paragraph.
 * §8b rule 7 cannot be satisfied by a runtime that never sees a URL — this SDK
 * bundles no AMQP client — so the SDK hands the integrator the check instead.
 * Documenting the requirement is precisely the failure contract 1.23 was written
 * to stop: three SDKs asserting `amqps://` in a doc comment above a call that
 * accepted anything.
 *
 * What it enforces:
 *
 *  1. The scheme MUST be `amqps://`. Every other scheme is refused, `amqp://`
 *     included, and there is NO LOOPBACK EXCEPTION (§8b rule 8): this applies to
 *     `localhost`, `127.0.0.1` and `::1` exactly as to any other host. §6's
 *     `http://localhost` dev carve-out does not extend here, and the server has
 *     no plaintext listener for such an exception to reach.
 *  2. A custom CA bundle is supported, because an in-cluster broker's certificate
 *     is not issued by a public CA — the common case, and it exists so nobody has
 *     a legitimate reason to want rule 4 relaxed.
 *  3. A client certificate and its key are required TOGETHER. Half a client
 *     identity fails closed rather than connecting without the mutual half.
 *  4. There is no verification-skip option, under any name. It is the most
 *     reliably misused option in TLS: it appears in a dev compose file, it works,
 *     and it travels unchanged into production, where it turns TLS into an
 *     expensive no-op against precisely the attacker TLS exists to stop.
 *  5. There is no plaintext fallback. A failed `amqps://` connection is an error
 *     to surface, not a condition to work around — and this call offers no way to
 *     express one.
 *
 * @return AXIAM_ERR_AUTH on any refusal, naming the rule. An unparseable URL
 *         fails closed: a URL this cannot read is not a URL it can vouch for.
 */
axiam_error_kind_t axiam_amqps_endpoint(const char *url, const char *ca_pem,
                                        const char *client_cert_pem, const char *client_key_pem,
                                        axiam_amqps_endpoint_t *out, axiam_error_t *err);

/* ------------------------------------------------------------------ */
/* §22.2 / §22.3 — the primitives, exposed because §22.13 tests them   */
/* ------------------------------------------------------------------ */

/** Why a delivery was refused. A CATEGORY, never the MAC, the key or the payload. */
typedef enum axiam_reactor_refusal {
    AXIAM_REACTOR_OK = 0,
    AXIAM_REACTOR_MALFORMED = 1,
    AXIAM_REACTOR_KEY_VERSION_TOO_OLD = 2,
    AXIAM_REACTOR_BAD_SIGNATURE = 3,
    AXIAM_REACTOR_STALE = 4,
    AXIAM_REACTOR_REPLAY = 5,
    AXIAM_REACTOR_TENANT_MISMATCH = 6,
    AXIAM_REACTOR_UNKNOWN_EVENT = 7
} axiam_reactor_refusal_t;

/** An opaque nonce seen-set. One per reactor, for its whole lifetime. */
typedef struct axiam_reactor_nonce_set axiam_reactor_nonce_set_t;

axiam_reactor_nonce_set_t *axiam_reactor_nonce_set_new(void);
void axiam_reactor_nonce_set_free(axiam_reactor_nonce_set_t *set);

/**
 * A verified event and the storage its borrowed strings point into. Dispose with
 * axiam_reactor_verified_dispose().
 */
typedef struct axiam_reactor_verified {
    axiam_reactor_event_t event;
    void *owned; /**< Opaque backing storage; not for inspection. */
} axiam_reactor_verified_t;

void axiam_reactor_verified_dispose(axiam_reactor_verified_t *verified);

/**
 * Verify one delivery body against §22.3, in order: `key_version` before anything
 * else about the body is considered; then the MAC over the body with
 * `hmac_signature` set to **null**; then freshness in both directions; then the
 * nonce. Identity and registry membership come after the MAC.
 *
 * `now` is Unix seconds. `seen` may be NULL to skip replay dedup — a real reactor
 * keeps one set for its whole lifetime, and building a fresh one per delivery
 * defeats the check entirely, which is why axiam_reactor_serve() owns one.
 */
axiam_reactor_refusal_t axiam_reactor_verify_event(const axiam_sensitive_t *signing_key,
                                                   const char *body, const char *expected_tenant,
                                                   long now, axiam_reactor_nonce_set_t *seen,
                                                   axiam_reactor_verified_t *out);

/**
 * The exact bytes a reply is signed over, before the MAC replaces the `null`
 * placeholder. Exposed because §22.13's sign-direction vectors compare against
 * `canonical_signed_json` byte-for-byte.
 *
 * @return a malloc'd string the caller frees, or NULL on OOM or on a decision
 *         this cannot serialize.
 */
char *axiam_reactor_canonical_reply(const char *correlation_id, const char *tenant_id,
                                    const char *event,
                                    const axiam_reactor_decision_t *decision, const char *nonce,
                                    const char *issued_at);

/**
 * The reply as it goes on the wire: the canonical bytes with the `null`
 * placeholder replaced by the MAC computed over them.
 *
 * WHAT EXACTLY IS SIGNED: the message serialized in its DECLARED FIELD ORDER,
 * with `hmac_signature` present and set to **null** — not omitted. That differs
 * from §8's own two message types, whose `hmac_signature` is absent from their
 * canonical bytes, and it is the single most likely place to produce a MAC that
 * will not verify.
 *
 * @return a malloc'd string the caller frees, or NULL when the decision is
 *         refused: `require_mfa` on any event other than `login.post_auth`
 *         (§22.4 row 7), or a `mutate` carrying an empty patch. Both are refusals
 *         rather than corrections — the result is NO REPLY, and the
 *         registration's failure policy decides.
 */
char *axiam_reactor_build_reply(const axiam_sensitive_t *signing_key, const char *correlation_id,
                                const char *tenant_id, const char *event,
                                const axiam_reactor_decision_t *decision, const char *nonce,
                                const char *issued_at);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_REACTOR_H */
