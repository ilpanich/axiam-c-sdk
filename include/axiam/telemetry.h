/*
 * AXIAM C SDK — Telemetry hooks (CONTRACT.md §19).
 *
 * An optional callback surface so a caller can wire OpenTelemetry, Prometheus
 * or a log line WITHOUT this library depending on any of them. Install one with
 * axiam_client_config_set_telemetry_hook(); with none installed the cost is a
 * single NULL check per request.
 *
 * Two of §19.2's rules are enforced by the shape of this header rather than
 * left to documentation:
 *
 *   - No secrets, ever (§19.2 rule 3). The event is a fixed struct with a fixed
 *     field list and NO free-form map or body pointer. There is nowhere to put
 *     a token in a payload bound for a metrics backend — the type, not a review
 *     comment, is what keeps them out.
 *   - No cost when uninstalled (§19.2 rule 1). Every field is a borrowed
 *     pointer or a scalar; nothing is allocated to build an event.
 *
 * LIFETIME: every `const char *` in an event borrows storage owned by the SDK
 * and valid only for the duration of the hook call. A hook that needs to keep a
 * string MUST copy it. Every pointer is either NULL or NUL-terminated; a field
 * not carried by the event's kind is NULL (or 0).
 *
 * THREADING: the hook is invoked on the calling thread, inside the operation
 * that produced the event, and MUST NOT block (§19.2 rule 4). Buffering is the
 * caller's job so they can pick the policy; every mature metrics library
 * already buffers.
 */
#ifndef AXIAM_TELEMETRY_H
#define AXIAM_TELEMETRY_H

#ifdef __cplusplus
extern "C" {
#endif

/** Which §19.1 event this is; selects the meaningful fields below. */
typedef enum axiam_telemetry_kind {
    /** Before an outbound call leaves the SDK. */
    AXIAM_TELEMETRY_REQUEST_START = 1,
    /** After a call completes, success or failure. */
    AXIAM_TELEMETRY_REQUEST_END = 2,
    /** Before each §16 retry wait. */
    AXIAM_TELEMETRY_RETRY = 3,
    /** Around a §9 single-flight refresh. */
    AXIAM_TELEMETRY_REFRESH = 4,
    /** At construction, once per clamped setting (§19.2 rule 6). */
    AXIAM_TELEMETRY_CONFIG_CLAMPED = 5
} axiam_telemetry_kind_t;

/** Why a request finished. */
typedef enum axiam_telemetry_outcome {
    AXIAM_TELEMETRY_SUCCESS = 0, /**< The call returned a usable response. */
    AXIAM_TELEMETRY_FAILURE = 1  /**< The call failed, at any layer. */
} axiam_telemetry_outcome_t;

/** Whether this caller performed a §9 refresh or waited on another thread's. */
typedef enum axiam_refresh_role {
    AXIAM_REFRESH_LEADER = 0,  /**< This caller performed the refresh. */
    AXIAM_REFRESH_FOLLOWER = 1 /**< This caller waited on another's. */
} axiam_refresh_role_t;

/**
 * One §19.1 event.
 *
 * A single tagged struct rather than a union of five: C has no sealed
 * hierarchy, and a discriminated struct is the closest thing that keeps the
 * "fixed field set, nowhere to hide a secret" guarantee checkable by reading
 * one declaration.
 */
typedef struct axiam_telemetry_event {
    /** Which event this is. Read this before any other field. */
    axiam_telemetry_kind_t kind;

    /* --- request_start, request_end, retry --- */

    /** Canonical operation name, e.g. "check_access". NULL for other kinds. */
    const char *operation;
    /** HTTP method. NULL outside request_start / request_end. */
    const char *method;
    /**
     * The route CONSTANT — "/api/v1/authz/check", never a URL with ids
     * substituted in. A metric label carrying a UUID is a cardinality bomb.
     */
    const char *path_template;
    /** 1 for the first try, incrementing per §16 retry. 0 for other kinds. */
    int attempt;

    /* --- request_end --- */

    /** HTTP status, or 0 when the call never got a response. */
    long status;
    /** Wall-clock time this attempt took, in milliseconds. */
    double duration_ms;
    /** Success or failure. */
    axiam_telemetry_outcome_t outcome;

    /* --- retry --- */

    /** The wait about to be taken, after jitter and any Retry-After. */
    long delay_ms;
    /**
     * A redacted description of the failure that triggered the retry. Carries
     * a status or a transport message, never a token — §2 redacts transport
     * errors at construction.
     */
    const char *reason;

    /* --- refresh --- */

    /** Whether this caller led or followed the §9 refresh. */
    axiam_refresh_role_t refresh_role;

    /* --- config_clamped --- */

    /** The setting's name, e.g. "decision_memo_ttl_ms". */
    const char *setting;
    /** The value the caller asked for, rendered. */
    const char *requested;
    /** The value actually in force, rendered. */
    const char *effective;
    /** The §-reference for the limit, e.g. "§17.1 rule 2". */
    const char *contract_reference;
} axiam_telemetry_event_t;

/**
 * A caller-supplied telemetry sink (§19).
 *
 * @param ctx   the opaque pointer registered alongside this function. NOT owned
 *              by the SDK; it must outlive the client.
 * @param event borrowed for the duration of the call; see LIFETIME above.
 */
typedef void (*axiam_telemetry_hook_fn)(void *ctx,
                                        const axiam_telemetry_event_t *event);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_TELEMETRY_H */
