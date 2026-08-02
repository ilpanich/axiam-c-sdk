/*
 * AXIAM C SDK — Webhook signature verification (CONTRACT.md §13, T-145).
 *
 * AXIAM signs every webhook delivery with a Stripe-style signed timestamp:
 *
 *   X-Axiam-Timestamp: 1785700000
 *   X-Axiam-Signature: t=1785700000,v1=<hex_lowercase_hmac_sha256>
 *   X-Axiam-Event:     user.created
 *   X-Axiam-Delivery:  <uuid>
 *
 * where `v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`.
 *
 * IMPORTANT — the body must be the EXACT raw bytes received off the wire.
 * Never re-serialize parsed JSON before verifying: key order and whitespace
 * changes break the MAC.
 *
 * `t=` (not `X-Axiam-Timestamp`) is the value covered by the MAC and is what
 * these helpers parse; axiam_webhook_verify_headers() additionally requires
 * the separate timestamp header, when present, to agree with it.
 *
 * The comparison is constant-time over the decoded MAC bytes, freshness is
 * two-sided (a future-dated timestamp is refused just like a stale one), and
 * every failure is a typed status that never carries the expected signature.
 *
 * Deliveries are at-least-once: a retry replays a valid signature inside the
 * freshness window, so receivers MUST de-duplicate on `X-Axiam-Delivery`
 * (exposed as axiam_webhook_event_t.delivery_id) with a short-lived seen-set.
 */
#ifndef AXIAM_WEBHOOK_H
#define AXIAM_WEBHOOK_H

#include <stddef.h>

#include "axiam/sensitive.h"
#include "axiam/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default freshness window in seconds (CONTRACT §13). */
#define AXIAM_WEBHOOK_DEFAULT_TOLERANCE_SECS 300

/** Outcome of a webhook verification. Anything other than AXIAM_WEBHOOK_OK
 *  means the delivery MUST be rejected. */
typedef enum axiam_webhook_status {
    AXIAM_WEBHOOK_OK = 0,               /**< Signature valid and fresh. */
    AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT, /**< NULL secret/header/body pairing. */
    AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE, /**< No/duplicate `t`, no `v1`, non-numeric `t`,
                                            *   or a timestamp header disagreeing with `t`. */
    AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH,  /**< No supplied `v1` matched. */
    AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP,     /**< |now - t| exceeded the tolerance. */
    AXIAM_WEBHOOK_ERR_INTERNAL             /**< HMAC/allocation failure. */
} axiam_webhook_status_t;

/** A verified delivery. Free the heap members with axiam_webhook_event_dispose. */
typedef struct axiam_webhook_event {
    char *event_type;   /**< X-Axiam-Event value, or NULL when absent. */
    char *delivery_id;  /**< X-Axiam-Delivery value (dedup key), or NULL. */
    char *body;         /**< Copy of the raw body, NUL-terminated for convenience. */
    size_t body_len;    /**< Length of body in bytes (excluding the NUL). */
    long long timestamp;/**< The verified `t` value, unix seconds. */
} axiam_webhook_event_t;

/** Release the heap members of an event (not the struct itself). Safe on NULL. */
void axiam_webhook_event_dispose(axiam_webhook_event_t *ev);

/**
 * Verify an `X-Axiam-Signature` header against the raw body.
 *
 * @param secret            the webhook's plaintext secret, behind Sensitive (§7).
 * @param signature_header  the raw `X-Axiam-Signature` value.
 * @param body              raw request body bytes (may be NULL only when body_len is 0).
 * @param body_len          length of body in bytes.
 * @param tolerance_secs    freshness window; <= 0 selects
 *                          AXIAM_WEBHOOK_DEFAULT_TOLERANCE_SECS.
 * @param out_timestamp     optional; receives the verified `t` on success.
 * @return AXIAM_WEBHOOK_OK, or a typed failure.
 */
axiam_webhook_status_t axiam_webhook_verify(const axiam_sensitive_t *secret,
                                            const char *signature_header,
                                            const void *body, size_t body_len,
                                            long tolerance_secs,
                                            long long *out_timestamp);

/**
 * As axiam_webhook_verify(), with the current time injected (unix seconds).
 * This is the seam tests use to exercise the freshness window deterministically.
 */
axiam_webhook_status_t axiam_webhook_verify_at(const axiam_sensitive_t *secret,
                                               const char *signature_header,
                                               const void *body, size_t body_len,
                                               long tolerance_secs,
                                               long long now_unix,
                                               long long *out_timestamp);

/**
 * Verify a delivery from its full header list, and on success populate
 * out_event with the event type, delivery id (dedup key) and body copy.
 *
 * Requires `X-Axiam-Signature`. When `X-Axiam-Timestamp` is also present it
 * MUST equal the `t=` field, else the delivery is refused as malformed.
 * out_event may be NULL if only the verdict is wanted.
 */
axiam_webhook_status_t axiam_webhook_verify_headers(const axiam_sensitive_t *secret,
                                                    const axiam_kv_t *headers,
                                                    const void *body, size_t body_len,
                                                    long tolerance_secs,
                                                    axiam_webhook_event_t *out_event);

/** Stable, secret-free description of a status (diagnostics). */
const char *axiam_webhook_status_str(axiam_webhook_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_WEBHOOK_H */
