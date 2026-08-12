/*
 * AXIAM C SDK — Sensitive material wrapper (CONTRACT.md §7).
 *
 * An opaque handle for secret material (token strings, mTLS private keys).
 * Any diagnostic rendering yields the placeholder "[SENSITIVE]".
 *
 * There is exactly ONE public accessor that returns the raw string —
 * axiam_sensitive_reveal() — and §7 rule 3 permits exactly one. Everything else
 * about this type exists to make reading a secret a deliberate, greppable act
 * rather than something a `printf("%s", …)` does by accident.
 */
#ifndef AXIAM_SENSITIVE_H
#define AXIAM_SENSITIVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle to sensitive material. */
typedef struct axiam_sensitive axiam_sensitive_t;

/** Create from a NUL-terminated string. Returns NULL on OOM/NULL input. */
axiam_sensitive_t *axiam_sensitive_new(const char *value);

/** Create from a byte buffer (not necessarily NUL-terminated). */
axiam_sensitive_t *axiam_sensitive_new_bytes(const void *data, size_t len);

/** Zero the backing memory and free the handle. Safe on NULL. */
void axiam_sensitive_free(axiam_sensitive_t *s);

/**
 * Redacted rendering. ALWAYS returns the literal "[SENSITIVE]" regardless of
 * content — this is the only string representation the public API exposes.
 */
const char *axiam_sensitive_to_string(const axiam_sensitive_t *s);

/** Length in bytes of the wrapped material (metadata only, not the value). */
size_t axiam_sensitive_len(const axiam_sensitive_t *s);

/**
 * THE ONE EXPLICIT ACCESSOR (§7 rule 3). Returns the wrapped bytes as a
 * NUL-terminated string, or NULL when the handle is NULL. The pointer is
 * BORROWED — it belongs to the handle and becomes dangling at
 * axiam_sensitive_free().
 *
 * ADDED FOR §12 (contract 1.11). Before the OIDC port this SDK returned no
 * tokens to its caller, so the raw accessor could stay module-private. §12,
 * §14 and §15 all hand a token back for the application to put in an outbound
 * Authorization header, and a wrapper a caller can never read makes those
 * sections unusable — the same reasoning contract 1.5 recorded when it
 * restructured §7 for the eight SDKs that shipped §12 first.
 *
 * THE RESULT MUST NEVER REACH A LOG, TRACE, ERROR MESSAGE OR SERIALIZATION
 * SINK. Call this at the point of use — building one header, one form field —
 * and let the return value die there. `axiam_sensitive_to_string()` remains
 * what diagnostics call, and it still answers "[SENSITIVE]" whatever the
 * content.
 */
const char *axiam_sensitive_reveal(const axiam_sensitive_t *s);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_SENSITIVE_H */
