/*
 * AXIAM C SDK — Sensitive material wrapper (CONTRACT.md §7).
 *
 * An opaque handle for secret material (token strings, mTLS private keys).
 * There is deliberately NO public accessor that returns the raw string.
 * Any diagnostic rendering yields the placeholder "[SENSITIVE]".
 * SDK-internal code obtains the raw bytes through a module-private accessor
 * declared in internal.h — never through this public header.
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

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_SENSITIVE_H */
