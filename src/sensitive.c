#include <stdlib.h>
#include <string.h>

#include "internal.h"

static const char AXIAM_REDACTED[] = "[SENSITIVE]";

axiam_sensitive_t *axiam_sensitive_new(const char *value) {
    if (!value) return NULL;
    return axiam_sensitive_new_bytes(value, strlen(value));
}

axiam_sensitive_t *axiam_sensitive_new_bytes(const void *data, size_t len) {
    if (!data) return NULL;
    axiam_sensitive_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->data = malloc(len + 1);
    if (!s->data) {
        free(s);
        return NULL;
    }
    memcpy(s->data, data, len);
    s->data[len] = '\0';
    s->len = len;
    return s;
}

void axiam_sensitive_free(axiam_sensitive_t *s) {
    if (!s) return;
    if (s->data) {
        /* Best-effort scrub before release (§7). */
        memset(s->data, 0, s->len);
        free(s->data);
    }
    free(s);
}

const char *axiam_sensitive_to_string(const axiam_sensitive_t *s) {
    (void)s;
    return AXIAM_REDACTED;
}

size_t axiam_sensitive_len(const axiam_sensitive_t *s) {
    return s ? s->len : 0;
}

const unsigned char *axiam_sensitive_bytes(const axiam_sensitive_t *s) {
    return s ? s->data : NULL;
}
