#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "internal.h"

char *axiam_strdup0(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

int axiam_str_ieq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    return strcasecmp(a, b) == 0;
}

int axiam_is_pem(const char *s) {
    if (!s) return 0;
    return strstr(s, "-----BEGIN") != NULL;
}

void axiam_secure_zero(void *p, size_t n) {
    if (!p) return;
    /* A plain memset() before free() is a dead store the compiler may elide;
     * writing through a volatile pointer keeps the scrub observable (§7). */
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* ---- transport-URL scheme guard (§6) ---- */

/* The sole exception to the plaintext ban: a loopback authority, so local
 * development / integration tests against a non-TLS dev server still work.
 * Mirrors the Rust SDK's `is_loopback_host`. */
static int is_loopback_host(const char *host, size_t len) {
    static const char *const loopback[] = {"localhost", "127.0.0.1", "::1", "[::1]"};
    for (size_t i = 0; i < sizeof(loopback) / sizeof(loopback[0]); i++) {
        if (strlen(loopback[i]) == len && strncasecmp(host, loopback[i], len) == 0)
            return 1;
    }
    return 0;
}

int axiam_url_is_secure(const char *url) {
    if (!url) return 0;
    const char *sep = strstr(url, "://");
    if (!sep || sep == url) return 0; /* no scheme at all — not a usable base URL */

    size_t scheme_len = (size_t)(sep - url);
    if (scheme_len == 5 && strncasecmp(url, "https", 5) == 0) return 1;

    /* Non-TLS scheme: tolerated only for a loopback authority. */
    const char *authority = sep + 3;
    size_t auth_len = strcspn(authority, "/?#");

    /* Drop any userinfo ("user:pass@host"). The LAST '@' delimits it, so
     * "http://localhost@evil.example/" resolves to the host `evil.example`
     * and is correctly refused. */
    const char *host = authority;
    size_t host_len = auth_len;
    for (size_t i = 0; i < auth_len; i++) {
        if (authority[i] == '@') {
            host = authority + i + 1;
            host_len = auth_len - i - 1;
        }
    }

    /* Strip the port, keeping a bracketed IPv6 literal intact. */
    if (host_len > 0 && host[0] == '[') {
        const char *close = memchr(host, ']', host_len);
        if (close) host_len = (size_t)(close - host) + 1;
    } else {
        const char *colon = memchr(host, ':', host_len);
        if (colon) host_len = (size_t)(colon - host);
    }
    return is_loopback_host(host, host_len);
}

/* ---- header key/value list ---- */

axiam_kv_t *axiam_kv_append(axiam_kv_t *head, const char *key, const char *value) {
    if (!key) return head;
    axiam_kv_t *node = calloc(1, sizeof(*node));
    if (!node) return head;
    node->key = axiam_strdup0(key);
    node->value = axiam_strdup0(value ? value : "");
    node->next = NULL;
    if (!head) return node;
    axiam_kv_t *cur = head;
    while (cur->next) cur = cur->next;
    cur->next = node;
    return head;
}

const char *axiam_kv_get(const axiam_kv_t *head, const char *key) {
    for (const axiam_kv_t *cur = head; cur; cur = cur->next) {
        if (axiam_str_ieq(cur->key, key)) return cur->value;
    }
    return NULL;
}

void axiam_kv_free(axiam_kv_t *head) {
    while (head) {
        axiam_kv_t *next = head->next;
        free(head->key);
        free(head->value);
        free(head);
        head = next;
    }
}

void axiam_http_response_dispose(axiam_http_response_t *resp) {
    if (!resp) return;
    free(resp->body);
    resp->body = NULL;
    axiam_kv_free(resp->headers);
    resp->headers = NULL;
    free(resp->transport_msg);
    resp->transport_msg = NULL;
}

/* ---- base64url decode (RFC 4648 §5, no padding required) ---- */

static int b64url_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

unsigned char *axiam_b64url_decode(const char *in, size_t in_len, size_t *out_len) {
    if (!in) return NULL;
    /* Strip any trailing '=' padding tolerated for robustness. */
    while (in_len > 0 && in[in_len - 1] == '=') in_len--;
    size_t full = in_len / 4;
    size_t rem = in_len % 4;
    if (rem == 1) return NULL; /* invalid length */
    size_t out_cap = full * 3 + (rem ? rem - 1 : 0) + 1;
    unsigned char *out = malloc(out_cap);
    if (!out) return NULL;
    size_t o = 0;
    size_t i = 0;
    while (i + 4 <= in_len) {
        int a = b64url_val((unsigned char)in[i]);
        int b = b64url_val((unsigned char)in[i + 1]);
        int c = b64url_val((unsigned char)in[i + 2]);
        int d = b64url_val((unsigned char)in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); return NULL; }
        unsigned v = (unsigned)a << 18 | (unsigned)b << 12 | (unsigned)c << 6 | (unsigned)d;
        out[o++] = (unsigned char)(v >> 16);
        out[o++] = (unsigned char)(v >> 8);
        out[o++] = (unsigned char)v;
        i += 4;
    }
    if (rem == 2) {
        int a = b64url_val((unsigned char)in[i]);
        int b = b64url_val((unsigned char)in[i + 1]);
        if (a < 0 || b < 0) { free(out); return NULL; }
        unsigned v = (unsigned)a << 18 | (unsigned)b << 12;
        out[o++] = (unsigned char)(v >> 16);
    } else if (rem == 3) {
        int a = b64url_val((unsigned char)in[i]);
        int b = b64url_val((unsigned char)in[i + 1]);
        int c = b64url_val((unsigned char)in[i + 2]);
        if (a < 0 || b < 0 || c < 0) { free(out); return NULL; }
        unsigned v = (unsigned)a << 18 | (unsigned)b << 12 | (unsigned)c << 6;
        out[o++] = (unsigned char)(v >> 16);
        out[o++] = (unsigned char)(v >> 8);
    }
    out[o] = '\0';
    if (out_len) *out_len = o;
    return out;
}

char *axiam_url_encode(const char *s) {
    static const char hex[] = "0123456789ABCDEF";
    if (!s) return NULL;
    /* Worst case every byte expands to three. */
    size_t n = strlen(s);
    char *out = malloc(n * 3 + 1);
    if (!out) return NULL;
    size_t at = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        int unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                         (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                         ch == '_' || ch == '~';
        if (unreserved) {
            out[at++] = (char)ch;
        } else {
            out[at++] = '%';
            out[at++] = hex[ch >> 4];
            out[at++] = hex[ch & 0xF];
        }
    }
    out[at] = '\0';
    return out;
}
