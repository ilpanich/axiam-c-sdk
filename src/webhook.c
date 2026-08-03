/*
 * Webhook signature verification (CONTRACT.md §13, T-145).
 *
 * v1 = HMAC-SHA256(secret, "<t>.<raw_body>"), hex lowercase. The comparison is
 * constant-time over the DECODED bytes (an explicit volatile accumulator, no
 * memcmp and no early return), the freshness check is two-sided, and every
 * failure path fails closed without ever revealing the expected MAC.
 */
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>

#include "internal.h"

#define AXIAM_WEBHOOK_MAC_LEN 32   /* SHA-256 output */
#define AXIAM_WEBHOOK_HEX_LEN 64   /* hex-encoded MAC */

/* ------------------------------------------------------------------ */
/* Small parsing helpers                                              */
/* ------------------------------------------------------------------ */

static int is_ws(char c) { return c == ' ' || c == '\t'; }

/* Iterate the comma-separated `key=value` pairs of a signature header.
 * Advances *cursor and returns 1 while a pair was produced, 0 at the end.
 * Keys/values are returned as (pointer, length) slices with surrounding
 * whitespace trimmed; an element with no '=' yields a zero-length key. */
static int sig_next_pair(const char **cursor, const char **k, size_t *klen,
                         const char **v, size_t *vlen) {
    const char *p = *cursor;
    if (!p || *p == '\0') return 0;

    const char *comma = strchr(p, ',');
    const char *end = comma ? comma : p + strlen(p);
    *cursor = comma ? comma + 1 : end;

    const char *eq = memchr(p, '=', (size_t)(end - p));
    const char *kb = p;
    const char *ke = eq ? eq : end;
    const char *vb = eq ? eq + 1 : end;
    const char *ve = end;

    while (kb < ke && is_ws(*kb)) kb++;
    while (ke > kb && is_ws(ke[-1])) ke--;
    while (vb < ve && is_ws(*vb)) vb++;
    while (ve > vb && is_ws(ve[-1])) ve--;

    *k = kb;
    *klen = (size_t)(ke - kb);
    *v = vb;
    *vlen = (size_t)(ve - vb);
    return 1;
}

static int slice_eq(const char *s, size_t len, const char *lit) {
    return strlen(lit) == len && memcmp(s, lit, len) == 0;
}

/* Strict non-negative decimal parse. Returns 1 on success. Any non-digit, an
 * empty slice, or an out-of-range value is a parse failure (never a silent 0). */
static int parse_unix_seconds(const char *s, size_t len, long long *out) {
    if (len == 0 || len > 19) return 0;
    long long v = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        if (v > (LLONG_MAX - (s[i] - '0')) / 10) return 0;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 1;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a 64-char hex MAC. Returns 1 on success; a failed decode fails closed
 * (the caller treats it as a non-matching candidate). */
static int hex_decode_mac(const char *hex, size_t len, unsigned char *out) {
    if (len != AXIAM_WEBHOOK_HEX_LEN) return 0;
    for (size_t i = 0; i < AXIAM_WEBHOOK_MAC_LEN; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* Constant-time byte comparison: every byte is always examined and the result
 * is only inspected after the full pass (no memcmp, no early return). */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* ------------------------------------------------------------------ */
/* Core verification                                                  */
/* ------------------------------------------------------------------ */

axiam_webhook_status_t axiam_webhook_verify_at(const axiam_sensitive_t *secret,
                                               const char *signature_header,
                                               const void *body, size_t body_len,
                                               long tolerance_secs,
                                               long long now_unix,
                                               long long *out_timestamp) {
    if (out_timestamp) *out_timestamp = 0;
    if (!secret || !signature_header) return AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT;
    if (!body && body_len > 0) return AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT;
    if (tolerance_secs <= 0) tolerance_secs = AXIAM_WEBHOOK_DEFAULT_TOLERANCE_SECS;

    /* Pass 1: locate exactly one `t` and at least one `v1`. Unknown keys and
     * future schemes are ignored for forward compatibility, but a header with
     * nothing to verify is a failure — never a silent success. */
    const char *cursor = signature_header;
    const char *k = NULL, *v = NULL;
    size_t klen = 0, vlen = 0;
    const char *t_raw = NULL;
    size_t t_raw_len = 0;
    int t_count = 0, v1_count = 0;
    while (sig_next_pair(&cursor, &k, &klen, &v, &vlen)) {
        if (slice_eq(k, klen, "t")) {
            t_count++;
            t_raw = v;
            t_raw_len = vlen;
        } else if (slice_eq(k, klen, "v1")) {
            v1_count++;
        }
    }
    if (t_count != 1 || v1_count == 0) return AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE;

    long long ts = 0;
    if (!parse_unix_seconds(t_raw, t_raw_len, &ts))
        return AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE;

    /* Signed payload: the `t` bytes exactly as they appear in the header,
     * a '.', then the untouched body bytes. */
    size_t signed_len = t_raw_len + 1 + body_len;
    unsigned char *signed_buf = malloc(signed_len ? signed_len : 1);
    if (!signed_buf) return AXIAM_WEBHOOK_ERR_INTERNAL;
    memcpy(signed_buf, t_raw, t_raw_len);
    signed_buf[t_raw_len] = '.';
    if (body_len) memcpy(signed_buf + t_raw_len + 1, body, body_len);

    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    const unsigned char *key = axiam_sensitive_bytes(secret);
    unsigned char *mac = HMAC(EVP_sha256(), key, (int)axiam_sensitive_len(secret),
                              signed_buf, signed_len, expected, &expected_len);
    free(signed_buf);
    if (!mac || expected_len != AXIAM_WEBHOOK_MAC_LEN) {
        axiam_secure_zero(expected, sizeof(expected));
        return AXIAM_WEBHOOK_ERR_INTERNAL;
    }

    /* Pass 2: compare every supplied `v1` in constant time. The loop never
     * breaks early — the verdict is only read after all candidates. */
    int matched = 0;
    cursor = signature_header;
    while (sig_next_pair(&cursor, &k, &klen, &v, &vlen)) {
        if (!slice_eq(k, klen, "v1")) continue;
        unsigned char candidate[AXIAM_WEBHOOK_MAC_LEN];
        int decoded = hex_decode_mac(v, vlen, candidate);
        int eq = decoded && ct_equal(candidate, expected, AXIAM_WEBHOOK_MAC_LEN);
        matched |= eq;
        axiam_secure_zero(candidate, sizeof(candidate));
    }
    axiam_secure_zero(expected, sizeof(expected));
    if (!matched) return AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH;

    /* Two-sided freshness: a future-dated `t` is refused like a stale one. */
    long long delta = (ts > now_unix) ? (ts - now_unix) : (now_unix - ts);
    if (delta > (long long)tolerance_secs) return AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP;

    if (out_timestamp) *out_timestamp = ts;
    return AXIAM_WEBHOOK_OK;
}

axiam_webhook_status_t axiam_webhook_verify(const axiam_sensitive_t *secret,
                                            const char *signature_header,
                                            const void *body, size_t body_len,
                                            long tolerance_secs,
                                            long long *out_timestamp) {
    return axiam_webhook_verify_at(secret, signature_header, body, body_len,
                                   tolerance_secs, (long long)time(NULL),
                                   out_timestamp);
}

axiam_webhook_status_t axiam_webhook_verify_headers(const axiam_sensitive_t *secret,
                                                    const axiam_kv_t *headers,
                                                    const void *body, size_t body_len,
                                                    long tolerance_secs,
                                                    axiam_webhook_event_t *out_event) {
    if (out_event) memset(out_event, 0, sizeof(*out_event));
    const char *sig = axiam_kv_get(headers, "X-Axiam-Signature");
    if (!sig) return AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE;

    long long ts = 0;
    axiam_webhook_status_t st = axiam_webhook_verify(secret, sig, body, body_len,
                                                     tolerance_secs, &ts);
    if (st != AXIAM_WEBHOOK_OK) return st;

    /* X-Axiam-Timestamp is redundant with `t=` and is NOT what the MAC covers;
     * when present it must agree, else the delivery is refused. */
    const char *ts_hdr = axiam_kv_get(headers, "X-Axiam-Timestamp");
    if (ts_hdr) {
        long long hdr_ts = 0;
        if (!parse_unix_seconds(ts_hdr, strlen(ts_hdr), &hdr_ts) || hdr_ts != ts)
            return AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE;
    }

    if (out_event) {
        out_event->timestamp = ts;
        out_event->event_type = axiam_strdup0(axiam_kv_get(headers, "X-Axiam-Event"));
        out_event->delivery_id = axiam_strdup0(axiam_kv_get(headers, "X-Axiam-Delivery"));
        out_event->body = malloc(body_len + 1);
        if (!out_event->body) {
            axiam_webhook_event_dispose(out_event);
            return AXIAM_WEBHOOK_ERR_INTERNAL;
        }
        if (body_len) memcpy(out_event->body, body, body_len);
        out_event->body[body_len] = '\0';
        out_event->body_len = body_len;
    }
    return AXIAM_WEBHOOK_OK;
}

void axiam_webhook_event_dispose(axiam_webhook_event_t *ev) {
    if (!ev) return;
    free(ev->event_type);
    free(ev->delivery_id);
    free(ev->body);
    memset(ev, 0, sizeof(*ev));
}

const char *axiam_webhook_status_str(axiam_webhook_status_t status) {
    switch (status) {
    case AXIAM_WEBHOOK_OK: return "ok";
    case AXIAM_WEBHOOK_ERR_INVALID_ARGUMENT: return "invalid argument";
    case AXIAM_WEBHOOK_ERR_MALFORMED_SIGNATURE: return "malformed signature header";
    case AXIAM_WEBHOOK_ERR_SIGNATURE_MISMATCH: return "signature mismatch";
    case AXIAM_WEBHOOK_ERR_STALE_TIMESTAMP: return "timestamp outside the freshness window";
    case AXIAM_WEBHOOK_ERR_INTERNAL: return "internal verification failure";
    }
    return "unknown";
}
