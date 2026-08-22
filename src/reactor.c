/*
 * AXIAM C SDK — Reactor (CONTRACT.md §22), the protocol core.
 *
 * §22.1–§22.8 and §22.14 over a transport the caller supplies. §22.11 defers
 * only the connection: the half that genuinely needed a vendored dependency was
 * the AMQP client, and the runtime around it needed none.
 *
 * THE ONE THING THIS FILE IS CAREFUL ABOUT. Both canonical forms are built by
 * hand rather than printed from a cJSON object. The signed bytes are the message
 * in its DECLARED FIELD ORDER with `hmac_signature` present and set to **null** —
 * not omitted, unlike §8's own two message types — and a JSON library will order
 * keys its own way and will drop or reorder the null. Every MAC here depends on
 * getting that exactly right, and §22.13's committed vectors are what says it is.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "cJSON.h"
#include "axiam/reactor.h"
#include "internal.h"

/* §8 v2 / §22.2: a body carrying less than this is refused before anything else
 * about it is considered — including its signature. */
#define REACTOR_KEY_VERSION 2
/* ±freshness window, applied in BOTH directions. A future timestamp is not
 * "extra fresh"; it is the shape of a captured message held for later. */
#define REACTOR_FRESHNESS_SKEW_SECS 300L

/* ------------------------------------------------------------------ */
/* §22.5 — the registry                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    int mutable_event;
    const char *fields[4]; /* exact names, or a `.`-suffixed namespace; NULL-terminated */
    const char *default_failure_policy;
} reactor_spec_t;

static const reactor_spec_t REGISTRY[] = {
    /* `ext.` is the COMPLETE allow-list here: no standard claim begins with it,
     * so `sub`, `aud`, `exp`, `scope` and the rest are unreachable. A hook that
     * could rewrite `sub` is a hook that could mint a token for anyone, and a
     * CORRECTLY SIGNED reply setting it is refused exactly as a forged one is. */
    {AXIAM_REACTOR_EVENT_TOKEN_PRE_ISSUE, 1, {"ext.", NULL, NULL, NULL}, "fail_open"},
    {AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH, 0, {NULL, NULL, NULL, NULL}, "fail_closed"},
    {AXIAM_REACTOR_EVENT_USER_PRE_CREATE, 1,
     {"username", "email", "metadata.", NULL}, "fail_closed"},
    {AXIAM_REACTOR_EVENT_USER_PRE_UPDATE, 1,
     {"username", "email", "metadata.", NULL}, "fail_closed"},
    {AXIAM_REACTOR_EVENT_GRANT_PRE_ASSIGN, 0, {NULL, NULL, NULL, NULL}, "fail_closed"},
};
#define REGISTRY_LEN (sizeof(REGISTRY) / sizeof(REGISTRY[0]))

static const reactor_spec_t *spec_for(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < REGISTRY_LEN; i++) {
        if (strcmp(name, REGISTRY[i].name) == 0) return &REGISTRY[i];
    }
    return NULL; /* includes every operation §22.7 keeps out of the registry */
}

const char *const *axiam_reactor_event_names(size_t *out_count) {
    static const char *names[REGISTRY_LEN];
    static int filled = 0;
    if (!filled) {
        for (size_t i = 0; i < REGISTRY_LEN; i++) names[i] = REGISTRY[i].name;
        filled = 1;
    }
    if (out_count) *out_count = REGISTRY_LEN;
    return names;
}

int axiam_reactor_patch_field_allowed(const char *event, const char *field) {
    const reactor_spec_t *spec = spec_for(event);
    if (!spec || !spec->mutable_event || !field) return 0;
    for (int i = 0; i < 4 && spec->fields[i]; i++) {
        const char *allowed = spec->fields[i];
        size_t n = strlen(allowed);
        /* §22.5's namespace-prefix rule: an entry ending in `.` matches a field
         * starting with the entry AND carrying at least one character after the
         * dot. `ext.` admits `ext.department` and `ext.a.b.c`; it refuses `ext.`
         * itself (that names the namespace, not a claim), `ext`, `extra`,
         * `external_id` (a prefix match on the string is not a match on the
         * namespace) and `evil.ext.department`. */
        if (n > 0 && allowed[n - 1] == '.') {
            if (strlen(field) > n && strncmp(field, allowed, n) == 0) return 1;
            continue;
        }
        if (strcmp(field, allowed) == 0) return 1;
    }
    return 0;
}

const char *axiam_reactor_default_failure_policy(const char *const *events, size_t count) {
    if (!events || count == 0) return "fail_closed";
    for (size_t i = 0; i < count; i++) {
        const reactor_spec_t *spec = spec_for(events[i]);
        if (!spec || strcmp(spec->default_failure_policy, "fail_closed") == 0) {
            return "fail_closed";
        }
    }
    return "fail_open";
}

char *axiam_reactor_routing_key(const char *tenant_id, const char *event) {
    if (!tenant_id || !event) return NULL;
    size_t n = strlen(tenant_id) + strlen(event) + 2;
    char *out = malloc(n);
    if (out) snprintf(out, n, "%s.%s", tenant_id, event);
    return out;
}

char *axiam_reactor_queue_name(const char *tenant_id, const char *reactor_id) {
    if (!tenant_id || !reactor_id) return NULL;
    const char *prefix = "axiam.reactor.q.";
    size_t n = strlen(prefix) + strlen(tenant_id) + strlen(reactor_id) + 2;
    char *out = malloc(n);
    if (out) snprintf(out, n, "%s%s.%s", prefix, tenant_id, reactor_id);
    return out;
}

/* ------------------------------------------------------------------ */
/* §22.2 — canonicalization and the HMAC                              */
/* ------------------------------------------------------------------ */

/** A growable text buffer. Returns 0 on OOM, at which point `sb` is freed. */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    int failed;
} sb_t;

static int sb_append(sb_t *sb, const char *text, size_t n) {
    if (sb->failed) return 0;
    if (sb->len + n + 1 > sb->cap) {
        size_t next = sb->cap ? sb->cap : 256;
        while (next < sb->len + n + 1) next *= 2;
        char *grown = realloc(sb->buf, next);
        if (!grown) {
            free(sb->buf);
            sb->buf = NULL;
            sb->failed = 1;
            return 0;
        }
        sb->buf = grown;
        sb->cap = next;
    }
    memcpy(sb->buf + sb->len, text, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 1;
}

static int sb_puts(sb_t *sb, const char *text) { return sb_append(sb, text, strlen(text)); }

/**
 * serde_json's string escaping: the two mandatory escapes, the five short forms,
 * `\u00XX` for the remaining control characters — and NOTHING else. Forward
 * slashes stay literal and UTF-8 passes through unescaped, which is where a naive
 * port usually diverges.
 */
static int sb_quoted(sb_t *sb, const char *value) {
    if (!sb_puts(sb, "\"")) return 0;
    for (const unsigned char *p = (const unsigned char *)(value ? value : ""); *p; p++) {
        switch (*p) {
        case '"':  if (!sb_puts(sb, "\\\"")) return 0; break;
        case '\\': if (!sb_puts(sb, "\\\\")) return 0; break;
        case '\b': if (!sb_puts(sb, "\\b")) return 0; break;
        case '\f': if (!sb_puts(sb, "\\f")) return 0; break;
        case '\n': if (!sb_puts(sb, "\\n")) return 0; break;
        case '\r': if (!sb_puts(sb, "\\r")) return 0; break;
        case '\t': if (!sb_puts(sb, "\\t")) return 0; break;
        default:
            if (*p < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)*p);
                if (!sb_puts(sb, esc)) return 0;
            } else {
                char one = (char)*p;
                if (!sb_append(sb, &one, 1)) return 0;
            }
        }
    }
    return sb_puts(sb, "\"");
}

static char *hmac_sha256_hex(const axiam_sensitive_t *key, const char *bytes, size_t n) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    const unsigned char *raw = (const unsigned char *)axiam_sensitive_bytes(key);
    if (!HMAC(EVP_sha256(), raw, (int)axiam_sensitive_len(key),
              (const unsigned char *)bytes, n, mac, &len)) {
        return NULL;
    }
    char *hex = malloc((size_t)len * 2 + 1);
    if (!hex) return NULL;
    for (unsigned int i = 0; i < len; i++) snprintf(hex + i * 2, 3, "%02x", mac[i]);
    return hex;
}

/** Constant-time comparison. Never strcmp on the hex strings. */
static int constant_time_equals(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/**
 * Field order, event (server → reactor): tenant_id, event, correlation_id,
 * payload, timeout_ms, key_version, nonce, issued_at, hmac_signature (null).
 *
 * `payload` is re-emitted through cJSON's compact print. That is safe here and
 * ONLY here: the server's payload map is a BTreeMap, so its keys are already in
 * byte order, and cJSON preserves the order it parsed them in. Everything above
 * this line is hand-ordered because the top-level order is the server's STRUCT
 * DECLARATION order, which no library will reproduce.
 */
static char *canonical_event(const cJSON *message) {
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(message, "payload");
    char *payload_text = cJSON_PrintUnformatted(payload);
    if (!payload_text) return NULL;

    sb_t sb = {0};
    char number[32];
    sb_puts(&sb, "{\"tenant_id\":");
    sb_quoted(&sb, cJSON_GetObjectItemCaseSensitive(message, "tenant_id")->valuestring);
    sb_puts(&sb, ",\"event\":");
    sb_quoted(&sb, cJSON_GetObjectItemCaseSensitive(message, "event")->valuestring);
    sb_puts(&sb, ",\"correlation_id\":");
    sb_quoted(&sb, cJSON_GetObjectItemCaseSensitive(message, "correlation_id")->valuestring);
    sb_puts(&sb, ",\"payload\":");
    sb_puts(&sb, payload_text);
    snprintf(number, sizeof(number), ",\"timeout_ms\":%lld",
             (long long)cJSON_GetObjectItemCaseSensitive(message, "timeout_ms")->valuedouble);
    sb_puts(&sb, number);
    snprintf(number, sizeof(number), ",\"key_version\":%lld",
             (long long)cJSON_GetObjectItemCaseSensitive(message, "key_version")->valuedouble);
    sb_puts(&sb, number);
    sb_puts(&sb, ",\"nonce\":");
    sb_quoted(&sb, cJSON_GetObjectItemCaseSensitive(message, "nonce")->valuestring);
    sb_puts(&sb, ",\"issued_at\":");
    sb_quoted(&sb, cJSON_GetObjectItemCaseSensitive(message, "issued_at")->valuestring);
    sb_puts(&sb, ",\"hmac_signature\":null}");
    free(payload_text);
    return sb.failed ? NULL : sb.buf;
}

/* ------------------------------------------------------------------ */
/* §22.4 — the decision                                               */
/* ------------------------------------------------------------------ */

axiam_reactor_decision_t axiam_reactor_allow(void) {
    axiam_reactor_decision_t d;
    memset(&d, 0, sizeof(d));
    d.kind = AXIAM_REACTOR_ALLOW;
    return d;
}

axiam_reactor_decision_t axiam_reactor_allow_with_step_up(void) {
    axiam_reactor_decision_t d = axiam_reactor_allow();
    d.require_mfa = 1;
    return d;
}

axiam_reactor_decision_t axiam_reactor_deny(const char *reason) {
    axiam_reactor_decision_t d;
    memset(&d, 0, sizeof(d));
    d.kind = AXIAM_REACTOR_DENY;
    /* An empty reason is OMITTED, not sent as "": the server substitutes
     * "denied by reactor", and the omission changes the canonical bytes. */
    d.reason = (reason && reason[0]) ? reason : NULL;
    return d;
}

axiam_reactor_decision_t axiam_reactor_mutate(const axiam_reactor_patch_entry_t *patch,
                                              size_t count) {
    axiam_reactor_decision_t d;
    memset(&d, 0, sizeof(d));
    d.kind = AXIAM_REACTOR_MUTATE;
    d.patch = patch;
    d.patch_count = count;
    return d;
}

axiam_reactor_decision_t axiam_reactor_abstain(void) {
    axiam_reactor_decision_t d;
    memset(&d, 0, sizeof(d));
    return d; /* AXIAM_REACTOR_ABSTAIN is the zero value, deliberately */
}

static const char *decision_word(axiam_reactor_answer_kind_t kind) {
    switch (kind) {
    case AXIAM_REACTOR_ALLOW: return "allow";
    case AXIAM_REACTOR_DENY: return "deny";
    case AXIAM_REACTOR_MUTATE: return "mutate";
    case AXIAM_REACTOR_ABSTAIN:
    default: return NULL;
    }
}

/** Byte-order the patch, which is what the server's BTreeMap emits. */
static int patch_key_cmp(const void *a, const void *b) {
    const axiam_reactor_patch_entry_t *x = a, *y = b;
    return strcmp(x->key ? x->key : "", y->key ? y->key : "");
}

char *axiam_reactor_canonical_reply(const char *correlation_id, const char *tenant_id,
                                    const char *event,
                                    const axiam_reactor_decision_t *decision, const char *nonce,
                                    const char *issued_at) {
    if (!decision) return NULL;
    const char *word = decision_word(decision->kind);
    if (!word) return NULL;

    /* Field order: correlation_id, tenant_id, event, decision, reason (OMITTED
     * when absent), patch (OMITTED when absent), require_mfa (OMITTED when
     * false), key_version, nonce, issued_at, hmac_signature (null while signing).
     *
     * The three conditional omissions are load-bearing. A reply that serializes
     * `"require_mfa": false` rather than omitting it produces different canonical
     * bytes and therefore a different MAC. */
    sb_t sb = {0};
    sb_puts(&sb, "{\"correlation_id\":");
    sb_quoted(&sb, correlation_id);
    sb_puts(&sb, ",\"tenant_id\":");
    sb_quoted(&sb, tenant_id);
    sb_puts(&sb, ",\"event\":");
    sb_quoted(&sb, event);
    sb_puts(&sb, ",\"decision\":");
    sb_quoted(&sb, word);
    if (decision->reason && decision->reason[0]) {
        sb_puts(&sb, ",\"reason\":");
        sb_quoted(&sb, decision->reason);
    }
    if (decision->patch && decision->patch_count > 0) {
        axiam_reactor_patch_entry_t *sorted =
            malloc(decision->patch_count * sizeof(*sorted));
        if (!sorted) {
            free(sb.buf);
            return NULL;
        }
        memcpy(sorted, decision->patch, decision->patch_count * sizeof(*sorted));
        qsort(sorted, decision->patch_count, sizeof(*sorted), patch_key_cmp);
        sb_puts(&sb, ",\"patch\":{");
        for (size_t i = 0; i < decision->patch_count; i++) {
            if (i) sb_puts(&sb, ",");
            sb_quoted(&sb, sorted[i].key);
            sb_puts(&sb, ":");
            sb_quoted(&sb, sorted[i].value);
        }
        sb_puts(&sb, "}");
        free(sorted);
    }
    if (decision->require_mfa) sb_puts(&sb, ",\"require_mfa\":true");
    {
        char number[40];
        snprintf(number, sizeof(number), ",\"key_version\":%d", REACTOR_KEY_VERSION);
        sb_puts(&sb, number);
    }
    sb_puts(&sb, ",\"nonce\":");
    sb_quoted(&sb, nonce);
    sb_puts(&sb, ",\"issued_at\":");
    sb_quoted(&sb, issued_at);
    sb_puts(&sb, ",\"hmac_signature\":null}");
    return sb.failed ? NULL : sb.buf;
}

char *axiam_reactor_build_reply(const axiam_sensitive_t *signing_key, const char *correlation_id,
                                const char *tenant_id, const char *event,
                                const axiam_reactor_decision_t *decision, const char *nonce,
                                const char *issued_at) {
    if (!signing_key || !decision) return NULL;
    /* Two client-side refusals §22.13 asks for. Both must result in NO REPLY
     * rather than a corrected one: the registration's failure_policy decides,
     * never a synthesized allow. */
    if (decision->require_mfa && strcmp(event ? event : "",
                                        AXIAM_REACTOR_EVENT_LOGIN_POST_AUTH) != 0) {
        return NULL;
    }
    if (decision->kind == AXIAM_REACTOR_MUTATE &&
        (!decision->patch || decision->patch_count == 0)) {
        return NULL;
    }

    char *canonical = axiam_reactor_canonical_reply(correlation_id, tenant_id, event, decision,
                                                    nonce, issued_at);
    if (!canonical) return NULL;
    char *signature = hmac_sha256_hex(signing_key, canonical, strlen(canonical));
    if (!signature) {
        free(canonical);
        return NULL;
    }

    const char *placeholder = "\"hmac_signature\":null";
    char *at = strstr(canonical, placeholder);
    if (!at) {
        free(canonical);
        free(signature);
        return NULL;
    }
    size_t head = (size_t)(at - canonical);
    const char *tail = at + strlen(placeholder);
    size_t need = head + strlen("\"hmac_signature\":\"\"") + strlen(signature) + strlen(tail) + 1;
    char *wire = malloc(need);
    if (wire) {
        snprintf(wire, need, "%.*s\"hmac_signature\":\"%s\"%s", (int)head, canonical, signature,
                 tail);
    }
    free(canonical);
    free(signature);
    return wire;
}

/* ------------------------------------------------------------------ */
/* §22.3 — verification                                               */
/* ------------------------------------------------------------------ */

struct axiam_reactor_nonce_set {
    struct entry {
        char *nonce;
        long expires_at;
    } *entries;
    size_t len;
    size_t cap;
};

axiam_reactor_nonce_set_t *axiam_reactor_nonce_set_new(void) {
    return calloc(1, sizeof(axiam_reactor_nonce_set_t));
}

void axiam_reactor_nonce_set_free(axiam_reactor_nonce_set_t *set) {
    if (!set) return;
    for (size_t i = 0; i < set->len; i++) free(set->entries[i].nonce);
    free(set->entries);
    free(set);
}

/** 1 when the nonce was unseen and has now been claimed. */
static int nonce_claim(axiam_reactor_nonce_set_t *set, const char *nonce, long now) {
    size_t kept = 0;
    for (size_t i = 0; i < set->len; i++) {
        if (set->entries[i].expires_at <= now) {
            free(set->entries[i].nonce);
        } else {
            set->entries[kept++] = set->entries[i];
        }
    }
    set->len = kept;
    for (size_t i = 0; i < set->len; i++) {
        if (strcmp(set->entries[i].nonce, nonce) == 0) return 0;
    }
    if (set->len == set->cap) {
        size_t next = set->cap ? set->cap * 2 : 16;
        struct entry *grown = realloc(set->entries, next * sizeof(*grown));
        if (!grown) return 1; /* cannot record it; do not turn OOM into a refusal */
        set->entries = grown;
        set->cap = next;
    }
    set->entries[set->len].nonce = axiam_strdup0(nonce);
    if (!set->entries[set->len].nonce) return 1;
    set->entries[set->len].expires_at = now + 2 * REACTOR_FRESHNESS_SKEW_SECS;
    set->len++;
    return 1;
}

/** The backing storage a verified event's borrowed strings point into. */
typedef struct {
    char *tenant_id;
    char *event;
    char *correlation_id;
    char *payload_json;
    char *nonce;
} verified_owned_t;

void axiam_reactor_verified_dispose(axiam_reactor_verified_t *verified) {
    if (!verified || !verified->owned) {
        if (verified) memset(verified, 0, sizeof(*verified));
        return;
    }
    verified_owned_t *owned = verified->owned;
    free(owned->tenant_id);
    free(owned->event);
    free(owned->correlation_id);
    free(owned->payload_json);
    free(owned->nonce);
    free(owned);
    memset(verified, 0, sizeof(*verified));
}

static long parse_rfc3339_utc(const char *value) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (!value || strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) return -1;
    return (long)timegm(&tm);
}

static void rfc3339_utc(long unix_seconds, char *out, size_t n) {
    time_t t = (time_t)unix_seconds;
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int is_string(const cJSON *o, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return cJSON_IsString(v) && v->valuestring != NULL;
}

axiam_reactor_refusal_t axiam_reactor_verify_event(const axiam_sensitive_t *signing_key,
                                                   const char *body, const char *expected_tenant,
                                                   long now, axiam_reactor_nonce_set_t *seen,
                                                   axiam_reactor_verified_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!signing_key || !body || !expected_tenant) return AXIAM_REACTOR_MALFORMED;

    cJSON *message = cJSON_Parse(body);
    if (!message || !cJSON_IsObject(message)) {
        if (message) cJSON_Delete(message);
        return AXIAM_REACTOR_MALFORMED;
    }

    axiam_reactor_refusal_t refusal = AXIAM_REACTOR_MALFORMED;

    /* 1. key_version, before anything else about the body is considered. */
    const cJSON *key_version = cJSON_GetObjectItemCaseSensitive(message, "key_version");
    if (!cJSON_IsNumber(key_version) || key_version->valuedouble < REACTOR_KEY_VERSION) {
        refusal = AXIAM_REACTOR_KEY_VERSION_TOO_OLD;
        goto done;
    }

    /* Every field the canonical form reads has to be there before it reads them;
     * a body missing one is malformed, not badly signed, and saying "bad
     * signature" would send an operator looking at the wrong key. */
    if (!is_string(message, "tenant_id") || !is_string(message, "event") ||
        !is_string(message, "correlation_id") || !is_string(message, "nonce") ||
        !is_string(message, "issued_at") ||
        !cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(message, "timeout_ms")) ||
        !cJSON_GetObjectItemCaseSensitive(message, "payload")) {
        refusal = AXIAM_REACTOR_MALFORMED;
        goto done;
    }

    /* 2. The MAC, over the body with hmac_signature set to null. */
    if (!is_string(message, "hmac_signature")) {
        refusal = AXIAM_REACTOR_BAD_SIGNATURE;
        goto done;
    }
    {
        char *canonical = canonical_event(message);
        if (!canonical) {
            refusal = AXIAM_REACTOR_MALFORMED;
            goto done;
        }
        char *expected = hmac_sha256_hex(signing_key, canonical, strlen(canonical));
        free(canonical);
        if (!expected) {
            refusal = AXIAM_REACTOR_MALFORMED;
            goto done;
        }
        const char *presented =
            cJSON_GetObjectItemCaseSensitive(message, "hmac_signature")->valuestring;
        int ok = constant_time_equals(presented, expected);
        free(expected);
        if (!ok) {
            refusal = AXIAM_REACTOR_BAD_SIGNATURE;
            goto done;
        }
    }

    /* 3. Freshness, in BOTH directions. */
    {
        long issued_at = parse_rfc3339_utc(
            cJSON_GetObjectItemCaseSensitive(message, "issued_at")->valuestring);
        if (issued_at < 0) {
            refusal = AXIAM_REACTOR_MALFORMED;
            goto done;
        }
        long drift = now - issued_at;
        if (drift > REACTOR_FRESHNESS_SKEW_SECS || drift < -REACTOR_FRESHNESS_SKEW_SECS) {
            refusal = AXIAM_REACTOR_STALE;
            goto done;
        }
    }

    /* 4. The nonce, against the seen-set. */
    {
        const char *nonce = cJSON_GetObjectItemCaseSensitive(message, "nonce")->valuestring;
        if (seen && !nonce_claim(seen, nonce, now)) {
            refusal = AXIAM_REACTOR_REPLAY;
            goto done;
        }
    }

    /* Identity and registry membership come AFTER the MAC: neither is
     * cryptography, and spending them on unauthenticated bytes tells an
     * unauthenticated party what this reactor accepts. */
    {
        const char *tenant =
            cJSON_GetObjectItemCaseSensitive(message, "tenant_id")->valuestring;
        if (strcmp(tenant, expected_tenant) != 0) {
            refusal = AXIAM_REACTOR_TENANT_MISMATCH;
            goto done;
        }
        const char *event = cJSON_GetObjectItemCaseSensitive(message, "event")->valuestring;
        if (!spec_for(event)) {
            /* Also how §22.7's exclusion refuses: those operations are in no
             * registry, so a delivery naming one never reaches a handler. */
            refusal = AXIAM_REACTOR_UNKNOWN_EVENT;
            goto done;
        }

        if (out) {
            verified_owned_t *owned = calloc(1, sizeof(*owned));
            if (!owned) {
                refusal = AXIAM_REACTOR_MALFORMED;
                goto done;
            }
            owned->tenant_id = axiam_strdup0(tenant);
            owned->event = axiam_strdup0(event);
            owned->correlation_id = axiam_strdup0(
                cJSON_GetObjectItemCaseSensitive(message, "correlation_id")->valuestring);
            owned->payload_json = cJSON_PrintUnformatted(
                cJSON_GetObjectItemCaseSensitive(message, "payload"));
            owned->nonce = axiam_strdup0(
                cJSON_GetObjectItemCaseSensitive(message, "nonce")->valuestring);
            if (!owned->tenant_id || !owned->event || !owned->correlation_id ||
                !owned->payload_json || !owned->nonce) {
                free(owned->tenant_id);
                free(owned->event);
                free(owned->correlation_id);
                free(owned->payload_json);
                free(owned->nonce);
                free(owned);
                refusal = AXIAM_REACTOR_MALFORMED;
                goto done;
            }
            out->owned = owned;
            out->event.tenant_id = owned->tenant_id;
            out->event.event = owned->event;
            out->event.correlation_id = owned->correlation_id;
            out->event.payload_json = owned->payload_json;
            out->event.nonce = owned->nonce;
            out->event.timeout_ms =
                (long)cJSON_GetObjectItemCaseSensitive(message, "timeout_ms")->valuedouble;
        }
        refusal = AXIAM_REACTOR_OK;
    }

done:
    cJSON_Delete(message);
    return refusal;
}

/* ------------------------------------------------------------------ */
/* §22.10 — the runtime                                               */
/* ------------------------------------------------------------------ */

static long real_clock(void *ctx) {
    (void)ctx;
    return (long)time(NULL);
}

/**
 * A v4-shaped random nonce. Not parsed by anyone — the server treats it as an
 * opaque string — but a UUID is what the fixtures look like and what an operator
 * expects to see in a log.
 */
static void real_nonce(void *ctx, char *out, size_t n) {
    (void)ctx;
    unsigned char b[16];
    if (RAND_bytes(b, sizeof(b)) != 1) {
        /* A reactor that cannot get randomness must not invent a predictable
         * nonce: a guessable one is a replay window an attacker can aim at. An
         * empty nonce makes the reply unbuildable, which is the fail-closed
         * outcome §22.10 rule 2 asks for. */
        if (n) out[0] = '\0';
        return;
    }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    snprintf(out, n, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
             b[13], b[14], b[15]);
}

axiam_error_kind_t axiam_reactor_serve(const axiam_reactor_config_t *config,
                                       const axiam_reactor_transport_t *transport,
                                       axiam_reactor_handler_fn handler, void *handler_ctx,
                                       axiam_error_t *err) {
    axiam_error_reset(err);
    if (!config || !transport || !handler || !transport->next_delivery ||
        !transport->publish_reply) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "axiam_reactor_serve needs a config, a transport and a handler");
        return AXIAM_ERR_NETWORK;
    }
    if (!config->tenant_id || !config->tenant_id[0] || !config->signing_key) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_reactor_serve needs a tenant_id and a signing key");
        return AXIAM_ERR_AUTH;
    }

    long (*clock_fn)(void *) = config->clock_fn ? config->clock_fn : real_clock;
    void *clock_ctx = config->clock_fn ? config->clock_ctx : NULL;
    void (*nonce_fn)(void *, char *, size_t) = config->nonce_fn ? config->nonce_fn : real_nonce;
    void *nonce_ctx = config->nonce_fn ? config->nonce_ctx : NULL;

    /* ONE seen-set for this call's whole lifetime. A fresh one per delivery
     * defeats replay dedup entirely, which is the failure §22.3 names. */
    axiam_reactor_nonce_set_t *seen = axiam_reactor_nonce_set_new();
    if (!seen) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    for (;;) {
        axiam_reactor_delivery_t delivery;
        memset(&delivery, 0, sizeof(delivery));
        if (!transport->next_delivery(transport->ctx, &delivery)) break;

        long received_at = clock_fn(clock_ctx);
        axiam_reactor_verified_t verified;
        axiam_reactor_refusal_t refusal =
            axiam_reactor_verify_event(config->signing_key, delivery.body, config->tenant_id,
                                       received_at, seen, &verified);
        if (refusal != AXIAM_REACTOR_OK) {
            /* §22.10 rule 2: NO REPLY. A body this runtime could not verify is
             * not a body it may answer on the handler's behalf — the
             * registration's failure_policy decides. */
            axiam_reactor_verified_dispose(&verified);
            continue;
        }

        axiam_reactor_decision_t decision = handler(&verified.event, handler_ctx);
        if (decision.kind == AXIAM_REACTOR_ABSTAIN) {
            /* The handler declined to decide (§22.14 rule 4). */
            axiam_reactor_verified_dispose(&verified);
            continue;
        }

        /* §22.10 rule 4: work whose window has closed is abandoned rather than
         * answered late. The server has already resolved the event by its
         * failure_policy, and a reply arriving after that is at best ignored. */
        if (verified.event.timeout_ms > 0 &&
            (clock_fn(clock_ctx) - received_at) * 1000 > verified.event.timeout_ms) {
            axiam_reactor_verified_dispose(&verified);
            continue;
        }

        char nonce[64];
        nonce[0] = '\0';
        nonce_fn(nonce_ctx, nonce, sizeof(nonce));
        char issued_at[32];
        rfc3339_utc(clock_fn(clock_ctx), issued_at, sizeof(issued_at));

        char *reply = axiam_reactor_build_reply(config->signing_key,
                                                verified.event.correlation_id,
                                                verified.event.tenant_id, verified.event.event,
                                                &decision, nonce, issued_at);
        if (!reply) {
            /* A refusal from the reply builder — require_mfa on the wrong event,
             * an empty mutate, no entropy for a nonce — is the runtime's own
             * error, and rule 2 applies to it exactly as to a handler that
             * failed. */
            axiam_reactor_verified_dispose(&verified);
            continue;
        }

        const char *destination = (delivery.reply_to && delivery.reply_to[0])
                                      ? delivery.reply_to
                                      : "axiam.reactor.replies";
        transport->publish_reply(transport->ctx, destination, verified.event.correlation_id,
                                 reply);
        free(reply);
        axiam_reactor_verified_dispose(&verified);
    }

    axiam_reactor_nonce_set_free(seen);
    return AXIAM_OK;
}

/* ------------------------------------------------------------------ */
/* §22.14 — the binding table                                         */
/* ------------------------------------------------------------------ */

struct axiam_reactor_router {
    struct binding {
        char *event;
        axiam_reactor_handler_fn handler;
        void *ctx;
    } *bindings;
    size_t len;
    size_t cap;
    const char **names; /* borrowed view for bound_events() */
    axiam_reactor_handler_fn fallback;
    void *fallback_ctx;
};

axiam_reactor_router_t *axiam_reactor_router_new(void) {
    return calloc(1, sizeof(axiam_reactor_router_t));
}

void axiam_reactor_router_free(axiam_reactor_router_t *router) {
    if (!router) return;
    for (size_t i = 0; i < router->len; i++) free(router->bindings[i].event);
    free(router->bindings);
    free(router->names);
    free(router);
}

axiam_error_kind_t axiam_reactor_router_on(axiam_reactor_router_t *router, const char *event,
                                           axiam_reactor_handler_fn handler, void *ctx,
                                           axiam_error_t *err) {
    axiam_error_reset(err);
    if (!router || !event || !handler) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (!spec_for(event)) {
        /* Rule 2: refused AT BIND TIME. The message names the registry; it does
         * not name what is absent from it — a separate hot-path list would be a
         * constant naming the three operations §22.13's hot-path assertion
         * forbids this SDK from exposing. */
        char msg[512];
        int at = snprintf(msg, sizeof(msg),
                          "reactor router: '%s' is not in the CONTRACT.md §22.5 event registry. "
                          "Bindable events:",
                          event);
        for (size_t i = 0; i < REGISTRY_LEN && at > 0 && (size_t)at < sizeof(msg); i++) {
            at += snprintf(msg + at, sizeof(msg) - (size_t)at, "%s %s", i ? "," : "",
                           REGISTRY[i].name);
        }
        axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
        return AXIAM_ERR_AUTH;
    }
    for (size_t i = 0; i < router->len; i++) {
        if (strcmp(router->bindings[i].event, event) == 0) {
            /* Rule 3: never a silent overwrite. Which of two handlers runs is not
             * something the author of either can see from their own file. */
            char msg[256];
            snprintf(msg, sizeof(msg), "reactor router: '%s' already has a handler bound", event);
            axiam_error_set(err, AXIAM_ERR_AUTH, 0, msg);
            return AXIAM_ERR_AUTH;
        }
    }
    if (router->len == router->cap) {
        size_t next = router->cap ? router->cap * 2 : 8;
        struct binding *grown = realloc(router->bindings, next * sizeof(*grown));
        if (!grown) {
            axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
            return AXIAM_ERR_NETWORK;
        }
        router->bindings = grown;
        router->cap = next;
    }
    router->bindings[router->len].event = axiam_strdup0(event);
    if (!router->bindings[router->len].event) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    router->bindings[router->len].handler = handler;
    router->bindings[router->len].ctx = ctx;
    router->len++;
    return AXIAM_OK;
}

axiam_error_kind_t axiam_reactor_router_fallback(axiam_reactor_router_t *router,
                                                 axiam_reactor_handler_fn handler, void *ctx,
                                                 axiam_error_t *err) {
    axiam_error_reset(err);
    if (!router || !handler) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    router->fallback = handler;
    router->fallback_ctx = ctx;
    return AXIAM_OK;
}

const char *const *axiam_reactor_router_bound_events(const axiam_reactor_router_t *router,
                                                     size_t *out_count) {
    if (out_count) *out_count = router ? router->len : 0;
    if (!router || router->len == 0) return NULL;
    axiam_reactor_router_t *mut = (axiam_reactor_router_t *)router;
    const char **names = realloc(mut->names, router->len * sizeof(*names));
    if (!names) return NULL;
    mut->names = names;
    for (size_t i = 0; i < router->len; i++) names[i] = router->bindings[i].event;
    return names;
}

static axiam_reactor_decision_t router_dispatch(const axiam_reactor_event_t *event, void *ctx) {
    const axiam_reactor_router_t *router = ctx;
    if (!router || !event) return axiam_reactor_abstain();
    for (size_t i = 0; i < router->len; i++) {
        /* Rule 5: the handler's own answer reaches the runtime UNCHANGED.
         * Nothing here rewrites it — §22.10 rule 2 puts the fail-closed
         * obligation on the runtime, and a binder that intercepted first would
         * satisfy the letter of that rule while defeating it. */
        if (strcmp(router->bindings[i].event, event->event) == 0) {
            return router->bindings[i].handler(event, router->bindings[i].ctx);
        }
    }
    /* Rule 4: an unbound event ABSTAINS. Not `allow`, and not `deny` either —
     * the binder does not know what the registration was for, and the operator's
     * policy does. */
    if (router->fallback) return router->fallback(event, router->fallback_ctx);
    return axiam_reactor_abstain();
}

axiam_reactor_handler_fn axiam_reactor_router_handler(void) { return router_dispatch; }

/* ------------------------------------------------------------------ */
/* §8b rules 1–5                                                      */
/* ------------------------------------------------------------------ */

void axiam_amqps_endpoint_dispose(axiam_amqps_endpoint_t *endpoint) {
    if (!endpoint) return;
    free(endpoint->url);
    free(endpoint->host);
    free(endpoint->virtual_host);
    free(endpoint->ca_pem);
    free(endpoint->client_cert_pem);
    free(endpoint->client_key_pem);
    memset(endpoint, 0, sizeof(*endpoint));
}

axiam_error_kind_t axiam_amqps_endpoint(const char *url, const char *ca_pem,
                                        const char *client_cert_pem, const char *client_key_pem,
                                        axiam_amqps_endpoint_t *out, axiam_error_t *err) {
    axiam_error_reset(err);
    if (out) memset(out, 0, sizeof(*out));
    if (!url || !out) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "invalid arguments");
        return AXIAM_ERR_NETWORK;
    }

    /* Rule 3, checked first because it is about the caller's arguments rather
     * than about the URL: half a client identity fails closed rather than
     * connecting without the mutual half. */
    int has_cert = client_cert_pem && client_cert_pem[0];
    int has_key = client_key_pem && client_key_pem[0];
    if (has_cert != has_key) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: a client certificate and its key must be supplied "
                        "together — half a client identity fails closed rather than connecting "
                        "without the mutual half (CONTRACT.md §8b rule 3)");
        return AXIAM_ERR_AUTH;
    }

    /* Rule 1, and there is NO LOOPBACK EXCEPTION (§8b rule 8): this applies to
     * localhost, 127.0.0.1 and ::1 exactly as to any other host. §6's
     * `http://localhost` dev carve-out does not extend here — §6 and §8b are
     * different rules, and the server has no plaintext listener for such an
     * exception to reach. */
    const char *sep = strstr(url, "://");
    if (!sep) {
        /* Rule 5's posture applied to parsing: a URL this cannot read is not a
         * URL it can vouch for, so it fails closed rather than being passed on
         * for a socket to interpret. */
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: not a URL. The broker URL must be amqps:// "
                        "(CONTRACT.md §8b rule 1)");
        return AXIAM_ERR_AUTH;
    }
    size_t scheme_len = (size_t)(sep - url);
    if (scheme_len != 5 || strncasecmp(url, "amqps", 5) != 0) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: scheme refused; the broker URL must be amqps:// "
                        "and there is no plaintext fallback and no loopback exception "
                        "(CONTRACT.md §8b rules 1, 5 and 8)");
        return AXIAM_ERR_AUTH;
    }

    const char *rest = sep + 3;
    /* Strip any userinfo — credentials belong to the connection, not to this
     * check, and leaving them in `host` would put them wherever host is logged. */
    const char *at = strrchr(rest, '@');
    if (at) rest = at + 1;

    const char *slash = strchr(rest, '/');
    size_t authority_len = slash ? (size_t)(slash - rest) : strlen(rest);
    const char *vhost = (slash && slash[1]) ? slash + 1 : "/";
    if (authority_len == 0) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: the URL names no broker host (CONTRACT.md §8b)");
        return AXIAM_ERR_AUTH;
    }

    char authority[512];
    if (authority_len >= sizeof(authority)) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: the broker authority is too long (CONTRACT.md §8b)");
        return AXIAM_ERR_AUTH;
    }
    memcpy(authority, rest, authority_len);
    authority[authority_len] = '\0';

    char host[512] = {0};
    int port = 5671; /* the broker TLS port */
    if (authority[0] == '[') {
        /* An IPv6 literal is bracketed; its colons are not a port separator. */
        char *close = strchr(authority, ']');
        if (!close) {
            axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                            "axiam_amqps_endpoint: unterminated IPv6 host (CONTRACT.md §8b)");
            return AXIAM_ERR_AUTH;
        }
        *close = '\0';
        snprintf(host, sizeof(host), "%s", authority + 1);
        if (close[1] == ':') port = atoi(close + 2);
    } else {
        char *colon = strrchr(authority, ':');
        if (colon) {
            *colon = '\0';
            port = atoi(colon + 1);
        }
        snprintf(host, sizeof(host), "%s", authority);
    }
    if (!host[0] || port <= 0 || port > 65535) {
        axiam_error_set(err, AXIAM_ERR_AUTH, 0,
                        "axiam_amqps_endpoint: the URL names no usable broker endpoint "
                        "(CONTRACT.md §8b)");
        return AXIAM_ERR_AUTH;
    }

    out->url = axiam_strdup0(url);
    out->host = axiam_strdup0(host);
    out->port = port;
    out->virtual_host = axiam_strdup0(vhost);
    /* Rule 2: a custom CA, for a privately-issued broker certificate. This is
     * the common case — an in-cluster broker's certificate is not issued by a
     * public CA — and it exists so nobody has a legitimate reason to want rule 4
     * relaxed. Rule 4 itself needs no code: there is no parameter for it, under
     * any name, and none may be added. */
    out->ca_pem = ca_pem ? axiam_strdup0(ca_pem) : NULL;
    out->client_cert_pem = has_cert ? axiam_strdup0(client_cert_pem) : NULL;
    out->client_key_pem = has_key ? axiam_strdup0(client_key_pem) : NULL;
    if (!out->url || !out->host || !out->virtual_host || (ca_pem && !out->ca_pem) ||
        (has_cert && !out->client_cert_pem) || (has_key && !out->client_key_pem)) {
        axiam_amqps_endpoint_dispose(out);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}
