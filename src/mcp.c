/*
 * AXIAM C SDK — MCP resource-server helpers (CONTRACT.md §28).
 *
 * See axiam/mcp.h for the ownership contract. This file is the whole of
 * §28.1's canonical operation set for C: the RFC 9728 document builder (in
 * its `_json` / `_path` / `_url` accommodation), the RFC 6750 challenge
 * builder, and the §28.5 rule 3 cross-check that stands in for `serve_`'s
 * optional guard argument.
 *
 * URI parsing below is DELIBERATELY NOT built on any normalising parser: it
 * slices the caller's string exactly as written, the same choice the
 * reference TypeScript implementation makes and for the same reason (§28.2:
 * validation must not adjust a value to make it pass, and §28.3 derives the
 * document's own path from the unmodified string).
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp */

#include "axiam/mcp.h"
#include "cJSON.h"
#include "internal.h"

/* --------------------------------------------------------------------- */
/* Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4          */
/* --------------------------------------------------------------------- */

/* NQCHAR: %x21 / %x23-%x5B / %x5D-%x7E. No space, no '"', no '\', no
 * control character, no non-ASCII. */
static int is_nqchar(unsigned char c) {
    return c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
}

/* NQSCHAR: NQCHAR plus the space (%x20). */
static int is_nqschar(unsigned char c) {
    return c == 0x20 || is_nqchar(c);
}

static int all_chars(const char *s, int (*pred)(unsigned char)) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!pred(*p)) return 0;
    }
    return 1;
}

/* --------------------------------------------------------------------- */
/* Absolute-URI parsing (§28.2 rules 1, 2, 3, 7) — offsets into `raw`,     */
/* nothing copied or normalised.                                          */
/* --------------------------------------------------------------------- */

typedef struct {
    size_t scheme_len;
    size_t authority_off;
    size_t authority_len;
    size_t path_off;
    size_t path_len;
    int has_query;
    int has_fragment;
} parsed_uri_t;

/* scheme "://" authority [path] [?query] [#fragment], matched against the
 * caller's string exactly as given. Returns 1 and fills `out`, or 0 when
 * `raw` is not shaped like an absolute URI (empty authority included: an
 * authority-less "scheme://" is refused, not treated as an empty host). */
static int parse_absolute_uri(const char *raw, parsed_uri_t *out) {
    if (!raw || raw[0] == '\0') return 0;
    if (!isalpha((unsigned char)raw[0])) return 0;
    size_t i = 1;
    while (raw[i] && (isalnum((unsigned char)raw[i]) || raw[i] == '+' ||
                      raw[i] == '-' || raw[i] == '.')) {
        i++;
    }
    if (raw[i] != ':' || raw[i + 1] != '/' || raw[i + 2] != '/') return 0;
    size_t scheme_len = i;
    size_t j = i + 3;
    size_t authority_off = j;
    while (raw[j] && raw[j] != '/' && raw[j] != '?' && raw[j] != '#') j++;
    if (j == authority_off) return 0; /* empty authority: refused */
    size_t authority_len = j - authority_off;
    size_t path_off = j;
    while (raw[j] && raw[j] != '?' && raw[j] != '#') j++;
    size_t path_len = j - path_off;
    int has_query = 0, has_fragment = 0;
    if (raw[j] == '?') {
        has_query = 1;
        while (raw[j] && raw[j] != '#') j++;
    }
    if (raw[j] == '#') has_fragment = 1;

    out->scheme_len = scheme_len;
    out->authority_off = authority_off;
    out->authority_len = authority_len;
    out->path_off = path_off;
    out->path_len = path_len;
    out->has_query = has_query;
    out->has_fragment = has_fragment;
    return 1;
}

/* The three hosts §28.2 rule 2 lets an http:// URL use, and the only ones —
 * AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
 * deliberately no flag, environment variable or debug build that widens
 * this. */
static int is_loopback_host(const char *host, size_t len) {
    static const char *const hosts[] = {"127.0.0.1", "[::1]", "localhost"};
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        size_t hl = strlen(hosts[i]);
        if (hl == len && strncasecmp(host, hosts[i], len) == 0) return 1;
    }
    return 0;
}

/* The host inside an authority: userinfo@ stripped, port stripped, an IPv6
 * literal's brackets kept. Stripping userinfo is what makes
 * "http://localhost@evil.example.com/" a refusal rather than a loopback
 * pass — the host there is evil.example.com. Returns a pointer into
 * `authority` and sets *out_len; does not allocate. */
static const char *host_of(const char *authority, size_t authority_len, size_t *out_len) {
    const char *at = NULL;
    for (size_t i = 0; i < authority_len; i++) {
        if (authority[i] == '@') at = authority + i;
    }
    const char *hostport = at ? at + 1 : authority;
    size_t hostport_len = authority_len - (size_t)(hostport - authority);
    if (hostport_len > 0 && hostport[0] == '[') {
        for (size_t i = 0; i < hostport_len; i++) {
            if (hostport[i] == ']') {
                *out_len = i + 1;
                return hostport;
            }
        }
        *out_len = hostport_len;
        return hostport;
    }
    for (size_t i = 0; i < hostport_len; i++) {
        if (hostport[i] == ':') {
            *out_len = i;
            return hostport;
        }
    }
    *out_len = hostport_len;
    return hostport;
}

typedef struct {
    int allow_query;
    int allow_fragment;
} uri_policy_t;

static const uri_policy_t IDENTIFIER_POLICY = {0, 0};
static const uri_policy_t LOCATOR_POLICY = {1, 1};

static void refuse(axiam_error_t *err, const char *op, const char *field, const char *detail) {
    char msg[256];
    snprintf(msg, sizeof(msg), "%s: %s: %s (CONTRACT.md §28)", op, field, detail);
    axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
}

/* §28.2 rules 1+2 / rule 7's relaxation via `policy`. Fills `out` on
 * success and returns 1; returns 0 and sets `err` on any refusal. */
static int require_absolute_uri(const char *op, const char *field, const char *raw,
                                uri_policy_t policy, parsed_uri_t *out, axiam_error_t *err) {
    if (!raw || raw[0] == '\0') {
        refuse(err, op, field, "must be a non-empty absolute URI");
        return 0;
    }
    if (!parse_absolute_uri(raw, out)) {
        refuse(err, op, field, "must be an absolute URI with a scheme and an authority");
        return 0;
    }
    if (out->has_query && !policy.allow_query) {
        refuse(err, op, field, "must carry no query — §28.3 derives the metadata path from it");
        return 0;
    }
    if (out->has_fragment && !policy.allow_fragment) {
        refuse(err, op, field, "must carry no fragment");
        return 0;
    }
    if (out->scheme_len == 5 && strncasecmp(raw, "https", 5) == 0) return 1;
    if (out->scheme_len == 4 && strncasecmp(raw, "http", 4) == 0) {
        size_t host_len = 0;
        const char *host = host_of(raw + out->authority_off, out->authority_len, &host_len);
        if (is_loopback_host(host, host_len)) return 1;
    }
    refuse(err, op, field,
          "must use https — http is accepted only on 127.0.0.1, [::1] or localhost");
    return 0;
}

/* --------------------------------------------------------------------- */
/* A tiny growable buffer for building the challenge string.              */
/* --------------------------------------------------------------------- */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} strbuf_t;

static int strbuf_init(strbuf_t *b) {
    b->cap = 64;
    b->len = 0;
    b->buf = malloc(b->cap);
    if (!b->buf) return 0;
    b->buf[0] = '\0';
    return 1;
}

static int strbuf_append(strbuf_t *b, const char *s) {
    size_t n = strlen(s);
    if (b->len + n + 1 > b->cap) {
        size_t newcap = b->cap;
        while (newcap < b->len + n + 1) newcap *= 2;
        char *nb = realloc(b->buf, newcap);
        if (!nb) return 0;
        b->buf = nb;
        b->cap = newcap;
    }
    memcpy(b->buf + b->len, s, n + 1);
    b->len += n;
    return 1;
}

static void strbuf_free(strbuf_t *b) {
    free(b->buf);
    b->buf = NULL;
}

/* --------------------------------------------------------------------- */
/* §28.2 / §28.3 — the document, the path, the url                        */
/* --------------------------------------------------------------------- */

typedef struct {
    cJSON *document; /* owned; NULL on failure */
    char *path;      /* owned; NULL on failure */
    char *url;       /* owned; NULL on failure */
} built_metadata_t;

static void built_metadata_dispose(built_metadata_t *b) {
    if (!b) return;
    cJSON_Delete(b->document);
    free(b->path);
    free(b->url);
    b->document = NULL;
    b->path = NULL;
    b->url = NULL;
}

static char *derive_metadata_path(const char *path, size_t path_len) {
    static const char PREFIX[] = AXIAM_MCP_METADATA_PATH_PREFIX;
    size_t prefix_len = sizeof(PREFIX) - 1;
    if (path_len == 0 || (path_len == 1 && path[0] == '/')) {
        return axiam_strdup0(PREFIX);
    }
    char *out = malloc(prefix_len + path_len + 1);
    if (!out) return NULL;
    memcpy(out, PREFIX, prefix_len);
    memcpy(out + prefix_len, path, path_len);
    out[prefix_len + path_len] = '\0';
    return out;
}

static int contains_string(const char *const *items, size_t count, const char *needle) {
    for (size_t i = 0; i < count; i++) {
        if (items[i] && strcmp(items[i], needle) == 0) return 1;
    }
    return 0;
}

static axiam_error_kind_t build_metadata(const axiam_protected_resource_metadata_options_t *options,
                                         built_metadata_t *out, axiam_error_t *err) {
    static const char *op = "protected_resource_metadata";
    axiam_error_reset(err);
    memset(out, 0, sizeof(*out));

    if (!options) {
        refuse(err, op, "options", "must not be NULL");
        return AXIAM_ERR_NETWORK;
    }

    /* Rule 1 + rule 2. */
    parsed_uri_t resource_uri;
    if (!require_absolute_uri(op, "resource", options->resource, IDENTIFIER_POLICY,
                              &resource_uri, err)) {
        return AXIAM_ERR_NETWORK;
    }

    /* Rule 3 + rule 4: at least one entry, each an issuer verbatim, no
     * duplicates. */
    if (options->authorization_server_count == 0 || !options->authorization_servers) {
        refuse(err, op, "authorization_servers",
              "must name at least one authorization server — a document that names none "
              "answers none of the question the client asked");
        return AXIAM_ERR_NETWORK;
    }
    const char *seen_servers[64];
    size_t seen_server_count = 0;
    for (size_t i = 0; i < options->authorization_server_count; i++) {
        const char *entry = options->authorization_servers[i];
        parsed_uri_t entry_uri;
        if (!require_absolute_uri(op, "authorization_servers", entry, IDENTIFIER_POLICY,
                                  &entry_uri, err)) {
            return AXIAM_ERR_NETWORK;
        }
        if (seen_server_count < sizeof(seen_servers) / sizeof(seen_servers[0]) &&
            contains_string(seen_servers, seen_server_count, entry)) {
            refuse(err, op, "authorization_servers", "duplicate entry");
            return AXIAM_ERR_NETWORK;
        }
        if (seen_server_count < sizeof(seen_servers) / sizeof(seen_servers[0])) {
            seen_servers[seen_server_count++] = entry;
        }
    }

    /* Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty
     * omits the member. */
    for (size_t i = 0; i < options->scopes_supported_count; i++) {
        const char *scope = options->scopes_supported ? options->scopes_supported[i] : NULL;
        if (!scope || scope[0] == '\0' || !all_chars(scope, is_nqchar)) {
            refuse(err, op, "scopes_supported",
                  "is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', "
                  "no control character, no non-ASCII)");
            return AXIAM_ERR_NETWORK;
        }
        if (contains_string(options->scopes_supported, i, scope)) {
            refuse(err, op, "scopes_supported", "duplicate scope");
            return AXIAM_ERR_NETWORK;
        }
    }

    /* Rule 6: exactly ["header"]. NULL pointer -> default; non-NULL pointer
     * (even zero-length) is validated as an explicit list. */
    const char *const *methods = options->bearer_methods_supported;
    size_t method_count = methods ? options->bearer_methods_supported_count : 1;
    static const char *const default_methods[] = {"header"};
    if (!methods) methods = default_methods;
    if (method_count != 1 || !methods[0] || strcmp(methods[0], "header") != 0) {
        refuse(err, op, "bearer_methods_supported",
              "must be exactly [\"header\"] in this contract version");
        return AXIAM_ERR_NETWORK;
    }

    /* Rule 7: absolute URL, query and fragment permitted, omitted when
     * absent. */
    if (options->resource_documentation) {
        parsed_uri_t doc_uri;
        if (!require_absolute_uri(op, "resource_documentation", options->resource_documentation,
                                  LOCATOR_POLICY, &doc_uri, err)) {
            return AXIAM_ERR_NETWORK;
        }
    }

    /* §28.2 fixes the member order; cJSON preserves insertion order when
     * printing, so building in this order is what produces it. */
    cJSON *doc = cJSON_CreateObject();
    if (!doc) {
        refuse(err, op, "document", "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    cJSON_AddStringToObject(doc, "resource", options->resource);
    cJSON *servers = cJSON_CreateStringArray(options->authorization_servers,
                                             (int)options->authorization_server_count);
    cJSON_AddItemToObject(doc, "authorization_servers", servers);
    if (options->scopes_supported_count > 0) {
        cJSON *scopes = cJSON_CreateStringArray(options->scopes_supported,
                                                (int)options->scopes_supported_count);
        cJSON_AddItemToObject(doc, "scopes_supported", scopes);
    }
    cJSON *bearer = cJSON_CreateStringArray(default_methods, 1);
    cJSON_AddItemToObject(doc, "bearer_methods_supported", bearer);
    if (options->resource_documentation) {
        cJSON_AddStringToObject(doc, "resource_documentation", options->resource_documentation);
    }

    char *path = derive_metadata_path(options->resource + resource_uri.path_off,
                                      resource_uri.path_len);
    if (!path) {
        cJSON_Delete(doc);
        refuse(err, op, "document", "out of memory");
        return AXIAM_ERR_NETWORK;
    }

    size_t url_len = resource_uri.scheme_len + 3 /* "://" */ + resource_uri.authority_len +
                     strlen(path);
    char *url = malloc(url_len + 1);
    if (!url) {
        cJSON_Delete(doc);
        free(path);
        refuse(err, op, "document", "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    size_t w = 0;
    memcpy(url + w, options->resource, resource_uri.scheme_len);
    w += resource_uri.scheme_len;
    memcpy(url + w, "://", 3);
    w += 3;
    memcpy(url + w, options->resource + resource_uri.authority_off, resource_uri.authority_len);
    w += resource_uri.authority_len;
    memcpy(url + w, path, strlen(path));
    w += strlen(path);
    url[w] = '\0';

    out->document = doc;
    out->path = path;
    out->url = url;
    return AXIAM_OK;
}

char *axiam_protected_resource_metadata_json(
    const axiam_protected_resource_metadata_options_t *options, axiam_error_t *err) {
    built_metadata_t b;
    if (build_metadata(options, &b, err) != AXIAM_OK) {
        built_metadata_dispose(&b);
        return NULL;
    }
    char *json = cJSON_PrintUnformatted(b.document);
    built_metadata_dispose(&b);
    if (!json) refuse(err, "protected_resource_metadata", "document", "out of memory");
    return json;
}

char *axiam_protected_resource_metadata_path(
    const axiam_protected_resource_metadata_options_t *options, axiam_error_t *err) {
    built_metadata_t b;
    if (build_metadata(options, &b, err) != AXIAM_OK) {
        built_metadata_dispose(&b);
        return NULL;
    }
    char *path = axiam_strdup0(b.path);
    built_metadata_dispose(&b);
    if (!path) refuse(err, "protected_resource_metadata", "path", "out of memory");
    return path;
}

char *axiam_protected_resource_metadata_url(
    const axiam_protected_resource_metadata_options_t *options, axiam_error_t *err) {
    built_metadata_t b;
    if (build_metadata(options, &b, err) != AXIAM_OK) {
        built_metadata_dispose(&b);
        return NULL;
    }
    char *url = axiam_strdup0(b.url);
    built_metadata_dispose(&b);
    if (!url) refuse(err, "protected_resource_metadata", "url", "out of memory");
    return url;
}

/* --------------------------------------------------------------------- */
/* §28.4 — bearer_challenge                                                */
/* --------------------------------------------------------------------- */

/* §28.4's `resource_metadata` rule: an absolute URL (query/fragment
 * allowed) that ALSO carries none of '"', '\\', a space or a control
 * character — a correctly encoded URL cannot, so one that does has not been
 * encoded. */
static int resource_metadata_ok(const char *op, const char *url, axiam_error_t *err) {
    parsed_uri_t parsed;
    if (!require_absolute_uri(op, "resource_metadata", url, LOCATOR_POLICY, &parsed, err)) {
        return 0;
    }
    if (!all_chars(url, is_nqchar)) {
        /* NQCHAR excludes the space and every control character, and the
         * URI already carries no '"'/'\\' if it parsed at all — but a caller
         * can still hand a raw space or control byte inside the path. */
        refuse(err, op, "resource_metadata",
              "must carry no '\"', no '\\', no space and no control character");
        return 0;
    }
    return 1;
}

axiam_error_kind_t axiam_mcp_validate_resource_metadata_url(const char *url, axiam_error_t *err) {
    return resource_metadata_ok("resource_metadata_url", url, err) ? AXIAM_OK : AXIAM_ERR_NETWORK;
}

char *axiam_bearer_challenge(const axiam_bearer_challenge_options_t *options, axiam_error_t *err) {
    static const char *op = "bearer_challenge";
    axiam_error_reset(err);
    if (!options) {
        refuse(err, op, "options", "must not be NULL");
        return NULL;
    }

    strbuf_t sb;
    if (!strbuf_init(&sb)) {
        refuse(err, op, "challenge", "out of memory");
        return NULL;
    }
    if (!strbuf_append(&sb, "Bearer ")) goto oom;

    int first = 1;
#define APPEND_SEP()                                    \
    do {                                                \
        if (!first && !strbuf_append(&sb, ", ")) goto oom; \
        first = 0;                                       \
    } while (0)

    if (options->error) {
        if (strcmp(options->error, AXIAM_BEARER_ERROR_INVALID_REQUEST) != 0 &&
            strcmp(options->error, AXIAM_BEARER_ERROR_INVALID_TOKEN) != 0 &&
            strcmp(options->error, AXIAM_BEARER_ERROR_INSUFFICIENT_SCOPE) != 0) {
            refuse(err, op, "error",
                  "must be one of invalid_request, invalid_token, insufficient_scope");
            strbuf_free(&sb);
            return NULL;
        }
        APPEND_SEP();
        char part[64];
        snprintf(part, sizeof(part), "error=\"%s\"", options->error);
        if (!strbuf_append(&sb, part)) goto oom;
    }

    if (options->error_description) {
        if (options->error_description[0] == '\0' ||
            !all_chars(options->error_description, is_nqschar)) {
            refuse(err, op, "error_description",
                  "must be one or more NQSCHAR (no '\"', no '\\', no control character, "
                  "no non-ASCII) — a value needing an escape does not belong in a challenge");
            strbuf_free(&sb);
            return NULL;
        }
        APPEND_SEP();
        size_t n = strlen("error_description=\"\"") + strlen(options->error_description) + 1;
        char *part = malloc(n);
        if (!part) goto oom;
        snprintf(part, n, "error_description=\"%s\"", options->error_description);
        int ok = strbuf_append(&sb, part);
        free(part);
        if (!ok) goto oom;
    }

    if (options->scope) {
        const char *scope = options->scope;
        /* A trailing space needs its own check: it advances the scan past
         * the last separator to the NUL terminator, so the loop below would
         * otherwise exit on `while (*p)` before ever forming the empty final
         * token a leading or doubled space produces. */
        if (scope[0] == '\0' || scope[strlen(scope) - 1] == ' ') {
            refuse(err, op, "scope", "must be one or more scope tokens joined by a single space");
            strbuf_free(&sb);
            return NULL;
        }
        /* Split on ' ': no leading or doubled space, no empty token, every
         * token NQCHAR — replicated as the reference implementation's
         * split-then-validate does, so a leading or doubled space surfaces
         * as an empty token. */
        const char *p = scope;
        while (*p) {
            const char *tok_start = p;
            while (*p && *p != ' ') p++;
            size_t tok_len = (size_t)(p - tok_start);
            if (tok_len == 0) {
                refuse(err, op, "scope",
                      "is not a space-joined list of scope tokens — no leading, trailing or "
                      "doubled space, and no empty token");
                strbuf_free(&sb);
                return NULL;
            }
            for (size_t i = 0; i < tok_len; i++) {
                if (!is_nqchar((unsigned char)tok_start[i])) {
                    refuse(err, op, "scope",
                          "is not a space-joined list of scope tokens — no leading, trailing "
                          "or doubled space, and no empty token");
                    strbuf_free(&sb);
                    return NULL;
                }
            }
            if (*p == ' ') p++;
            else break;
        }
        /* A trailing space leaves p pointing at '\0' having just consumed
         * the separator with no token after it — that final iteration is
         * caught by the loop condition producing tok_len == 0 above. */
        APPEND_SEP();
        size_t n = strlen("scope=\"\"") + strlen(scope) + 1;
        char *part = malloc(n);
        if (!part) goto oom;
        snprintf(part, n, "scope=\"%s\"", scope);
        int ok = strbuf_append(&sb, part);
        free(part);
        if (!ok) goto oom;
    }

    if (!resource_metadata_ok(op, options->resource_metadata_url, err)) {
        strbuf_free(&sb);
        return NULL;
    }
    APPEND_SEP();
    {
        size_t n = strlen("resource_metadata=\"\"") + strlen(options->resource_metadata_url) + 1;
        char *part = malloc(n);
        if (!part) goto oom;
        snprintf(part, n, "resource_metadata=\"%s\"", options->resource_metadata_url);
        int ok = strbuf_append(&sb, part);
        free(part);
        if (!ok) goto oom;
    }

#undef APPEND_SEP
    return sb.buf;

oom:
    strbuf_free(&sb);
    refuse(err, op, "challenge", "out of memory");
    return NULL;
}

/* --------------------------------------------------------------------- */
/* §28.5 rule 3 — the serve_-less cross-check                             */
/* --------------------------------------------------------------------- */

axiam_error_kind_t axiam_mcp_check_resource_metadata(
    const axiam_client_config_t *cfg,
    const axiam_protected_resource_metadata_options_t *options, axiam_error_t *err) {
    static const char *op = "axiam_mcp_check_resource_metadata";
    axiam_error_reset(err);
    if (!cfg) {
        refuse(err, op, "cfg", "must not be NULL");
        return AXIAM_ERR_NETWORK;
    }
    const char *configured_url = cfg->resource_metadata_url;
    if (!configured_url) return AXIAM_OK; /* §28 is off: nothing to check */

    built_metadata_t b;
    if (build_metadata(options, &b, err) != AXIAM_OK) {
        built_metadata_dispose(&b);
        return AXIAM_ERR_NETWORK;
    }

    axiam_error_kind_t result = AXIAM_OK;
    if (strcmp(configured_url, b.url) != 0) {
        refuse(err, op, "resource_metadata_url",
              "does not equal this document's metadata_url — the challenge would point at a "
              "document that is not this resource server's");
        result = AXIAM_ERR_NETWORK;
    } else {
        const char *expected_audience = cfg->expected_audience;
        if (!expected_audience || strcmp(expected_audience, options->resource) != 0) {
            refuse(err, op, "expected_audience",
                  "does not equal this document's resource — the document would announce one "
                  "identifier while the guard checked aud against another");
            result = AXIAM_ERR_NETWORK;
        }
    }
    built_metadata_dispose(&b);
    return result;
}
