/*
 * A stub `libaxiam_opaque_ffi`, built as a real shared library.
 *
 * tests/opaque_fake.h substitutes a vtable through the internal test seam,
 * which covers everything above the ABI but jumps over src/opaque.c's actual
 * dlopen()/dlsym() resolution — the one part a Swift or C# SDK cannot test at
 * all without shipping a per-platform binary. C can: this file exports the
 * twelve symbols the real library exports, gets built into a `MODULE` library
 * next to the test binary, and is loaded through AXIAM_OPAQUE_LIBRARY by the
 * genuine loader path.
 *
 * It performs NO cryptography and is not a reference implementation of
 * anything. Its whole job is to be a library that loads, so the resolution,
 * the availability check, the string-ownership rules and the state-handle
 * lifetime are exercised against a real dynamic object rather than a function
 * pointer table the test wrote by hand.
 *
 * Two environment variables let one library stand in for the failure shapes
 * the loader has to survive:
 *
 *   AXIAM_OPAQUE_STUB_UNAVAILABLE — axiam_opaque_available() returns 0, which
 *       is a library that loads and then declines. The loader must not adopt
 *       it.
 *   AXIAM_OPAQUE_STUB_FAIL — a comma-free substring naming an entry point
 *       ("login_finish", "registration_finish", "login_start",
 *       "registration_start", "ksf") that should return NULL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The stub's own handle types. The SDK only ever passes these back. */
typedef struct { int is_login; } stub_state_t;
typedef struct { unsigned tag; } stub_ksf_t;

static char g_last_error[256];

static int failing(const char *entry_point) {
    const char *spec = getenv("AXIAM_OPAQUE_STUB_FAIL");
    if (!spec || !spec[0]) return 0;
    if (!strstr(spec, entry_point)) return 0;
    snprintf(g_last_error, sizeof(g_last_error), "stub refused %s", entry_point);
    return 1;
}

/* Rust hands back heap strings the caller frees through string_free; malloc and
 * free are the same contract. */
static char *stub_string(const char *text) {
    size_t n = strlen(text);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, text, n + 1);
    return p;
}

int axiam_opaque_available(void) {
    const char *off = getenv("AXIAM_OPAQUE_STUB_UNAVAILABLE");
    return (off && off[0]) ? 0 : 1;
}

/* Borrowed, not owned — the SDK must NOT free this. */
const char *axiam_opaque_last_error(void) { return g_last_error; }

void axiam_opaque_string_free(char *ptr) { free(ptr); }

void *axiam_opaque_ksf_argon2id(unsigned memory_kib, unsigned iterations,
                                unsigned parallelism) {
    if (failing("ksf")) return NULL;
    stub_ksf_t *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->tag = 0xA0000u + memory_kib + iterations + parallelism;
    return k;
}

void *axiam_opaque_ksf_scrypt(unsigned char log_n, unsigned r, unsigned p) {
    if (failing("ksf")) return NULL;
    stub_ksf_t *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->tag = 0xB0000u + log_n + r + p;
    return k;
}

void axiam_opaque_ksf_free(void *ksf) { free(ksf); }

static void *stub_start(const char *prefix, const char *password, int is_login,
                        char **out_message) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s%s", prefix, password ? password : "");
    *out_message = stub_string(buf);
    if (!*out_message) return NULL;
    stub_state_t *s = calloc(1, sizeof(*s));
    if (!s) {
        free(*out_message);
        *out_message = NULL;
        return NULL;
    }
    s->is_login = is_login;
    return s;
}

void *axiam_opaque_registration_start(const char *password, char **out_request) {
    *out_request = NULL;
    if (failing("registration_start")) return NULL;
    return stub_start("req:", password, 0, out_request);
}

char *axiam_opaque_registration_finish(void *state, const char *password,
                                       const char *registration_response, const void *ksf,
                                       char **out_export_key) {
    if (out_export_key) *out_export_key = NULL;
    const stub_ksf_t *k = ksf;
    free(state); /* consumed, success or failure */
    if (failing("registration_finish")) return NULL;
    char buf[600];
    snprintf(buf, sizeof(buf), "record:%s:%s:%x", password ? password : "",
             registration_response ? registration_response : "", k ? k->tag : 0u);
    return stub_string(buf);
}

void axiam_opaque_registration_free(void *state) { free(state); }

void *axiam_opaque_login_start(const char *password, char **out_ke1) {
    *out_ke1 = NULL;
    if (failing("login_start")) return NULL;
    return stub_start("ke1:", password, 1, out_ke1);
}

char *axiam_opaque_login_finish(void *state, const char *password, const char *ke2,
                                const void *ksf, char **out_session_key,
                                char **out_export_key) {
    if (out_session_key) *out_session_key = NULL;
    if (out_export_key) *out_export_key = NULL;
    const stub_ksf_t *k = ksf;
    free(state); /* consumed, success or failure */
    if (failing("login_finish")) return NULL;
    char buf[600];
    snprintf(buf, sizeof(buf), "ke3:%s:%s:%x", password ? password : "", ke2 ? ke2 : "",
             k ? k->tag : 0u);
    return stub_string(buf);
}

#ifdef AXIAM_OPAQUE_STUB_INCOMPLETE
/* Built a second time with this defined, the library is missing one export.
 * That is not a broken AXIAM library — it is some OTHER library of the same
 * name that happened to be first on the search path, and src/opaque.c has to
 * refuse it at load time rather than crash at the first login. */
void axiam_opaque_login_free_renamed(void *state) { free(state); }
#else
void axiam_opaque_login_free(void *state) { free(state); }
#endif
