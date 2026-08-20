/*
 * An in-process stand-in for `libaxiam_opaque_ffi`.
 *
 * CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no
 * cryptography to test and no cross-language vector suite to run — the SRP
 * suite this replaces spent 600 lines proving a hand-written modular
 * exponentiation reproduced six vectors, and that arithmetic is gone. What
 * remains, and what this fake exercises, is the layer above the ABI:
 * single-use exchanges, the key-stretching function the SERVER named being the
 * one used, which failure means what, and what goes on the wire.
 *
 * It does NOT stand in for the dlopen()/dlsym() resolution, which needs the
 * real shared library — which is exactly why src/opaque.c keeps that part as
 * small as it can be. Requiring the real cdylib here would give a suite that
 * runs only where a per-platform release asset happens to be installed, and
 * would be testing `opaque-ke` rather than this SDK.
 *
 * Every value it returns is heap-allocated with the same ownership the real
 * ABI has, and every allocation is counted: `fake_opaque_leaked()` is non-zero
 * if the SDK dropped a string, a key-stretching handle or a state handle. That
 * counter is the assertion that matters here — the ordering defect this
 * migration was built to avoid (spending the state handle before the KSF is
 * built) shows up in it and nowhere else.
 */
#ifndef AXIAM_TEST_OPAQUE_FAKE_H
#define AXIAM_TEST_OPAQUE_FAKE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "internal.h"

/* Entry points that can be made to fail, by index. */
typedef enum {
    FAKE_KSF_ARGON2ID = 0,
    FAKE_KSF_SCRYPT,
    FAKE_REGISTRATION_START,
    FAKE_REGISTRATION_FINISH,
    FAKE_LOGIN_START,
    FAKE_LOGIN_FINISH,
    FAKE_ENTRY_POINT_COUNT
} fake_entry_point_t;

/* A live state handle, so the fake can insist a finish gets a handle that is
 * really outstanding and really of the right kind. */
typedef struct {
    int is_login;
    int used;
} fake_state_handle_t;

typedef struct {
    int available;
    int fail[FAKE_ENTRY_POINT_COUNT];
    char last_error[256];
    /* Overrides last_error for a failing entry point. An empty string models a
     * library that failed without saying why — a bug, but one the caller still
     * needs a sentence for. */
    const char *fail_message[FAKE_ENTRY_POINT_COUNT];

    int strings_alive;  /**< returned char* not yet passed to string_free. */
    int ksf_alive;      /**< ksf handles built and not yet freed. */
    int states_alive;   /**< state handles neither consumed nor freed. */

    /* What the last finish was given, so a test can assert the SERVER's ksf is
     * the one that reached the library. */
    unsigned last_ksf_tag;
    char last_peer_message[512];
    char last_password[256];
} fake_opaque_t;

extern fake_opaque_t g_fake_opaque;

/* A ksf handle is a heap cell carrying a tag the finish echoes, so a test can
 * tell argon2id from scrypt and one cost from another. */
typedef struct { unsigned tag; } fake_ksf_t;

static inline void fake_opaque_reset(void) {
    memset(&g_fake_opaque, 0, sizeof(g_fake_opaque));
    g_fake_opaque.available = 1;
}

/** Non-zero when the SDK dropped a string, a ksf handle or a state handle. */
static inline int fake_opaque_leaked(void) {
    return g_fake_opaque.strings_alive != 0 || g_fake_opaque.ksf_alive != 0 ||
           g_fake_opaque.states_alive != 0;
}

static inline int fake_failed(fake_entry_point_t ep, const char *fallback) {
    if (!g_fake_opaque.fail[ep]) return 0;
    const char *msg = g_fake_opaque.fail_message[ep] ? g_fake_opaque.fail_message[ep] : fallback;
    snprintf(g_fake_opaque.last_error, sizeof(g_fake_opaque.last_error), "%s", msg);
    return 1;
}

/* A NULL return models a library that could not allocate, which is a refusal
 * like any other — the alloc-failure sweep makes exactly that happen, and the
 * SDK has to survive it rather than the fake asserting on the test's behalf. */
static inline char *fake_string(const char *text) {
    char *copy = strdup(text);
    if (!copy) return NULL;
    g_fake_opaque.strings_alive++;
    return copy;
}

/* -- the ABI ------------------------------------------------------------- */

static inline int fake_available(void) { return g_fake_opaque.available; }

static inline const char *fake_last_error(void) { return g_fake_opaque.last_error; }

static inline void fake_string_free(char *ptr) {
    TEST_ASSERT_NOT_NULL(ptr);
    g_fake_opaque.strings_alive--;
    free(ptr);
}

static inline void *fake_ksf_argon2id(unsigned memory_kib, unsigned iterations,
                                      unsigned parallelism) {
    if (fake_failed(FAKE_KSF_ARGON2ID, "argon2id parameters rejected")) return NULL;
    fake_ksf_t *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->tag = 0xA0000u + memory_kib + iterations + parallelism;
    g_fake_opaque.ksf_alive++;
    return k;
}

static inline void *fake_ksf_scrypt(unsigned char log_n, unsigned r, unsigned p) {
    if (fake_failed(FAKE_KSF_SCRYPT, "scrypt parameters rejected")) return NULL;
    fake_ksf_t *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->tag = 0xB0000u + log_n + r + p;
    g_fake_opaque.ksf_alive++;
    return k;
}

static inline void fake_ksf_free(void *ksf) {
    TEST_ASSERT_NOT_NULL(ksf);
    g_fake_opaque.ksf_alive--;
    free(ksf);
}

static inline void *fake_state_new(int is_login) {
    fake_state_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->is_login = is_login;
    g_fake_opaque.states_alive++;
    return h;
}

/* The library CONSUMES a state handle in its finish, success or failure. */
static inline void fake_state_consume(void *state, int is_login) {
    fake_state_handle_t *h = state;
    TEST_ASSERT_NOT_NULL(h);
    TEST_ASSERT_FALSE_MESSAGE(h->used, "a spent state handle reached the library again");
    TEST_ASSERT_EQUAL_INT_MESSAGE(is_login, h->is_login, "state handle used by the wrong half");
    h->used = 1;
    g_fake_opaque.states_alive--;
    free(h);
}

static inline void fake_record_finish(const char *password, const char *peer, const void *ksf) {
    const fake_ksf_t *k = ksf;
    g_fake_opaque.last_ksf_tag = k ? k->tag : 0;
    snprintf(g_fake_opaque.last_password, sizeof(g_fake_opaque.last_password), "%s",
             password ? password : "");
    snprintf(g_fake_opaque.last_peer_message, sizeof(g_fake_opaque.last_peer_message), "%s",
             peer ? peer : "");
}

/* Both starts hand back a state AND a message, so neither may half-succeed:
 * a state with no message would be an allocation the caller can never reach. */
static inline void *fake_start(const char *prefix, const char *password, int is_login,
                               char **out_message) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s%s", prefix, password ? password : "");
    *out_message = fake_string(buf);
    if (!*out_message) return NULL;
    void *state = fake_state_new(is_login);
    if (!state) {
        fake_string_free(*out_message);
        *out_message = NULL;
    }
    return state;
}

static inline void *fake_registration_start(const char *password, char **out_request) {
    *out_request = NULL;
    if (fake_failed(FAKE_REGISTRATION_START, "registration could not be started")) return NULL;
    return fake_start("req:", password, 0, out_request);
}

static inline char *fake_registration_finish(void *state, const char *password,
                                             const char *registration_response,
                                             const void *ksf, char **out_export_key) {
    (void)out_export_key;
    fake_state_consume(state, 0);
    fake_record_finish(password, registration_response, ksf);
    if (fake_failed(FAKE_REGISTRATION_FINISH, "the envelope could not be sealed")) return NULL;
    char buf[512];
    snprintf(buf, sizeof(buf), "record:%s:%s:%x", password ? password : "",
             registration_response ? registration_response : "", g_fake_opaque.last_ksf_tag);
    return fake_string(buf);
}

static inline void fake_registration_free(void *state) { fake_state_consume(state, 0); }

static inline void *fake_login_start(const char *password, char **out_ke1) {
    *out_ke1 = NULL;
    if (fake_failed(FAKE_LOGIN_START, "login could not be started")) return NULL;
    return fake_start("ke1:", password, 1, out_ke1);
}

static inline char *fake_login_finish(void *state, const char *password, const char *ke2,
                                      const void *ksf, char **out_session_key,
                                      char **out_export_key) {
    (void)out_session_key;
    (void)out_export_key;
    fake_state_consume(state, 1);
    fake_record_finish(password, ke2, ksf);
    if (fake_failed(FAKE_LOGIN_FINISH, "the envelope did not open")) return NULL;
    char buf[512];
    snprintf(buf, sizeof(buf), "ke3:%s:%s:%x", password ? password : "", ke2 ? ke2 : "",
             g_fake_opaque.last_ksf_tag);
    return fake_string(buf);
}

static inline void fake_login_free(void *state) { fake_state_consume(state, 1); }

static inline const axiam_opaque_native_t *fake_opaque_vtable(void) {
    static const axiam_opaque_native_t vtable = {
        fake_available,
        fake_last_error,
        fake_string_free,
        fake_ksf_argon2id,
        fake_ksf_scrypt,
        fake_ksf_free,
        fake_registration_start,
        fake_registration_finish,
        fake_registration_free,
        fake_login_start,
        fake_login_finish,
        fake_login_free,
    };
    return &vtable;
}

/** Install the fake and clear its counters. */
static inline void fake_opaque_install(void) {
    fake_opaque_reset();
    axiam_opaque_native_set_for_tests(fake_opaque_vtable());
}

#endif /* AXIAM_TEST_OPAQUE_FAKE_H */
