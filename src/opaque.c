/*
 * OPAQUE (RFC 9807) — the binding, CONTRACT.md §23.
 *
 * There is no cryptography in this file, and that is what §23.1 requires.
 * OPAQUE needs an oblivious PRF, hash_to_curve, expand_message_xmd, an envelope
 * construction and a three-message AKE; eleven independent implementations of
 * that is eleven chances to be subtly and silently wrong, in a way test vectors
 * do not catch because a wrong answer is still a well-formed group element.
 * The SRP-6a this replaces was arithmetic every language can express — which
 * here meant BN_mod_exp plus a hard dependency on OpenSSL >= 3.2 for Argon2id,
 * and a build against anything older could not serve a tenant on AXIAM's
 * default KDF.
 *
 * What is here instead: dlopen() of `libaxiam_opaque_ffi`, the exchange
 * lifecycle around it, and the bounds this SDK applies to a server-named cost.
 *
 * Two ownership rules run through the whole file, both stated at the point they
 * are implemented:
 *
 *  1. Every `char *` the library returns is Rust-allocated and must be released
 *     with `string_free` EXACTLY ONCE — on the failure paths as well as the
 *     success ones. A binding that freed only on success would leak once per
 *     failed login, which is the login rate an installation under attack sees.
 *  2. A state handle is CONSUMED by its finish, success or failure, and this
 *     file never frees one afterwards.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <pthread.h>

#include "internal.h"

/* ------------------------------------------------------------------------
 * Loading
 * ---------------------------------------------------------------------- */

/* The platform default. A bare name, so the dynamic loader resolves it from
 * its own search path — dlopen() is handed the string as-is. */
#if defined(__APPLE__)
#define AXIAM_OPAQUE_DEFAULT_LIBRARY "libaxiam_opaque_ffi.dylib"
#else
#define AXIAM_OPAQUE_DEFAULT_LIBRARY "libaxiam_opaque_ffi.so"
#endif

/* The resolved vtable. `g_attempted` memoizes FAILURE as well as success:
 * retrying dlopen() on every login is a per-request filesystem walk for a file
 * that is not going to appear. */
static axiam_opaque_native_t g_dynamic;
static const axiam_opaque_native_t *g_native = NULL;
static int g_attempted = 0;
static pthread_mutex_t g_native_mtx = PTHREAD_MUTEX_INITIALIZER;

/* Resolve every symbol up front rather than lazily. A library that loads and is
 * missing one export is some OTHER library of the same name on the search path,
 * and the moment to discover that is now, not at the first login. */
static int resolve_all(void *handle, axiam_opaque_native_t *out) {
    struct {
        const char *name;
        void **slot;
    } table[] = {
        { "axiam_opaque_available", (void **)&out->available },
        { "axiam_opaque_last_error", (void **)&out->last_error },
        { "axiam_opaque_string_free", (void **)&out->string_free },
        { "axiam_opaque_ksf_argon2id", (void **)&out->ksf_argon2id },
        { "axiam_opaque_ksf_scrypt", (void **)&out->ksf_scrypt },
        { "axiam_opaque_ksf_free", (void **)&out->ksf_free },
        { "axiam_opaque_registration_start", (void **)&out->registration_start },
        { "axiam_opaque_registration_finish", (void **)&out->registration_finish },
        { "axiam_opaque_registration_free", (void **)&out->registration_free },
        { "axiam_opaque_login_start", (void **)&out->login_start },
        { "axiam_opaque_login_finish", (void **)&out->login_finish },
        { "axiam_opaque_login_free", (void **)&out->login_free },
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        /* An object pointer is not a function pointer in ISO C, and dlsym()
         * hands back the former. The memcpy is the portable spelling of the
         * conversion POSIX blesses; a direct cast is what -Wpedantic objects
         * to. */
        void *sym = dlsym(handle, table[i].name);
        if (!sym) return -1;
        memcpy(table[i].slot, &sym, sizeof(sym));
    }
    return 0;
}

/* Caller must hold g_native_mtx. */
static const axiam_opaque_native_t *load_locked(void) {
    if (g_attempted) return g_native;
    g_attempted = 1;

    const char *override = getenv(AXIAM_OPAQUE_LIBRARY_ENV);
    const char *path = (override && override[0]) ? override : AXIAM_OPAQUE_DEFAULT_LIBRARY;

    /* RTLD_NOW so a missing symbol is a failure to load rather than a crash at
     * the first login. No dlclose(): the vtable is memoized for the process
     * lifetime, and closing a library whose function pointers are still
     * reachable is a worse failure than holding a handle until exit. */
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return NULL;

    memset(&g_dynamic, 0, sizeof(g_dynamic));
    if (resolve_all(handle, &g_dynamic) != 0) return NULL;
    if (!g_dynamic.available()) return NULL;

    g_native = &g_dynamic;
    return g_native;
}

const axiam_opaque_native_t *axiam_opaque_native(void) {
    pthread_mutex_lock(&g_native_mtx);
    const axiam_opaque_native_t *n = load_locked();
    pthread_mutex_unlock(&g_native_mtx);
    return n;
}

void axiam_opaque_native_set_for_tests(const axiam_opaque_native_t *native) {
    pthread_mutex_lock(&g_native_mtx);
    g_native = native;
    g_attempted = 1;
    pthread_mutex_unlock(&g_native_mtx);
}

void axiam_opaque_native_reset_for_tests(void) {
    pthread_mutex_lock(&g_native_mtx);
    g_native = NULL;
    g_attempted = 0;
    pthread_mutex_unlock(&g_native_mtx);
}

int axiam_opaque_available(void) {
    return axiam_opaque_native() != NULL ? 1 : 0;
}

/* ------------------------------------------------------------------------
 * Error text
 * ---------------------------------------------------------------------- */

/* The library's description of the last failure, or `fallback`. A failure with
 * nothing behind it is a library bug, but a caller still deserves a sentence
 * rather than an empty one. */
static const char *last_error(const axiam_opaque_native_t *lib, const char *fallback) {
    const char *msg = lib->last_error ? lib->last_error() : NULL;
    return (msg && msg[0]) ? msg : fallback;
}

static void set_prefixed(axiam_error_t *err, axiam_error_kind_t kind, const char *detail) {
    char msg[256];
    snprintf(msg, sizeof(msg), "OPAQUE: %s", detail ? detail : "");
    axiam_error_set(err, kind, 0, msg);
}

/* The library refused, and it is not a credential failure. */
static axiam_error_kind_t refuse(const axiam_opaque_native_t *lib, axiam_error_t *err,
                                 const char *fallback) {
    set_prefixed(err, AXIAM_ERR_NETWORK, last_error(lib, fallback));
    return AXIAM_ERR_NETWORK;
}

/* ------------------------------------------------------------------------
 * Key stretching (§23.4)
 * ---------------------------------------------------------------------- */

/* The bands this SDK will act on, per field.
 *
 * A server is trusted to name its own policy, not to name a cost that would
 * wedge every device an account owns. The library range-checks too; doing it
 * here as well means the refusal names the field. */
#define KSF_MEMORY_KIB_MIN 8192u
#define KSF_MEMORY_KIB_MAX 1048576u
#define KSF_ITERATIONS_MIN 1u
#define KSF_ITERATIONS_MAX 10u
#define KSF_PARALLELISM_MIN 1u
#define KSF_PARALLELISM_MAX 16u
#define KSF_LOG_N_MIN 14u
#define KSF_LOG_N_MAX 20u
#define KSF_R_MIN 1u
#define KSF_R_MAX 16u
#define KSF_P_MIN 1u
#define KSF_P_MAX 16u

/* One cost the named function needs: present, and inside the band.
 *
 * `present` is a flag rather than a "value != 0" test because a field that does
 * not apply to the named function is ABSENT on the wire, not zero (§23.4
 * rule 5), and the two failures deserve different sentences. */
static int require_cost(const char *ksf_name, const char *field, int present, unsigned value,
                        unsigned lo, unsigned hi, axiam_error_t *err) {
    char msg[256];
    if (!present) {
        snprintf(msg, sizeof(msg), "OPAQUE: the server named ksf `%s` without `%s`",
                 ksf_name, field);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
        return -1;
    }
    if (value < lo || value > hi) {
        snprintf(msg, sizeof(msg),
                 "OPAQUE: the server named %s=%u for `%s`, outside the accepted %u..%u",
                 field, value, ksf_name, lo, hi);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
        return -1;
    }
    return 0;
}

void *axiam_opaque_ksf_build(const axiam_opaque_native_t *lib,
                             const axiam_opaque_ksf_params_t *ksf,
                             axiam_error_t *err) {
    if (!lib || !ksf) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "OPAQUE: invalid arguments");
        return NULL;
    }
    const char *name = ksf->ksf ? ksf->ksf : "";
    void *handle = NULL;

    if (strcmp(name, AXIAM_OPAQUE_KSF_ARGON2ID) == 0) {
        if (require_cost(name, "memory_kib", ksf->has_memory_kib, ksf->memory_kib,
                         KSF_MEMORY_KIB_MIN, KSF_MEMORY_KIB_MAX, err) != 0 ||
            require_cost(name, "iterations", ksf->has_iterations, ksf->iterations,
                         KSF_ITERATIONS_MIN, KSF_ITERATIONS_MAX, err) != 0 ||
            require_cost(name, "parallelism", ksf->has_parallelism, ksf->parallelism,
                         KSF_PARALLELISM_MIN, KSF_PARALLELISM_MAX, err) != 0) {
            return NULL;
        }
        handle = lib->ksf_argon2id(ksf->memory_kib, ksf->iterations, ksf->parallelism);
    } else if (strcmp(name, AXIAM_OPAQUE_KSF_SCRYPT) == 0) {
        if (require_cost(name, "log_n", ksf->has_log_n, ksf->log_n,
                         KSF_LOG_N_MIN, KSF_LOG_N_MAX, err) != 0 ||
            require_cost(name, "r", ksf->has_r, ksf->r, KSF_R_MIN, KSF_R_MAX, err) != 0 ||
            require_cost(name, "p", ksf->has_p, ksf->p, KSF_P_MIN, KSF_P_MAX, err) != 0) {
            return NULL;
        }
        handle = lib->ksf_scrypt((unsigned char)ksf->log_n, ksf->r, ksf->p);
    } else {
        /* Refused, never substituted. Substituting produces a well-formed
         * randomized password no AXIAM server agrees with, which surfaces to
         * the user as a wrong password (§23.4 rule 3). AXIAM_ERR_NETWORK, not
         * AXIAM_ERR_AUTH — a client capability gap reported as a credential
         * failure would send a user to reset a working password. */
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "OPAQUE: this SDK cannot perform the key-stretching function the server "
                 "named (`%s`)", name);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg);
        return NULL;
    }

    if (!handle) {
        set_prefixed(err, AXIAM_ERR_NETWORK, last_error(lib, "invalid KSF parameters"));
        return NULL;
    }
    return handle;
}

/* ------------------------------------------------------------------------
 * Exchanges
 * ---------------------------------------------------------------------- */

/* Copies a library-returned string into an SDK-owned one and releases the
 * original. Doing the free in the same function that reads the value makes
 * "exactly once" true by construction rather than by every caller remembering.
 * Returns NULL on allocation failure, having still freed the original. */
static char *take(const axiam_opaque_native_t *lib, char *owned) {
    if (!owned) return NULL;
    /* axiam_strdup0 rather than strdup: it allocates with malloc, which
     * tests/test_alloc_failures.c can make fail at link time, so the guard
     * below is a branch the suite actually reaches rather than one gcovr
     * reports uncovered forever. */
    char *copy = axiam_strdup0(owned);
    lib->string_free(owned);
    return copy;
}

static axiam_error_kind_t start(axiam_opaque_exchange_t *x, const char *password,
                                int is_login, axiam_error_t *err) {
    memset(x, 0, sizeof(*x));

    const axiam_opaque_native_t *lib = axiam_opaque_native();
    if (!lib) {
        /* Names the artifact, never the password. Absent is a deployment fact,
         * and reporting it as a credential failure would send a user off to
         * reset a password that works. */
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "OPAQUE is not available: the shared library `libaxiam_opaque_ffi` "
                        "could not be loaded. Download the asset for your platform, then put "
                        "it on the system library path or set " AXIAM_OPAQUE_LIBRARY_ENV
                        " to its full path.");
        return AXIAM_ERR_NETWORK;
    }

    char *message = NULL;
    void *state = is_login ? lib->login_start(password, &message)
                           : lib->registration_start(password, &message);
    if (!state) {
        /* A start that failed produced no message to free, but a library that
         * wrote one anyway must not leak it. */
        if (message) lib->string_free(message);
        return refuse(lib, err, is_login ? "login could not be started"
                                         : "registration could not be started");
    }

    x->lib = lib;
    x->state = state;
    x->is_login = is_login;
    x->first_message = take(lib, message);
    if (!x->first_message) {
        axiam_opaque_exchange_close(x);
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

axiam_error_kind_t axiam_opaque_start_registration(axiam_opaque_exchange_t *x,
                                                   const char *password,
                                                   axiam_error_t *err) {
    return start(x, password, 0, err);
}

axiam_error_kind_t axiam_opaque_start_login(axiam_opaque_exchange_t *x,
                                            const char *password,
                                            axiam_error_t *err) {
    return start(x, password, 1, err);
}

void axiam_opaque_exchange_close(axiam_opaque_exchange_t *x) {
    if (!x) return;
    if (x->state && x->lib) {
        if (x->is_login) x->lib->login_free(x->state);
        else x->lib->registration_free(x->state);
    }
    x->state = NULL;
    if (x->first_message) {
        /* The first message is not secret — it is about to cross the wire —
         * but it is derived from the password, so it is cleared on the same
         * principle §7 applies to a request body. */
        OPENSSL_cleanse(x->first_message, strlen(x->first_message));
        free(x->first_message);
        x->first_message = NULL;
    }
    x->lib = NULL;
}

axiam_error_kind_t axiam_opaque_exchange_finish(axiam_opaque_exchange_t *x,
                                                const char *password,
                                                const char *peer_message,
                                                const axiam_opaque_ksf_params_t *ksf,
                                                char **out_hex,
                                                axiam_error_t *err) {
    if (out_hex) *out_hex = NULL;
    if (!x || !x->lib || !out_hex) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "OPAQUE: invalid arguments");
        return AXIAM_ERR_NETWORK;
    }
    if (!x->state) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "OPAQUE: this exchange has already been completed");
        return AXIAM_ERR_NETWORK;
    }

    const axiam_opaque_native_t *lib = x->lib;

    /* The key-stretching handle is built BEFORE the state is spent, and the
     * order is load-bearing. axiam_opaque_ksf_build() refuses an unrecognised
     * function or an out-of-band cost, and if the state had already been taken
     * out of `x` by then it could never be freed — a leaked native allocation
     * per refused attempt, which is once per login against a misconfigured
     * tenant. Built first, a refusal leaves the exchange intact: close() still
     * releases it, and a caller who fixes the parameters can retry. */
    void *ksf_handle = axiam_opaque_ksf_build(lib, ksf, err);
    if (!ksf_handle) return AXIAM_ERR_NETWORK;

    void *state = x->state;
    x->state = NULL; /* consumed by the call below, success or failure */

    char *raw = x->is_login
                    ? lib->login_finish(state, password, peer_message, ksf_handle, NULL, NULL)
                    : lib->registration_finish(state, password, peer_message, ksf_handle, NULL);
    lib->ksf_free(ksf_handle);

    if (!raw) {
        if (x->is_login) {
            /* The whole of the client's authentication check, and it covers
             * both halves of the mutual authentication: the envelope only opens
             * under the right password, and KE2's MAC only verifies if the
             * server actually holds the record. RFC 9807's AKE authenticates
             * the server during the handshake, so there is no separate M2 step
             * the way SRP needed one — and per §23.4 rule 7 nothing may be sent
             * to login/finish after this. */
            char msg[256];
            snprintf(msg, sizeof(msg), "invalid credentials: %s",
                     last_error(lib, "the OPAQUE envelope did not open"));
            set_prefixed(err, AXIAM_ERR_AUTH, msg);
            return AXIAM_ERR_AUTH;
        }
        return refuse(lib, err, "the envelope could not be sealed");
    }

    *out_hex = take(lib, raw);
    if (!*out_hex) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "out of memory");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

/* ------------------------------------------------------------------------
 * The public enrolment type
 * ---------------------------------------------------------------------- */

void axiam_opaque_enrollment_dispose(axiam_opaque_enrollment_t *e) {
    if (!e) return;
    if (e->opaque_session) {
        OPENSSL_cleanse(e->opaque_session, strlen(e->opaque_session));
        free(e->opaque_session);
    }
    if (e->registration_record) {
        /* §23.5: credential material. Cleared rather than merely freed. */
        OPENSSL_cleanse(e->registration_record, strlen(e->registration_record));
        free(e->registration_record);
    }
    memset(e, 0, sizeof(*e));
}
