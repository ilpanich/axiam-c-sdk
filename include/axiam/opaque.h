/*
 * AXIAM C SDK — OPAQUE (RFC 9807), CONTRACT.md §23.
 *
 * OPAQUE is an *augmented PAKE*: the client proves knowledge of the password
 * without the password, or anything from which the password can be cheaply
 * recovered, ever crossing the wire. The server stores a registration record
 * sealed under a tenant-scoped oblivious PRF instead of a password hash.
 *
 * What this closes, and what it does not (§23.0). OPAQUE defends against a
 * TLS-terminating proxy, an accidental request-body log, and a heap dump —
 * places a plaintext password exists today and would not under OPAQUE. It also
 * does what the SRP-6a it replaces could not: a stolen record database is not
 * offline-crackable on its own, because grinding candidates needs the tenant's
 * OPRF seed as well as the records. That property is pre-computation
 * resistance. It does NOT defend against a compromised AXIAM server.
 *
 * THIS SDK DOES NOT IMPLEMENT OPAQUE (§23.1), and that is the design rather
 * than a gap. OPAQUE needs an oblivious PRF, hash_to_curve, expand_message_xmd,
 * an envelope construction and a three-message authenticated key exchange;
 * eleven independent implementations of that is eleven chances to be subtly
 * and silently wrong, in a way test vectors do not catch because a wrong
 * answer is still a well-formed group element. What lives here is a binding to
 * `libaxiam_opaque_ffi`, the C ABI of the same audited core the AXIAM server
 * links.
 *
 * That library is a per-platform release asset, resolved with dlopen() at run
 * time rather than linked. A consumer who never uses OPAQUE therefore needs
 * nothing extra, and axiam_opaque_available() can honestly answer 0. Install
 * the library where the dynamic loader looks, or set AXIAM_OPAQUE_LIBRARY to
 * its full path.
 *
 * THE CONDITIONAL SUPPORT THIS REPLACES IS GONE. The SRP client needed
 * OpenSSL >= 3.2 for Argon2id, so a build against an older libcrypto could not
 * serve a tenant on AXIAM's default KDF. Key stretching now happens inside
 * `libaxiam_opaque_ffi`, so the OpenSSL version no longer decides which tenants
 * work — and unlike axiam_srp_available(), a 1 from axiam_opaque_available()
 * IS a promise that every tenant will work.
 */
#ifndef AXIAM_OPAQUE_H
#define AXIAM_OPAQUE_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Wire name of the memory-hard key-stretching function AXIAM asks for by default. */
#define AXIAM_OPAQUE_KSF_ARGON2ID "argon2id"
/** Wire name of the alternative AXIAM accepts. */
#define AXIAM_OPAQUE_KSF_SCRYPT "scrypt"

/**
 * Environment variable naming the full path to `libaxiam_opaque_ffi`.
 *
 * Checked before the platform's own search path, which is the normal case for
 * a container image that ships the artifact alongside the application rather
 * than installing it system-wide.
 */
#define AXIAM_OPAQUE_LIBRARY_ENV "AXIAM_OPAQUE_LIBRARY"

/**
 * The key-stretching function and cost a `*_/start` response names (§23.4).
 *
 * Every cost carries a `has_` flag rather than using 0 as "absent". A field
 * that does not apply to the named function is ABSENT on the wire, not zero
 * (§23.4 rule 5), and reading a missing memory_kib as 0 would stretch at the
 * wrong cost and fail against a record that is perfectly good.
 *
 * These arrive per exchange and are honoured as given. They are deliberately
 * NOT cached across logins and never defaulted locally (§23.4 rule 2): a
 * credential enrolled under one cost keeps working after a tenant raises its
 * policy, so a client that guessed would derive a different randomized
 * password and report "invalid password" for one that is entirely correct.
 */
typedef struct axiam_opaque_ksf_params {
    const char *ksf;      /**< AXIAM_OPAQUE_KSF_ARGON2ID or AXIAM_OPAQUE_KSF_SCRYPT. */
    int has_memory_kib;   /**< Non-zero when the server named `memory_kib`. */
    unsigned memory_kib;  /**< Argon2id's memory cost in KiB. */
    int has_iterations;   /**< Non-zero when the server named `iterations`. */
    unsigned iterations;  /**< Argon2id's time cost. */
    int has_parallelism;  /**< Non-zero when the server named `parallelism`. */
    unsigned parallelism; /**< Argon2id's lane count. */
    int has_log_n;        /**< Non-zero when the server named `log_n`. */
    unsigned log_n;       /**< scrypt's base-2 CPU/memory cost. */
    int has_r;            /**< Non-zero when the server named `r`. */
    unsigned r;           /**< scrypt's block size. */
    int has_p;            /**< Non-zero when the server named `p`. */
    unsigned p;           /**< scrypt's parallelisation parameter. */
} axiam_opaque_ksf_params_t;

/**
 * The `opaque` object §23.5 defines: a registration record and the server-issued
 * handle identifying the exchange it came from.
 *
 * The server cannot build this — it never sees the plaintext — so any request
 * that SETS a password has to carry it: POST /api/v1/users,
 * /auth/password/change, /auth/reset/confirm and /admin/bootstrap.
 *
 * Note what is NOT here. The SRP enrolment this replaces carried a salt, a
 * group and a full set of KDF costs, and required the account's canonical
 * USERNAME — an email there produced a verifier no login could ever satisfy,
 * and renaming a user invalidated their verifier outright. A record binds to a
 * credential identifier the server chooses, and the key-stretching parameters
 * are the server's, so there is nothing here a caller can get wrong.
 *
 * `registration_record` is credential material and may not be logged. Release
 * with axiam_opaque_enrollment_dispose(), which zeroizes it.
 */
typedef struct axiam_opaque_enrollment {
    char *opaque_session;       /**< The handle `register/start` issued. */
    char *registration_record;  /**< The hex RegistrationRecord. */
} axiam_opaque_enrollment_t;

/** Release and zeroize an enrolment's heap members (not the struct itself). */
void axiam_opaque_enrollment_dispose(axiam_opaque_enrollment_t *e);

/**
 * Whether this installation can perform OPAQUE (§23.2).
 *
 * Returns 1 when `libaxiam_opaque_ffi` loaded and reports itself usable, 0
 * otherwise. Reports rather than failing, so an application chooses the
 * password path up front instead of discovering the gap mid-login.
 *
 * Genuinely able to answer 0 — and unlike axiam_srp_available(), which was
 * effectively hard-coded to 1 while an argon2id tenant still failed at login,
 * a 1 here IS a promise that every tenant will work. The result is memoized:
 * retrying dlopen() per login is a filesystem walk for a file that is not
 * going to appear.
 */
int axiam_opaque_available(void);

/**
 * POST /api/v1/auth/opaque/login/start followed by /finish — OPAQUE login (§23).
 *
 * A sibling of axiam_login(), not a replacement. It takes the same arguments
 * and fills the same axiam_login_result_t, MFA branch included, so an
 * application can switch a tenant to OPAQUE without touching its own code
 * (§23.1).
 *
 * The password never leaves this process. What crosses the wire is a blinded
 * group element and a MAC, neither useful without the account's registration
 * record AND the tenant's OPRF seed.
 *
 * Cost: runs the tenant's key-stretching function — Argon2id at 19 MiB and t=2
 * by default, tens to hundreds of milliseconds of CPU plus that memory, per
 * attempt. That cost is the point: it is what makes a stolen record expensive
 * to attack even by someone holding the OPRF seed.
 *
 * Returns AXIAM_ERR_NETWORK when the tenant has OPAQUE disabled (the endpoint
 * answers 404 — a property of the tenant, not of any user), when
 * `libaxiam_opaque_ffi` is absent, when the server names a key-stretching
 * function this SDK cannot ask for, and when the response is not the shape §23
 * defines. Deliberately not AXIAM_ERR_AUTH: reporting a configuration gap as a
 * credential failure would send a user off to reset a password that works, and
 * would stop a caller falling back to axiam_login().
 *
 * Returns AXIAM_ERR_AUTH when the envelope does not open — a wrong password, an
 * account that does not exist, and a server that does not hold the record,
 * indistinguishable by design. That single check is the whole of the client's
 * authentication, both halves of the mutual authentication included: RFC 9807's
 * AKE authenticates the server during the handshake, so opening KE2 IS the
 * proof that it holds the record, and the separate M2 step §23.3 rule 6 had to
 * mandate for SRP no longer exists. NOTHING is sent to `login/finish` in that
 * case (§23.4 rule 7), `out` is left empty, and a caller must not retry over
 * axiam_login(): that hands the plaintext to an endpoint that has just failed
 * to prove itself.
 */
axiam_error_kind_t axiam_login_opaque(axiam_client_t *client,
                                      const char *username_or_email,
                                      const char *password,
                                      axiam_login_result_t *out,
                                      axiam_error_t *err);

/**
 * Build a registration record for `password`, to send with any request that
 * sets one.
 *
 * Unlike the axiam_srp_enrollment() it replaces this performs I/O: one
 * `register/start` round trip, which is why it takes a client. OPAQUE's
 * envelope is sealed under the server's oblivious PRF, so there is no offline
 * computation that produces a valid record.
 *
 * Note the parameters that are gone. There is no `identity`: the SRP version
 * required the account's USERNAME and an email there produced a dead verifier,
 * whereas a record binds to a credential identifier the server chooses — so a
 * later rename cannot invalidate a credential. And there is no `group` or
 * `params`, because those come from the `register/start` response; a caller
 * cannot pick a cost the server will not honour.
 *
 * Same AXIAM_ERR_NETWORK cases as axiam_login_opaque(). Release `out` with
 * axiam_opaque_enrollment_dispose().
 */
axiam_error_kind_t axiam_opaque_enrollment(axiam_client_t *client,
                                           const char *password,
                                           axiam_opaque_enrollment_t *out,
                                           axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_OPAQUE_H */
