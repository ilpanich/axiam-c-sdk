/*
 * AXIAM C SDK — Secure Remote Password (SRP-6a), CONTRACT.md §23.
 *
 * SRP is an *augmented PAKE*: the client proves knowledge of the password
 * without the password, or anything from which the password can be cheaply
 * recovered, ever crossing the wire. The server stores a verifier
 * v = g^x mod N instead of a password hash.
 *
 * What this closes, and what it does not (§23.0). SRP defends against a
 * TLS-terminating proxy, an accidental request-body log, and a heap dump —
 * places a plaintext password exists today and would not under SRP. It does
 * NOT defend against a compromised AXIAM server.
 *
 * CONDITIONAL SUPPORT (§23.8). This SDK computes the arithmetic with OpenSSL's
 * BN_mod_exp, always available. Argon2id needs OpenSSL >= 3.2, which supplies
 * it as an EVP_KDF; PBKDF2-HMAC-SHA256 is available everywhere. A build linked
 * against an older OpenSSL therefore cannot serve a tenant configured for
 * argon2id, and axiam_login_srp() reports that as AXIAM_ERR_NETWORK naming the
 * KDF rather than deriving a wrong x and reporting a wrong password.
 * axiam_srp_available() answers the capability question up front.
 */
#ifndef AXIAM_SRP_H
#define AXIAM_SRP_H

#include <stddef.h>

#include "axiam/client.h"
#include "axiam/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Wire name of the RFC 5054 Appendix A 2048-bit group (g = 2). */
#define AXIAM_SRP_GROUP_2048 "rfc5054_2048"
/** Wire name of the RFC 5054 Appendix A 3072-bit group (g = 5). */
#define AXIAM_SRP_GROUP_3072 "rfc5054_3072"
/**
 * Wire name of the RFC 5054 Appendix A 4096-bit group (g = 5).
 *
 * AXIAM's default: it matches the RSA-4096 floor the project already sets for
 * certificates.
 */
#define AXIAM_SRP_GROUP_4096 "rfc5054_4096"

/** Wire name of the memory-hard KDF AXIAM asks for by default. */
#define AXIAM_SRP_KDF_ARGON2ID "argon2id"
/** Wire name of the fallback for runtimes with no vetted Argon2. */
#define AXIAM_SRP_KDF_PBKDF2 "pbkdf2_sha256"

/**
 * The KDF and cost the server dictates for one exchange (§23.5).
 *
 * §23.3 rule 4: these arrive per exchange and are honoured as given. They are
 * deliberately NOT cached across logins — a verifier enrolled under different
 * costs is still valid and has to keep working.
 */
typedef struct axiam_srp_kdf_params {
    const char *kdf;   /**< AXIAM_SRP_KDF_ARGON2ID or AXIAM_SRP_KDF_PBKDF2. */
    unsigned iterations;  /**< Argon2id's time cost, or PBKDF2's iteration count. */
    unsigned memory_kib;  /**< Argon2id's memory cost; ignored for PBKDF2. */
    unsigned parallelism; /**< Argon2id's lane count; ignored for PBKDF2. */
} axiam_srp_kdf_params_t;

/**
 * The `srp` object §23.5 defines: a verifier and the parameters it was
 * computed under.
 *
 * The server cannot compute this — it never sees the plaintext — so any
 * request that SETS a password has to carry it: POST /api/v1/users,
 * /auth/password/change, /auth/reset/confirm and /admin/bootstrap
 * (§23.3 rule 11).
 *
 * Neither `salt` nor `verifier` may be logged (§23.3 rule 12). Release with
 * axiam_srp_enrollment_dispose(), which zeroizes both.
 */
typedef struct axiam_srp_enrollment {
    char *group;        /**< The wire group name the verifier lives in. */
    char *kdf;          /**< The KDF used to derive x. */
    unsigned memory_kib;  /**< Argon2id's memory cost, or 0 for PBKDF2. */
    unsigned iterations;  /**< The KDF's iteration/time cost. */
    unsigned parallelism; /**< Argon2id's lane count, or 0 for PBKDF2. */
    char *salt;         /**< The 32-byte enrolment salt, lowercase hex. */
    char *verifier;     /**< v = g^x mod N, lowercase hex. */
} axiam_srp_enrollment_t;

/** Release and zeroize an enrolment's heap members (not the struct itself). */
void axiam_srp_enrollment_dispose(axiam_srp_enrollment_t *e);

/**
 * Whether this build can perform SRP at all, and with which KDFs.
 *
 * Returns 1 when the arithmetic and at least PBKDF2-HMAC-SHA256 are available,
 * which on any OpenSSL this SDK links against is unconditional. It exists
 * because §23.1 puts the probe in every SDK's vocabulary, and because a `1`
 * here is NOT a promise that every tenant will work: see
 * axiam_srp_argon2_available().
 */
int axiam_srp_available(void);

/**
 * Whether this build can perform the Argon2id KDF (§23.8).
 *
 * Argon2id arrives as an OpenSSL EVP_KDF in 3.2 and later. Against an older
 * libcrypto this returns 0, and a tenant configured for `argon2id` cannot be
 * served — axiam_login_srp() reports AXIAM_ERR_NETWORK naming the KDF rather
 * than substituting PBKDF2, which would derive a different x and surface as a
 * wrong password.
 *
 * Split out from axiam_srp_available() rather than folded into it because the
 * two answer different questions at different times: whether to offer SRP at
 * all, and whether a particular tenant's policy is servable.
 */
int axiam_srp_argon2_available(void);

/**
 * POST /api/v1/auth/srp/challenge followed by /verify — SRP-6a login (§23).
 *
 * A sibling of axiam_login(), not a replacement. It takes the same arguments
 * and fills the same axiam_login_result_t, MFA branch included, so an
 * application can switch a tenant to SRP without touching its own code
 * (§23.1).
 *
 * The password never leaves this process. What crosses the wire is A and a
 * proof, neither of which is useful without the account's verifier.
 *
 * Cost: runs the tenant's KDF — Argon2id at 19 MiB and t=2 by default, tens to
 * hundreds of milliseconds of CPU plus that memory, per attempt. That cost is
 * the point.
 *
 * Returns AXIAM_ERR_NETWORK when the tenant has SRP disabled (the endpoint
 * answers 404 — a property of the tenant, not of any user), or when this build
 * cannot perform the group or KDF the server named. Deliberately not
 * AXIAM_ERR_AUTH: reporting a client capability gap as a credential failure
 * would send a user off to reset a password that works.
 *
 * Returns AXIAM_ERR_AUTH for a wrong password, and for a server whose M2 does
 * not verify — in the latter case `out` is left empty, because an endpoint
 * that cannot prove it holds the verifier is not the server it claims to be
 * (§23.3 rule 6).
 */
axiam_error_kind_t axiam_login_srp(axiam_client_t *client,
                                   const char *username_or_email,
                                   const char *password,
                                   axiam_login_result_t *out,
                                   axiam_error_t *err);

/**
 * Compute a verifier for `password`, to send with any request that sets one
 * (§23.3 rule 11).
 *
 * `identity` MUST be the account's USERNAME — the canonical identity the
 * challenge endpoint hands back. An email here produces a verifier no login
 * can ever satisfy.
 *
 * `group` may be NULL for AXIAM's default. `params` may be NULL for Argon2id
 * at AXIAM's costs; any zero cost inside it is filled in the same way.
 *
 * Performs no I/O and needs no client. The salt is 32 fresh bytes from the
 * platform CSPRNG on every call.
 */
axiam_error_kind_t axiam_srp_enrollment(const char *identity,
                                        const char *password,
                                        const char *group,
                                        const axiam_srp_kdf_params_t *params,
                                        axiam_srp_enrollment_t *out,
                                        axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_SRP_H */
