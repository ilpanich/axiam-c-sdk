/*
 * AXIAM C SDK — umbrella header.
 *
 * The AXIAM C SDK conforms to CONTRACT.md §1–§7, §9–§13, §14, §15, §16–§20,
 * §23, and §24–§26 (including §6.1 mTLS, §12.7 logout, and the §11 rule 9
 * decision reason codes). §24 ships the six wire operations and §24.6a's JSON
 * bridge but no §24.6b ceremony helper: a C program has no authenticator, and
 * rule 2 forbids emulating one in software. gRPC and §8 AMQP are out of scope
 * for v1.0 (tracked as follow-ups).
 *
 * All public symbols are prefixed `axiam_` and use snake_case (CONTRACT §1).
 */
#ifndef AXIAM_H
#define AXIAM_H

#include "axiam/error.h"
#include "axiam/sensitive.h"
#include "axiam/telemetry.h"
#include "axiam/transport.h"
#include "axiam/config.h"
#include "axiam/client.h"
#include "axiam/jwks.h"
#include "axiam/guard.h"
#include "axiam/oidc.h"
#include "axiam/opaque.h"
#include "axiam/reactor.h"
#include "axiam/uma.h"
#include "axiam/webhook.h"
#include "axiam/webauthn.h"
#include "axiam/account.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AXIAM_VERSION_MAJOR 1
#define AXIAM_VERSION_MINOR 0
#define AXIAM_VERSION_PATCH 0
/** Full version string, including the pre-release qualifier. */
#define AXIAM_VERSION "1.0.0-beta10"

/**
 * The minimum C standard this SDK is compiled against, as the `__STDC_VERSION__`
 * value for C11.
 *
 * The SDK is built at this standard and additionally compiled and tested under C23,
 * so a consumer whose own project selects a newer standard is on ground a green build
 * already covers. That upper claim is the one worth stating: a newer C standard
 * REMOVES things and tightens others — K&R declarations are gone in C23,
 * `bool`/`true`/`false` become keywords, an implicit function declaration is an error
 * rather than a warning — and none of that is visible from a C11-only build.
 *
 * The floor is enforced below at compile time, so a toolchain too old to satisfy it
 * fails at `#include` with a message that says so, rather than at some later
 * unexplained syntax error.
 */
#define AXIAM_MIN_C_STANDARD 201112L

/**
 * The newest C standard this SDK has a green build against, as `__STDC_VERSION__`
 * would report it for C23.
 *
 * Nothing enforces this and nothing can: it is a statement about what CI covers, not
 * about what the compiler will accept.
 *
 * Note that a C23 build does not report this value everywhere. gcc 13 has no
 * `-std=c23`, so `CMAKE_C_STANDARD 23` selects `-std=c2x` and `__STDC_VERSION__` is
 * the pre-ratification `202000L`; clang 18 reports `202311L`. Both are C23 builds.
 * Compare against this macro as a lower bound, never for equality.
 */
#define AXIAM_NEWEST_TESTED_C_STANDARD 202311L

/*
 * Refuse a toolchain older than the declared floor at the point of inclusion.
 *
 * Without this the failure is a cascade of syntax errors from whichever header first
 * uses something C11 introduced, which reads like a broken SDK rather than an
 * out-of-date compiler. `__STDC_VERSION__` is undefined entirely in C89, hence the
 * two-part condition.
 */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < AXIAM_MIN_C_STANDARD
#error "The AXIAM C SDK requires C11 or newer (see AXIAM_MIN_C_STANDARD)."
#endif

/** Returns the compiled-in version string (e.g. "1.0.0-beta10"). */
const char *axiam_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_H */
