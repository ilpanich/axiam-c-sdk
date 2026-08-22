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
#define AXIAM_VERSION "1.0.0-alpha38"

/** Returns the compiled-in version string (e.g. "1.0.0-alpha38"). */
const char *axiam_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_H */
