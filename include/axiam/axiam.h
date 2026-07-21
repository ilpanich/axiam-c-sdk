/*
 * AXIAM C SDK — umbrella header.
 *
 * The AXIAM C SDK conforms to CONTRACT.md §1–§7, §9, §10, §11 (including §6.1
 * mTLS). gRPC and §8 AMQP are out of scope for v1.0 (tracked as follow-ups).
 *
 * All public symbols are prefixed `axiam_` and use snake_case (CONTRACT §1).
 */
#ifndef AXIAM_H
#define AXIAM_H

#include "axiam/error.h"
#include "axiam/sensitive.h"
#include "axiam/transport.h"
#include "axiam/config.h"
#include "axiam/client.h"
#include "axiam/jwks.h"
#include "axiam/guard.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AXIAM_VERSION_MAJOR 1
#define AXIAM_VERSION_MINOR 0
#define AXIAM_VERSION_PATCH 0
/** Full version string, including the pre-release qualifier. */
#define AXIAM_VERSION "1.0.0-alpha15"

/** Returns the compiled-in version string (e.g. "1.0.0-alpha15"). */
const char *axiam_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_H */
