/*
 * AXIAM C SDK — internals shared by the §12 / §12.7 / §14 / §15 translation
 * units (NOT installed).
 *
 * Everything here exists so that oidc.c, oidc_device.c, oidc_exchange.c and
 * oidc_logout.c agree on the wire shape of a token-endpoint call. The four
 * sections issue the same `POST /oauth2/token?tenant_id=<uuid>` with a different
 * `grant_type`, and the ways to get that wrong — JSON instead of form encoding,
 * the tenant in the body instead of the query, HTTP Basic instead of
 * client_secret_post — are the ones §12.1's "non-obvious wire details" enumerate.
 * One builder means one place to get them right.
 */
#ifndef AXIAM_OIDC_INTERNAL_H
#define AXIAM_OIDC_INTERNAL_H

#include <stddef.h>

#include "internal.h"

/** A form body under construction. Fields are appended percent-encoded. */
typedef struct oidc_form {
    char *buf;
    size_t len;
    size_t cap;
    int failed; /* sticky: one OOM poisons the whole body */
} oidc_form_t;

void oidc_form_init(oidc_form_t *f);
/** Append `key=value`. A NULL or empty `value` is OMITTED entirely — §12.1's
 *  rule that an optional field the caller did not supply is absent, never sent
 *  empty. */
void oidc_form_add(oidc_form_t *f, const char *key, const char *value);
/** Release the buffer, scrubbing it first: a form body routinely carries a
 *  client secret, a refresh token or an authorization code (§7). */
void oidc_form_dispose(oidc_form_t *f);

/** 1 when `s` is an 8-4-4-4-12 hex UUID. A tenant SLUG is not one, and §12.3
 *  rule 4 forbids substituting it in `?tenant_id=`. */
int oidc_is_uuid(const char *s);

/**
 * Resolve the `?tenant_id=` UUID for the five tenant-scoped operations.
 * Prefers `explicit`, falls back to the client's configured `tenant_id`, and
 * fails CLIENT-SIDE with no wire call when neither is a UUID (§12.3 rule 4).
 * Returns NULL after filling `err`.
 */
const char *oidc_require_tenant_uuid(axiam_client_t *c, const char *explicit_id,
                                     const char *operation, axiam_error_t *err);

/** The configured `client_id`, or NULL after filling `err` (§12.1: fail fast,
 *  no wire call — a missing client registration is a deployment mistake). */
const char *oidc_require_client_id(axiam_client_t *c, const char *operation,
                                   axiam_error_t *err);
/** The configured `client_secret`, or NULL after filling `err`. For the
 *  confidential-only operations (§12.1 rule 4, §15.1). */
const char *oidc_require_client_secret(axiam_client_t *c, const char *operation,
                                       axiam_error_t *err);

/** Append `?tenant_id=<uuid>` to an absolute endpoint. malloc'd, or NULL. */
char *oidc_endpoint_with_tenant(const char *endpoint, const char *tenant_uuid);

/**
 * §12.1 rule 3: `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(verifier)))`,
 * without padding. malloc'd, or NULL.
 *
 * Not static, because §12.1 rule 3 requires every SDK to carry the RFC 7636
 * Appendix B test vector as a unit test and a vector asserted through a
 * randomly-generated verifier is not a vector.
 */
char *oidc_s256_challenge(const char *verifier);

/**
 * One POST against an ABSOLUTE url (an endpoint read from the discovery
 * document), with an explicit content type.
 *
 * `retryable` selects whether the §16 bounded read-only policy applies. It is
 * 0 for every grant here: §16.2 lists `oidc_exchange`, `device_authorize`,
 * `device_login` and `token_exchange` as ineligible because their credentials
 * are single-use, and retrying replays a spent one.
 */
int oidc_post(axiam_client_t *c, const char *url, const char *content_type,
              const char *body, int retryable, axiam_http_response_t *resp);

/**
 * Map a non-2xx token-endpoint response (§12.3 rule 3, §14.2 rule 5, §15.3).
 *
 * Dispatches on the body's `error` field FIRST and at any status, filling
 * axiam_error_t::oauth_error with it verbatim. A `400` from `/oauth2/token`
 * therefore surfaces as AXIAM_ERR_AUTH with the code intact rather than as the
 * generic §2 400 row, which is exactly what §12.3 rule 3 requires and what lets
 * §14.2's five answers be told apart. A body that is not an
 * `OAuth2ErrorResponse` at all — a proxy's HTML 502 — falls back to the §2
 * status mapping.
 */
axiam_error_kind_t oidc_map_grant_error(const axiam_http_response_t *resp,
                                        const char *context, axiam_error_t *err);

/** Client-usability gate shared by every entry point (§18.1 rule 4). */
int oidc_client_unusable(axiam_client_t *c, axiam_error_t *err);

/**
 * One `POST /oauth2/token?tenant_id=<uuid>`, form-encoded, with the caller's
 * grant fields already in `form`. Fills `*out_body` with the 2xx body.
 *
 * `retryable` is 0 for every grant §16.2 names ineligible. It is a parameter
 * rather than a constant so `device_poll` — the one token-endpoint call that
 * section DOES allow to retry, on a 5xx or transport failure — can share this
 * body instead of forking it.
 */
axiam_error_kind_t oidc_token_grant(axiam_client_t *c, oidc_form_t *form,
                                    const axiam_oidc_config_t *config,
                                    const char *tenant_uuid, int retryable,
                                    const char *context, char **out_body,
                                    axiam_error_t *err);

/**
 * Parse a `TokenResponse` and, when it carries an `id_token`, validate it
 * against every §12.4 rule before returning.
 *
 * `expected_nonce` non-NULL enables rule 6; NULL skips it, which is correct for
 * `oidc_refresh`, `login_client_credentials` and `device_poll` — OIDC Core
 * §12.2 does not require a nonce in a refresh-issued ID token, and those flows
 * had no authorization request to carry one.
 *
 * ALL-OR-NOTHING (§12.4 rule 7): on any validation failure `out` is left zeroed
 * and the access and refresh tokens from the same response are discarded.
 */
axiam_error_kind_t oidc_parse_token_set(axiam_client_t *c, const char *json,
                                        const axiam_oidc_config_t *config,
                                        const char *expected_nonce,
                                        axiam_oidc_token_set_t *out,
                                        axiam_error_t *err);

/** Deep-copy a token set (the §9 single-flight guard hands one outcome to every
 *  waiter, and each waiter disposes its own). */
int oidc_token_set_copy(const axiam_oidc_token_set_t *src, axiam_oidc_token_set_t *dst);

/** Deep-copy a discovery document. */
axiam_error_kind_t oidc_config_copy(const axiam_oidc_config_t *src, axiam_oidc_config_t *dst);

#endif /* AXIAM_OIDC_INTERNAL_H */
