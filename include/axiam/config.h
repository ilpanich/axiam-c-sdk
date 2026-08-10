/*
 * AXIAM C SDK — Client configuration (CONTRACT.md §5, §6, §6.1).
 *
 * Construction requires a base URL and exactly one tenant identifier
 * (slug or id). There is NO default tenant (§5). Custom CA (§6) and client
 * certificate / mTLS (§6.1) are optional, PEM-only.
 */
#ifndef AXIAM_CONFIG_H
#define AXIAM_CONFIG_H

#include "axiam/error.h"
#include "axiam/telemetry.h"
#include "axiam/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque configuration builder. */
typedef struct axiam_client_config axiam_client_config_t;

/** Allocate a new empty config. Returns NULL on OOM. */
axiam_client_config_t *axiam_client_config_new(void);

/** Free a config. Safe on NULL. */
void axiam_client_config_free(axiam_client_config_t *cfg);

/** Set the AXIAM server base URL (required), e.g. "https://iam.example.com". */
void axiam_client_config_set_base_url(axiam_client_config_t *cfg, const char *base_url);

/* --- Tenant context (§5): set exactly one of slug / id. --- */
void axiam_client_config_set_tenant_slug(axiam_client_config_t *cfg, const char *tenant_slug);
void axiam_client_config_set_tenant_id(axiam_client_config_t *cfg, const char *tenant_id);

/* --- Organization context (optional; used to build refresh requests). --- */
void axiam_client_config_set_org_slug(axiam_client_config_t *cfg, const char *org_slug);
void axiam_client_config_set_org_id(axiam_client_config_t *cfg, const char *org_id);

/* --- Local token-verification expectations (§10.1 rules 5 and 6). ---
 *
 * Both are OPTIONAL and default to UNSET. When unset, the corresponding claim
 * is not checked by axiam_jwt_verify(); when set, a token whose claim is
 * absent, of the wrong JSON type, or different MUST be rejected. Passing NULL
 * or "" clears the expectation. The SDK never assumes an issuer or audience.
 *
 * A resource server guarding a user-facing API SHOULD set the audience to
 * "axiam:user". The issuer is deployment-specific (typically the AXIAM base
 * URL) and is therefore never defaulted.
 */
void axiam_client_config_set_expected_issuer(axiam_client_config_t *cfg, const char *issuer);
void axiam_client_config_set_expected_audience(axiam_client_config_t *cfg, const char *audience);

/**
 * Add a custom CA certificate to the verification chain (§6). PEM only.
 * This NEVER relaxes verification — it augments the trust store for dev/
 * self-signed servers. Returns AXIAM_ERR_NETWORK if the value is not PEM.
 */
axiam_error_kind_t axiam_client_config_set_custom_ca(axiam_client_config_t *cfg, const char *ca_pem);

/**
 * Configure a client identity certificate for mutual TLS (§6.1). Both a PEM
 * certificate chain and a PEM private key are required. The private key is
 * retained behind a Sensitive handle and never logged (§7). Strict server
 * verification is unchanged. Returns AXIAM_ERR_NETWORK if either value is not PEM.
 */
axiam_error_kind_t axiam_client_config_set_client_cert(axiam_client_config_t *cfg,
                                                       const char *cert_pem,
                                                       const char *key_pem);

/** Total request timeout in milliseconds (0 = library default). */
void axiam_client_config_set_timeout_ms(axiam_client_config_t *cfg, long timeout_ms);
/** Connection timeout in milliseconds (0 = library default). */
void axiam_client_config_set_connect_timeout_ms(axiam_client_config_t *cfg, long connect_timeout_ms);

/**
 * Override the HTTP transport (testability). When unset, the libcurl
 * transport is used. The ctx pointer is passed to every invocation and is
 * NOT owned by the config.
 */
void axiam_client_config_set_transport(axiam_client_config_t *cfg,
                                        axiam_transport_fn fn,
                                        void *ctx);

/* --- §16 bounded read-only retry --- */

/**
 * Enable or disable the §16 read-only retry policy. **On by default.**
 *
 * There is deliberately no setter for the attempt cap, the base delay or the
 * delay cap: §16.1 permits lowering or disabling, never raising, and eleven
 * SDKs agreeing on one table is the point. Pass 0 to make every operation
 * exactly one attempt — the right choice for a caller who owns their own retry
 * layer and knows their own deadline.
 */
void axiam_client_config_set_retry_enabled(axiam_client_config_t *cfg, int enabled);

/* --- §17 client-side decision memo --- */

/**
 * Enable the §17 decision memo with a TTL in milliseconds. **Disabled by
 * default** (`0`), which means off — not "cache for zero milliseconds".
 *
 * A TTL above 5000 ms is **clamped to 5000 ms**, not rejected (§17.1 rule 2),
 * and the clamp is reported through the §19 `config_clamped` event.
 *
 * READ-YOUR-OWN-WRITES IS NOT GUARANTEED. The staleness bound is the TTL in
 * both directions: a grant revoked on the server can still read as allowed for
 * up to the TTL, and a grant just *added* can still read as denied for up to
 * the TTL. An admin UI that grants a role and immediately re-checks is the case
 * that breaks, and it breaks silently. Switch this on having read that, not
 * because it looks like an easy win.
 */
void axiam_client_config_set_decision_memo_ttl(axiam_client_config_t *cfg, long ttl_ms);

/* --- §19 telemetry --- */

/**
 * Install a §19 telemetry sink. Pass NULL to clear.
 *
 * `ctx` is passed to every invocation and is NOT owned by the config or the
 * client; it must outlive the client. A hook that throws — in C, one that
 * longjmps or aborts — is outside what the SDK can defend against; §19.2 rule 2
 * is satisfied here by the SDK never inspecting a return value and never
 * letting a hook influence control flow.
 */
void axiam_client_config_set_telemetry_hook(axiam_client_config_t *cfg,
                                            axiam_telemetry_hook_fn fn,
                                            void *ctx);

/**
 * Validate the config (§5: base URL + exactly one tenant identifier).
 * Fills err with a descriptive message on failure. Returns AXIAM_OK if valid.
 */
axiam_error_kind_t axiam_client_config_validate(const axiam_client_config_t *cfg, axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_CONFIG_H */
