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

/**
 * Validate the config (§5: base URL + exactly one tenant identifier).
 * Fills err with a descriptive message on failure. Returns AXIAM_OK if valid.
 */
axiam_error_kind_t axiam_client_config_validate(const axiam_client_config_t *cfg, axiam_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* AXIAM_CONFIG_H */
