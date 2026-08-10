#include <stdlib.h>
#include <string.h>

#include "internal.h"

axiam_client_config_t *axiam_client_config_new(void) {
    axiam_client_config_t *cfg = calloc(1, sizeof(axiam_client_config_t));
    if (!cfg) return NULL;
    /* §16.1: the disable switch MUST default to on. calloc would have made the
     * policy opt-in, which is the one thing that section forbids — an SDK whose
     * retry is off unless asked for retries nothing in practice. */
    cfg->retry_enabled = 1;
    /* §17.1 rule 1: the memo is off by default, and 0 means disabled — not
     * "cache for zero milliseconds". calloc already says so; this is here to
     * make the intent unmissable to the next reader. */
    cfg->decision_memo_ttl_ms = 0;
    return cfg;
}

void axiam_client_config_free(axiam_client_config_t *cfg) {
    if (!cfg) return;
    free(cfg->base_url);
    free(cfg->tenant_slug);
    free(cfg->tenant_id);
    free(cfg->org_slug);
    free(cfg->org_id);
    free(cfg->custom_ca_pem);
    free(cfg->client_cert_pem);
    free(cfg->expected_issuer);
    free(cfg->expected_audience);
    axiam_sensitive_free(cfg->client_key);
    free(cfg);
}

static void set_str(char **dst, const char *v) {
    free(*dst);
    *dst = axiam_strdup0(v);
}

void axiam_client_config_set_base_url(axiam_client_config_t *cfg, const char *base_url) {
    if (cfg) set_str(&cfg->base_url, base_url);
}
void axiam_client_config_set_tenant_slug(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->tenant_slug, v);
}
void axiam_client_config_set_tenant_id(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->tenant_id, v);
}
void axiam_client_config_set_org_slug(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->org_slug, v);
}
void axiam_client_config_set_org_id(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->org_id, v);
}

/* §10.1 rules 5/6: optional local-verification expectations. Unset (NULL or an
 * empty string) means "not configured", which means the claim is not checked —
 * never a hardcoded default issuer/audience. */
void axiam_client_config_set_expected_issuer(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->expected_issuer, (v && v[0]) ? v : NULL);
}
void axiam_client_config_set_expected_audience(axiam_client_config_t *cfg, const char *v) {
    if (cfg) set_str(&cfg->expected_audience, (v && v[0]) ? v : NULL);
}

axiam_error_kind_t axiam_client_config_set_custom_ca(axiam_client_config_t *cfg,
                                                     const char *ca_pem) {
    if (!cfg || !ca_pem) return AXIAM_ERR_NETWORK;
    if (!axiam_is_pem(ca_pem)) return AXIAM_ERR_NETWORK; /* §6: PEM only */
    set_str(&cfg->custom_ca_pem, ca_pem);
    return AXIAM_OK;
}

axiam_error_kind_t axiam_client_config_set_client_cert(axiam_client_config_t *cfg,
                                                       const char *cert_pem,
                                                       const char *key_pem) {
    if (!cfg || !cert_pem || !key_pem) return AXIAM_ERR_NETWORK;
    if (!axiam_is_pem(cert_pem) || !axiam_is_pem(key_pem))
        return AXIAM_ERR_NETWORK; /* §6.1: PEM cert + PEM key only */
    set_str(&cfg->client_cert_pem, cert_pem);
    axiam_sensitive_free(cfg->client_key);
    cfg->client_key = axiam_sensitive_new(key_pem); /* §7: behind Sensitive */
    if (!cfg->client_key) return AXIAM_ERR_NETWORK;
    return AXIAM_OK;
}

void axiam_client_config_set_timeout_ms(axiam_client_config_t *cfg, long ms) {
    if (cfg) cfg->timeout_ms = ms;
}
void axiam_client_config_set_connect_timeout_ms(axiam_client_config_t *cfg, long ms) {
    if (cfg) cfg->connect_timeout_ms = ms;
}

void axiam_client_config_set_transport(axiam_client_config_t *cfg,
                                        axiam_transport_fn fn, void *ctx) {
    if (!cfg) return;
    cfg->transport = fn;
    cfg->transport_ctx = ctx;
}

void axiam_client_config_set_retry_enabled(axiam_client_config_t *cfg, int enabled) {
    if (cfg) cfg->retry_enabled = enabled ? 1 : 0;
}

void axiam_client_config_set_decision_memo_ttl(axiam_client_config_t *cfg, long ttl_ms) {
    /* Stored UNCLAMPED. The clamp happens when the memo is built, so the §19
     * config_clamped event can report what the caller actually asked for
     * rather than the value it was quietly turned into. */
    if (cfg) cfg->decision_memo_ttl_ms = ttl_ms;
}

void axiam_client_config_set_telemetry_hook(axiam_client_config_t *cfg,
                                            axiam_telemetry_hook_fn fn, void *ctx) {
    if (!cfg) return;
    cfg->telemetry_hook = fn;
    cfg->telemetry_ctx = ctx;
}

axiam_error_kind_t axiam_client_config_validate(const axiam_client_config_t *cfg,
                                                axiam_error_t *err) {
    axiam_error_reset(err);
    if (!cfg) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "config is NULL");
        return AXIAM_ERR_NETWORK;
    }
    if (!cfg->base_url || cfg->base_url[0] == '\0') {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "base_url is required");
        return AXIAM_ERR_NETWORK;
    }
    /* §6: refuse a plaintext base URL at construction. The SDK forwards
     * credentials, session cookies, CSRF and tenant headers, none of which may
     * traverse a cleartext link; a loopback host is the only dev exception and
     * there is no flag to disable this check for a routable host. */
    if (!axiam_url_is_secure(cfg->base_url)) {
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "base_url must use https:// (plaintext transport is "
                        "refused; only a loopback host — localhost, 127.0.0.1, "
                        "::1 — may use http:// for local development)");
        return AXIAM_ERR_NETWORK;
    }
    int have_slug = cfg->tenant_slug && cfg->tenant_slug[0];
    int have_id = cfg->tenant_id && cfg->tenant_id[0];
    if (!have_slug && !have_id) {
        /* §5: no default tenant. */
        axiam_error_set(err, AXIAM_ERR_NETWORK, 0,
                        "tenant_slug or tenant_id is required (no default tenant)");
        return AXIAM_ERR_NETWORK;
    }
    return AXIAM_OK;
}

axiam_client_config_t *axiam_client_config_clone(const axiam_client_config_t *src) {
    if (!src) return NULL;
    axiam_client_config_t *c = axiam_client_config_new();
    if (!c) return NULL;
    c->base_url = axiam_strdup0(src->base_url);
    c->tenant_slug = axiam_strdup0(src->tenant_slug);
    c->tenant_id = axiam_strdup0(src->tenant_id);
    c->org_slug = axiam_strdup0(src->org_slug);
    c->org_id = axiam_strdup0(src->org_id);
    c->custom_ca_pem = axiam_strdup0(src->custom_ca_pem);
    c->client_cert_pem = axiam_strdup0(src->client_cert_pem);
    c->expected_issuer = axiam_strdup0(src->expected_issuer);
    c->expected_audience = axiam_strdup0(src->expected_audience);
    if (src->client_key) {
        c->client_key = axiam_sensitive_new_bytes(
            axiam_sensitive_bytes(src->client_key),
            axiam_sensitive_len(src->client_key));
    }
    c->timeout_ms = src->timeout_ms;
    c->connect_timeout_ms = src->connect_timeout_ms;
    c->transport = src->transport;
    c->transport_ctx = src->transport_ctx;
    c->retry_enabled = src->retry_enabled;
    c->decision_memo_ttl_ms = src->decision_memo_ttl_ms;
    c->telemetry_hook = src->telemetry_hook;
    c->telemetry_ctx = src->telemetry_ctx;
    return c;
}
