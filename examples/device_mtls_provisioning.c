/*
 * examples/device_mtls_provisioning.c — provision an IoT device with a certificate from
 * the tenant's signing CA, then authenticate as that device over §6.1 mutual TLS.
 *
 * This is the flow AXIAM exists for at the edge: a device holding no password, carrying
 * no shared secret, proving who it is with a private key that never left it.
 *
 * Two actors, and keeping them apart is the point:
 *   1. THE OPERATOR — an administrator who mints the certificate and binds it to a
 *      service account, using the §27 management surface.
 *   2. THE DEVICE — holds only its certificate and key, and touches no management
 *      operation at all.
 *
 * The private key is a §27.5 ONE-TIME SECRET: the server returns it exactly once, at
 * generation, and never again. A provisioning run that does not persist it here has
 * produced a certificate nobody can use — so it is written immediately, with 0600 set
 * before any byte reaches the file rather than chmod'ed afterwards (a window in which the
 * key is world-readable is a window, however short).
 *
 * Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "axiam/axiam.h"
#include "axiam/management_ops.h"

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

/*
 * Write a secret readable only by this user.
 *
 * The mode is applied by umask+open before any content is written, not by a chmod after:
 * between fopen and chmod the key sits on disk world-readable, and on a shared
 * provisioning host that window is enough.
 */
static int write_secret(const char *path, const char *contents) {
    mode_t old = umask(0177);           /* 0666 & ~0177 == 0600 */
    FILE *f = fopen(path, "wb");
    umask(old);
    if (!f) return -1;
    size_t n = strlen(contents);
    int ok = fwrite(contents, 1, n, f) == n;
    fclose(f);
    return ok ? 0 : -1;
}

int main(void) {
    const char *serial = env_or("AXIAM_DEVICE_SERIAL", "device-001");
    char cert_path[512], key_path[512];
    snprintf(cert_path, sizeof cert_path, "%s/%s.crt", env_or("AXIAM_DEVICE_DIR", "."), serial);
    snprintf(key_path, sizeof key_path, "%s/%s.key", env_or("AXIAM_DEVICE_DIR", "."), serial);

    /* ================================================================
     * 1. THE OPERATOR
     * ================================================================ */

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, env_or("AXIAM_BASE_URL", "https://axiam.example.com"));
    axiam_client_config_set_tenant_id(cfg, env_or("AXIAM_TENANT_ID", "11111111-1111-4111-8111-111111111111"));
    axiam_client_config_set_org_id(cfg, env_or("AXIAM_ORG_ID", "11111111-1111-4111-8111-111111111111"));

    axiam_error_t err;
    axiam_client_t *op = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    if (!op) { fprintf(stderr, "client: %s\n", err.message); return 1; }

    axiam_login_result_t login;
    if (axiam_login(op, env_or("AXIAM_ADMIN", "admin@example.com"),
                    env_or("AXIAM_PASSWORD", "secret"), &login, &err) != AXIAM_OK) {
        fprintf(stderr, "login: %s\n", err.message);
        axiam_client_free(op);
        return 1;
    }
    axiam_login_result_dispose(&login);

    /* ---- the tenant's signing CA ---------------------------------------
     *
     * §27.4 rule 3 has an exception worth noticing here. On most routes `{tenant_id}`
     * names the CALLING CONTEXT and the SDK substitutes it. On the signing-CA routes it
     * names the tenant being ADMINISTERED, so it is an ordinary argument — and
     * axiam_mgmt_resolved_tenant_id() is how you pass the same one the implicit routes
     * would have used.
     */
    const char *tenant_id = axiam_mgmt_resolved_tenant_id(op, NULL);
    axiam_mgmt_ca_certificate_page_t *cas = NULL;
    if (axiam_ca_certificates_list_signing_cas(op, NULL, tenant_id, NULL, &cas, &err)
            != AXIAM_OK || !cas || cas->count == 0) {
        fprintf(stderr, "tenant has no signing CA; generate one first\n");
        axiam_mgmt_ca_certificate_page_free(cas);
        axiam_client_free(op);
        return 1;
    }
    printf("signing CA: %s (%ld in this tenant)\n",
           cas->items[0]->id ? cas->items[0]->id : "?", cas->total);

    /* ---- mint the device certificate ------------------------------------
     *
     * `Device` rather than `User` or `Service`: the certificate type is what the server
     * uses to decide which authentication paths its holder may take.
     *
     * Ed25519 rather than RSA-4096: the device performs the handshake signature itself,
     * on whatever CPU it has, and the difference is felt on every reconnect.
     */
    axiam_mgmt_create_certificate_request_t req;
    memset(&req, 0, sizeof req);
    char subject[256];
    snprintf(subject, sizeof subject, "CN=%s", serial);
    req.cert_type = AXIAM_MGMT_CERTIFICATE_TYPE_DEVICE;
    req.issuer_ca_id = cas->items[0]->id;
    req.key_algorithm = AXIAM_MGMT_KEY_ALGORITHM_ED25519;
    req.subject = subject;
    req.validity_days = 365;

    axiam_mgmt_generated_certificate_t *issued = NULL;
    axiam_error_kind_t rc = axiam_certificates_generate(op, &req, &issued, &err);
    axiam_mgmt_ca_certificate_page_free(cas);
    if (rc != AXIAM_OK || !issued) {
        fprintf(stderr, "certificate: %s\n", err.message);
        axiam_client_free(op);
        return 1;
    }
    printf("issued certificate %s\n", issued->id ? issued->id : "?");

    /* ---- persist the one-time secret ------------------------------------
     *
     * §27.5: `private_key_pem` is an axiam_sensitive_t. It stringifies as `[SENSITIVE]`,
     * so it cannot reach a log line by accident; axiam_sensitive_reveal() is the single,
     * explicit way to obtain it, called at the point of use.
     *
     * This is the ONLY moment the key exists outside the server.
     */
    if (issued->private_key_pem && issued->public_cert_pem) {
        if (write_secret(key_path, axiam_sensitive_reveal(issued->private_key_pem)) != 0 ||
            write_secret(cert_path, issued->public_cert_pem) != 0) {
            fprintf(stderr, "could not write %s / %s\n", cert_path, key_path);
            axiam_mgmt_generated_certificate_free(issued);
            axiam_client_free(op);
            return 1;
        }
        printf("wrote %s and %s (0600)\n", cert_path, key_path);
    }

    /* ---- give the device an identity ------------------------------------
     *
     * The certificate proves WHO connected. A service account is WHAT they may do —
     * binding the two is what turns a valid handshake into an authorization subject.
     */
    axiam_mgmt_create_service_account_request_t sa_req;
    memset(&sa_req, 0, sizeof sa_req);
    char sa_name[256];
    snprintf(sa_name, sizeof sa_name, "device-%s", serial);
    sa_req.name = sa_name;

    axiam_mgmt_service_account_created_response_t *account = NULL;
    if (axiam_service_accounts_create(op, &sa_req, &account, &err) == AXIAM_OK && account) {
        axiam_mgmt_bind_certificate_t bind;
        memset(&bind, 0, sizeof bind);
        bind.certificate_id = issued->id;
        if (axiam_service_accounts_bind_certificate(op, account->id, &bind, &err) == AXIAM_OK)
            printf("bound certificate to service account %s\n", account->id);
    }
    axiam_mgmt_service_account_created_response_free(account);
    axiam_mgmt_generated_certificate_free(issued);
    axiam_client_free(op);

    /* ================================================================
     * 2. THE DEVICE
     * ================================================================
     *
     * A separate client, built the way the device itself would: certificate and key, no
     * password, no client secret, and no management surface at all. §6.1 mutual TLS —
     * the private key is used for the handshake and never transmitted.
     */

    axiam_client_config_t *dcfg = axiam_client_config_new();
    axiam_client_config_set_base_url(dcfg, env_or("AXIAM_BASE_URL", "https://axiam.example.com"));
    axiam_client_config_set_tenant_id(dcfg, env_or("AXIAM_TENANT_ID", "11111111-1111-4111-8111-111111111111"));
    /* §6.1: the certificate and its key are set together, because a client cert without
     * its key is not a credential -- the API refuses to let you configure half of one. */
    axiam_client_config_set_client_cert(dcfg, cert_path, key_path);

    axiam_client_t *device = axiam_client_new(dcfg, &err);
    axiam_client_config_free(dcfg);
    if (!device) { fprintf(stderr, "device client: %s\n", err.message); return 1; }

    /* No login: the TLS handshake IS the authentication. What the device may do from
     * here is whatever its service account was granted. */
    axiam_check_result_t decision;
    if (axiam_check_access(device, "telemetry:publish",
                           env_or("AXIAM_RESOURCE_ID", serial), NULL, NULL,
                           &decision, &err) == AXIAM_OK) {
        printf("device may publish telemetry: %s\n", decision.allowed ? "yes" : "no");
    } else {
        fprintf(stderr, "device authentication failed: %s\n", err.message);
    }

    axiam_client_free(device);
    return 0;
}
