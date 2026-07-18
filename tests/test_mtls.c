/* Exercises the §6/§6.1 PEM wiring path with runtime-generated PKI (passed as
 * argv[1] — a directory produced by the gen_pki CTest fixture). Confirms the
 * custom-CA and client-certificate PEMs are accepted and that a real
 * libcurl-backed client constructs with them (blob wiring), without asserting a
 * full TLS handshake. Private keys are generated at build time and never
 * committed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "axiam/axiam.h"

static char g_dir[1024];

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

static char *join(const char *name) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    return read_file(path);
}

void setUp(void) {}
void tearDown(void) {}

static void test_mtls_pem_wiring(void) {
    char *ca = join("ca.crt");
    char *cert = join("client.crt");
    char *key = join("client.key");
    TEST_ASSERT_NOT_NULL_MESSAGE(ca, "missing ca.crt (fixture not run?)");
    TEST_ASSERT_NOT_NULL_MESSAGE(cert, "missing client.crt");
    TEST_ASSERT_NOT_NULL_MESSAGE(key, "missing client.key");

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com");
    axiam_client_config_set_tenant_slug(cfg, "acme");
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_custom_ca(cfg, ca));
    /* §6.1: PEM cert + PEM key accepted. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_client_cert(cfg, cert, key));

    /* Construct a real libcurl-backed client (default transport) — this drives
     * axiam_curl_ctx_new's CAINFO/SSLCERT/SSLKEY blob wiring. */
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    TEST_ASSERT_NOT_NULL(c);

    axiam_client_free(c);
    axiam_client_config_free(cfg);
    free(ca);
    free(cert);
    free(key);
}

int main(int argc, char **argv) {
    if (argc > 1) snprintf(g_dir, sizeof(g_dir), "%s", argv[1]);
    else snprintf(g_dir, sizeof(g_dir), ".");
    UNITY_BEGIN();
    RUN_TEST(test_mtls_pem_wiring);
    return UNITY_END();
}
