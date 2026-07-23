/* Real TLS/mTLS round-trip through the SDK's default libcurl transport.
 *
 * Unlike test_mtls.c (which only proves the blob setopt calls are accepted) and
 * test_transport_curl_extra.c (which exercises the same blob wiring against a
 * CLOSED port, so no handshake ever completes), this test stands up a genuine
 * loopback TLS server on a background thread with OpenSSL and drives one
 * authenticated HTTPS GET all the way through:
 *
 *   (1) server-auth HTTPS: the SDK is configured with the fixture CA
 *       (CURLOPT_CAINFO_BLOB) and completes a real handshake + HTTP exchange.
 *   (2) mTLS: the server REQUIRES a client certificate; the SDK is configured
 *       with the fixture client cert + key (CURLOPT_SSLCERT_BLOB /
 *       CURLOPT_SSLKEY_BLOB) and the round-trip succeeds only because the
 *       client presented its certificate.
 *
 * PKI (CA, server cert w/ IP:127.0.0.1 SAN, client cert/key) is generated at
 * build time by the gen_pki CTest fixture (argv[1] = its output dir). No
 * private key is ever committed.
 *
 * Determinism: the server handles exactly one connection then returns; the
 * accept is bounded by select(2) with a timeout and the accepted socket carries
 * SO_RCVTIMEO/SO_SNDTIMEO, so the thread always exits within a few seconds even
 * if the client never connects. The thread is joined before each test returns.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"

static char g_pki_dir[1024];

/* Paths into the fixture directory, filled in by main(). */
static char g_ca_path[2048];
static char g_server_crt[2048];
static char g_server_key[2048];

typedef struct {
    int listen_fd;
    int require_client_cert;
    const char *resp_body;
    /* results (read after join) */
    int handshake_ok;
    int saw_client_cert;
    int handled;
} tls_srv_t;

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

/* Bind a fresh loopback socket to an ephemeral port and start listening.
 * Mirrors the raw-HTTP fixture servers in test_integration_curl.c. */
static int bind_listen(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, 4) != 0) { close(fd); return -1; }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

static void *tls_server_thread(void *arg) {
    tls_srv_t *s = arg;

    /* Bounded accept: never block the thread indefinitely. */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s->listen_fd, &rfds);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    int sel = select(s->listen_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel <= 0) return NULL;

    int cfd = accept(s->listen_fd, NULL, NULL);
    if (cfd < 0) return NULL;

    /* Every socket op after this point is time-bounded. */
    struct timeval io = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof(io));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof(io));

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(cfd); return NULL; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, g_server_crt, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, g_server_key, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        close(cfd);
        return NULL;
    }
    if (s->require_client_cert) {
        /* mTLS: demand a client cert that chains to the fixture CA. */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_load_verify_locations(ctx, g_ca_path, NULL);
        STACK_OF(X509_NAME) *cas = SSL_load_client_CA_file(g_ca_path);
        if (cas) SSL_CTX_set_client_CA_list(ctx, cas);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(cfd); return NULL; }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) == 1) {
        s->handshake_ok = 1;
        X509 *peer = SSL_get1_peer_certificate(ssl);
        if (peer) { s->saw_client_cert = 1; X509_free(peer); }

        char buf[4096];
        int r = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
        (void)r; /* content of the HTTP request line is not asserted here */

        char resp[512];
        int n = snprintf(resp, sizeof(resp),
                         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                         strlen(s->resp_body), s->resp_body);
        if (n > 0) SSL_write(ssl, resp, n);
        s->handled = 1;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(cfd);
    return NULL;
}

void setUp(void) {}
void tearDown(void) {}

/* Shared driver: stand up the TLS server, point a real SDK client at it over
 * https://127.0.0.1:<port>, perform one GET, and return results. */
static void run_roundtrip(int require_client_cert, const char *resp_body,
                          int with_client_cert, axiam_error_kind_t *out_kind,
                          char **out_body, tls_srv_t *out_srv) {
    char *ca = read_file(g_ca_path);
    char *ccert = read_file(g_server_crt); /* just to prove fixture ran */
    TEST_ASSERT_NOT_NULL_MESSAGE(ca, "missing ca.crt (gen_pki fixture not run?)");
    TEST_ASSERT_NOT_NULL_MESSAGE(ccert, "missing server.crt (extend gen_pki.sh?)");
    free(ccert);

    int port = -1;
    int fd = bind_listen(&port);
    TEST_ASSERT_TRUE_MESSAGE(fd >= 0, "failed to bind loopback listener");

    tls_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.listen_fd = fd;
    srv.require_client_cert = require_client_cert;
    srv.resp_body = resp_body;

    pthread_t th;
    pthread_create(&th, NULL, tls_server_thread, &srv);

    char base[64];
    snprintf(base, sizeof(base), "https://127.0.0.1:%d", port);

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_client_config_set_connect_timeout_ms(cfg, 3000);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_custom_ca(cfg, ca));

    if (with_client_cert) {
        char cpath[2048], kpath[2048];
        snprintf(cpath, sizeof(cpath), "%s/client.crt", g_pki_dir);
        snprintf(kpath, sizeof(kpath), "%s/client.key", g_pki_dir);
        char *cert = read_file(cpath);
        char *key = read_file(kpath);
        TEST_ASSERT_NOT_NULL_MESSAGE(cert, "missing client.crt");
        TEST_ASSERT_NOT_NULL_MESSAGE(key, "missing client.key");
        TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                              axiam_client_config_set_client_cert(cfg, cert, key));
        free(cert);
        free(key);
    }

    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    char *body = NULL;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);

    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(c);
    free(ca);

    *out_kind = k;
    *out_body = body;
    *out_srv = srv;
}

/* (1) Plain server-auth HTTPS: real handshake against the fixture CA, no client
 * cert. Exercises CURLOPT_CAINFO_BLOB + a completed TLS session. */
static void test_server_auth_https_roundtrip(void) {
    axiam_error_kind_t k;
    char *body = NULL;
    tls_srv_t srv;
    run_roundtrip(/*require_client_cert=*/0, "{\"keys\":[]}",
                  /*with_client_cert=*/0, &k, &body, &srv);

    TEST_ASSERT_TRUE_MESSAGE(srv.handshake_ok, "server-side TLS handshake failed");
    TEST_ASSERT_TRUE_MESSAGE(srv.handled, "server never sent a response");
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_OK, k, "SDK did not report success");
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING("{\"keys\":[]}", body);
    free(body);
}

/* (2) mTLS: server requires a client cert; SDK presents the fixture client
 * cert/key blobs. Exercises CURLOPT_SSLCERT_BLOB / CURLOPT_SSLKEY_BLOB across a
 * real mutually-authenticated handshake. */
static void test_mtls_https_roundtrip(void) {
    axiam_error_kind_t k;
    char *body = NULL;
    tls_srv_t srv;
    run_roundtrip(/*require_client_cert=*/1, "{\"ok\":true}",
                  /*with_client_cert=*/1, &k, &body, &srv);

    TEST_ASSERT_TRUE_MESSAGE(srv.handshake_ok, "mTLS handshake failed server-side");
    TEST_ASSERT_TRUE_MESSAGE(srv.saw_client_cert,
                             "server did not receive the client certificate");
    TEST_ASSERT_TRUE_MESSAGE(srv.handled, "server never sent a response");
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_OK, k, "SDK did not report mTLS success");
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING("{\"ok\":true}", body);
    free(body);
}

int main(int argc, char **argv) {
    /* A server write to a client-closed socket must not kill the test process. */
    signal(SIGPIPE, SIG_IGN);

    if (argc > 1) snprintf(g_pki_dir, sizeof(g_pki_dir), "%s", argv[1]);
    else snprintf(g_pki_dir, sizeof(g_pki_dir), ".");
    snprintf(g_ca_path, sizeof(g_ca_path), "%s/ca.crt", g_pki_dir);
    snprintf(g_server_crt, sizeof(g_server_crt), "%s/server.crt", g_pki_dir);
    snprintf(g_server_key, sizeof(g_server_key), "%s/server.key", g_pki_dir);

    UNITY_BEGIN();
    RUN_TEST(test_server_auth_https_roundtrip);
    RUN_TEST(test_mtls_https_roundtrip);
    return UNITY_END();
}
