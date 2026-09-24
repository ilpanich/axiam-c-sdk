/*
 * CONTRACT.md §6.1 rule 6 — "the device token withholds a stale cookie", against a
 * REAL loopback TLS server and the SDK's real libcurl transport.
 *
 * The lesson this file exists to not repeat (found in the TypeScript port): a fake
 * transport has no cookie jar to leak from, so a "withholds the stale cookie" test
 * against one can pass even with the withholding code deleted — it is testing
 * nothing. libcurl's per-handle cookie engine is what actually has to be told not
 * to attach a stored cookie, and the only way to prove that happened is to look at
 * the raw HTTP text libcurl put on the wire.
 *
 * Sequence, one client object, one curl handle, two requests to ONE server that
 * accepts two connections in turn:
 *   1. An ordinary GET that returns `Set-Cookie: axiam_access=stale-session-cookie`
 *      — this is what a PRIOR cookie-based login would have left in the jar.
 *   2. axiam_authenticate_device() over mTLS. The server captures the raw request
 *      text and the test asserts it carries no `Cookie:` line naming the stale
 *      value — proving the withhold happened at the transport libcurl actually
 *      used, not merely in a header list a mock never forwarded to a cookie jar.
 *
 * PKI (CA, server cert w/ IP:127.0.0.1 SAN, client cert/key) is generated at build
 * time by the gen_pki CTest fixture (argv[1] = its output dir), mirroring
 * test_tls_server.c.
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
#include <strings.h>
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
static char g_ca_path[2048];
static char g_server_crt[2048];
static char g_server_key[2048];

typedef struct {
    int listen_fd;
    /* results, read after join */
    int round1_ok;
    int round2_ok;
    int round2_saw_client_cert;
    char round2_request[8192]; /* the raw HTTP text of the SECOND request */
} tls_srv_t;

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t) n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t) n, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

static int bind_listen(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, 4) != 0) { close(fd); return -1; }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *) &addr, &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

/* Accept ONE connection, requiring a client certificate (the fixture client always
 * presents one, whether or not this round's SDK call needs it), handle exactly one
 * HTTP request/response, and return. Bounded throughout so the thread always exits. */
static void handle_one(int listen_fd, const char *resp_body, const char *set_cookie,
                       int *out_ok, int *out_saw_cert,
                       char *out_raw, size_t out_raw_cap) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    int sel = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
    if (sel <= 0) return;

    int cfd = accept(listen_fd, NULL, NULL);
    if (cfd < 0) return;
    struct timeval io = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof(io));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof(io));

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { close(cfd); return; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, g_server_crt, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, g_server_key, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        close(cfd);
        return;
    }
    /* The fixture client is configured with a certificate for BOTH rounds (§6.1
     * rule 4: one identity serves the whole client), so requesting it here is
     * harmless for round 1 and required for round 2. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, g_ca_path, NULL);
    STACK_OF(X509_NAME) *cas = SSL_load_client_CA_file(g_ca_path);
    if (cas) SSL_CTX_set_client_CA_list(ctx, cas);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(cfd); return; }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) == 1) {
        if (out_saw_cert) {
            X509 *peer = SSL_get1_peer_certificate(ssl);
            if (peer) { *out_saw_cert = 1; X509_free(peer); }
        }

        char buf[8192];
        int total = 0;
        /* Read until we have the blank line ending the headers, or the buffer/
         * timeout runs out -- there is no body on either request this test
         * makes, so the header terminator is the whole message. */
        while (total < (int) sizeof(buf) - 1) {
            int r = SSL_read(ssl, buf + total, (int) sizeof(buf) - 1 - total);
            if (r <= 0) break;
            total += r;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
        }
        if (out_raw && total > 0) {
            snprintf(out_raw, out_raw_cap, "%s", buf);
        }

        char resp[512];
        int n;
        if (set_cookie) {
            n = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        "Set-Cookie: %s\r\n"
                        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                        set_cookie, strlen(resp_body), resp_body);
        } else {
            n = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                        strlen(resp_body), resp_body);
        }
        if (n > 0) SSL_write(ssl, resp, n);
        if (out_ok) *out_ok = 1;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(cfd);
}

static void *tls_server_thread(void *arg) {
    tls_srv_t *s = arg;
    /* Round 1: an ordinary GET whose response sets the cookie a prior
     * cookie-based login would have left in this client's jar. */
    handle_one(s->listen_fd, "{\"keys\":[]}",
              "axiam_access=stale-session-cookie; Path=/",
              &s->round1_ok, NULL, NULL, 0);
    /* Round 2: the device login. No Set-Cookie on this response -- the
     * assertion is about what the CLIENT sent, not what the server sends
     * back. */
    handle_one(s->listen_fd,
              "{\"access_token\":\"dev-tok\",\"token_type\":\"Bearer\",\"expires_in\":900}",
              NULL,
              &s->round2_ok, &s->round2_saw_client_cert,
              s->round2_request, sizeof(s->round2_request));
    return NULL;
}

void setUp(void) {}
void tearDown(void) {}

static void test_device_login_withholds_a_stale_cookie(void) {
    char *ca = read_file(g_ca_path);
    TEST_ASSERT_NOT_NULL_MESSAGE(ca, "missing ca.crt (gen_pki fixture not run?)");

    char cpath[2048], kpath[2048];
    snprintf(cpath, sizeof(cpath), "%s/client.crt", g_pki_dir);
    snprintf(kpath, sizeof(kpath), "%s/client.key", g_pki_dir);
    char *cert = read_file(cpath);
    char *key = read_file(kpath);
    TEST_ASSERT_NOT_NULL_MESSAGE(cert, "missing client.crt");
    TEST_ASSERT_NOT_NULL_MESSAGE(key, "missing client.key");

    int port = -1;
    int fd = bind_listen(&port);
    TEST_ASSERT_TRUE_MESSAGE(fd >= 0, "failed to bind loopback listener");

    tls_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.listen_fd = fd;

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
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_client_cert(cfg, cert, key));
    free(cert);
    free(key);

    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    /* Round 1: an ordinary GET whose response carries Set-Cookie. libcurl's
     * per-handle cookie engine (the SAME curl handle every call this client
     * makes reuses) stores it -- exactly the state a prior cookie-based
     * login would have left behind before a caller switched to the device
     * login on this client object. */
    char *round1_body = NULL;
    axiam_client_raw_get(c, "/oauth2/jwks", &round1_body, &err);
    free(round1_body);
    TEST_ASSERT_TRUE_MESSAGE(srv.round1_ok, "round 1 (GET) did not complete server-side");

    /* Round 2: the device login itself. */
    axiam_device_auth_result_t out;
    axiam_error_kind_t k = axiam_authenticate_device(c, &out, &err);

    pthread_join(th, NULL);
    close(fd);

    TEST_ASSERT_TRUE_MESSAGE(srv.round2_ok, "round 2 (device login) did not complete server-side");
    TEST_ASSERT_TRUE_MESSAGE(srv.round2_saw_client_cert,
                             "server did not receive the client certificate on round 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(AXIAM_OK, k, "SDK did not report device-login success");
    TEST_ASSERT_NOT_NULL(out.access_token);
    axiam_device_auth_result_dispose(&out);

    /* The assertion this file exists for: no Cookie header naming ANYTHING
     * reached the server on round 2 -- an empty/suppressed Cookie header, or
     * no Cookie header line at all, are both "withheld"; a Cookie header
     * carrying a value is not. */
    const char *cookie_line = NULL;
    {
        /* Case-insensitive search for a "cookie:" header LINE (bounded by \r\n
         * on both sides, or by the start of the buffer / the header
         * terminator), since strcasestr is not portable/always declared. */
        const char *p = srv.round2_request;
        size_t plen = strlen(p);
        for (size_t i = 0; i + 7 <= plen && !cookie_line; i++) {
            if (strncasecmp(p + i, "cookie:", 7) == 0 &&
                (i == 0 || (p[i - 1] == '\n'))) {
                cookie_line = p + i;
            }
        }
    }
    if (cookie_line) {
        const char *eol = strstr(cookie_line, "\r\n");
        size_t len = eol ? (size_t) (eol - cookie_line) : strlen(cookie_line);
        char snippet[256];
        snprintf(snippet, sizeof(snippet), "%.*s", (int) len, cookie_line);
        /* A bare "Cookie:" (libcurl's own suppress-this-header spelling, no
         * value at all) is the withheld case; anything with a value after
         * the colon is the defect this test exists to catch. */
        int has_value = 0;
        for (const char *q = cookie_line + 7; q < cookie_line + len; q++) {
            if (*q != ' ' && *q != '\t') { has_value = 1; break; }
        }
        TEST_ASSERT_FALSE_MESSAGE(has_value, snippet);
    }
    /* No "cookie:" line at all is the other acceptable withheld shape. */

    axiam_client_free(c);
    free(ca);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1) snprintf(g_pki_dir, sizeof(g_pki_dir), "%s", argv[1]);
    else snprintf(g_pki_dir, sizeof(g_pki_dir), ".");
    snprintf(g_ca_path, sizeof(g_ca_path), "%s/ca.crt", g_pki_dir);
    snprintf(g_server_crt, sizeof(g_server_crt), "%s/server.crt", g_pki_dir);
    snprintf(g_server_key, sizeof(g_server_key), "%s/server.key", g_pki_dir);

    UNITY_BEGIN();
    RUN_TEST(test_device_login_withholds_a_stale_cookie);
    return UNITY_END();
}
