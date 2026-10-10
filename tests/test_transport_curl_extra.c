/* Phase D3: src/transport_curl.c non-TLS coverage sweep against the REAL
 * libcurl transport (no fake). Covers:
 *   - the plain GET branch (CURLOPT_HTTPGET) via axiam_client_raw_get(),
 *   - the "custom method with body" branch (CURLOPT_CUSTOMREQUEST +
 *     CURLOPT_POSTFIELDS) via the client's own transport function pointer,
 *   - connect_timeout_ms wiring,
 *   - the CURLE_* transport-failure path (rc != CURLE_OK) via a closed
 *     loopback port,
 *   - the custom-CA / client-cert(+key) blob wiring, which is unconditional
 *     setopt code executed before curl_easy_perform() — a closed port is
 *     enough to exercise it without a live TLS server.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"

static char g_pki_dir[1024];

void setUp(void) {}
void tearDown(void) {}

/* ---- small loopback server helpers (pattern: test_integration_curl.c) ---- */
static int bind_ephemeral(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

/* A port nothing listens on: bind (to claim a free ephemeral port) then close
 * immediately without ever calling listen(). Connuecting to it afterwards
 * gets an immediate RST/ECONNREFUSED -> CURLE_COULDNT_CONNECT, no timeout
 * needed. */
static int closed_port(void) {
    int port = -1;
    int fd = bind_ephemeral(&port);
    if (fd < 0) return -1;
    close(fd);
    return port;
}

typedef struct {
    int listen_fd;
    const char *expect_method;
    const char *respond_body;
} single_req_srv_t;

static void *single_request_server(void *arg) {
    single_req_srv_t *s = arg;
    int cfd = accept(s->listen_fd, NULL, NULL);
    if (cfd < 0) return NULL;
    char buf[4096];
    ssize_t r = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (r < 0) r = 0;
    buf[r] = '\0';
    /* Sanity: confirm the expected HTTP method line landed on the wire. */
    if (s->expect_method) {
        char line[64];
        snprintf(line, sizeof(line), "%s ", s->expect_method);
        if (strncmp(buf, line, strlen(line)) != 0) {
            /* Still respond so the client doesn't hang; test assertion on
             * the client side will fail if this path is ever hit. */
        }
    }
    char resp[512];
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             strlen(s->respond_body), s->respond_body);
    write(cfd, resp, strlen(resp));
    close(cfd);
    return NULL;
}

/* GET through the real transport (src/transport_curl.c:164-165). */
static void test_get_request_via_real_transport(void) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));

    single_req_srv_t srv = { .listen_fd = fd, .expect_method = "GET",
                             .respond_body = "{\"keys\":[]}" };
    pthread_t th;
    pthread_create(&th, NULL, single_request_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    char *body = NULL;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", &body, &err);
    pthread_join(th, NULL);
    close(fd);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING("{\"keys\":[]}", body);

    free(body);
    axiam_client_free(c);
}

/* Custom method ("PATCH") with a body through the real transport
 * (src/transport_curl.c:171-175), invoked via the client's own transport fn
 * pointer (no public API issues a non-GET/POST verb). */
static void test_custom_method_with_body_via_real_transport(void) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));

    single_req_srv_t srv = { .listen_fd = fd, .expect_method = "PATCH",
                             .respond_body = "{\"ok\":true}" };
    pthread_t th;
    pthread_create(&th, NULL, single_request_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/v1/whatever", base);
    const char *body_str = "{\"field\":1}";
    axiam_http_request_t req = {0};
    req.method = "PATCH";
    req.url = url;
    req.body = body_str;
    req.body_len = strlen(body_str);
    axiam_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int rc = c->transport(c->transport_ctx, &req, &resp);
    pthread_join(th, NULL);
    close(fd);

    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(200, (int)resp.status);
    axiam_http_response_dispose(&resp);
    axiam_client_free(c);
}

/* CURLE_* failure path (transport_curl.c:193-199), connect_timeout_ms wiring
 * (line 137), and CA/client-cert(+key) blob setup (lines 140-161) — all of
 * the blob setopt calls run before curl_easy_perform(), so a closed loopback
 * port is enough to exercise them without a live TLS server. */
static void test_closed_port_failure_with_tls_material_configured(void) {
    int port = closed_port();
    TEST_ASSERT_TRUE(port > 0);

    char ca_path[2048], cert_path[2048], key_path[2048];
    snprintf(ca_path, sizeof(ca_path), "%s/ca.crt", g_pki_dir);
    snprintf(cert_path, sizeof(cert_path), "%s/client.crt", g_pki_dir);
    snprintf(key_path, sizeof(key_path), "%s/client.key", g_pki_dir);

    FILE *fca = fopen(ca_path, "rb");
    FILE *fcert = fopen(cert_path, "rb");
    FILE *fkey = fopen(key_path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(fca, "missing ca.crt (gen_pki fixture not run?)");
    TEST_ASSERT_NOT_NULL_MESSAGE(fcert, "missing client.crt");
    TEST_ASSERT_NOT_NULL_MESSAGE(fkey, "missing client.key");

    char ca[8192] = {0}, cert[8192] = {0}, key[8192] = {0};
    if (fca) { size_t n = fread(ca, 1, sizeof(ca) - 1, fca); ca[n] = '\0'; fclose(fca); }
    if (fcert) { size_t n = fread(cert, 1, sizeof(cert) - 1, fcert); cert[n] = '\0'; fclose(fcert); }
    if (fkey) { size_t n = fread(key, 1, sizeof(key) - 1, fkey); key[n] = '\0'; fclose(fkey); }

    char base[64];
    snprintf(base, sizeof(base), "https://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_connect_timeout_ms(cfg, 500);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_custom_ca(cfg, ca));
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_config_set_client_cert(cfg, cert, key));

    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    char *out_body = NULL;
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", &out_body, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, k);
    TEST_ASSERT_NULL(out_body);
    TEST_ASSERT_TRUE(strlen(err.message) > 0);

    axiam_client_free(c);
}

/* ---- §34.2 P11 / §34.4 A6 (contract 1.60; R-17): a write is delivered exactly once -----
 *
 * libcurl re-sends a request by itself when it was put on a REUSED connection and that
 * connection died before any byte of the reply. The server below keeps the first connection
 * alive after answering a GET, and then READS a write and closes without answering. Without
 * CURLOPT_FRESH_CONNECT + CURLOPT_FORBID_REUSE the write rides the kept-alive connection,
 * is read, dropped, and libcurl sends it again on a new one: the server counts two. With
 * them it counts one, whatever the library does. */
typedef struct {
    int listen_fd;
    volatile int stop;
    int gets;
    int writes;       /* requests whose method line is not GET */
    int connections;
} drop_srv_t;

static void *drop_writes_server(void *arg) {
    drop_srv_t *s = arg;
    int fds[16];
    int nfds = 0;
    while (!s->stop) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(s->listen_fd, &rd);
        int maxfd = s->listen_fd;
        for (int i = 0; i < nfds; i++) {
            FD_SET(fds[i], &rd);
            if (fds[i] > maxfd) maxfd = fds[i];
        }
        struct timeval tv = {0, 50 * 1000};
        if (select(maxfd + 1, &rd, NULL, NULL, &tv) <= 0) continue;
        if (FD_ISSET(s->listen_fd, &rd) && nfds < 16) {
            int cfd = accept(s->listen_fd, NULL, NULL);
            if (cfd >= 0) {
                fds[nfds++] = cfd;
                s->connections++;
            }
        }
        for (int i = 0; i < nfds; i++) {
            if (!FD_ISSET(fds[i], &rd)) continue;
            char buf[4096];
            ssize_t r = recv(fds[i], buf, sizeof(buf) - 1, 0);
            if (r <= 0) { /* the client closed it */
                close(fds[i]);
                fds[i] = fds[--nfds];
                i--;
                continue;
            }
            buf[r] = '\0';
            if (strncmp(buf, "GET ", 4) == 0) {
                s->gets++;
                static const char ok[] =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Content-Length: 11\r\nConnection: keep-alive\r\n\r\n{\"keys\":[]}";
                if (write(fds[i], ok, sizeof(ok) - 1) < 0) {}
            } else {
                /* A write: read it, count it, drop the connection with no answer. */
                s->writes++;
                close(fds[i]);
                fds[i] = fds[--nfds];
                i--;
            }
        }
    }
    for (int i = 0; i < nfds; i++) close(fds[i]);
    return NULL;
}

static void test_a_write_a_server_drops_unanswered_arrives_exactly_once_A6(void) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 8));
    drop_srv_t srv;
    memset(&srv, 0, sizeof srv);
    srv.listen_fd = fd;
    pthread_t th;
    pthread_create(&th, NULL, drop_writes_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    /* A GET first: it leaves a kept-alive connection in libcurl's pool. */
    char *body = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_raw_get(c, "/oauth2/jwks", &body, &err));
    free(body);

    /* Every verb a never-retried write uses; each is read and dropped by the server. */
    static const char *const verbs[] = {"POST", "PUT", "DELETE", "PATCH"};
    int expected_writes = 0;
    for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
        /* Re-prime the pool so the next write meets a reusable connection. */
        body = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_raw_get(c, "/oauth2/jwks", &body, &err));
        free(body);

        char url[128];
        snprintf(url, sizeof(url), "%s/api/v1/things", base);
        const char *payload = "{\"a\":1}";
        axiam_http_request_t req = {0}; /* replayable = 0: a write the SDK never retries */
        req.method = verbs[i];
        req.url = url;
        req.body = payload;
        req.body_len = strlen(payload);
        axiam_http_response_t resp;
        memset(&resp, 0, sizeof(resp));
        int rc = c->transport(c->transport_ctx, &req, &resp);
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, rc, "the dropped write is a transport failure");
        TEST_ASSERT_EQUAL_INT(0, (int)resp.status);
        axiam_http_response_dispose(&resp);
        expected_writes++;

        /* Give a (wrongly) re-sent copy time to arrive before counting. */
        usleep(150 * 1000);
        TEST_ASSERT_EQUAL_INT_MESSAGE(expected_writes, srv.writes,
                                      "the write must reach the server exactly once");
    }

    /* And through a public write -- login is one the SDK never retries by itself. */
    body = NULL;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_raw_get(c, "/oauth2/jwks", &body, &err));
    free(body);
    axiam_login_result_t lr;
    TEST_ASSERT_EQUAL_INT(AXIAM_ERR_NETWORK, axiam_login(c, "alice", "pw", &lr, &err));
    usleep(150 * 1000);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_writes + 1, srv.writes,
                                  "a login the server drops arrives exactly once");

    srv.stop = 1;
    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(c);
}

/* The converse: a request the SDK itself replays (req.replayable) and a GET keep the pool,
 * so the connection of the first GET serves the second. */
static void test_a_get_keeps_the_connection_pool(void) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 8));
    drop_srv_t srv;
    memset(&srv, 0, sizeof srv);
    srv.listen_fd = fd;
    pthread_t th;
    pthread_create(&th, NULL, drop_writes_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    for (int i = 0; i < 2; i++) {
        char *body = NULL;
        TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_client_raw_get(c, "/oauth2/jwks", &body, &err));
        free(body);
    }
    srv.stop = 1;
    pthread_join(th, NULL);
    close(fd);
    TEST_ASSERT_EQUAL_INT(2, srv.gets);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, srv.connections, "reads share one connection");
    axiam_client_free(c);
}

int main(int argc, char **argv) {
    if (argc > 1) snprintf(g_pki_dir, sizeof(g_pki_dir), "%s", argv[1]);
    else snprintf(g_pki_dir, sizeof(g_pki_dir), ".");
    UNITY_BEGIN();
    RUN_TEST(test_get_request_via_real_transport);
    RUN_TEST(test_custom_method_with_body_via_real_transport);
    RUN_TEST(test_closed_port_failure_with_tls_material_configured);
    RUN_TEST(test_a_write_a_server_drops_unanswered_arrives_exactly_once_A6);
    RUN_TEST(test_a_get_keeps_the_connection_pool);
    return UNITY_END();
}
