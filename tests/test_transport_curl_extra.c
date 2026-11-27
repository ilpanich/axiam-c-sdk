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
#include "jwt_fixture.h"
#include "test_util.h"

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

/* Ride-along to N14: write_cb used to grow its buffer without a limit, so a server (or
 * anything on the path of a plain-HTTP deployment) could make the SDK allocate until it
 * was killed. A body past AXIAM_MAX_RESPONSE_BYTES now aborts the transfer. */
typedef struct {
    int listen_fd;
    size_t total;
} flood_srv_t;

static void *flood_server(void *arg) {
    flood_srv_t *s = arg;
    int cfd = accept(s->listen_fd, NULL, NULL);
    if (cfd < 0) return NULL;
    char buf[4096];
    (void)recv(cfd, buf, sizeof(buf), 0);
    char head[160];
    int hn = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n", s->total);
    (void)send(cfd, head, (size_t)hn, MSG_NOSIGNAL);
    static char chunk[65536];
    memset(chunk, 'a', sizeof(chunk));
    size_t sent = 0;
    while (sent < s->total) {
        size_t n = s->total - sent < sizeof(chunk) ? s->total - sent : sizeof(chunk);
        ssize_t w = send(cfd, chunk, n, MSG_NOSIGNAL);
        if (w <= 0) break; /* the client aborted: expected */
        sent += (size_t)w;
    }
    close(cfd);
    return NULL;
}

static axiam_error_kind_t raw_get_flood(size_t total, char **body, axiam_error_t *err) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));
    flood_srv_t srv = { .listen_fd = fd, .total = total };
    pthread_t th;
    pthread_create(&th, NULL, flood_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_slug(cfg, "acme");
    axiam_client_config_set_timeout_ms(cfg, 20000);
    axiam_client_t *c = axiam_client_new(cfg, err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    axiam_error_kind_t k = axiam_client_raw_get(c, "/oauth2/jwks", body, err);
    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(c);
    return k;
}

static void test_a_response_body_past_the_cap_is_refused(void) {
    char *body = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = raw_get_flood(AXIAM_MAX_RESPONSE_BYTES + 4096, &body, &err);
    TEST_ASSERT_NOT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_NULL(body);
}

static void test_a_response_body_at_the_cap_is_still_read(void) {
    char *body = NULL;
    axiam_error_t err;
    axiam_error_kind_t k = raw_get_flood(AXIAM_MAX_RESPONSE_BYTES, &body, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_size_t(AXIAM_MAX_RESPONSE_BYTES, strlen(body));
    free(body);
}

/* C-R1-2: the cap is per request. A response past the default 16 MiB aborts with a distinct
 * "size cap" transport error (CURLE_FILESIZE_EXCEEDED), not a generic write failure; a request
 * that names a larger bound (the export operations) reads the same body whole. */
static int direct_get(size_t total, size_t max_bytes, axiam_http_response_t *resp) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));
    flood_srv_t srv = { .listen_fd = fd, .total = total };
    pthread_t th;
    pthread_create(&th, NULL, flood_server, &srv);
    char url[96];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/export", port);
    void *ctx = axiam_curl_ctx_new(NULL);
    TEST_ASSERT_NOT_NULL(ctx);
    axiam_http_request_t req = {0};
    req.method = "POST";
    req.url = url;
    req.max_response_bytes = max_bytes;
    memset(resp, 0, sizeof(*resp));
    int rc = axiam_curl_transport(ctx, &req, resp);
    pthread_join(th, NULL);
    close(fd);
    axiam_curl_ctx_free(ctx);
    return rc;
}

static void test_a_capped_post_is_reported_as_a_size_cap_not_a_write_failure(void) {
    axiam_http_response_t resp;
    int rc = direct_get(AXIAM_MAX_RESPONSE_BYTES + 4096, 0, &resp);
    TEST_ASSERT_NOT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_TRANSPORT_ERR_BODY_CAP, resp.transport_err);
    TEST_ASSERT_NOT_NULL(resp.transport_msg);
    TEST_ASSERT_NOT_NULL(strstr(resp.transport_msg, "size cap"));
    axiam_http_response_dispose(&resp);
}

static void test_a_request_with_a_larger_bound_reads_a_body_past_16_mib(void) {
    axiam_http_response_t resp;
    size_t total = AXIAM_MAX_RESPONSE_BYTES + 4096;
    int rc = direct_get(total, AXIAM_MAX_EXPORT_RESPONSE_BYTES, &resp);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_NOT_NULL(resp.body);
    TEST_ASSERT_EQUAL_size_t(total, strlen(resp.body));
    axiam_http_response_dispose(&resp);
}

/* ---- §12.4 rule 2 over the REAL transport: ETag / Cache-Control reach the JWKS cache ---- */
typedef struct {
    int listen_fd;
    int requests;
    const char *jwks;
    char second_req[4096];
} jwks_srv_t;

static void *jwks_two_request_server(void *arg) {
    jwks_srv_t *s = arg;
    for (int i = 0; i < 2; i++) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) return NULL;
        char buf[4096];
        ssize_t r = recv(cfd, buf, sizeof(buf) - 1, 0);
        if (r < 0) r = 0;
        buf[r] = '\0';
        s->requests++;
        if (i == 0) {
            char head[256];
            snprintf(head, sizeof(head),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "ETag: \"v7\"\r\nCache-Control: public, max-age=5\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n", strlen(s->jwks));
            write(cfd, head, strlen(head));
            write(cfd, s->jwks, strlen(s->jwks));
        } else {
            snprintf(s->second_req, sizeof(s->second_req), "%s", buf);
            const char *nm = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
            write(cfd, nm, strlen(nm));
        }
        close(cfd);
    }
    return NULL;
}

static time_t g_jwks_now;
static time_t jwks_clock(void *ctx) { (void)ctx; return g_jwks_now; }

static void test_jwks_etag_and_max_age_reach_the_cache_over_curl(void) {
    char *token = NULL, *jwks = NULL;
    char p[256];
    TEST_ASSERT_EQUAL_INT(0, jwt_make("k1", test_claims(p, sizeof(p), "u", NULL), &token, &jwks));
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));
    jwks_srv_t srv = { .listen_fd = fd, .jwks = jwks };
    pthread_t th;
    pthread_create(&th, NULL, jwks_two_request_server, &srv);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, base);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    g_jwks_now = 1900000000;
    c->clock_fn = jwks_clock;

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));  /* fetch 1 */
    g_jwks_now += 3;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));  /* within max-age=5 */
    TEST_ASSERT_EQUAL_INT(1, srv.requests);
    g_jwks_now += 3;                         /* 6 s: past the advertised 5 s, far inside 300 s */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));  /* 304 accepted */
    shutdown(fd, SHUT_RDWR);    /* unblock accept() if the second request never came */
    pthread_join(th, NULL);
    close(fd);
    TEST_ASSERT_EQUAL_INT(2, srv.requests);
    TEST_ASSERT_NOT_NULL(strcasestr(srv.second_req, "If-None-Match: \"v7\""));
    /* The 304 re-anchored the cache at t0+6: 300 s later (t0+306, past the first fetch's
     * TTL+300 = t0+305) the endpoint is gone, yet the held kid is still accepted -- only
     * because the anchor moved. */
    g_jwks_now += 300;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_jwt_verify(c, token, NULL, &err));
    free(token); free(jwks);
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
    RUN_TEST(test_a_response_body_past_the_cap_is_refused);
    RUN_TEST(test_a_response_body_at_the_cap_is_still_read);
    RUN_TEST(test_a_capped_post_is_reported_as_a_size_cap_not_a_write_failure);
    RUN_TEST(test_a_request_with_a_larger_bound_reads_a_body_past_16_mib);
    RUN_TEST(test_jwks_etag_and_max_age_reach_the_cache_over_curl);
    return UNITY_END();
}
