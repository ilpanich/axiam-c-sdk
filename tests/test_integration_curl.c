#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* Integration test: exercises the REAL libcurl transport against a tiny
 * in-process HTTP server (raw socket/accept/recv/send on a background thread).
 * Verifies §4 cookie persistence, §3 CSRF echo, and §5 tenant header over the
 * wire. Plain HTTP (loopback) — strict TLS verification remains ON in the SDK
 * but is not engaged for an http:// origin. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"

typedef struct {
    int listen_fd;
    int saw_tenant_on_req1;
    int saw_cookie_on_req2;
    int saw_csrf_on_req2;
    int handled;
} srv_t;

static srv_t g_srv;

static void send_all(int fd, const char *s) {
    size_t n = strlen(s);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, s + off, n - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
}

static void *server_thread(void *arg) {
    srv_t *s = arg;
    for (int i = 0; i < 2; i++) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char buf[4096];
        ssize_t r = recv(cfd, buf, sizeof(buf) - 1, 0);
        if (r < 0) r = 0;
        buf[r] = '\0';
        if (i == 0) {
            if (strcasestr(buf, "X-Tenant-ID: acme")) s->saw_tenant_on_req1 = 1;
            const char *body =
                "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\","
                "\"username\":\"a\",\"email\":\"e\",\"tenant_id\":\"t\"}}";
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "X-CSRF-Token: srv-csrf\r\n"
                     "Set-Cookie: axiam_access=abc; Path=/\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     strlen(body), body);
            send_all(cfd, resp);
        } else {
            if (strcasestr(buf, "Cookie:") && strcasestr(buf, "axiam_access=abc"))
                s->saw_cookie_on_req2 = 1;
            if (strcasestr(buf, "X-CSRF-Token: srv-csrf"))
                s->saw_csrf_on_req2 = 1;
            send_all(cfd,
                     "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        }
        s->handled++;
        close(cfd);
    }
    return NULL;
}

void setUp(void) {}
void tearDown(void) {}

static void test_real_curl_roundtrip(void) {
    memset(&g_srv, 0, sizeof(g_srv));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT_TRUE(fd >= 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    TEST_ASSERT_EQUAL_INT(0, bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);
    g_srv.listen_fd = fd;

    pthread_t th;
    pthread_create(&th, NULL, server_thread, &g_srv);

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

    axiam_login_result_t res;
    axiam_error_kind_t k = axiam_login(c, "a", "b", &res, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);
    TEST_ASSERT_TRUE(res.authenticated);
    axiam_login_result_dispose(&res);

    /* Second request should carry the persisted cookie + echoed CSRF token. */
    k = axiam_logout(c, &err);
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, k);

    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(c);

    TEST_ASSERT_TRUE_MESSAGE(g_srv.saw_tenant_on_req1, "X-Tenant-ID not sent");
    TEST_ASSERT_TRUE_MESSAGE(g_srv.saw_cookie_on_req2, "cookie jar did not persist");
    TEST_ASSERT_TRUE_MESSAGE(g_srv.saw_csrf_on_req2, "CSRF token not echoed");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_real_curl_roundtrip);
    return UNITY_END();
}
