#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * CONTRACT.md §12.1 rule 12b (contract 1.66, #837): a federated sign-in is completed through the
 * cookie jar that started it. Against the REAL libcurl cookie engine (a fake transport has no jar),
 * the `Set-Cookie: axiam_fed_bind=...` of an `sso_start` response is presented on the following
 * `sso_complete` from the SAME client, and is absent from a SECOND client's `sso_complete`.
 *
 * The mock answers over plain http, so the cookie is the `axiam_fed_bind` spelling without
 * `Secure` (the server's cookie_secure-off form); `__Host-` would need https.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "test_util.h"

#define MAX_REQ 8
/* 43 characters: the base64url form of 32 random bytes, as the server mints it. */
#define FED_BIND "Zm9vYmFyYmF6cXV4LWZlZC1iaW5kLXZhbHVlLTQzY2g"

typedef struct {
    int listen_fd;
    int n;
    char line[MAX_REQ][96];
    char cookie[MAX_REQ][512]; /* the Cookie header value on the wire, "" when absent */
    char base[64];
} srv_t;

static srv_t g_srv;

static void send_all(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t w = write(fd, s + off, n - off);
        if (w <= 0) break;
        off += (size_t) w;
    }
}

/* Read the head, then the body Content-Length announces, so closing does not reset the peer. */
static void read_request(int fd, char *head, size_t cap) {
    size_t len = 0;
    char *end = NULL;
    while (len + 1 < cap && !(end = strstr(head, "\r\n\r\n"))) {
        ssize_t r = recv(fd, head + len, cap - 1 - len, 0);
        if (r <= 0) break;
        len += (size_t) r;
        head[len] = '\0';
    }
    if (!end) return;
    const char *cl = strcasestr(head, "Content-Length:");
    size_t want = cl ? (size_t) strtol(cl + 15, NULL, 10) : 0;
    size_t have = len - (size_t) (end + 4 - head);
    char scratch[512];
    while (have < want) {
        ssize_t r = recv(fd, scratch, sizeof scratch, 0);
        if (r <= 0) break;
        have += (size_t) r;
    }
}

static void respond(int fd, const char *extra_headers, const char *body) {
    char resp[2048];
    snprintf(resp, sizeof resp,
             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             extra_headers, strlen(body), body);
    send_all(fd, resp);
}

static void *server_thread(void *arg) {
    srv_t *s = arg;
    for (;;) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char head[4096] = "";
        read_request(cfd, head, sizeof head);
        if (strncmp(head, "STOP", 4) == 0 || head[0] == '\0') { close(cfd); if (head[0]) break; continue; }
        if (s->n >= MAX_REQ) { close(cfd); continue; }
        int i = s->n++;
        size_t ln = strcspn(head, "\r\n");
        snprintf(s->line[i], sizeof s->line[i], "%.*s", (int) ln, head);
        const char *ck = strcasestr(head, "\r\nCookie:");
        if (ck) {
            ck += 9;
            while (*ck == ' ') ck++;
            snprintf(s->cookie[i], sizeof s->cookie[i], "%.*s", (int) strcspn(ck, "\r\n"), ck);
        }
        if (strstr(head, "POST /api/v1/auth/federation/oidc/start"))
            respond(cfd,
                    "Set-Cookie: axiam_fed_bind=" FED_BIND "; Path=/; HttpOnly; SameSite=Strict\r\n",
                    "{\"authorize_url\":\"https://idp.test/authorize?state=st-1\","
                    "\"state\":\"st-1\",\"expires_in_secs\":600}");
        else if (strstr(head, "POST /api/v1/auth/federation/oidc/callback"))
            respond(cfd, "Set-Cookie: axiam_access=abc; Path=/\r\n",
                    "{\"user_id\":\"u\",\"session_id\":\"s\",\"expires_in\":900,"
                    "\"redirect_uri\":\"https://app.test/cb\"}");
        else send_all(cfd, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        close(cfd);
    }
    return NULL;
}

void setUp(void) {}
void tearDown(void) {}

static axiam_client_t *new_client(void) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, g_srv.base);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);
    return c;
}

static void complete(axiam_client_t *c) {
    axiam_error_t err;
    axiam_sso_complete_result_t done;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_sso_complete(c, "the-code", "st-1", &done, &err));
    axiam_sso_complete_result_dispose(&done);
}

static void test_sso_complete_presents_the_binding_cookie_of_its_own_sso_start_only(void) {
    memset(&g_srv, 0, sizeof g_srv);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT_TRUE(fd >= 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT_EQUAL_INT(0, bind(fd, (struct sockaddr *) &addr, sizeof addr));
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 8));
    socklen_t alen = sizeof addr;
    getsockname(fd, (struct sockaddr *) &addr, &alen);
    g_srv.listen_fd = fd;
    snprintf(g_srv.base, sizeof g_srv.base, "http://127.0.0.1:%d", ntohs(addr.sin_port));
    pthread_t th;
    pthread_create(&th, NULL, server_thread, &g_srv);

    axiam_client_t *a = new_client();
    axiam_client_t *b = new_client();
    axiam_error_t err;

    axiam_sso_start_result_t started;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK,
                          axiam_sso_start(a, "fed-1", "https://app.test/cb", &started, &err));
    TEST_ASSERT_EQUAL_STRING("st-1", started.state);
    axiam_sso_start_result_dispose(&started);

    complete(a); /* request 1: the client that started the sign-in */
    complete(b); /* request 2: a separate client, with its own jar */

    TEST_ASSERT_EQUAL_INT(3, g_srv.n);
    TEST_ASSERT_EQUAL_STRING("POST /api/v1/auth/federation/oidc/start HTTP/1.1", g_srv.line[0]);
    TEST_ASSERT_EQUAL_STRING("POST /api/v1/auth/federation/oidc/callback HTTP/1.1", g_srv.line[1]);
    TEST_ASSERT_EQUAL_STRING("POST /api/v1/auth/federation/oidc/callback HTTP/1.1", g_srv.line[2]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_srv.cookie[1], "axiam_fed_bind=" FED_BIND),
                                 "the starting client's completion presents the binding cookie");
    TEST_ASSERT_NULL_MESSAGE(strstr(g_srv.cookie[2], "axiam_fed_bind"),
                             "a second client's completion does not");

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *) &addr, sizeof addr) == 0) send_all(s, "STOP");
    close(s);
    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(a);
    axiam_client_free(b);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sso_complete_presents_the_binding_cookie_of_its_own_sso_start_only);
    return UNITY_END();
}
