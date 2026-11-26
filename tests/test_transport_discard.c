/*
 * C-R3-2: a body the SDK will discard is not buffered.
 *
 * The two export operations (tenants.export_audit, privacy.download_export) hand the archive to
 * nobody; the C API returns only an error kind. A request with `discard_body` set therefore has
 * its body COUNTED against `max_response_bytes` while it is read, and dropped as it arrives. A
 * body past the bound aborts the transfer; nothing near the bound is ever held in memory.
 *
 * Memory is measured as the process's peak resident set (getrusage), taken before and after a
 * transfer of tens of MiB. The control at the end proves the measurement: the same transfer
 * WITHOUT discard_body raises the peak by at least the body size.
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
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unity.h"
#include "axiam/axiam.h"
#include "internal.h"

#define MIB ((size_t)1024 * 1024)

void setUp(void) {}
void tearDown(void) {}

static int bind_ephemeral(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

typedef struct {
    int listen_fd;
    int status;
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
                      "HTTP/1.1 %d X\r\nContent-Type: application/json\r\n"
                      "Content-Length: %zu\r\nConnection: close\r\n\r\n", s->status, s->total);
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

static long peak_rss_kib(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
}

/* One request through the real transport; returns the peak-RSS growth in KiB. */
static long transfer(int status, size_t total, size_t cap, int discard, int *rc,
                     axiam_http_response_t *resp) {
    int port;
    int fd = bind_ephemeral(&port);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, listen(fd, 4));
    flood_srv_t srv = { .listen_fd = fd, .status = status, .total = total };
    pthread_t th;
    pthread_create(&th, NULL, flood_server, &srv);
    char url[96];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/export", port);
    void *ctx = axiam_curl_ctx_new(NULL);
    TEST_ASSERT_NOT_NULL(ctx);
    axiam_http_request_t req = {0};
    req.method = "GET";
    req.url = url;
    req.max_response_bytes = cap;
    req.discard_body = discard;
    memset(resp, 0, sizeof(*resp));
    long before = peak_rss_kib();
    *rc = axiam_curl_transport(ctx, &req, resp);
    long grew = peak_rss_kib() - before;
    pthread_join(th, NULL);
    close(fd);
    axiam_curl_ctx_free(ctx);
    return grew;
}

/* Sizes are small on purpose (loopback under ASan is slow): the bodies are 4-8 MiB, so a held
 * body shows as several MiB of peak-RSS growth against a ~1 MiB allowance for the transport's
 * own buffers. A warm-up transfer first takes libcurl's one-off allocations out of the delta. */
#define HELD_LIMIT_KIB (2 * 1024)
#define CONTROL_MIN_KIB (4 * 1024)

static void test_a_discarded_body_over_the_cap_is_refused_without_being_held(void) {
    axiam_http_response_t resp;
    int rc;
    long grew = transfer(200, 4 * MIB + 4096, 4 * MIB, 1, &rc, &resp);
    TEST_ASSERT_NOT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(AXIAM_TRANSPORT_ERR_BODY_CAP, resp.transport_err);
    TEST_ASSERT_NULL(resp.body);
    TEST_ASSERT_TRUE_MESSAGE(grew < HELD_LIMIT_KIB, "a refused discarded body was held in memory");
    axiam_http_response_dispose(&resp);
}

static void test_a_discarded_2xx_body_within_the_cap_is_counted_and_dropped(void) {
    axiam_http_response_t resp;
    int rc;
    long grew = transfer(200, 3 * MIB, 4 * MIB, 1, &rc, &resp);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(200, resp.status);
    TEST_ASSERT_NULL(resp.body);
    TEST_ASSERT_TRUE_MESSAGE(grew < HELD_LIMIT_KIB, "a discarded body was held in memory");
    axiam_http_response_dispose(&resp);
}

static void test_a_discarded_error_body_keeps_only_a_prefix(void) {
    axiam_http_response_t resp;
    int rc;
    long grew = transfer(500, 3 * MIB, 4 * MIB, 1, &rc, &resp);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(500, resp.status);
    TEST_ASSERT_NOT_NULL(resp.body);
    TEST_ASSERT_EQUAL_size_t(AXIAM_DISCARD_BODY_KEEP_BYTES, strlen(resp.body));
    TEST_ASSERT_TRUE(grew < HELD_LIMIT_KIB);
    axiam_http_response_dispose(&resp);
}

/* Control, LAST (it raises the process peak): the same transfer without discard_body does hold
 * the body, so the measurement above can tell the two apart. */
static void test_control_a_kept_body_is_held(void) {
    axiam_http_response_t resp;
    int rc;
    long grew = transfer(200, 8 * MIB, 8 * MIB + 4096, 0, &rc, &resp);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(resp.body);
    TEST_ASSERT_TRUE_MESSAGE(grew > CONTROL_MIN_KIB, "the control did not grow the peak RSS");
    axiam_http_response_dispose(&resp);
}

int main(void) {
    {
        axiam_http_response_t warm;
        int rc;
        (void)transfer(200, 64 * 1024, 4 * MIB, 1, &rc, &warm);
        axiam_http_response_dispose(&warm);
    }
    UNITY_BEGIN();
    RUN_TEST(test_a_discarded_body_over_the_cap_is_refused_without_being_held);
    RUN_TEST(test_a_discarded_2xx_body_within_the_cap_is_counted_and_dropped);
    RUN_TEST(test_a_discarded_error_body_keeps_only_a_prefix);
    RUN_TEST(test_control_a_kept_body_is_held);
    return UNITY_END();
}
