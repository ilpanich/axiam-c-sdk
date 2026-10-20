#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * CONTRACT.md §6.1 rule 11 and §12.1 rule 3 (contract 1.63), §14.6 "no session cookie and no CSRF
 * header on /oauth2/*": against the REAL libcurl cookie engine (a fake transport has no jar to
 * leak from), a client whose jar holds the session cookies from a cookie sign-in runs
 * device_authorize, device_poll and a token request; none of the three carries a `Cookie` or an
 * `X-CSRF-Token` header. The control: the same client's next state-changing /api/v1 request (the
 * logout) carries both, so the assertions cannot pass for want of them.
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

#define MAX_REQ 16

typedef struct {
    int listen_fd;
    int n;
    char line[MAX_REQ][96];
    int cookie[MAX_REQ]; /* a Cookie header was on the wire */
    int csrf[MAX_REQ];   /* an X-CSRF-Token header was on the wire */
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
    char discovery[1024];
    snprintf(discovery, sizeof discovery,
             "{\"issuer\":\"%s\",\"authorization_endpoint\":\"%s/oauth2/authorize\","
             "\"token_endpoint\":\"%s/oauth2/token\",\"jwks_uri\":\"%s/oauth2/jwks\","
             "\"device_authorization_endpoint\":\"%s/oauth2/device_authorization\","
             "\"response_types_supported\":[\"code\"],"
             "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],\"scopes_supported\":[\"openid\"]}",
             s->base, s->base, s->base, s->base, s->base);
    for (;;) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char head[4096] = "";
        read_request(cfd, head, sizeof head);
        if (strncmp(head, "STOP", 4) == 0 || head[0] == '\0') { close(cfd); if (head[0]) break; continue; }
        int i = s->n++;
        size_t ln = strcspn(head, "\r\n");
        snprintf(s->line[i], sizeof s->line[i], "%.*s", (int) ln, head);
        s->cookie[i] = strcasestr(head, "\r\nCookie:") != NULL;
        s->csrf[i] = strcasestr(head, "\r\nX-CSRF-Token:") != NULL;
        if (strstr(head, "POST /api/v1/auth/login"))
            respond(cfd,
                    "X-CSRF-Token: srv-csrf\r\nSet-Cookie: axiam_access=abc; Path=/\r\n"
                    "Set-Cookie: axiam_csrf=srv-csrf; Path=/\r\n",
                    "{\"session_id\":\"s\",\"expires_in\":900,\"user\":{\"id\":\"u\",\"username\":\"a\","
                    "\"email\":\"e\",\"tenant_id\":\"t\"}}");
        else if (strstr(head, "GET /.well-known/openid-configuration")) respond(cfd, "", discovery);
        else if (strstr(head, "GET /.well-known/uma2-configuration")) {
            char uma[1024];
            snprintf(uma, sizeof uma,
                     "{\"issuer\":\"%s\",\"token_endpoint\":\"%s/oauth2/token\","
                     "\"introspection_endpoint\":\"%s/oauth2/introspect\","
                     "\"permission_endpoint\":\"%s/uma2/perm\","
                     "\"resource_registration_endpoint\":\"%s/uma2/rreg/resource_set\","
                     "\"jwks_uri\":\"%s/oauth2/jwks\",\"grant_types_supported\":[\"%s\"],"
                     "\"uma_profiles_supported\":[],\"permission_ticket_lifetime\":60}",
                     s->base, s->base, s->base, s->base, s->base, s->base, AXIAM_UMA_TICKET_GRANT_TYPE);
            respond(cfd, "", uma);
        } else if (strstr(head, "POST /oauth2/device_authorization"))
            respond(cfd, "",
                    "{\"device_code\":\"the-device-code\",\"user_code\":\"WDJB-MJHT\","
                    "\"verification_uri\":\"https://id.test/device\",\"expires_in\":600,\"interval\":1}");
        else if (strstr(head, "POST /oauth2/token"))
            respond(cfd, "", "{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\",\"expires_in\":900}");
        else send_all(cfd, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        close(cfd);
    }
    return NULL;
}

void setUp(void) {}
void tearDown(void) {}

static int find(const char *prefix) {
    for (int i = 0; i < g_srv.n; i++)
        if (strncmp(g_srv.line[i], prefix, strlen(prefix)) == 0) return i;
    return -1;
}

static void assert_bare(const char *prefix) {
    int i = find(prefix);
    TEST_ASSERT_TRUE_MESSAGE(i >= 0, prefix);
    TEST_ASSERT_FALSE_MESSAGE(g_srv.cookie[i], "no Cookie header on an /oauth2/* request");
    TEST_ASSERT_FALSE_MESSAGE(g_srv.csrf[i], "no X-CSRF-Token header on an /oauth2/* request");
}

static void test_oauth2_requests_carry_no_session_cookie_and_no_csrf_header(void) {
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

    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, g_srv.base);
    axiam_client_config_set_tenant_id(cfg, AXIAM_TEST_TENANT_ID);
    axiam_client_config_set_oidc_client_id(cfg, "rp-client");
    axiam_client_config_set_oidc_client_secret(cfg, "rp-secret");
    axiam_client_config_set_timeout_ms(cfg, 5000);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);
    TEST_ASSERT_NOT_NULL(c);

    /* A cookie sign-in: the jar now holds the session cookies and the CSRF token is armed. */
    axiam_login_result_t res;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login(c, "a", "b", &res, &err));
    axiam_login_result_dispose(&res);

    axiam_device_authorization_t da;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_device_authorize(c, NULL, NULL, &da, &err));
    axiam_device_authorization_dispose(&da);

    axiam_sensitive_t *code = axiam_sensitive_new("the-device-code");
    axiam_oidc_token_set_t set;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_device_poll(c, code, NULL, &set, &err));
    axiam_oidc_token_set_dispose(&set);
    axiam_sensitive_free(code);

    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_login_client_credentials(c, NULL, NULL, &set, &err));
    axiam_oidc_token_set_dispose(&set);

    /* The UMA ticket grant is POST /oauth2/token?tenant_id= and withholds the jar too. */
    axiam_sensitive_t *ticket = axiam_sensitive_new("ticket-value");
    axiam_sensitive_t *claim = axiam_sensitive_new("claim-token-value");
    axiam_sensitive_t *secret = axiam_sensitive_new("resource-server-secret");
    axiam_uma_exchange_params_t up = {ticket, claim, "orders-resource-server", secret, NULL};
    axiam_uma_rpt_t rpt;
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_uma_exchange_ticket(c, &up, &rpt, &err));
    axiam_uma_rpt_dispose(&rpt);
    axiam_sensitive_free(ticket);
    axiam_sensitive_free(claim);
    axiam_sensitive_free(secret);

    /* The control: a state-changing /api/v1 request does carry both. */
    TEST_ASSERT_EQUAL_INT(AXIAM_OK, axiam_logout(c, &err));

    int dev = find("POST /oauth2/device_authorization");
    int tok = find("POST /oauth2/token");
    TEST_ASSERT_TRUE(dev >= 0 && tok >= 0);
    assert_bare("POST /oauth2/device_authorization");
    assert_bare("POST /oauth2/token");
    int tokens = 0;
    for (int i = 0; i < g_srv.n; i++) {
        if (strncmp(g_srv.line[i], "POST /oauth2/token", 18) != 0) continue;
        tokens++;
        TEST_ASSERT_FALSE(g_srv.cookie[i]);
        TEST_ASSERT_FALSE(g_srv.csrf[i]);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(3, tokens, "the device poll, the client-credentials request and the UMA ticket grant");
    TEST_ASSERT_TRUE(find("POST /oauth2/token?tenant_id=") >= 0);
    int out = find("POST /api/v1/auth/logout");
    TEST_ASSERT_TRUE(out >= 0);
    TEST_ASSERT_TRUE_MESSAGE(g_srv.cookie[out], "the control carries the session cookie");
    TEST_ASSERT_TRUE_MESSAGE(g_srv.csrf[out], "the control carries the CSRF token");

    /* Stop the server thread. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *) &addr, sizeof addr) == 0) send_all(s, "STOP");
    close(s);
    pthread_join(th, NULL);
    close(fd);
    axiam_client_free(c);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_oauth2_requests_carry_no_session_cookie_and_no_csrf_header);
    return UNITY_END();
}
