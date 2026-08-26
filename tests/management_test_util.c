/* Implementation of the §27 test rig -- see management_test_util.h. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "management_test_util.h"

typedef struct {
    long status;
    char *body;
} canned_t;

static canned_t g_queue[4];
static size_t g_queued;
static size_t g_served;

static int g_count;
static char g_method[16];
static char g_url[512];
static char g_path[512];
static char g_body[4096];

static void queue_push(long status, const char *body) {
    if (g_queued >= sizeof g_queue / sizeof g_queue[0]) return;
    g_queue[g_queued].status = status;
    g_queue[g_queued].body = body ? strdup(body) : NULL;
    g_queued++;
}

void mgmt_reset(void) {
    for (size_t i = 0; i < g_queued; i++) free(g_queue[i].body);
    memset(g_queue, 0, sizeof g_queue);
    g_queued = 0;
    g_served = 0;
    g_count = 0;
    g_method[0] = '\0';
    g_url[0] = '\0';
    g_path[0] = '\0';
    g_body[0] = '\0';
}

void mgmt_mount(long status, const char *body) {
    /* The login response comes first and is queued by the client factory below; this is
     * the management response that follows it. */
    queue_push(status, body);
}

void mgmt_mount_next(long status, const char *body) { queue_push(status, body); }

/* Split "https://host/a/b?x=1" into the path part, which is what a route assertion
 * cares about -- the host is the fixture's and the query has its own accessor. */
static void record_path(const char *url) {
    g_path[0] = '\0';
    if (!url) return;
    const char *p = strstr(url, "://");
    p = p ? strchr(p + 3, '/') : strchr(url, '/');
    if (!p) return;
    size_t n = strcspn(p, "?");
    if (n >= sizeof g_path) n = sizeof g_path - 1;
    memcpy(g_path, p, n);
    g_path[n] = '\0';
}

static int fake_transport(void *ctx, const axiam_http_request_t *req,
                          axiam_http_response_t *resp) {
    (void) ctx;
    g_count++;
    snprintf(g_method, sizeof g_method, "%s", req->method ? req->method : "");
    snprintf(g_url, sizeof g_url, "%s", req->url ? req->url : "");
    snprintf(g_body, sizeof g_body, "%s", req->body ? req->body : "");
    record_path(req->url);

    memset(resp, 0, sizeof *resp);
    if (g_served < g_queued) {
        resp->status = g_queue[g_served].status;
        if (g_queue[g_served].body) resp->body = strdup(g_queue[g_served].body);
        g_served++;
    } else {
        resp->status = 204;
    }
    return 0;
}

static axiam_client_t *make_client(int sign_in) {
    axiam_client_config_t *cfg = axiam_client_config_new();
    axiam_client_config_set_base_url(cfg, "https://iam.example.com/");
    axiam_client_config_set_tenant_id(cfg, "11111111-1111-4111-8111-111111111111");
    axiam_client_config_set_org_id(cfg, "11111111-1111-4111-8111-111111111111");
    axiam_client_config_set_transport(cfg, fake_transport, NULL);
    axiam_error_t err;
    axiam_client_t *c = axiam_client_new(cfg, &err);
    axiam_client_config_free(cfg);

    if (c && sign_in) {
        /* The login consumes one queued response; shift the mounted ones behind it. */
        for (size_t i = g_queued; i > 0; i--) g_queue[i] = g_queue[i - 1];
        g_queue[0].status = 200;
        g_queue[0].body = strdup("{\"authenticated\":true,\"mfa_required\":false}");
        g_queued++;

        axiam_login_result_t res;
        axiam_login(c, "admin@example.com", "pw", &res, &err);
        axiam_login_result_dispose(&res);
    }
    return c;
}

axiam_client_t *mgmt_signed_in_client(void) { return make_client(1); }
axiam_client_t *mgmt_anonymous_client(void) { return make_client(0); }

const char *mgmt_last_method(void) { return g_method; }
const char *mgmt_last_path(void) { return g_path; }
const char *mgmt_last_url(void) { return g_url; }
const char *mgmt_last_body(void) { return g_body; }
int mgmt_request_count(void) { return g_count; }
