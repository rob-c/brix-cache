/* Tape REST requests use real quoting, identity selection and locality parsing. */
#include "fs/backend/http/sd_http_internal.h"
#include <assert.h>

typedef struct {
    const char *mode, *body;
    int status, stage_status;
    unsigned requests, releases, certificates;
    int stage;
} fixture;
static int request(void *opaque, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, brix_s3_resp_t *response, char *error, size_t cap)
{
    fixture *f = opaque; (void) error; (void) cap;
    assert(!strcmp(host, "primary.invalid") && port == 443 && tls && timeout == 1000);
    assert(!strcmp(method, "POST") && length == strlen(body));
    assert(strstr(headers, "Content-Type: application/json"));
    const char *token = !strcmp(f->mode, "bearer") ? "caller-token" : "service-token";
    assert(strstr(headers, token));
    f->requests++; f->stage = strstr(path, "/stage") != NULL;
    printf("path=%s\nbody=%s\n", path, (const char *) body);
    int status = f->stage ? f->stage_status : f->status;
    if (status < 0) { errno = EIO; return -1; }
    response->status = status; response->opaque = f; return 0;
}
static int request_cred(void *opaque, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, const char *certificate, brix_s3_resp_t *response,
    char *error, size_t cap)
{
    fixture *f = opaque; assert(!strcmp(certificate, "caller.pem")); f->certificates++;
    return request(opaque, host, port, tls, method, path, headers, body, length, timeout, response, error, cap);
}
static const void *response_body(const brix_s3_resp_t *response, size_t *length)
{
    fixture *f = response->opaque;
    const char *body = f->stage ? "{\"requestId\":\"fixture-id\"}" : f->body;
    *length = strlen(body); return !strcmp(f->mode, "null-body") ? NULL : body;
}
static void response_free(brix_s3_resp_t *response)
{ fixture *f = response->opaque; f->releases++; }

int main(int argc, char **argv)
{
    assert(argc == 8); fixture f = {.mode = argv[2], .body = argv[3], .status = atoi(argv[4]), .stage_status = atoi(argv[5])};
    brix_s3_transport_t transport = {.request = request, .request_cred = request_cred,
        .resp_body = response_body, .resp_free = response_free};
    if (!strcmp(f.mode, "unsupported-cert")) { transport.request_cred = NULL; }
    brix_sd_http_ep_cfg_t secondary = {.host = "secondary.invalid", .port = 443, .tls = 1};
    brix_sd_http_cfg_t config = {.host = "primary.invalid", .port = 443, .tls = 1,
        .transport = &transport, .tctx = &f, .timeout_ms = 1000, .bearer_token = "service-token",
        .tape_api = argv[7], .extra = &secondary, .n_extra = 1};
    brix_sd_instance_t *inst = brix_sd_http_create(&config, NULL); assert(inst);
    brix_sd_residency_t residency = (brix_sd_residency_t) 99;
    char request_id[40] = "";
    brix_sd_cred_t cred = {.fallback_deny = 1};
    if (!strcmp(f.mode, "bearer")) { cred.bearer = "caller-token"; }
    if (!strcmp(f.mode, "proxy") || !strcmp(f.mode, "unsupported-cert")) { cred.x509_proxy = "caller.pem"; }
    ngx_int_t rc;
    if (!strcmp(argv[1], "residency")) {
        void *saved = inst->state;
        if (!strcmp(f.mode, "null-state")) { inst->state = NULL; }
        rc = sd_http_residency(!strcmp(f.mode, "null-instance") ? NULL : inst,
            !strcmp(f.mode, "null-key") ? NULL : argv[6], !strcmp(f.mode, "null-out") ? NULL : &residency);
        inst->state = saved;
    } else if (!strcmp(argv[1], "credential")) {
        rc = sd_http_recall_cred(inst, argv[6], &cred, request_id);
    } else { rc = sd_http_recall(inst, argv[6], !strcmp(f.mode, "null-id") ? NULL : request_id); }
    printf("rc=%ld\nerrno=%d\nresidency=%d\nrequest_id=%s\nrequests=%u\nreleases=%u\ncertificates=%u\n",
        (long) rc, errno, (int) residency, request_id, f.requests, f.releases, f.certificates);
    brix_sd_http_destroy(inst); return 0;
}
