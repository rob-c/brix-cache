/* HTTP staged ownership and atomic publish policy over an observed transport. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"
#include "native_alloc_fail.h"

typedef struct {
    int status, probe, calls, releases, certs, deletes, puts;
    const char *mode;
} fixture;

static int request(void *context, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, brix_s3_resp_t *response, char *error, size_t capacity) {
    fixture *f = context;
    (void) timeout; (void) error; (void) capacity;
    assert(strcmp(host, "primary.test") == 0 && port == 443 && tls);
    f->calls++;
    printf("REQUEST %s %s\n%s", method, path, headers ? headers : "");
    if (strcmp(method, "DELETE") == 0) { f->deletes++; }
    else if (strstr(path, ".brix-cond-probe") == NULL) {
        assert(strcmp(path, "/base/object") == 0);
        f->puts++;
        if (strcmp(f->mode, "grow") == 0) { assert(length == 3 * 1024 * 1024); }
        else { assert(length == 3 && memcmp(body, "abc", 3) == 0); }
    }
    int status = strstr(path, ".brix-cond-probe") ? f->probe : f->status;
    if (status < 0) { return -1; }
    response->status = status; response->opaque = f;
    return 0;
}
static int request_cred(void *context, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, const char *cert, brix_s3_resp_t *response,
    char *error, size_t capacity) {
    fixture *f = context;
    assert(strcmp(cert, "caller.pem") == 0); f->certs++;
    return request(context, host, port, tls, method, path, headers, body, length,
                   timeout, response, error, capacity);
}
static void release(brix_s3_resp_t *response) {
    fixture *f = response->opaque; f->releases++;
}

static brix_sd_staged_t *open_staged(brix_sd_instance_t *inst, const char *mode,
    const char *identity, int *error) {
    brix_sd_cred_t cred = {0};
    char token[] = "caller-token", proxy[] = "caller.pem";
    cred.fallback_deny = 1;
    if (strcmp(identity, "bearer") == 0 || strcmp(identity, "both") == 0) { cred.bearer = token; }
    if (strcmp(identity, "proxy") == 0 || strcmp(identity, "both") == 0) { cred.x509_proxy = proxy; }
    off_t declared = strcmp(mode, "oversize") == 0 ? (1LL << 30) + 1 : -1;
    if (strncmp(mode, "calloc", 6) == 0) { native_alloc_arm("calloc", (unsigned) atoi(mode+6)); }
    brix_sd_staged_t *h = strcmp(identity, "service") == 0
        ? inst->driver->staged_open(inst, "/object", 0644, declared, error)
        : inst->driver->staged_open_cred(inst, "/object", 0644, declared, &cred, error);
    native_alloc_disarm();
    memset(token, 'x', sizeof(token)-1); memset(proxy, 'x', sizeof(proxy)-1);
    return h;
}
static int fill_staged(brix_sd_instance_t *inst, brix_sd_staged_t *h, const char *mode) {
    if (strcmp(mode, "realloc") == 0) { native_alloc_arm("realloc", 0); }
    size_t length = strcmp(mode, "write-cap") == 0 ? (1ULL << 30) + 1 : 3;
    off_t offset = strcmp(mode, "offset") == 0 ? 1 : 0;
    ssize_t written = inst->driver->staged_write(h, "abc", length, offset);
    native_alloc_disarm();
    if (written < 0) { return -1; }
    if (strcmp(mode, "grow") == 0) {
        size_t extra = 3 * 1024 * 1024 - 3;
        char *body = calloc(1, extra); assert(body);
        written = inst->driver->staged_write(h, body, extra, 3);
        free(body); assert(written == (ssize_t) extra);
    }
    return 0;
}
static brix_sd_precond_t condition(const char *kind) {
    brix_sd_precond_t pre = {0};
    if (strcmp(kind, "absent") == 0) { pre.kind = BRIX_SD_PRECOND_ABSENT; }
    if (strcmp(kind, "meta") == 0) { pre.kind = BRIX_SD_PRECOND_MATCH_META; }
    if (strncmp(kind, "etag", 4) == 0) {
        pre.kind = BRIX_SD_PRECOND_MATCH_ETAG;
        pre.etag = "\"original\""; pre.etag_len = strlen(pre.etag);
        if (strcmp(kind, "etag-empty") == 0) { pre.etag_len = 0; }
        if (strcmp(kind, "etag-long") == 0) { pre.etag_len = 200; }
        if (strcmp(kind, "etag-null") == 0) { pre.etag = NULL; }
    }
    return pre;
}
static int commit_one(brix_sd_instance_t *inst, fixture *f, const char *identity,
    const char *kind, int expected) {
    int error = 0;
    brix_sd_precond_t pre = condition(kind);
    brix_sd_staged_t *h = open_staged(inst, f->mode, identity, &error);
    if (!h) { assert(error == expected); return -1; }
    if (fill_staged(inst, h, f->mode) != 0) {
        assert(errno == expected); inst->driver->staged_abort(h); return -1;
    }
    errno = 0;
    int rc = inst->driver->staged_commit(h, strcmp(kind, "null") == 0 ? NULL : &pre);
    if (rc != 0) { assert(errno == expected); inst->driver->staged_abort(h); }
    else { assert(expected == 0); }
    printf("VERDICT %d atomic=%d\n", rc, pre.atomic);
    return rc;
}
int main(int argc, char **argv) {
    assert(argc == 8); ngx_os_argv = argv;
    fixture f = {.status=atoi(argv[1]), .probe=atoi(argv[2]), .mode=argv[3]};
    brix_s3_transport_t transport = {.request=request, .resp_free=release};
    if (atoi(argv[7])) { transport.request_cred = request_cred; }
    brix_sd_http_ep_cfg_t secondary = {.host="secondary.test", .port=443, .tls=1};
    brix_sd_http_cfg_t cfg = {.host="primary.test", .port=443, .tls=1, .base_path="/base",
        .transport=&transport, .tctx=&f, .timeout_ms=1000, .bearer_token="service-token",
        .put_checksum=1, .extra=&secondary, .n_extra=1};
    brix_sd_instance_t *inst = brix_sd_http_create(&cfg, NULL); assert(inst);
    int expected = atoi(argv[6]);
    int rc = commit_one(inst, &f, argv[4], argv[5], expected);
    assert((rc == 0) == (expected == 0));
    if (strcmp(f.mode, "twice") == 0) { commit_one(inst, &f, argv[4], argv[5], expected); }
    printf("COUNTS calls=%d freed=%d certs=%d puts=%d deletes=%d\n",
           f.calls, f.releases, f.certs, f.puts, f.deletes);
    brix_sd_http_destroy(inst);
    return 0;
}
