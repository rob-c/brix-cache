/* Signed batch-delete request and response-integrity contracts at transport. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/s3/sd_s3.h"
#include "core/compat/crypto.h"
#include "native_alloc_fail.h"

typedef struct { const char *body, *mode; int status, calls, freed; } fixture;

static int request(void *context, const char *host, int port, int tls,
    const char *method, const char *path, const char *headers, const void *body,
    size_t length, int timeout, brix_s3_resp_t *response, char *error, size_t capacity) {
    fixture *f = context;
    (void) error; (void) capacity;
    assert(!strcmp(host, "storage.test") && port == 443 && tls && timeout == 1000);
    assert(!strcmp(method, "POST") && !strcmp(path, "/bucket?delete"));
    printf("REQUEST %s %s\n%s\nBODY %.*s\n", method, path, headers, (int) length, (const char *) body);
    f->calls++;
    if (f->status < 0) { errno = f->status == -2 ? EACCES : 0; return -1; }
    response->status = f->status; response->opaque = f; return 0;
}
static const void *response_body(const brix_s3_resp_t *response, size_t *length) {
    fixture *f = response->opaque; *length = strlen(f->body);
    return !strcmp(f->mode, "null-body") ? NULL : f->body;
}
static void release(brix_s3_resp_t *response) { ((fixture *) response->opaque)->freed++; }

int main(int argc, char **argv) {
    assert(argc >= 6);
    fixture f = {.mode = argv[1], .status = atoi(argv[2]), .body = argv[3]};
    brix_s3_transport_t transport = {.request = request, .resp_body = response_body, .resp_free = release};
    sd_s3_open_params parameters = {.host = "storage.test", .port = 443, .tls = 1,
        .key = "/bucket", .ak = "test-access", .sk = "test-secret", .region = "test-1",
        .session_token = strcmp(argv[4], "none") ? argv[4] : NULL,
        .transport = &transport, .tctx = &f, .timeout_ms = 1000};
    size_t n = (size_t) argc - 5;
    if (!strcmp(f.mode, "zero")) { n = 0; }
    int *errors = malloc((n + 1) * sizeof(*errors)); assert(errors);
    for (size_t i = 0; i <= n; i++) { errors[i] = 777; }
    assert(brix_crypto_init());
    if (!strcmp(f.mode, "malloc")) { native_alloc_arm("malloc", 0); }
    if (!strcmp(f.mode, "calloc")) { native_alloc_arm("calloc", 0); }
    size_t done = 987; char error[512] = {0}; errno = 0;
    int rc = sd_s3_delete_many(&parameters, (const char *const *) argv + 5,
        n, errors, &done, error, sizeof(error));
    int saved_errno = errno; native_alloc_disarm();
    printf("RESULT rc=%d errno=%d done=%zu calls=%d freed=%d errors=", rc, saved_errno,
           done, f.calls, f.freed);
    for (size_t i = 0; i < n; i++) { printf("%s%d", i ? "," : "", errors[i]); }
    puts(""); assert(errors[n] == 777);
    free(errors); brix_crypto_cleanup(); return 0;
}
