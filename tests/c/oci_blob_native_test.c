/* Blob verification and redirect policy with finite HTTP transport replies. */
#include "oci/reg_internal.h"
#include "oci/digest.h"
#include "protocols/http/http_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int mode(const char *name) { return !strcmp(getenv("BRIX_BLOB_CASE"), name); }
static int number(const char *key) { const char *v = getenv(key); return v ? atoi(v) : 0; }
static void value(const char *key, int n)
{ char text[32]; snprintf(text, sizeof(text), "%d", n); assert(!setenv(key, text, 1)); }

/* WHAT: Open one observable transport descriptor.
 * WHY: Every early return must close its owned hop, including TLS failures.
 * HOW: Supply a harmless real descriptor while retaining the actual GET builder. */
int __wrap_httpx_connect(brix_io *io, const char *host, int port, int tls,
    int verify, const char *ca, const char *cert, int timeout, void **ctx, brix_status *st)
{
    (void) verify; (void) ca; (void) cert; (void) timeout;
    assert(port == 443 && (!strcmp(host, "registry.test") || !strcmp(host, "cdn.test")));
    value("BRIX_BLOB_HOPS", number("BRIX_BLOB_HOPS") + 1);
    if (mode("connect")) { brix_status_set(st, XRDC_ESOCK, EIO, "fixture connect"); return -1; }
    memset(io, 0, sizeof(*io)); io->fd = open("/dev/null", O_RDONLY); assert(io->fd >= 0);
    value("BRIX_BLOB_LAST_FD", io->fd); value("BRIX_BLOB_ORIGIN", !strcmp(host, "registry.test"));
    *ctx = tls ? io : NULL; return 0;
}
void __wrap_brix_tls_client_free(brix_io *io, void *ctx)
{ assert(ctx == io); value("BRIX_BLOB_TLS_CLOSE", number("BRIX_BLOB_TLS_CLOSE") + 1); }

int __wrap_brix_write_full(brix_io *io, const void *bytes, size_t size, brix_status *st)
{
    assert(io->fd >= 0 && size == strlen(bytes));
    assert(!strncmp(bytes, "GET /", 5) && strstr(bytes, "Connection: close\r\n"));
    assert((strstr(bytes, "Authorization: Bearer fixture-secret") != NULL) == number("BRIX_BLOB_ORIGIN"));
    if (mode("send")) { brix_status_set(st, XRDC_ESOCK, EIO, "fixture send"); return -1; }
    if (mode("allocation")) { value("BRIX_BLOB_ALLOC", 1); }
    return 0;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    if (number("BRIX_BLOB_ALLOC") && size == XRDC_HDR_CAP) { value("BRIX_BLOB_ALLOC", 0); return NULL; }
    return __real_malloc(size);
}

/* WHAT: Supply a response at the header-reader boundary.
 * WHY: The real blob state machine must bound redirects and authentication.
 * HOW: Emit exact owned header bytes for one selected origin or CDN response. */
int __wrap_read_resp_headers(brix_io *io, char *hdr, size_t cap, int timeout,
    int *status, size_t *total, size_t *body, brix_status *st)
{
    (void) timeout; assert(io->fd >= 0); const char *extra = ""; *status = 200;
    if (mode("headers")) { brix_status_set(st, XRDC_ESOCK, EIO, "fixture headers"); return -1; }
    if (mode("status")) { *status = 503; }
    if (mode("no-challenge") || mode("auth") || mode("auth-error")) {
        if (number("BRIX_BLOB_HOPS") == 1) {
            *status = 401;
            if (!mode("no-challenge")) { extra = "WWW-Authenticate: Bearer realm=\"https://registry.test/token\"\r\n"; }
        }
    }
    if (mode("redirect") && number("BRIX_BLOB_HOPS") == 1) {
        *status = 302; extra = "Location: https://cdn.test:443/data\r\n";
    }
    if (mode("loop")) { *status = 307; extra = "Location: /again\r\n"; }
    if (mode("no-location")) { *status = 302; }
    if (mode("bad-location")) { *status = 302; extra = "Location: ftp://cdn.test/data\r\n"; }
    if (mode("downgrade")) { *status = 302; extra = "Location: http://cdn.test:443/data\r\n"; }
    int n = snprintf(hdr, cap, "HTTP/1.1 %d Fixture\r\n%sContent-Length: 7\r\n\r\n", *status, extra);
    assert(n > 0 && (size_t) n < cap); *total = *body = (size_t) n; return 0;
}
int __wrap_regc_token_dance(brix_oci_reg_t *registry, const char *challenge,
    const char *scope, char *error, size_t cap)
{
    assert(!strcmp(registry->host, "registry.test") && strstr(challenge, "https://registry.test/token"));
    assert(!strcmp(scope, "repository:lab/app:pull"));
    value("BRIX_BLOB_DANCES", number("BRIX_BLOB_DANCES") + 1);
    if (mode("auth-error")) { snprintf(error, cap, "fixture token refusal"); return BRIX_OCI_REG_EAUTH; }
    return BRIX_OCI_REG_OK;
}
int __wrap_httpx_download_body(brix_io *io, char *hdr, size_t total, size_t body,
    int fd, int timeout, long long *length, brix_status *st)
{
    (void) timeout; assert(io->fd >= 0 && hdr && total == body);
    if (mode("body")) { brix_status_set(st, XRDC_ESOCK, EIO, "fixture body"); return -1; }
    assert(write(fd, "payload", 7) == 7); *length = 7; return 0;
}

/* WHAT: Fail only the caller-owned staging descriptor or digest operation.
 * WHY: Transport success cannot hide a failed read-back integrity check.
 * HOW: Keep real file bytes and real OpenSSL hashing for every other step. */
off_t __real_lseek(int, off_t, int);
off_t __wrap_lseek(int fd, off_t offset, int whence)
{ if (mode("seek") && fd == number("BRIX_BLOB_OUTPUT")) { errno = ESPIPE; return -1; } return __real_lseek(fd, offset, whence); }
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *bytes, size_t size)
{ if (mode("read") && fd == number("BRIX_BLOB_OUTPUT")) { errno = EIO; return -1; } return __real_read(fd, bytes, size); }
int __real_ftruncate(int, off_t);
int __wrap_ftruncate(int fd, off_t length)
{ if (mode("truncate") && fd == number("BRIX_BLOB_OUTPUT")) { errno = EIO; return -1; } return __real_ftruncate(fd, length); }
int __real_brix_oci_hash_init(brix_oci_hash_ctx_t *, brix_oci_alg_t);
int __wrap_brix_oci_hash_init(brix_oci_hash_ctx_t *ctx, brix_oci_alg_t alg)
{ return mode("hash-init") ? -1 : __real_brix_oci_hash_init(ctx, alg); }
int __real_brix_oci_hash_update(brix_oci_hash_ctx_t *, const void *, size_t);
int __wrap_brix_oci_hash_update(brix_oci_hash_ctx_t *ctx, const void *bytes, size_t size)
{ return mode("hash-update") ? -1 : __real_brix_oci_hash_update(ctx, bytes, size); }
int __real_brix_oci_hash_final(brix_oci_hash_ctx_t *, brix_oci_digest_t *);
int __wrap_brix_oci_hash_final(brix_oci_hash_ctx_t *ctx, brix_oci_digest_t *out)
{
    if (mode("hash-final")) { brix_oci_hash_abort(ctx); return -1; }
    return __real_brix_oci_hash_final(ctx, out);
}

int main(int argc, char **argv)
{
    assert(argc == 6); assert(!setenv("BRIX_BLOB_CASE", argv[1], 1));
    int fd = open(argv[2], O_CREAT | O_EXCL | O_RDWR, 0600); assert(fd >= 0);
    value("BRIX_BLOB_OUTPUT", fd); value("BRIX_BLOB_LAST_FD", -1);
    brix_oci_reg_t r = {0}; strcpy(r.host, "registry.test"); r.port = 443; r.verify = 1;
    strcpy(r.bearer, "fixture-secret"); char error[512] = {0}, name[600];
    memset(name, 'a', sizeof(name)); name[sizeof(name) - 1] = 0;
    int rc = brix_oci_reg_blob_fetch(&r, mode("name") ? name : "lab/app", argv[3], fd, error, sizeof(error));
    assert(rc == atoi(argv[4])); if (rc) { assert(error[0]); }
    int transport = number("BRIX_BLOB_LAST_FD");
    if (transport >= 0) { assert(fcntl(transport, F_GETFD) == -1 && errno == EBADF); }
    assert(fcntl(fd, F_GETFD) >= 0); assert(!close(fd));
    assert(number("BRIX_BLOB_HOPS") == atoi(argv[5]));
    assert(number("BRIX_BLOB_TLS_CLOSE") == atoi(argv[5]) - mode("connect"));
    if (mode("auth") || mode("auth-error")) { assert(number("BRIX_BLOB_DANCES") == 1); }
    printf("result=%d error=%s\n", rc, error); return 0;
}
