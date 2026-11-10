/* Download framing uses bounded streaming and preserves partial output on error. */
#include "protocols/http/http_internal.h"
#include <assert.h>
#include <fcntl.h>

typedef struct {
    unsigned char *wire;
    size_t length, offset, chunk;
    int fail_read, fail_send;
    long long resume;
} fixture;

/* WHAT: Deliver bounded response fragments. WHY: Exercise all buffer boundaries.
 * HOW: Read from caller-owned wire data or inject one selected transport fault. */
ssize_t __wrap_httpx_read_some(brix_io *io, void *out, size_t cap,
    int timeout, brix_status *status)
{
    fixture *f = (fixture *) io->ssl; assert(timeout == 1000);
    if (f->fail_read) {
        brix_status_set(status, XRDC_ESOCK, EIO, "fixture read failed"); return -1;
    }
    size_t n = f->length - f->offset;
    if (n > cap) { n = cap; }
    if (n > f->chunk) { n = f->chunk; }
    memcpy(out, f->wire + f->offset, n); f->offset += n; return (ssize_t) n;
}

/* WHAT: Observe one GET request. WHY: Pin resume and extra-header construction.
 * HOW: Require exact method/authority and the selected Range before response I/O. */
int __wrap_brix_write_full(brix_io *io, const void *data, size_t size, brix_status *status)
{
    fixture *f = (fixture *) io->ssl; const char *text = data;
    assert(size == strlen(text) && strstr(text, "GET /data HTTP/1.1\r\n"));
    assert(strstr(text, "Host: origin.invalid:1234\r\n"));
    assert(strstr(text, "X-Contract: yes\r\n"));
    assert((strstr(text, "Range: bytes=5-\r\n") != NULL) == (f->resume > 0));
    if (f->fail_send) {
        brix_status_set(status, XRDC_ESOCK, EPIPE, "fixture send failed"); return -1;
    }
    return 0;
}

/* WHAT: Execute the real download exchange. WHY: Verify byte and error outcomes.
 * HOW: Load an isolated response, stream into a real file, and report the result. */
int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0};
    f.chunk = (size_t) atol(argv[4]); assert(f.chunk > 0); f.resume = atoll(argv[5]);
    f.fail_read = !strcmp(argv[3], "read-error"); f.fail_send = !strcmp(argv[3], "send-error");
    FILE *input = fopen(argv[1], "rb"); assert(input);
    assert(fseek(input, 0, SEEK_END) == 0); long size = ftell(input); assert(size >= 0);
    rewind(input); f.length = (size_t) size; f.wire = malloc(f.length + 1); assert(f.wire);
    assert(fread(f.wire, 1, f.length, input) == f.length); fclose(input);
    int output = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0600); assert(output >= 0);
    int fd = !strcmp(argv[3], "write-error") ? -1 : output;
    brix_io io = {.fd = -1, .ssl = (struct ssl_st *) &f}; brix_status status;
    brix_status_clear(&status); int http = 0; long long length = 0;
    const char *path = !strcmp(argv[3], "long-request") ? argv[6] : "/data";
    int rc = httpx_download_exchange(&io, "origin.invalid", 1234, path,
        "X-Contract: yes\r\n", f.resume, fd, 1000, &http, &length, &status);
    printf("%d %d %lld\n%s\n", rc, http, length, status.msg);
    assert(close(output) == 0); free(f.wire); return 0;
}
