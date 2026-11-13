/* Real multi-block truncation: re-encode transformed boundaries, remove tails,
 * and retain metadata/descriptor ownership when a storage operation fails. */
#include "fs/backend/pblock/sd_pblock_internal.h"
#include <assert.h>
#include <stdarg.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int armed, fd; } fixture_t;
static fixture_t *state(void) { return (fixture_t *)ngx_cycle; }
static int mode(const char *s) { return state() && state()->armed && !strcmp(state()->mode, s); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n)
{ if (mode("allocation")) { errno = ENOMEM; return NULL; } return __real_malloc(n); }
int __real_pblock_block_path(const pblock_state_t *, const char *, int64_t, char *, size_t);
int __wrap_pblock_block_path(const pblock_state_t *st, const char *id, int64_t b, char *out, size_t cap)
{ if (mode("path")) { errno = ENAMETOOLONG; return -1; } return __real_pblock_block_path(st, id, b, out, cap); }
int __real_ftruncate64(int, off_t);
int __wrap_ftruncate64(int fd, off_t n)
{ if (mode("truncate")) { state()->fd = fd; errno = ENOSPC; return -1; } return __real_ftruncate64(fd, n); }
int __real_open64(const char *, int, ...);
int __wrap_open64(const char *path, int flags, ...)
{
    mode_t permissions = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); permissions = va_arg(args, int); va_end(args); }
    if (mode("open")) { errno = EACCES; return -1; }
    return __real_open64(path, flags, permissions);
}

int main(int argc, char **argv)
{
    assert(argc == 5); fixture_t f = {0}; f.mode = argv[2]; f.fd = -1; ngx_cycle = &f.cycle;
    brix_sd_instance_t inst = {.driver = &brix_sd_pblock_driver}; inst.caps = inst.driver->caps;
    brix_sd_pblock_conf_t conf = {.root = argv[1], .block_size = 4096, .busy_timeout_ms = 1000};
    const brix_sd_driver_t *d = inst.driver; assert(d->init(&inst, &conf) == NGX_OK);
    unsigned char bytes[10000], actual[10000];
    for (size_t i = 0; i < sizeof(bytes); i++) { bytes[i] = (unsigned char)(i % 251); }
    brix_sd_obj_t *obj = d->open(&inst, "/file", BRIX_SD_O_READ | BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0600, NULL);
    assert(obj && d->pwrite(obj, bytes, sizeof(bytes), 0) == sizeof(bytes));
    assert(d->fsync(obj) == NGX_OK); off_t length = atol(argv[3]); int expected = atoi(argv[4]);
    f.armed = 1; int rc = d->ftruncate(obj, length), error = errno; f.armed = 0;
    assert(rc == (expected ? NGX_ERROR : NGX_OK));
    if (expected) { assert(error == expected); }
    brix_sd_stat_t sb; assert(d->fstat(obj, &sb) == NGX_OK);
    assert(sb.size == (expected ? (off_t)sizeof(bytes) : length));
    if (f.fd >= 0 && length > 4096) { assert(fcntl(f.fd, F_GETFD) == -1 && errno == EBADF); }
    ssize_t n = d->pread(obj, actual, sizeof(actual), 0);
    assert(n == sb.size && !memcmp(bytes, actual, n));
    assert(d->fsync(obj) == NGX_OK); brix_sd_obj_release(obj);
    obj = d->open(&inst, "/file", BRIX_SD_O_READ, 0, NULL); assert(obj);
    assert(d->pread(obj, actual, sizeof(actual), 0) == n && !memcmp(bytes, actual, n));
    brix_sd_obj_release(obj); d->cleanup(&inst); ngx_cycle = NULL; return 0;
}
