/* Real CVMFS trust verification over owned files and finite source failures. */
#include "fs/backend/cache/sd_cache_internal.h"
#include <assert.h>
#include <stdarg.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode, *web, *part;
    brix_sd_obj_t object;
    unsigned calls, opens, closes, allocations;
    int part_fd, interrupted;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Inject bounded allocation and staged-file read failures.
 * WHY: An incomplete trust chain must never be treated as verified content.
 * HOW: Keep other operations real and consume EINTR exactly once. */
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    fixture *f = state();
    if (f && size == 65536) {
        f->allocations++;
        if (!strncmp(f->mode, "malloc-", 7) && f->allocations == (unsigned) atoi(f->mode + 7)) { return NULL; }
    }
    return __real_malloc(size);
}
int __real_open64(const char *, int, ...);
int __wrap_open64(const char *path, int flags, ...)
{
    mode_t permissions = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); permissions = va_arg(args, int); va_end(args); }
    int fd = __real_open64(path, flags, permissions);
    if (state() && !strcmp(path, state()->part)) { state()->part_fd = fd; }
    return fd;
}
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *bytes, size_t size)
{
    if (fd == state()->part_fd) {
        if (mode("part-read")) { errno = EIO; return -1; }
        if (mode("part-eintr") && !state()->interrupted++) { errno = EINTR; return -1; }
    }
    return __real_read(fd, bytes, size);
}

/* WHAT: Fetch trust siblings from the real signed repository.
 * WHY: Cryptography and parsing stay real while source transport may fail.
 * HOW: Translate fixture keys and count descriptor ownership around reads. */
static brix_sd_obj_t *source_open(brix_sd_instance_t *inst, const char *key,
    int flags, mode_t permissions, int *error)
{
    fixture *f = state(); f->calls++;
    assert(flags == BRIX_SD_O_READ && permissions == 0 && !strncmp(key, "/cvmfs/test.cern.ch/", 19));
    if ((mode("source-open") && f->calls == 1) || (mode("cert-open") && f->calls == 2)) {
        *error = EIO; return NULL;
    }
    char path[PATH_MAX]; assert(snprintf(path, sizeof(path), "%s%s", f->web, key) < PATH_MAX);
    int fd = open(path, O_RDONLY); if (fd < 0) { *error = errno; return NULL; }
    assert(f->opens == f->closes); f->opens++;
    f->object = (brix_sd_obj_t) {.driver = inst->driver, .inst = inst, .fd = fd};
    return &f->object;
}
static ssize_t source_read(brix_sd_obj_t *object, void *bytes, size_t size, off_t offset)
{
    assert(object == &state()->object);
    if (mode("source-read")) { errno = EIO; return -1; }
    if (mode("source-eintr") && !state()->interrupted++) { errno = EINTR; return -1; }
    return pread(object->fd, bytes, size, offset);
}
static ngx_int_t source_close(brix_sd_obj_t *object)
{
    assert(object == &state()->object && object->fd >= 0);
    assert(!close(object->fd)); object->fd = -1; state()->closes++; return NGX_OK;
}

int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0}; f.web = argv[1]; f.part = argv[3]; f.mode = argv[5];
    f.part_fd = -1; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file}; f.cycle.log = &log; ngx_time_init();
    unsigned char master[8192]; FILE *pub = fopen(argv[2], "rb"); assert(pub);
    size_t length = fread(master, 1, sizeof(master), pub); assert(length > 0 && length < sizeof(master));
    assert(!fclose(pub));
    brix_sd_driver_t driver = {.open = source_open, .pread = source_read, .close = source_close};
    brix_sd_instance_t source = {.driver = &driver, .log = &log};
    sd_cache_inst_state cache = {.source = &source, .log = &log};
    cache.policy.cvmfs_master_pub = master; cache.policy.cvmfs_master_pub_len = length;
    if (mode("disabled")) { cache.policy.cvmfs_master_pub = NULL; }
    if (mode("source-null")) { cache.source = NULL; }
    if (mode("source-no-open")) { driver.open = NULL; }
    if (mode("source-no-read")) { driver.pread = NULL; }
    ngx_int_t rc = sd_cache_verify_manifest(&cache, argv[4], mode("part-null") ? NULL : f.part);
    assert(rc == atoi(argv[6])); assert(f.opens == f.closes);
    if (f.part_fd >= 0) { assert(fcntl(f.part_fd, F_GETFD) == -1 && errno == EBADF); }
    printf("result=%ld calls=%u opens=%u closes=%u\n", (long) rc, f.calls, f.opens, f.closes);
    ngx_cycle = NULL; return 0;
}
