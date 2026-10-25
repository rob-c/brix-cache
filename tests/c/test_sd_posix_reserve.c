/* Deterministic capacity/allocation seam for the real POSIX reserve slot. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "fs/backend/sd.h"

static struct statvfs capacity;
static struct stat allocation;
static int metadata_error;
static int allocation_error;
static int allocator_calls;

static int probe_statvfs(int fd, struct statvfs *out)
{
    assert(fd == 7);
    if (metadata_error) { errno = metadata_error; return -1; }
    *out = capacity;
    return 0;
}

static int probe_stat(int fd, struct stat *out)
{
    assert(fd == 7);
    *out = allocation;
    return 0;
}

#define fstatvfs probe_statvfs
#define fstat probe_stat
#include "fs/backend/posix/sd_posix_io.c"
#undef fstatvfs
#undef fstat

int brix_plat_reserve(int fd, off_t size)
{
    assert(fd == 7 && size > 0);
    allocator_calls++;
    errno = allocation_error;
    return allocation_error ? -1 : 0;
}

ssize_t brix_plat_pwrite_at(int fd, const void *buf, size_t len, off_t off,
    int append)
{
    (void)fd; (void)buf; (void)len; (void)off; (void)append;
    return -1;
}

ssize_t brix_plat_preadv2(int fd, const struct iovec *iov, int count,
    off_t off, int flags)
{
    (void)fd; (void)iov; (void)count; (void)off; (void)flags;
    return -1;
}

ssize_t brix_plat_copy_range(int in, off_t *ioff, int out, off_t *ooff,
    size_t len, unsigned flags)
{
    (void)in; (void)ioff; (void)out; (void)ooff; (void)len; (void)flags;
    return -1;
}

void sd_posix_fill_stat(const struct stat *st, brix_sd_stat_t *out)
{
    (void)st; (void)out;
}

int main(int argc, char **argv)
{
    brix_sd_obj_t object;
    off_t size = 8192;
    int wanted_errno = 0, wanted_calls = 1;

    assert(argc == 2);
    memset(&object, 0, sizeof(object));
    object.fd = 7;
    capacity.f_frsize = 4096;
    capacity.f_bsize = 4096;
    capacity.f_bavail = 2;
    if (strcmp(argv[1], "already-reserved") == 0) {
        allocation.st_blocks = 16; /* st_size stays zero: KEEP_SIZE reservation */
        capacity.f_bavail = 0;
    } else if (strcmp(argv[1], "fragment-fallback") == 0) {
        capacity.f_frsize = 0;
    } else if (strcmp(argv[1], "metadata-error") == 0) {
        metadata_error = EBADF; wanted_errno = EBADF; wanted_calls = 0;
    } else if (strcmp(argv[1], "allocator-quota") == 0) {
        allocation_error = EDQUOT; wanted_errno = EDQUOT;
    } else if (strcmp(argv[1], "zero-unit") == 0) {
        capacity.f_frsize = capacity.f_bsize = 0;
        wanted_errno = EIO; wanted_calls = 0;
    } else if (strcmp(argv[1], "oversized") == 0) {
        size = INT64_MAX; wanted_errno = ENOSPC; wanted_calls = 0;
    } else if (strcmp(argv[1], "round-up") == 0) {
        size++; wanted_errno = ENOSPC; wanted_calls = 0;
    } else if (strcmp(argv[1], "huge-capacity") == 0) {
        capacity.f_bavail = (fsblkcnt_t)-1;
    } else if (strcmp(argv[1], "huge-allocation") == 0) {
        allocation.st_blocks = INT64_MAX;
        capacity.f_bavail = 0;
    } else {
        assert(strcmp(argv[1], "fresh-fit") == 0);
    }
    errno = 0;
    assert(sd_posix_reserve(&object, size) == (wanted_errno ? NGX_ERROR : NGX_OK));
    assert(errno == wanted_errno);
    assert(allocator_calls == wanted_calls);
    return 0;
}
