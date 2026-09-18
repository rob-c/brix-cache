/*
 * client/lib/platform/linux/preload_lfs.c - the glibc-only entry points
 *
 * WHAT: The LFS *64 spellings (open64, stat64, readdir64, fopen64, ...) and
 *       statx, forwarded to the shim's portable wrappers.
 * WHY:  Tools built with _FILE_OFFSET_BITS=64 (coreutils, python) call the
 *       *64 names, and modern coreutils (ls, stat, find, du) call statx; left
 *       uninterposed they would stat the real (absent) local path and
 *       ENOENT. None of these names exists on Darwin, which is why this
 *       is a host file rather than part of the portable shim.
 * HOW:  Each forwarder calls the wrapper by its libc name, which under
 *       LD_PRELOAD is the shim's own definition. On LP64 glibc the *64
 *       structures are layout-identical to the plain ones (asserted), so the
 *       forward is a cast, not a copy.
 */

#include "platform/preload.h"

#if BRIX_PLATFORM_LINUX

#include "brixposix_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(struct stat) == sizeof(struct stat64),
               "struct stat / stat64 layout differ; *64 stat forwards need rework");
_Static_assert(sizeof(struct dirent) == sizeof(struct dirent64)
               && offsetof(struct dirent, d_name) == offsetof(struct dirent64, d_name),
               "struct dirent / dirent64 layout differ; readdir64 forward needs rework");

static mode_t
open_mode(int flags, va_list ap)
{
    return (flags & O_CREAT) ? (mode_t) va_arg(ap, int) : 0;
}

int
open64(const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;

    va_start(ap, flags);
    mode = open_mode(flags, ap);
    va_end(ap);
    return open(path, flags, mode);
}

int
openat64(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;

    va_start(ap, flags);
    mode = open_mode(flags, ap);
    va_end(ap);
    return openat(dirfd, path, flags, mode);
}

ssize_t
pread64(int fd, void *buf, size_t count, off_t offset)
{
    return pread(fd, buf, count, offset); /* vfs-seam-allow: SEAM_CORRECT - LFS forward onto the shim's own wrapper */
}

ssize_t
pwrite64(int fd, const void *buf, size_t count, off_t offset)
{
    return pwrite(fd, buf, count, offset); /* vfs-seam-allow: SEAM_CORRECT - LFS forward onto the shim's own wrapper */
}

off_t
lseek64(int fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

int
stat64(const char *path, struct stat64 *stbuf)
{
    return stat(path, (struct stat *) stbuf);
}

int
lstat64(const char *path, struct stat64 *stbuf)
{
    return lstat(path, (struct stat *) stbuf);
}

int
fstat64(int fd, struct stat64 *stbuf)
{
    return fstat(fd, (struct stat *) stbuf);
}

int
fstatat64(int dirfd, const char *path, struct stat64 *stbuf, int flags)
{
    return fstatat(dirfd, path, (struct stat *) stbuf, flags);
}

struct dirent64 *
readdir64(DIR *dirp)
{
    return (struct dirent64 *) readdir(dirp);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int
readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result)
{
    return readdir_r(dirp, (struct dirent *) entry, (struct dirent **) result);
}
#pragma GCC diagnostic pop

FILE *
fopen64(const char *path, const char *mode)
{
    return fopen(path, mode);
}

FILE *
freopen64(const char *path, const char *mode, FILE *stream)
{
    return freopen(path, mode, stream);
}

/*
 * statx() answers the common fields (type/mode/nlink/size/times/ino) for a
 * remote path from the shim's own stat(), so statx and stat can never
 * disagree; the caller's `mask` is satisfied for what XRootD can report.
 */
int
statx(int dirfd, const char *path, int flags, unsigned int mask,
      struct statx *stxbuf)
{
    char        remote[XRDC_PATH_MAX];
    struct stat mapped;
    REAL(statx);

    if (path[0] != '/' || !map_path(path, remote, sizeof(remote))) {
        return real_statx(dirfd, path, flags, mask, stxbuf);
    }
    if (stat(path, &mapped) != 0) {
        return -1;
    }
    memset(stxbuf, 0, sizeof(*stxbuf));
    stxbuf->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_SIZE
                       | STATX_MTIME | STATX_INO;
    stxbuf->stx_mode    = (uint16_t) mapped.st_mode;
    stxbuf->stx_nlink   = (uint32_t) mapped.st_nlink;
    stxbuf->stx_size    = (uint64_t) mapped.st_size;
    stxbuf->stx_ino     = (uint64_t) mapped.st_ino;
    stxbuf->stx_blksize = (uint32_t) mapped.st_blksize;
    stxbuf->stx_blocks  = (uint64_t) mapped.st_blocks;
    stxbuf->stx_mtime.tv_sec = mapped.st_mtime;
    stxbuf->stx_atime.tv_sec = mapped.st_atime;
    stxbuf->stx_ctime.tv_sec = mapped.st_ctime;
    return 0;
}

#endif /* BRIX_PLATFORM_LINUX */
