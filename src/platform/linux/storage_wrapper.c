/*
 * src/platform/linux/storage_wrapper.c - linux storage primitives beneath the SD driver
 *
 * WHAT: BLKGETSIZE64, F_ADD_SEALS, fallocate(KEEP_SIZE) with the ENOSPC release,
 *       preadv2, pwrite on an O_APPEND fd, pipe2 and copy_file_range: the platform_api_posix.h storage entry points.
 * WHY:  These bodies are pure libc, so the native client links this file too
 *       (client/Makefile PLATFORM_SRCS) instead of carrying copies: one body
 *       per host, no duplication. posix_wrapper.c stays module-only (it owns
 *       symbols shared/cvmfs/platform/platform.c provides to the client).
 * HOW:  Thin wrappers; raw byte syscalls carry the VFS seam owner marker.
 */

/* The glibc feature-test macro these bodies need (pipe2, fallocate, preadv2, copy_file_range, F_ADD_SEALS).  Guarded, not
 * bare, because both real builds already pass -D_GNU_SOURCE on the command
 * line (./config for the module, client/Makefile's HARDEN for the client) and
 * an unguarded redefinition is an error under -Werror.  Declared HERE rather
 * than left to the caller so a standalone harness that links one PAL body --
 * every tests/cmdscripts compile line that reaches brix_plat_* -- gets the
 * prototypes too, instead of an implicit declaration and a silent link
 * failure.  It must precede every include, hence its place above them. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>       /* BLKGETSIZE64 */
#include <linux/falloc.h>   /* FALLOC_FL_KEEP_SIZE */
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>

int
brix_plat_pipe2(int pipefd[2], int flags)
{
    /* BRIX_PIPE_* are PAL values, not the kernel's O_* bits */
    return pipe2(pipefd, ((flags & BRIX_PIPE_CLOEXEC) ? O_CLOEXEC : 0)
                         | ((flags & BRIX_PIPE_NONBLOCK) ? O_NONBLOCK : 0));
}

ssize_t
brix_plat_copy_range(int in_fd, off_t *in_off,
                     int out_fd, off_t *out_off,
                     size_t len, unsigned int flags)
{
    (void)flags;  /* Linux copy_file_range doesn't use flags parameter */
    return copy_file_range(in_fd, in_off, out_fd, out_off, len, 0); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_blockdev_size(int fd, uint64_t *bytes)
{
    uint64_t sz = 0;

    if (ioctl(fd, BLKGETSIZE64, &sz) != 0) {
        return -1;
    }
    *bytes = sz;
    return 0;
}

int
brix_plat_fd_seal(int fd)
{
    return fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE);
}

int
brix_plat_reserve(int fd, off_t size)
{
    int rc;

    do {
        rc = fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, size);
    } while (rc != 0 && errno == EINTR);

    if (rc == 0) {
        return 0;
    }
    /* fallocate is NOT atomic on ENOSPC (ext4 allocates extent-by-extent and
     * keeps what it got): a refused oversized declaration can park nearly all
     * free space on a file whose st_size is still 0. ftruncate to the
     * UNCHANGED st_size releases the beyond-EOF part of the failed range;
     * data inside EOF survives and a failed release changes nothing the
     * caller can act on. */
    if (errno == ENOSPC || errno == EDQUOT) {
        int          err = errno;
        struct stat  st;

        if (fstat(fd, &st) == 0 && st.st_size < size /* vfs-seam-allow: SEAM_CORRECT - fstat on the caller's storage fd */
            && ftruncate(fd, st.st_size) != 0) /* vfs-seam-allow: SEAM_CORRECT - PAL reserve release beneath the SD driver */
        {
            /* nothing left to do: the open is failing with ENOSPC either way */
        }
        errno = err;
    }
    return -1;
}

ssize_t
brix_plat_preadv2(int fd, const struct iovec *iov, int iovcnt, off_t off,
    int flags)
{
    return preadv2(fd, iov, iovcnt, off, flags); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_pwrite_at(int fd, const void *buf, size_t len, off_t off, int append)
{
    (void) append;   /* Linux pwrite(2) lands at EOF on an O_APPEND fd */
    return pwrite(fd, buf, len, off); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

int
brix_plat_fd_reopen_readonly(int fd)
{
    char proc[32];

    (void) snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    return open(proc, O_RDONLY | O_CLOEXEC); /* vfs-seam-allow: NOT_STORAGE - PAL descriptor alias of an already-open file */
}

#endif /* BRIX_PLATFORM_LINUX */
