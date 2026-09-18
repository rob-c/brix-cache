/*
 * src/platform/darwin/storage_wrapper.c - darwin storage primitives beneath the SD driver
 *
 * WHAT: DKIOCGETBLOCK*, the sealing / reserve / copy_file_range "unavailable"
 *       answers, preadv (no preadv2), write(2) for an O_APPEND handle, pipe + fcntl: the platform_api_posix.h storage entry points.
 * WHY:  These bodies are pure libc, so the native client links this file too
 *       (client/Makefile PLATFORM_SRCS) instead of carrying copies: one body
 *       per host, no duplication. posix_wrapper.c stays module-only (it owns
 *       symbols shared/cvmfs/platform/platform.c provides to the client).
 * HOW:  Thin wrappers; raw byte syscalls carry the VFS seam owner marker.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <fcntl.h>
#include <sys/disk.h>       /* DKIOCGETBLOCKCOUNT / DKIOCGETBLOCKSIZE */
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>

int
brix_plat_pipe2(int pipefd[2], int flags)
{
    if (pipe(pipefd) < 0) {
        return -1;
    }
    
    /* Apply flags via fcntl */
    if (flags & BRIX_PIPE_CLOEXEC) {
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    
    if (flags & BRIX_PIPE_NONBLOCK) {
        int fflags;
        fflags = fcntl(pipefd[0], F_GETFL, 0);
        fcntl(pipefd[0], F_SETFL, fflags | O_NONBLOCK);
        fflags = fcntl(pipefd[1], F_GETFL, 0);
        fcntl(pipefd[1], F_SETFL, fflags | O_NONBLOCK);
    }
    
    return 0;
}

ssize_t
brix_plat_copy_range(int in_fd, off_t *in_off,
                     int out_fd, off_t *out_off,
                     size_t len, unsigned int flags)
{
    /* macOS lacks copy_file_range - use buffered copy */
    (void)in_fd; (void)in_off; (void)out_fd; (void)out_off;
    (void)len; (void)flags;
    errno = ENOSYS;
    return -1;
}

int
brix_plat_blockdev_size(int fd, uint64_t *bytes)
{
    uint64_t count = 0;
    uint32_t bsize = 0;

    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &count) != 0
        || ioctl(fd, DKIOCGETBLOCKSIZE, &bsize) != 0)
    {
        return -1;
    }
    *bytes = count * (uint64_t) bsize;
    return 0;
}

int
brix_plat_fd_seal(int fd)
{
    (void) fd;
    return 0;   /* no file sealing on Darwin */
}

int
brix_plat_reserve(int fd, off_t size)
{
    (void) fd; (void) size;
    errno = EOPNOTSUPP;
    return -1;
}

ssize_t
brix_plat_preadv2(int fd, const struct iovec *iov, int iovcnt, off_t off,
    int flags)
{
    (void) flags;   /* no preadv2: preadv ignores the per-call hints */
    return preadv(fd, iov, iovcnt, off); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

ssize_t
brix_plat_pwrite_at(int fd, const void *buf, size_t len, off_t off, int append)
{
    if (append) {
        /* Darwin pwrite(2) honours the offset on an O_APPEND fd: write(2)
         * is what lands the bytes at EOF. */
        return write(fd, buf, len); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
    }
    return pwrite(fd, buf, len, off); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
}

/* Same inode (and device) behind both descriptors: guards the F_GETPATH
 * re-open against a rename/replace between the name lookup and the open. */
static int
darwin_same_file(int a, int b)
{
    struct stat sa, sb;

    if (fstat(a, &sa) != 0 || fstat(b, &sb) != 0) { /* vfs-seam-allow: NOT_STORAGE - PAL identity check of an already-open file */
        return 0;
    }
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

int
brix_plat_fd_reopen_readonly(int fd)
{
    char path[MAXPATHLEN];
    int  rfd, flags;

    if (fcntl(fd, F_GETPATH, path) == 0) {
        rfd = open(path, O_RDONLY | O_CLOEXEC); /* vfs-seam-allow: NOT_STORAGE - PAL descriptor alias of an already-open file */
        if (rfd >= 0) {
            if (darwin_same_file(fd, rfd)) {
                return rfd;
            }
            close(rfd);
        }
    }
    /* Unlinked (no live name): only a readable original can be aliased. */
    flags = fcntl(fd, F_GETFL);
    if (flags >= 0 && (flags & O_ACCMODE) != O_WRONLY) {
        rfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        return rfd;
    }
    errno = EACCES;
    return -1;
}

#endif /* BRIX_PLATFORM_DARWIN */
