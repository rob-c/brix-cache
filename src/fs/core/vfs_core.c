/*
 * vfs_core.c — shared, ngx-free VFS I/O verbs. See vfs_core.h.
 *
 * The EINTR / short-I/O loop policy lives here; the raw syscalls live in the
 * backend driver (obj->driver->...). Lifted verbatim from the server's
 * brix_vfs_pread_full (src/fs/vfs/vfs_read.c) and brix_vfs_io_write_counted
 * (src/fs/vfs/vfs_io_core.c) so behaviour is byte-identical across both trees.
 */
#include "vfs_core.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
xvfs_pread_full(brix_sd_obj_t *obj, void *buf, size_t len, off_t off,
                size_t *nread)
{
    size_t   done = 0;
    u_char  *p    = buf;

    while (done < len) {
        ssize_t n = obj->driver->pread(obj, p + done, len - done,
                                       off + (off_t) done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (nread != NULL) {
                *nread = done;
            }
            return -1;
        }
        if (n == 0) {
            break;   /* EOF — short read is success */
        }
        done += (size_t) n;
    }

    if (nread != NULL) {
        *nread = done;
    }
    return 0;
}

ssize_t
xvfs_pread_once(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    ssize_t n;

    do {
        n = obj->driver->pread(obj, buf, len, off);
    } while (n < 0 && errno == EINTR);

    return n;
}

int
xvfs_pwrite_full(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off,
                 size_t *written, int *short_io)
{
    size_t        done = 0;
    const u_char *p    = buf;

    if (short_io != NULL) {
        *short_io = 0;
    }

    while (done < len) {
        ssize_t n = obj->driver->pwrite(obj, p + done, len - done,
                                        off + (off_t) done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (done > 0 && short_io != NULL) {
                *short_io = 1;   /* partial-then-error */
            }
            if (written != NULL) {
                *written = done;
            }
            return -1;
        }
        if (n == 0) {
            if (short_io != NULL) {
                *short_io = 1;
            }
            if (written != NULL) {
                *written = done;
            }
            errno = EIO;
            return -1;
        }
        done += (size_t) n;
    }

    if (written != NULL) {
        *written = done;
    }
    return 0;
}

int
xvfs_fsync(brix_sd_obj_t *obj)
{
    /* driver->fsync returns NGX_OK(0)/NGX_ERROR(-1); normalise to 0/-1. */
    return (obj->driver->fsync(obj) == 0) ? 0 : -1;
}

int
xvfs_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    return (obj->driver->ftruncate(obj, len) == 0) ? 0 : -1;
}

int
xvfs_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    return (obj->driver->fstat(obj, out) == 0) ? 0 : -1;
}

int
xvfs_drain(brix_sd_obj_t *src, brix_sd_obj_t *dst, void *buf, size_t bufsz,
           off_t *total)
{
    off_t off = 0;

    if (buf == NULL || bufsz == 0) {
        errno = EINVAL;
        return -1;
    }

    for ( ;; ) {
        ssize_t r = xvfs_pread_once(src, buf, bufsz, off);

        if (r < 0) {
            return -1;                       /* read error (errno set by driver) */
        }
        if (r == 0) {
            break;                           /* EOF — whole object copied */
        }
        if (xvfs_pwrite_full(dst, buf, (size_t) r, off, NULL, NULL) != 0) {
            return -1;                       /* write error (errno set) */
        }
        off += r;
    }

    if (total != NULL) {
        *total = off;
    }
    return 0;
}

int
xvfs_stage_fd(int src_fd, const char *stage_dir)
{
    char            tmpl[PATH_MAX];
    char            proc[64];
    char           *buf;
    brix_sd_obj_t s, d;
    int             dst_fd, rd_fd, e, n;

    if (stage_dir == NULL || stage_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    n = snprintf(tmpl, sizeof(tmpl), "%s/.vfsstage.XXXXXX", stage_dir);
    if (n < 0 || (size_t) n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    dst_fd = mkstemp(tmpl);
    if (dst_fd < 0) {
        return -1;
    }
    (void) unlink(tmpl);                 /* anonymous: bytes live behind the fd(s) */

    buf = malloc(256 * 1024);
    if (buf == NULL) {
        e = ENOMEM;
        close(dst_fd);
        errno = e;
        return -1;
    }
    brix_sd_posix_wrap(&s, src_fd);
    brix_sd_posix_wrap(&d, dst_fd);
    if (xvfs_drain(&s, &d, buf, 256 * 1024, NULL) != 0) {
        e = errno;
        free(buf);
        close(dst_fd);
        errno = e;
        return -1;
    }
    free(buf);

    /* Reopen the unlinked inode O_RDONLY at offset 0 (clean pread semantics). */
    (void) snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dst_fd);
    rd_fd = open(proc, O_RDONLY | O_CLOEXEC);
    e = errno;
    close(dst_fd);
    if (rd_fd < 0) {
        errno = e;
        return -1;
    }
    return rd_fd;
}
