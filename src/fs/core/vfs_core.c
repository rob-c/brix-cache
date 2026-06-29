/*
 * vfs_core.c — shared, ngx-free VFS I/O verbs. See vfs_core.h.
 *
 * The EINTR / short-I/O loop policy lives here; the raw syscalls live in the
 * backend driver (obj->driver->...). Lifted verbatim from the server's
 * xrootd_vfs_pread_full (src/fs/vfs_read.c) and xrootd_vfs_io_write_counted
 * (src/fs/vfs_io_core.c) so behaviour is byte-identical across both trees.
 */
#include "vfs_core.h"

#include <errno.h>

int
xvfs_pread_full(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off,
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
xvfs_pread_once(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    ssize_t n;

    do {
        n = obj->driver->pread(obj, buf, len, off);
    } while (n < 0 && errno == EINTR);

    return n;
}

int
xvfs_pwrite_full(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off,
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
xvfs_fsync(xrootd_sd_obj_t *obj)
{
    /* driver->fsync returns NGX_OK(0)/NGX_ERROR(-1); normalise to 0/-1. */
    return (obj->driver->fsync(obj) == 0) ? 0 : -1;
}

int
xvfs_ftruncate(xrootd_sd_obj_t *obj, off_t len)
{
    return (obj->driver->ftruncate(obj, len) == 0) ? 0 : -1;
}

int
xvfs_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    return (obj->driver->fstat(obj, out) == 0) ? 0 : -1;
}
