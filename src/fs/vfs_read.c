/*
 * vfs_read.c — the shared full-read primitive.
 *
 * WHAT: Implements xrootd_vfs_pread_full(), the EINTR-safe, short-read-tolerant
 *       pread loop used throughout the VFS (the I/O core in vfs_io_core.c and the
 *       per-buffer write copier, plus the AIO offload bodies).
 *
 * WHY:  Every VFS read has to apply the same short-read/EINTR retry policy, and
 *       every data byte has to traverse the Storage Driver seam rather than a raw
 *       syscall. Concentrating the loop here guarantees both, once.
 *
 * HOW:  xrootd_vfs_pread_full() wraps the fd in a POSIX storage-driver object and
 *       drives driver.pread() in a loop until len bytes are read or EOF, retrying
 *       on EINTR and reporting the byte count in *nread even on error.
 */
#include "vfs_internal.h"
#include "backend/sd.h"
#include "core/vfs_core.h"   /* shared ngx-free VFS I/O verbs */

/* EINTR-safe, short-read-tolerant pread into buf. Loops until len bytes are
 * read or EOF; *nread (if non-NULL) reports the byte count even on error.
 *
 * Thin server wrapper over the shared `vfs` core (xvfs_pread_full): the EINTR/
 * short-read loop + the Storage Driver seam live in src/fs/core/vfs_core.c, the
 * single copy shared with the userland clients. This wrapper keeps the existing
 * fd-keyed signature so the server's callers (vfs_io_core, AIO bodies) are
 * unchanged. */
ngx_int_t
xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
    off_t offset, size_t *nread)
{
    xrootd_sd_obj_t obj;

    xrootd_sd_posix_wrap(&obj, fd);
    return (xvfs_pread_full(&obj, buf, len, offset, nread) == 0)
           ? NGX_OK : NGX_ERROR;
}
