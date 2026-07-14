/*
 * sd_posix_io.c — the POSIX Storage Driver's worker-safe raw byte I/O ops.
 *
 * WHAT: The raw fd byte primitives of brix_sd_posix_driver (pread/pwrite/
 *       preadv/preadv2/copy_range/read_sendfile_fd/ftruncate/fsync/fstat),
 *       split VERBATIM out of sd_posix.c. The driver descriptor stays in
 *       sd_posix.c and references these via sd_posix_internal.h.
 *
 * WHY:  These ops are pure POSIX (no pool/metrics/log) and also build into the
 *       ngx-free shared libxrdproto, so a shared kernel can route its fd reads
 *       through the one driver in both worlds. Splitting them keeps every unit
 *       under the file-size cap with zero behaviour change.
 *
 * HOW:  Each op is a thin wrapper over the raw syscall; the VFS owns every
 *       EINTR/short-io loop and policy above the seam.
 */

#include "fs/backend/sd.h"

/* The instance lifecycle + namespace/dir/xattr/staged ops below are nginx-coupled
 * (confined open, ngx pool, the shared brix_ns_* helpers). They — and these
 * headers — compile only in the module. The worker-safe raw fd byte ops
 * (pread/pwrite/preadv/...) are pure POSIX and also build into the ngx-free
 * shared libxrdproto, so a shared kernel (src/compat/checksum_core.c) can route
 * its fd reads through brix_sd_posix_driver in both worlds. */
#ifndef XRDPROTO_NO_NGX
#include "fs/vfs/vfs_internal.h"          /* pread_full/pwrite_full + ns_status_errno */
#include "core/compat/crc32c.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/staged_file.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sd_posix_internal.h"

/* worker-safe raw byte I/O (no pool/metrics/log) */

/* sd_posix_pread — one pread(2) at off (0 = EOF, -1 = errno). The raw storage
 * primitive; the VFS owns the EINTR/short-read loop (brix_vfs_pread_full), so
 * every VFS read funnels through the driver without changing semantics. */
ssize_t
sd_posix_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

/* sd_posix_pwrite — one pwrite(2) at off (bytes written, or -1). The raw
 * primitive; the VFS owns the EINTR/short-write loops (brix_vfs_pwrite_full,
 * brix_vfs_io_write_counted), so every VFS write funnels through the driver. */
ssize_t
sd_posix_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    return pwrite(obj->fd, buf, len, off);
}

/* sd_posix_preadv — one preadv(2) of iovcnt segments at off (bytes read or -1):
 * the raw vectored-read primitive behind kXR_readv coalescing and the pgread batch
 * reader. The VFS owns the EINTR loop and the coalescing policy. */
ssize_t
sd_posix_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    return preadv(obj->fd, iov, iovcnt, off);
}

/* sd_posix_preadv2 — one preadv2(2) of iovcnt segments at off with flags (e.g.
 * RWF_NOWAIT), for the kXR_read warm-cache non-blocking page-cache probe; bytes
 * read or -1. */
ssize_t
sd_posix_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    return preadv2(obj->fd, iov, iovcnt, off, flags);
}

/* sd_posix_copy_range — one copy_file_range(2) of up to len bytes src->dst (0 =
 * EOF, -1/ENOSYS where unavailable): the server-side zero-copy primitive. The VFS
 * owns the loop and the pread/pwrite fallback. */
ssize_t
sd_posix_copy_range(brix_sd_obj_t *src, off_t src_off, brix_sd_obj_t *dst,
    off_t dst_off, size_t len)
{
#if defined(__linux__) && defined(__NR_copy_file_range)
    loff_t si = (loff_t) src_off;
    loff_t di = (loff_t) dst_off;

    return (ssize_t) syscall(__NR_copy_file_range, src->fd, &si, dst->fd, &di,
                             len, 0u);
#else
    (void) src; (void) src_off; (void) dst; (void) dst_off; (void) len;
    errno = ENOSYS;
    return -1;
#endif
}

/* sd_posix_read_sendfile_fd — return the object's kernel fd when the caller will
 * accept zero-copy (want_zerocopy), else NGX_INVALID_FILE. A POSIX file is a
 * seekable fd so any range is sendfile-able; offset/len matter only to backends
 * with alignment/residency constraints. The backend, not the VFS, makes this call. */
ngx_fd_t
sd_posix_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    (void) off;
    (void) len;

    if (!want_zerocopy || obj->fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    return obj->fd;
}

/* sd_posix_ftruncate / _fsync / _fstat — direct fd ops */
ngx_int_t
sd_posix_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    return ftruncate(obj->fd, len) == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_posix_fsync(brix_sd_obj_t *obj)
{
    return fsync(obj->fd) == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_posix_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    sd_posix_fill_stat(&sb, out);
    return NGX_OK;
}
