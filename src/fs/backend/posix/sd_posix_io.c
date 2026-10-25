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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "sd_posix_internal.h"
#include "platform/platform_api.h"   /* brix_plat_pwrite_at/preadv2/copy_range/reserve */

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
 * brix_vfs_io_write_counted), so every VFS write funnels through the driver.
 * kXR_open_apnd means "the write lands at EOF whatever offset the client
 * sent": Linux pwrite(2) already does that on an O_APPEND fd, but hosts whose
 * pwrite honours the offset on an O_APPEND fd need write(2); the PAL picks. */
ssize_t
sd_posix_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    return brix_plat_pwrite_at(obj->fd, buf, len, off, obj->append);
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
    return brix_plat_preadv2(obj->fd, iov, iovcnt, off, flags);
}

/* sd_posix_copy_range — one copy_file_range(2) of up to len bytes src->dst (0 =
 * EOF, -1/ENOSYS where unavailable): the server-side zero-copy primitive. The VFS
 * owns the loop and the pread/pwrite fallback. */
ssize_t
sd_posix_copy_range(brix_sd_obj_t *src, off_t src_off, brix_sd_obj_t *dst,
    off_t dst_off, size_t len)
{
    off_t si = src_off;
    off_t di = dst_off;

    return brix_plat_copy_range(src->fd, &si, dst->fd, &di, len, 0);
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

/* ---- Reject reservations that cannot fit before allocating any blocks ----
 * WHAT: Return NGX_ERROR/ENOSPC when the requested additional allocation
 *       exceeds available filesystem space, or preserve a metadata error.
 * WHY: An oversized fallocate can occupy all free extents before failing,
 *      starving unrelated exports and blocking the worker during the attempt.
 * HOW: 1. Read capacity and actual allocation from the already-open object.
 *      2. Credit allocated blocks, including reservations beyond EOF.
 *      3. Compare rounded-up additional blocks without multiplying capacity.
 *         The allocator still resolves concurrent capacity changes/quotas.
 */
static ngx_int_t
sd_posix_reserve_space(int fd, off_t size)
{
    struct statvfs space;
    struct stat st;
    uint64_t required = (uint64_t) size;
    uint64_t unit, blocks;

    if (fstatvfs(fd, &space) != 0 || fstat(fd, &st) != 0) {
        return NGX_ERROR;
    }
    if (st.st_blocks > 0) {
        blocks = (uint64_t) st.st_blocks;
        required = blocks > required / 512 ? 0 : required - blocks * 512;
    }
    unit = space.f_frsize != 0 ? space.f_frsize : space.f_bsize;
    if (unit == 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    blocks = required / unit + (required % unit != 0);
    if (blocks > space.f_bavail) {
        errno = ENOSPC;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- Preallocate the declared final size without changing the file size ----
 * WHAT: Return NGX_OK on reservation, NGX_ERROR with the storage errno otherwise.
 * WHY: Capacity hints must not expose promised bytes through stat or exhaust
 *      shared storage while an impossible reservation is being attempted.
 * HOW: 1. Reject impossible additional allocations using handle metadata.
 *      2. Delegate allocation and partial-failure release to the host PAL.
 *         The VFS treats ENOSPC/EDQUOT as fatal and other errors as advisory.
 */
ngx_int_t
sd_posix_reserve(brix_sd_obj_t *obj, off_t size)
{
    if (size > 0 && sd_posix_reserve_space(obj->fd, size) != NGX_OK) {
        return NGX_ERROR;
    }
    return brix_plat_reserve(obj->fd, size) == 0 ? NGX_OK : NGX_ERROR;
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

/* sd_posix_read_advise — map the backend-neutral advice onto posix_fadvise(2).
 * Advisory only: NGX_OK whether or not the kernel honours the hint; NGX_ERROR
 * (errno set) only for a hard failure (bad fd). posix_fadvise RETURNS the error
 * number rather than setting errno, so it is copied into errno here to keep the
 * seam's NGX_ERROR-with-errno contract. */
ngx_int_t
sd_posix_read_advise(brix_sd_obj_t *obj, off_t off, size_t len, int advice)
{
#if defined(POSIX_FADV_SEQUENTIAL)
    int a, rc;

    a = advice == BRIX_SD_ADV_WILLNEED ? POSIX_FADV_WILLNEED
      : advice == BRIX_SD_ADV_RANDOM   ? POSIX_FADV_RANDOM
      :                                  POSIX_FADV_SEQUENTIAL;

    rc = posix_fadvise(obj->fd, off, (off_t) len, a);
    if (rc != 0) {
        errno = rc;
        return NGX_ERROR;
    }
    return NGX_OK;
#else
    (void) obj;
    (void) off;
    (void) len;
    (void) advice;
    return NGX_OK;
#endif
}
