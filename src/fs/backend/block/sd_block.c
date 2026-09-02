/*
 * sd_block.c — block-device storage driver (shared by the nginx server and the
 * userland clients).
 *
 * WHAT: brix_sd_block_driver — a backend for writing/reading a raw block
 *       device (or a file used as one) in place, plus the driver descriptor. The
 *       raw byte I/O is identical to POSIX, so the pread/pwrite/preadv/fsync
 *       slots delegate to the POSIX driver; the block-specific behaviour is
 *       `fstat`, which reports the true device capacity via BLKGETSIZE64 (a
 *       block device's struct.st_size is 0), `open`, which never creates or
 *       truncates the device, and the EXTENT WINDOW every offset is translated
 *       through.
 *
 *       The server plane — the per-export instance and the fixed-extent
 *       namespace it synthesizes — lives in sd_block_ns.c and compiles only in
 *       the module build.
 * WHY:  block was previously implemented only in client/lib/vfs_block.c — a
 *       second storage driver outside src/. This is the single home: both the
 *       client (block:// copy endpoints) and a block-backed server export use the
 *       same driver. ngx-free (dual-build via sd.h's XRDPROTO_NO_NGX fallback) so
 *       the client links the raw-I/O surface from libxrdproto; the namespace /
 *       instance ops (which need an nginx pool + log) compile only in the module.
 * HOW:  flat, POD-pointer-only vtable. A per-open object carries its extent
 *       window (sd_block_obj_t base/len); a NULL window (the client/unconfined
 *       path, which wraps a bare fd) means "absolute offset, no clamp" so the raw
 *       ops serve both worlds from one implementation.
 */
#include "sd_block_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>   /* BLKGETSIZE64 */
#endif

/* Trailing-cap on a single windowed preadv so the iovec trim uses a bounded
 * stack copy; a larger iovcnt is honoured as a (legal) short read. */
#define BRIX_BLOCK_IOV_MAX 64

/* Declared in sd_block_internal.h — sd_block_ns.c has no use for it, but the
 * advisory slot below and the byte ops share the one translation. */
int
sd_block_read_window(const sd_block_obj_t *os, off_t *off, size_t *len)
{
    off_t avail;

    if (os == NULL) {
        return 1;                       /* unconfined: absolute offset */
    }
    if (*off < 0 || *off >= os->len) {
        return 0;                       /* past the extent → EOF */
    }
    avail = os->len - *off;
    if ((off_t) *len > avail) {
        *len = (size_t) avail;
    }
    *off += os->base;
    return 1;
}

/* Raw byte I/O == POSIX: delegate to the POSIX driver's slots so the syscall
 * loop policy stays single-sourced (vfs_core) and there is no second copy. For a
 * server extent the offset is first windowed; the client path (state == NULL)
 * passes straight through. */
static ssize_t
sd_block_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    if (!sd_block_read_window(obj->state, &off, &len)) {
        return 0;                       /* read wholly past the extent → EOF */
    }
    return brix_sd_posix_driver.pread(obj, buf, len, off);
}

/* sd_block_pwrite — a fixed extent cannot grow: a write that starts at/after the
 * extent end, or that would cross the extent boundary, is refused with ENOSPC
 * (never silently truncated into the neighbouring extent). */
static ssize_t
sd_block_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    const sd_block_obj_t *os = obj->state;

    if (os != NULL) {
        if (off < 0 || off >= os->len
            || (off_t) len > os->len - off)
        {
            errno = ENOSPC;
            return -1;
        }
        off += os->base;
    }
    return brix_sd_posix_driver.pwrite(obj, buf, len, off);
}

/* sd_block_preadv_window — the vectored counterpart of sd_block_read_window:
 * shift the base offset and trim the iovec run so the total never crosses the
 * extent end. The client path (state == NULL) delegates unmodified. */
static ssize_t
sd_block_preadv_window(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags, int has_flags)
{
    const sd_block_obj_t *os = obj->state;
    struct iovec          tmp[BRIX_BLOCK_IOV_MAX];
    off_t                 remaining;
    int                   i, n;

    if (os == NULL) {
        return has_flags
             ? brix_sd_posix_driver.preadv2(obj, iov, iovcnt, off, flags)
             : brix_sd_posix_driver.preadv(obj, iov, iovcnt, off);
    }
    if (iovcnt < 0) {
        errno = EINVAL;
        return -1;
    }
    if (off < 0 || off >= os->len) {
        return 0;                       /* past the extent → EOF */
    }
    if (iovcnt > BRIX_BLOCK_IOV_MAX) {
        iovcnt = BRIX_BLOCK_IOV_MAX;    /* bounded; the tail is a short read */
    }
    remaining = os->len - off;
    for (i = 0, n = 0; i < iovcnt && remaining > 0; i++) {
        size_t l = iov[i].iov_len;

        if ((off_t) l > remaining) {
            l = (size_t) remaining;
        }
        tmp[n].iov_base = iov[i].iov_base;
        tmp[n].iov_len  = l;
        remaining -= l;
        n++;
    }
    off += os->base;
    return has_flags
         ? brix_sd_posix_driver.preadv2(obj, tmp, n, off, flags)
         : brix_sd_posix_driver.preadv(obj, tmp, n, off);
}

static ssize_t
sd_block_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    return sd_block_preadv_window(obj, iov, iovcnt, off, 0, 0);
}

static ssize_t
sd_block_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    return sd_block_preadv_window(obj, iov, iovcnt, off, flags, 1);
}

static ngx_int_t
sd_block_fsync(brix_sd_obj_t *obj)
{
    return brix_sd_posix_driver.fsync(obj);
}

/* sd_block_fstat — a server extent reports as a fixed-size regular object (its
 * window length); the client/unconfined path reports the real file, and for a
 * true block device (st_size == 0) queries the capacity via BLKGETSIZE64. */
static ngx_int_t
sd_block_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    const sd_block_obj_t *os = obj->state;
    struct stat           sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->ino    = sb.st_ino;

    if (os != NULL) {
        out->size   = os->len;
        out->mode   = S_IFREG | 0644;
        out->is_reg = 1;
        return NGX_OK;
    }

    out->size   = sb.st_size;
    out->mode   = sb.st_mode;
    out->is_dir = S_ISDIR(sb.st_mode) ? 1 : 0;
    out->is_reg = S_ISREG(sb.st_mode) ? 1 : 0;

#ifdef BLKGETSIZE64
    if (S_ISBLK(sb.st_mode)) {
        uint64_t sz = 0;
        if (ioctl(obj->fd, BLKGETSIZE64, &sz) == 0) {
            out->size = (off_t) sz;
        }
    }
#endif
    return NGX_OK;
}

/* sd_block_reserve — phase-107 C5: a fixed extent IS the reservation, so this
 * is a pure capacity check. A declared final size that cannot fit the extent
 * refuses the OPEN with ENOSPC (kXR_NoSpace / 507) before any byte lands,
 * instead of the write that eventually crosses the boundary. A server extent
 * checks os->len; the unconfined client handle (state == NULL) queries the
 * device capacity via fstat, and reports nothing on a probe failure (the
 * caller treats a non-ENOSPC errno as advisory). */
static ngx_int_t
sd_block_reserve(brix_sd_obj_t *obj, off_t size)
{
    const sd_block_obj_t *os = obj->state;
    brix_sd_stat_t        st;

    if (os != NULL) {
        if (size > os->len) {
            errno = ENOSPC;
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    if (sd_block_fstat(obj, &st) != NGX_OK) {
        return NGX_ERROR;               /* errno from the probe: advisory */
    }
    if (st.size > 0 && size > st.size) {
        errno = ENOSPC;
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* sd_block_read_sendfile_fd — hand back the device fd for zero-copy ONLY when
 * the object's extent starts at device offset 0.
 *
 * WHAT: Returns obj->fd for the unconfined (client) handle and for extent 0;
 *       NGX_INVALID_FILE for every extent with a non-zero base.
 * WHY:  The fd this slot returns is consumed by callers that address it with
 *       LOGICAL offsets — brix_vfs_file_sendfile_fd asks for the whole object and
 *       the protocol handler then builds its own range from the object size. The
 *       driver never sees that range, so it cannot clamp it after the fact; a
 *       base-shifted extent handed out as a bare fd would serve the START of the
 *       device under every object's name and let a ranged GET walk into the
 *       neighbouring extent. base == 0 is exactly the condition under which
 *       logical and physical offsets coincide, so it is the whole gate. This is
 *       the common single-extent export (extent_size == 0 makes the device one
 *       object "/0"), which is where the zero-copy win actually matters.
 * HOW:  want_zerocopy is the VFS's transport verdict and is honoured first; a
 *       NULL window is the client path, whose offsets are already absolute.
 */
static ngx_fd_t
sd_block_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    const sd_block_obj_t *os = obj->state;

    if (!want_zerocopy || obj->fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    if (os != NULL) {
        if (os->base != 0) {
            return NGX_INVALID_FILE;      /* logical 0 is not physical 0 */
        }
        if (off < 0 || (off_t) len > os->len - off) {
            return NGX_INVALID_FILE;      /* the ask already leaves the extent */
        }
    }
    return obj->fd;
}

/* sd_block_read_advise — map the backend-neutral advice onto posix_fadvise(2)
 * over the extent's absolute device range.
 *
 * WHAT: Windows [off, off+len) through the extent (len == 0 ⇒ from off to the
 *       extent end) and advises the device fd over the resulting absolute range.
 * WHY:  Without this slot brix_vfs_file_read_advise is a no-op on a block
 *       export, so the sequential-serve and WILLNEED prefetch engines lose their
 *       read-ahead entirely. Advising the UNWINDOWED offset would be worse than
 *       nothing: it would warm the wrong extent's pages and evict the right
 *       ones.
 * HOW:  Advisory throughout, per the slot contract — NGX_OK whether or not the
 *       kernel honoured the hint, NGX_ERROR (errno set) only on a hard failure.
 *       posix_fadvise RETURNS the error number rather than setting errno, so it
 *       is copied into errno to keep the seam's contract. Position, size and
 *       contents are untouched.
 */
static ngx_int_t
sd_block_read_advise(brix_sd_obj_t *obj, off_t off, size_t len, int advice)
{
    const sd_block_obj_t *os = obj->state;
#if defined(POSIX_FADV_SEQUENTIAL)
    int                   a, rc;
#endif

    if (os != NULL && len == 0) {
        if (off < 0 || off >= os->len) {
            return NGX_OK;                /* nothing at/after the extent end */
        }
        len = (size_t) (os->len - off);   /* "to EOF" is the EXTENT's end */
    }
    if (!sd_block_read_window(os, &off, &len)) {
        return NGX_OK;                    /* wholly past the extent */
    }

#if defined(POSIX_FADV_SEQUENTIAL)
    a = advice == BRIX_SD_ADV_WILLNEED ? POSIX_FADV_WILLNEED
      : advice == BRIX_SD_ADV_RANDOM   ? POSIX_FADV_RANDOM
      :                                  POSIX_FADV_SEQUENTIAL;

    rc = posix_fadvise(obj->fd, off, (off_t) len, a);
    if (rc != 0) {
        errno = rc;
        return NGX_ERROR;
    }
#else
    (void) advice;
#endif
    return NGX_OK;
}

/* brix_sd_block_open_unconfined — open a block device (no O_CREAT/O_TRUNC: the
 * device exists and must not be re-created or zeroed). Returns an fd or -1. */
int
brix_sd_block_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    /* Strip create/truncate intent — a block device is opened in place. */
    sd_flags &= ~(BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC);
    return brix_sd_posix_open_unconfined(path, sd_flags, mode);
}

/* The block driver: raw-I/O caps everywhere; in the module build it also grows a
 * fixed-extent server namespace (open/stat/dir + CAP_DIRS). No truncate (a fixed
 * extent), no rename, no xattr, no staged commit. Zero-copy is offered only for
 * an extent based at device offset 0 — see sd_block_read_sendfile_fd for why the
 * base is the whole gate. */
const brix_sd_driver_t brix_sd_block_driver = {
    .name = "block",
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_RANGE_READ
#ifndef XRDPROTO_NO_NGX
          | BRIX_SD_CAP_DIRS
#endif
          ,
    .pread    = sd_block_pread,
    .pwrite   = sd_block_pwrite,
    .preadv   = sd_block_preadv,
    .preadv2  = sd_block_preadv2,
    .fsync    = sd_block_fsync,
    .fstat    = sd_block_fstat,
    .read_sendfile_fd = sd_block_read_sendfile_fd,
    .read_advise      = sd_block_read_advise,
    .reserve  = sd_block_reserve,   /* phase-107 C5 extent-capacity admit */
#ifndef XRDPROTO_NO_NGX
    .init     = sd_block_init,
    .open     = sd_block_open,
    .close    = sd_block_close,
    .stat     = sd_block_stat,
    .opendir  = sd_block_opendir,
    .readdir  = sd_block_readdir,
    .closedir = sd_block_closedir,
    /* The DEVICE capacity, so kXR_Qspace stops answering with the statvfs of
     * whatever filesystem the mount point happens to sit on. */
    .space    = sd_block_space,
#endif
};
