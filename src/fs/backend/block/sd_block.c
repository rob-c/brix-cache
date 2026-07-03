/*
 * sd_block.c — block-device storage driver (shared by the nginx server and the
 * userland clients).
 *
 * WHAT: brix_sd_block_driver — a backend for writing/reading a raw block
 *       device (or a file used as one) in place. The raw byte I/O is identical to
 *       POSIX, so the pread/pwrite/preadv/fsync slots delegate to the POSIX
 *       driver; the only block-specific behaviour is `fstat`, which reports the
 *       true device capacity via BLKGETSIZE64 (a block device's struct.st_size is
 *       0), and `open`, which never creates or truncates the device.
 * WHY:  block was previously implemented only in client/lib/vfs_block.c — a
 *       second storage driver outside src/. This is the single home: both the
 *       client (block:// copy endpoints) and, in future, a block-backed server
 *       export use the same driver. ngx-free (dual-build via sd.h's
 *       XRDPROTO_NO_NGX fallback) so the client links it from libxrdproto.
 * HOW:  flat, POD-pointer-only vtable; no instance/namespace ops (a block device
 *       has no directory namespace). The unconfined open helper mirrors
 *       brix_sd_posix_open_unconfined but is exposed under the block name for
 *       call-site clarity.
 */
#include "fs/backend/sd.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>   /* BLKGETSIZE64 */
#endif

/* Raw byte I/O == POSIX: delegate to the POSIX driver's slots so the syscall
 * loop policy stays single-sourced (vfs_core) and there is no second copy. */
static ssize_t
sd_block_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return brix_sd_posix_driver.pread(obj, buf, len, off);
}

static ssize_t
sd_block_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    return brix_sd_posix_driver.pwrite(obj, buf, len, off);
}

static ssize_t
sd_block_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    return brix_sd_posix_driver.preadv(obj, iov, iovcnt, off);
}

static ssize_t
sd_block_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    return brix_sd_posix_driver.preadv2(obj, iov, iovcnt, off, flags);
}

static ngx_int_t
sd_block_fsync(brix_sd_obj_t *obj)
{
    return brix_sd_posix_driver.fsync(obj);
}

/* sd_block_fstat — like POSIX fstat, but a block device reports st_size == 0, so
 * query the real capacity via BLKGETSIZE64 when the fd is a block device. */
static ngx_int_t
sd_block_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sb.st_size;
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->mode   = sb.st_mode;
    out->ino    = sb.st_ino;
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

/* brix_sd_block_open_unconfined — open a block device (no O_CREAT/O_TRUNC: the
 * device exists and must not be re-created or zeroed). Returns an fd or -1. */
int
brix_sd_block_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    /* Strip create/truncate intent — a block device is opened in place. */
    sd_flags &= ~(BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC);
    return brix_sd_posix_open_unconfined(path, sd_flags, mode);
}

/* The block driver: raw-I/O caps only (random write/range read, a real fd), no
 * truncate, no directories, no rename, no xattr, no staged commit. */
const brix_sd_driver_t brix_sd_block_driver = {
    .name = "block",
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_RANDOM_WRITE
          | BRIX_SD_CAP_RANGE_READ,
    .pread    = sd_block_pread,
    .pwrite   = sd_block_pwrite,
    .preadv   = sd_block_preadv,
    .preadv2  = sd_block_preadv2,
    .fsync    = sd_block_fsync,
    .fstat    = sd_block_fstat,
};
