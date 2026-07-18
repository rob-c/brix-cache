/*
 * sd_pblock_io.c — worker-safe byte I/O for the pblock storage driver.
 *
 * WHAT: Implements the data-plane vtable slots of brix_sd_pblock_driver:
 *       pread/pwrite, the vectored preadv/preadv2, copy_range, the sendfile-fd
 *       selector, ftruncate, fsync and fstat. These map a byte range across an
 *       object's fixed-size block files (holes read as zeros) and keep the cached
 *       size/mtime coherent, flushing dirty metadata to the catalog on fsync.
 *
 * WHY:  Split out of sd_pblock.c (phase-79) so every pblock file stays under the
 *       ~500-line, one-concept cap. This is the hot path — block-file reads and
 *       writes with no SQLite work — kept separate from the object lifecycle and
 *       namespace concerns. All functions are non-static because the driver
 *       descriptor in sd_pblock.c names them (and the object-open O_TRUNC path
 *       calls sd_pblock_ftruncate); declarations live in sd_pblock_internal.h.
 *
 * HOW:  Each object's block 0 is the persistently-open obj->fd; higher blocks are
 *       opened transiently per I/O through the packed-block engine (pblock_store.h).
 *       Reads clamp to the cached size (EOF → 0); writes advance the cached
 *       high-water size and set the dirty flag. ngx-free (libc + the block engine)
 *       so the module and the standalone unit test compile it identically. Gated
 *       by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* preadv2(2) (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"
#include "pblock_fault.h"        /* Phase-83 lab fault injection + I/O shaping */
#include "pblock_csi.h"          /* Phase-83 F3 per-block CRC32c integrity */
#include "pblock_quota.h"        /* Phase-83 F5 quotas + space accounting */
#include "pblock_locks.h"        /* Phase-83 F15 range-lease snapshot check */
#include "core/compat/wverify.h" /* Phase-83 F10 whole-object CRC accumulator */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/uio.h>

/* ---- worker-safe raw byte I/O (block files; no SQLite on the hot path) ----- */

ssize_t
sd_pblock_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    pblock_obj_t *os = obj->state;
    size_t        avail;

    if (off < 0 || off >= os->meta.size) {
        return 0;                          /* at/after EOF */
    }
    avail = (size_t) (os->meta.size - off);
    if (len > avail) {
        len = avail;
    }
    if (len == 0) {
        return 0;
    }
    if (os->lab != NULL) {                       /* Phase-83 F1/F8 */
        int e = pblock_lab_io_gate(os->lab, 0, &len, off);

        if (e != 0) {
            errno = e;
            return -1;
        }
        if (len == 0) {
            return 0;
        }
    }
    {
        ssize_t n = pblock_read_blocks(os->st, os->blob_id, os->block_size,
                                       obj->fd, buf, len, off);

        if (n > 0 && os->st->csi                     /* F3: at-rest integrity */
            && pblock_csi_verify(os->csi_crc, os->csi_n, os->block_size,
                                 os->meta.size, buf, off, (size_t) n,
                                 os->csi_dlo, os->csi_dhi) != 0)
        {
            return -1;                               /* errno=EIO; never serve  *
                                                      * corrupt bytes            */
        }
        if (n > 0 && os->st->audit) {                /* F17: fold into close */
            int64_t last = pblock_last_block(off + n, os->block_size) + 1;

            os->a_rbytes += n;
            if (last > os->a_maxblock) {
                os->a_maxblock = last;
            }
        }
        return n;
    }
}

ssize_t
sd_pblock_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    pblock_obj_t *os = obj->state;
    ssize_t       n;

    if (len == 0) {
        return 0;
    }
    if (os->lab != NULL) {                       /* Phase-83 F1/F8 */
        int e = pblock_lab_io_gate(os->lab, 1, &len, off);

        if (e != 0) {
            errno = e;
            return -1;
        }
        if (len == 0) {
            return 0;
        }
    }
    if ((int64_t) off + (int64_t) len > os->quota_max) {     /* F5 */
        errno = EDQUOT;
        return -1;
    }
    if (os->lock_n && pblock_locks_range_denied(os, off, len)) {   /* F15 */
        errno = EBUSY;
        return -1;
    }
    n = pblock_write_blocks(os->st, os->blob_id, os->block_size, obj->fd,
                            buf, len, off);
    if (n > 0) {
        os->meta.mtime = pblock_now();
        if ((int64_t) off + n > os->meta.size) {
            os->meta.size = (int64_t) off + n;
        }
        os->dirty = 1;
        if (os->wv != NULL) {                        /* F10: grow the dedup CRC */
            (void) brix_wverify_update(os->wv, buf, off, (size_t) n);
        }
        if (os->st->csi) {                           /* F3: widen written extent */
            int64_t fb = off / os->block_size;
            int64_t lb = (off + n - 1) / os->block_size;

            if (fb < os->csi_dlo) {
                os->csi_dlo = fb;
            }
            if (lb + 1 > os->csi_dhi) {
                os->csi_dhi = lb + 1;
            }
        }
        if (os->st->audit) {                         /* F17: fold into close */
            int64_t last = pblock_last_block(off + n, os->block_size) + 1;

            os->a_wbytes += n;
            if (last > os->a_maxblock) {
                os->a_maxblock = last;
            }
        }
        pblock_lab_crash(os->st->lab, "after_block_write");   /* F7 */
    }
    return n;
}

/* sd_pblock_preadv — vectored read as a loop of the block-aware pread (stops at
 * the first short/EOF segment); bytes read or -1. */
ssize_t
sd_pblock_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t total = 0;
    int     i;

    for (i = 0; i < iovcnt; i++) {
        ssize_t n = sd_pblock_pread(obj, iov[i].iov_base, iov[i].iov_len,
                                    off + total);

        if (n < 0) {
            return total ? total : -1;
        }
        total += n;
        if ((size_t) n < iov[i].iov_len) {
            break;                         /* short read / EOF */
        }
    }
    return total;
}

ssize_t
sd_pblock_preadv2(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{
    (void) flags;   /* RWF_* flags not distinguished by this backend */
    return sd_pblock_preadv(obj, iov, iovcnt, off);
}

/* sd_pblock_copy_range — copy up to `len` bytes src->dst through a bounded
 * userspace buffer (blocks straddle file boundaries, so copy_file_range across
 * whole objects does not apply). The VFS owns the outer loop; one call copies up
 * to the buffer size. Returns bytes copied (0 = src EOF) or -1. */
ssize_t
sd_pblock_copy_range(brix_sd_obj_t *src, off_t src_off, brix_sd_obj_t *dst,
    off_t dst_off, size_t len)
{
    pblock_obj_t *sos = src->state;
    pblock_obj_t *dos = dst->state;
    char          buf[65536];
    size_t        chunk = len < sizeof(buf) ? len : sizeof(buf);
    ssize_t       r, w;

    if (src_off < 0 || src_off >= sos->meta.size) {
        return 0;
    }
    if (chunk > (size_t) (sos->meta.size - src_off)) {
        chunk = (size_t) (sos->meta.size - src_off);
    }
    if (chunk == 0) {
        return 0;
    }

    r = pblock_read_blocks(sos->st, sos->blob_id, sos->block_size, src->fd,
                           buf, chunk, src_off);
    if (r <= 0) {
        return r;
    }
    if ((int64_t) dst_off + r > dos->quota_max) {            /* F5 */
        errno = EDQUOT;
        return -1;
    }
    if (dos->lock_n
        && pblock_locks_range_denied(dos, dst_off, (size_t) r))    /* F15 */
    {
        errno = EBUSY;
        return -1;
    }
    w = pblock_write_blocks(dos->st, dos->blob_id, dos->block_size, dst->fd,
                            buf, (size_t) r, dst_off);
    if (w > 0) {
        dos->meta.mtime = pblock_now();
        if ((int64_t) dst_off + w > dos->meta.size) {
            dos->meta.size = (int64_t) dst_off + w;
        }
        dos->dirty = 1;
        if (dos->wv != NULL) {                       /* F10: grow the dedup CRC */
            (void) brix_wverify_update(dos->wv, buf, dst_off, (size_t) w);
        }
    }
    return w;
}

/* sd_pblock_read_sendfile_fd — zero-copy only for an offset-0 range that lies
 * within block 0 (the persistently-open obj->fd): small files and the start of
 * large ones. Multi-block ranges return NGX_INVALID_FILE (served memory-backed)
 * until the VFS read path is block-aware. */
ngx_fd_t
sd_pblock_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    pblock_obj_t *os = obj->state;

    if (!want_zerocopy || obj->fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    if (pblock_xform_active(&os->st->xform)) {
        return NGX_INVALID_FILE;   /* F12/F13: block 0 holds transformed bytes */
    }
    if (off == 0 && (int64_t) len <= os->block_size) {
        return obj->fd;
    }
    return NGX_INVALID_FILE;
}

ngx_int_t
sd_pblock_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    pblock_obj_t *os = obj->state;
    int64_t       bs = os->block_size;
    int64_t       old_last = pblock_last_block(os->meta.size, bs);
    int64_t       keep = pblock_last_block(len, bs);
    int64_t       boundary = (int64_t) len - keep * bs;   /* bytes kept in `keep` */
    int64_t       i;
    int           fd, transient = 0;

    /* F12/F13: transformed blocks carry a header — trim the boundary block by
     * re-encoding its surviving logical prefix, not a raw ftruncate. */
    if (pblock_xform_active(&os->st->xform)) {
        unsigned char *scratch = malloc((size_t) bs);
        char           bp[PATH_MAX];
        uint32_t       llen;

        if (scratch == NULL) {
            return NGX_ERROR;
        }
        if (pblock_block_path(os->st, os->blob_id, keep, bp, sizeof(bp)) != 0
            || pblock_xform_block_load(&os->st->xform, keep, bp, scratch, bs,
                                       &llen) != 0
            || pblock_xform_block_store(&os->st->xform, keep, bp, scratch,
                                        (uint32_t) boundary, bs) != 0)
        {
            free(scratch);
            return NGX_ERROR;
        }
        free(scratch);
        for (i = keep + 1; i <= old_last; i++) {
            if (pblock_block_path(os->st, os->blob_id, i, bp, sizeof(bp)) == 0) {
                unlink(bp);
            }
        }
        os->meta.size  = (int64_t) len;
        os->meta.mtime = pblock_now();
        os->dirty      = 1;
        return NGX_OK;
    }

    /* trim the boundary block to its surviving length */
    if (keep == 0) {
        fd = obj->fd;
    } else {
        char bp[PATH_MAX];

        if (pblock_block_path(os->st, os->blob_id, keep, bp, sizeof(bp)) != 0) {
            return NGX_ERROR;
        }
        fd = open(bp, O_RDWR | O_CREAT, 0600);
        if (fd < 0) {
            return NGX_ERROR;
        }
        transient = 1;
    }
    if (ftruncate(fd, (off_t) boundary) != 0) {
        if (transient) {
            close(fd);
        }
        return NGX_ERROR;
    }
    if (transient) {
        close(fd);
    }

    /* drop whole blocks past the new size */
    for (i = keep + 1; i <= old_last; i++) {
        char bp[PATH_MAX];

        if (pblock_block_path(os->st, os->blob_id, i, bp, sizeof(bp)) == 0) {
            unlink(bp);
        }
    }

    os->meta.size  = (int64_t) len;
    os->meta.mtime = pblock_now();
    os->dirty      = 1;
    return NGX_OK;
}

/* sd_pblock_fsync — durability barrier: fsync every block file backing the
 * object, then flush dirty size/mtime to the catalog. */
ngx_int_t
sd_pblock_fsync(brix_sd_obj_t *obj)
{
    pblock_obj_t *os = obj->state;
    int64_t       last = pblock_last_block(os->meta.size, os->block_size);
    int64_t       i;

    if (obj->fd != NGX_INVALID_FILE && fsync(obj->fd) != 0) {
        return NGX_ERROR;
    }
    for (i = 1; i <= last; i++) {
        char bp[PATH_MAX];
        int  fd;

        if (pblock_block_path(os->st, os->blob_id, i, bp, sizeof(bp)) != 0) {
            continue;
        }
        fd = open(bp, O_RDONLY);
        if (fd >= 0) {
            if (fsync(fd) != 0) {
                close(fd);
                return NGX_ERROR;
            }
            close(fd);
        }
    }

    if (os->dirty) {
        if (pblock_quota_touch_admit(os->st, os->path, os->meta.uid,
                                     os->meta.size) != 0             /* F5 */
            || pblock_catalog_touch(os->st->cat, os->path, os->meta.size,
                                 os->meta.mtime) != 0)
        {
            return NGX_ERROR;
        }
        os->dirty = 0;
    }
    return NGX_OK;
}

ngx_int_t
sd_pblock_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    pblock_obj_t *os = obj->state;

    pblock_fill_sd_stat(&os->meta, os->path, out);
    return NGX_OK;
}

#endif /* BRIX_HAVE_SQLITE */
