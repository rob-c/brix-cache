/* client/lib/vfs_block.c
 *
 * WHAT: Block-device storage backend for brix_vfs.
 *       Handles writes directly to block devices (or plain files used as such)
 *       — no temp file, no rename.  commit() = fsync only; abort() = no-op.
 *       Advertises RANDOM_WRITE and FADVISE but NOT TRUNCATE or ATOMIC_TEMP.
 * WHY:  Copying to a block device (/dev/sdb, loop file, etc.) requires writing
 *       in-place.  A sibling temp would need to be on the same filesystem as the
 *       device node — which is undefined — and a rename onto a device is wrong.
 * HOW:  open() for READ: O_RDONLY direct open.  open() for WRITE: O_WRONLY direct
 *       open (no O_CREAT|O_TRUNC — the device already exists and must not be
 *       re-created or zeroed; the caller supplies XRDC_VFS_FORCE to permit
 *       writing to an existing target).  An io_uring ring is optionally wrapped
 *       around the fd using the same AUTO/ON/OFF tri-state as the POSIX backend.
 *       fstat reports device size via BLKGETSIZE64 when S_ISBLK; else st_size.
 *       ngx-free; no goto; functional/modular; one responsibility per function.
 */

#include "vfs.h"
#include "core/aio/uring.h"
#include "brix.h"
#include "fs/backend/sd.h"   /* shared Storage Driver (ngx-free) */
#include "fs/core/vfs_core.h" /* shared `vfs` I/O verbs (single-sourced with the
                               * server data plane). block_fstat keeps its
                               * BLKGETSIZE64 device-size logic (block-specific). */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>   /* BLKGETSIZE64 */
#endif

/* Concrete per-handle struct */
/*
 * vfs_block_file — concrete file handle for the block-device backend.
 *
 * WHAT: extends brix_vfs_file with the fd and optional ring.
 *       No temp/final path fields are needed (in-place write, no rename).
 * HOW:  base MUST be first (struct alias cast to brix_vfs_file *).
 *       path is stored for error messages and fstat fallback.
 */
typedef struct {
    brix_vfs_file  base;      /* MUST be first — aliased by façade */
    int            fd;
    brix_disk_ring *ring;     /* NULL when io_uring is OFF or unavailable */
    char          *path;      /* heap-allocated path (for diagnostics) */
} vfs_block_file;

/* Ring selection */
/*
 * block_ring_select — attach an optional io_uring ring to an already-open fd.
 *
 * WHAT: implements the AUTO/ON/OFF tri-state, identical to the POSIX backend.
 *       OFF → *ring=NULL, return 0.
 *       ON with unavailable io_uring → *ring=NULL, return -1, st set.
 *       AUTO with unavailable io_uring → *ring=NULL, return 0 (silent fallback).
 * WHY:  mirrors posix_ring_select so the same semantics apply across backends.
 * HOW:  mode from opts->io_uring; guards brix_uring_available(); delegates to
 *       brix_disk_ring_create with a modest window (4 ops, 64 KiB each).
 */
static int
block_ring_select(int fd, int mode, brix_disk_ring **ring, brix_status *st)
{
    *ring = NULL;

    if (mode == XRDC_IO_URING_OFF) {
        return 0;
    }

    if (!brix_uring_available()) {
        if (mode == XRDC_IO_URING_ON) {
            brix_status_set(st, XRDC_EUNSUPPORTED, 0,
                            "vfs block: io_uring=on but io_uring is unavailable "
                            "on this host or this build lacks liburing");
            return -1;
        }
        return 0;   /* AUTO: classic path */
    }

    {
        brix_status tmp_st;
        brix_status_clear(&tmp_st);
        *ring = brix_disk_ring_create(fd, 4, 65536, 0, &tmp_st);
        if (*ring == NULL && mode == XRDC_IO_URING_ON) {
            if (st != NULL) {
                *st = tmp_st;
            }
            return -1;
        }
        /* AUTO: create failure leaves *ring NULL → classic pread/pwrite */
    }
    return 0;
}

/* vtable operations */
/*
 * block_pread — read n bytes at offset off into buf.
 *
 * WHAT: delegates to the ring when present; falls back to plain pread(2).
 * WHY:  single dispatch point — callers never see the ring vs. plain difference.
 * HOW:  ring path: brix_disk_ring_pread; plain path: pread(2) with EINTR retry.
 */
static ssize_t
block_pread(brix_vfs_file *f, int64_t off, void *buf, size_t n, brix_status *st)
{
    vfs_block_file *bf = (vfs_block_file *) f;

    if (bf->ring != NULL) {
        return brix_disk_ring_pread(bf->ring, off, (uint8_t *) buf, n, st);
    }

    {
        brix_sd_obj_t obj;
        ssize_t         r;

        brix_sd_posix_wrap(&obj, bf->fd);
        r = xvfs_pread_once(&obj, buf, n, (off_t) off);
        if (r < 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block pread: %s", strerror(errno));
        }
        return r;
    }
}

/*
 * block_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: delegates to the ring when present; falls back to plain pwrite(2).
 * WHY:  single dispatch point; ring path avoids blocking device writes.
 * HOW:  ring path: split into ring-buffer-sized pieces (brix_disk_ring_pwrite
 *       requires n <= the ring's per-op buffer size; the caller — transfer_pump
 *       — may supply XRDC_COPY_CHUNK = 8 MiB which far exceeds the 64 KiB
 *       ring buffer).  Plain path: pwrite(2) retry loop.
 */
static int
block_pwrite(brix_vfs_file *f, int64_t off, const void *buf, size_t n,
             brix_status *st)
{
    vfs_block_file *bf = (vfs_block_file *) f;

    if (bf->ring != NULL) {
        const uint8_t *p   = (const uint8_t *) buf;
        size_t         rem = n;
        size_t         rsz = brix_disk_ring_bufsz(bf->ring);

        while (rem > 0) {
            size_t chunk = rem < rsz ? rem : rsz;
            if (brix_disk_ring_pwrite(bf->ring, off, p, chunk, st) != 0) {
                return -1;
            }
            p   += chunk;
            off += (int64_t) chunk;
            rem -= chunk;
        }
        return 0;
    }

    {
        brix_sd_obj_t obj;

        brix_sd_posix_wrap(&obj, bf->fd);
        if (xvfs_pwrite_full(&obj, buf, n, (off_t) off, NULL, NULL) != 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block pwrite: %s", strerror(errno));
            return -1;
        }
        return 0;
    }
}


/*
 * block_fstat — fill *out with size, mtime, is_dir, exists for the open handle.
 *
 * WHAT: calls fstat(2); for block devices (S_ISBLK) queries BLKGETSIZE64 for
 *       the real device size; for other files uses st_size.
 * WHY:  block devices report st_size==0 from fstat; the ioctl gives the real
 *       capacity for copy-progress accounting.
 * HOW:  fstat; if S_ISBLK → BLKGETSIZE64 (with fallback to st_size); populate out.
 */
static int
block_fstat(brix_vfs_file *f, brix_vfs_stat *out, brix_status *st)
{
    vfs_block_file  *bf = (vfs_block_file *) f;
    brix_sd_obj_t  obj;
    brix_sd_stat_t sd;

    /* The shared block driver's fstat applies BLKGETSIZE64 for a device's true
     * size (fd-keyed; the obj wrap's driver is irrelevant for fstat). */
    brix_sd_posix_wrap(&obj, bf->fd);
    if (brix_sd_block_driver.fstat(&obj, &sd) != NGX_OK) {
        brix_status_set(st, XRDC_EIO, errno,
                        "vfs block fstat: %s", strerror(errno));
        return -1;
    }

    out->size   = (int64_t) sd.size;
    out->mtime  = (int64_t) sd.mtime;
    out->is_dir = sd.is_dir ? 1 : 0;
    out->exists = 1;
    return 0;
}

/*
 * block_truncate — rejected: block devices do not support truncation.
 *
 * WHAT: always returns -1 with XRDC_EUSAGE, because the backend does not
 *       advertise XRDC_VFS_CAP_TRUNCATE.
 * WHY:  ftruncate(2) on a block device is undefined behaviour; callers must
 *       check caps before calling truncate.  Returning a clean error here
 *       protects against callers that skip the caps check.
 * HOW:  unconditional brix_status_set + return -1.
 */
static int
block_truncate(brix_vfs_file *f, int64_t size, brix_status *st)
{
    (void) f;
    (void) size;
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "vfs block: block backend does not support truncate");
    return -1;
}

/*
 * block_sync — flush dirty pages to durable storage.
 *
 * WHAT: drains any ring write-behind queue, then calls fsync(2) on bf->fd.
 * WHY:  ensures callers can rely on data being durable after sync() returns.
 * HOW:  brix_disk_ring_flush (no-op on NULL ring); fsync; set st on failure.
 */
static int
block_sync(brix_vfs_file *f, brix_status *st)
{
    vfs_block_file *bf = (vfs_block_file *) f;

    if (bf->ring != NULL) {
        if (brix_disk_ring_flush(bf->ring, st) != 0) {
            return -1;
        }
    }

    {
        brix_sd_obj_t obj;
        brix_sd_posix_wrap(&obj, bf->fd);
        if (xvfs_fsync(&obj) != 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block fsync: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/*
 * block_commit — finalise a block write: drain ring then fsync.
 *
 * WHAT: no rename — the write was in-place.  Drains any ring queue and fsyncs
 *       to make data durable.  Identical to block_sync; kept separate so commit
 *       semantics remain explicit in the vtable.
 * WHY:  block devices have no temp-then-rename path; fsync is the commit.
 * HOW:  ring flush → fsync; return -1 with st on failure.
 */
static int
block_commit(brix_vfs_file *f, brix_status *st)
{
    vfs_block_file *bf = (vfs_block_file *) f;

    if (bf->ring != NULL) {
        if (brix_disk_ring_flush(bf->ring, st) != 0) {
            return -1;
        }
    }

    {
        brix_sd_obj_t obj;
        brix_sd_posix_wrap(&obj, bf->fd);
        if (xvfs_fsync(&obj) != 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block commit fsync: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/*
 * block_abort — no-op: there is no temp to remove.
 *
 * WHAT: does nothing; the in-place write may have partially overwritten the
 *       device, which cannot be undone without a backup.
 * WHY:  ATOMIC_TEMP is not advertised; callers that need rollback must not
 *       use this backend.
 * HOW:  unconditional no-op.
 */
static void
block_abort(brix_vfs_file *f)
{
    (void) f;
}

/*
 * block_close — release the handle: drain ring, close fd, free heap memory.
 *
 * WHAT: frees the ring (if any), closes the fd, frees the path string, and
 *       frees the handle struct.  Must be called after commit() or abort().
 * WHY:  owns all resources allocated by block_be_open(); one release point.
 * HOW:  brix_disk_ring_destroy (safe on NULL); close(fd); free path; free bf.
 */
static void
block_close(brix_vfs_file *f)
{
    vfs_block_file *bf = (vfs_block_file *) f;

    brix_disk_ring_destroy(bf->ring);

    if (bf->fd >= 0) {
        close(bf->fd);
    }

    free(bf->path);
    free(bf);
}

/* vtable singleton */
static const brix_vfs_ops s_block_ops = {
    .pread    = block_pread,
    .pwrite   = block_pwrite,
    .fstat    = block_fstat,
    .truncate = block_truncate,
    .sync     = block_sync,
    .commit   = block_commit,
    .abort    = block_abort,
    .close    = block_close,
};

/* Backend open + stat */
/*
 * block_be_open — allocate a vfs_block_file and open the underlying fd.
 *
 * WHAT: READ → open(path, O_RDONLY).  WRITE → open(path, O_WRONLY) directly,
 *       without O_CREAT|O_TRUNC (an existing device must not be re-created or
 *       zeroed; the FORCE flag permits writing to an existing path but does not
 *       change the open flags for devices).  Both paths optionally wrap the fd
 *       in an io_uring ring.
 * WHY:  block devices already exist in /dev/; creating or truncating them via
 *       O_CREAT|O_TRUNC is wrong and potentially destructive.
 * HOW:  allocate bf; open fd; ring_select; set caps.
 *       Caller receives NULL *out on any failure.
 */
static int
block_be_open(const brix_vfs_backend *be, const char *path, int flags,
              const brix_vfs_open_opts *opts, brix_vfs_file **out,
              brix_status *st)
{
    vfs_block_file *bf;
    int             fd = -1;
    char           *path_copy = NULL;
    int             uring_mode;

    (void) be;

    *out = NULL;

    uring_mode = (opts != NULL) ? opts->io_uring : XRDC_IO_URING_AUTO;

    path_copy = strdup(path);
    if (path_copy == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM,
                        "vfs block open: out of memory");
        return -1;
    }

    if (flags & XRDC_VFS_WRITE) {
        /* Open the target in place through the shared block driver. No create/
         * truncate (a device node must pre-exist and must not be zeroed);
         * O_NOFOLLOW guards against a symlink being swapped in. */
        fd = brix_sd_block_open_unconfined(path,
                 BRIX_SD_O_WRITE | BRIX_SD_O_NOFOLLOW, 0);
        if (fd < 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block open write %s: %s",
                            path, strerror(errno));
            free(path_copy);
            return -1;
        }
    } else {
        /* READ — in place through the shared block driver. */
        fd = brix_sd_block_open_unconfined(path, BRIX_SD_O_READ, 0);
        if (fd < 0) {
            brix_status_set(st, XRDC_EIO, errno,
                            "vfs block open read %s: %s",
                            path, strerror(errno));
            free(path_copy);
            return -1;
        }
    }

    bf = calloc(1, sizeof(*bf));
    if (bf == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM,
                        "vfs block open: out of memory");
        close(fd);
        free(path_copy);
        return -1;
    }

    bf->fd   = fd;
    bf->path = path_copy;
    bf->ring = NULL;

    if (block_ring_select(fd, uring_mode, &bf->ring, st) != 0) {
        close(fd);
        free(path_copy);
        free(bf);
        return -1;
    }

    bf->base.ops  = &s_block_ops;
    bf->base.caps = (XRDC_VFS_CAP_RANDOM_WRITE | XRDC_VFS_CAP_FADVISE);
    /* XRDC_VFS_CAP_TRUNCATE and XRDC_VFS_CAP_ATOMIC_TEMP are deliberately absent */

    *out = &bf->base;
    return 0;
}

/*
 * block_be_stat — stat a path by name without opening a handle.
 *
 * WHAT: calls stat(2) on path; fills brix_vfs_stat.  For block devices reports
 *       BLKGETSIZE64 size by opening the path briefly for the ioctl.
 * WHY:  allows pre-transfer existence/size checks without a full open.
 * HOW:  stat(2); ENOENT → exists=0, return 0; S_ISBLK → open+BLKGETSIZE64;
 *       other errors → -1, st.
 */
static int
block_be_stat(const brix_vfs_backend *be, const char *path,
              brix_vfs_stat *out, brix_status *st)
{
    struct stat sb;

    (void) be;

    if (stat(path, &sb) != 0) {
        if (errno == ENOENT) {
            out->exists = 0;
            out->size   = 0;
            out->mtime  = 0;
            out->is_dir = 0;
            return 0;
        }
        brix_status_set(st, XRDC_EIO, errno,
                        "vfs block stat %s: %s", path, strerror(errno));
        return -1;
    }

    if (S_ISBLK(sb.st_mode)) {
        int tmp_fd = brix_sd_block_open_unconfined(path,
                         BRIX_SD_O_READ | BRIX_SD_O_NOFOLLOW, 0);
        if (tmp_fd >= 0) {
            brix_sd_obj_t  obj;
            brix_sd_stat_t sd;
            brix_sd_posix_wrap(&obj, tmp_fd);
            if (brix_sd_block_driver.fstat(&obj, &sd) == NGX_OK
                && sd.size > 0) {
                out->size = (int64_t) sd.size;
            } else {
                out->size = (int64_t) sb.st_size;
            }
            close(tmp_fd);
        } else {
            out->size = (int64_t) sb.st_size;
        }
    } else {
        out->size = (int64_t) sb.st_size;
    }

    out->mtime  = (int64_t) sb.st_mtime;
    out->is_dir = S_ISDIR(sb.st_mode) ? 1 : 0;
    out->exists = 1;
    return 0;
}

/* Backend descriptor + accessor */
static const brix_vfs_backend s_block_backend = {
    .scheme = "block",
    .caps   = (XRDC_VFS_CAP_RANDOM_WRITE | XRDC_VFS_CAP_FADVISE),
    .open   = block_be_open,
    .stat   = block_be_stat,
};

/*
 * brix_vfs_block_backend — pure factory: return the block backend descriptor.
 *
 * WHAT: strong definition that overrides the weak stub in vfs.c; called once
 *       during vfs_init_backends() (pthread_once).  Returns the static
 *       descriptor; vfs.c's init owns the brix_vfs_register_backend() call.
 * WHY:  registration is the façade's responsibility — the accessor must not
 *       double-register (which would consume two of the 8 registry slots).
 * HOW:  return the static descriptor directly.
 */
const brix_vfs_backend *
brix_vfs_block_backend(void)
{
    return &s_block_backend;
}
