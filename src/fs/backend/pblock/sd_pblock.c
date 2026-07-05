/*
 * sd_pblock.c — the pblock ("pseudo-block") Storage Driver: a full-capability,
 * block-based drop-in for POSIX.
 *
 * WHAT: Implements brix_sd_pblock_driver, a complete backend that stores each
 *       object's bytes striped across fixed-size POSIX "block" files and the
 *       entire logical namespace + metadata in a SQLite catalog
 *       (sd_pblock_catalog.c). It advertises the same capabilities as the POSIX
 *       driver and implements every vtable slot.
 *
 * WHY:  Striping bulk content into fixed-size blocks (default 64 MiB, set per
 *       file at creation and configurable per export) is the defining property
 *       of a block backend, and splitting that content from the namespace/
 *       metadata keeps the hot byte path free of any database work. SQLite is
 *       touched only at metadata boundaries.
 *
 * HOW:  An object's bytes live at <data>/<aa>/<bb>/<blob_id>/<block_index>;
 *       block 0 is opened persistently as obj->fd (so small files keep a real
 *       fd for zero-copy sendfile), and higher blocks are opened transiently per
 *       I/O. Reads/writes map [off,off+len) across blocks (holes read as zeros);
 *       writes update the cached size/mtime in memory and flush to the catalog
 *       on fsync/close. The whole file is ngx-free (libc + sqlite, malloc-owned
 *       state) so it is identical in the module and the standalone unit test.
 *       Compiled only when the build found libsqlite3 (BRIX_HAVE_SQLITE).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* preadv2(2) (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

/* ---- driver-private state ------------------------------------------------- */


/* Per-open object state (obj->state); obj->fd is the block-0 fd (or INVALID for
 * directories). Higher blocks are opened transiently per I/O. */
typedef struct {
    pblock_state_t *st;                   /* borrowed from inst->state */
    char            path[PATH_MAX];       /* logical path (catalog key)        */
    char            blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t         block_size;           /* this file's stripe size           */
    pblock_meta     meta;                 /* cached metadata row               */
    unsigned        dirty:1;              /* size/mtime need catalog write-back */
} pblock_obj_t;

/* Per-open directory state (dir->state). */
typedef struct {
    pblock_catalog_iter *it;
} pblock_dir_t;

/* Staged (atomic-publish) state (staged->state). */
typedef struct {
    pblock_state_t *st;
    char            final_path[PATH_MAX];
    char            blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t         block_size;
    int64_t         size;                 /* high-water mark of staged writes  */
    mode_t          mode;
} pblock_staged_t;

/* Forward declaration: open's O_TRUNC path reuses the block-aware truncate. */
static ngx_int_t sd_pblock_ftruncate(brix_sd_obj_t *obj, off_t len);


/* ---- instance lifecycle --------------------------------------------------- */

static ngx_int_t
sd_pblock_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_pblock_conf_t *conf = driver_conf;
    pblock_state_t                *st;
    char                           db[PATH_MAX];

    if (conf == NULL || conf->root == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    snprintf(st->root, sizeof(st->root), "%s", conf->root);
    snprintf(st->data_dir, sizeof(st->data_dir), "%s/data", conf->root);
    st->block_size = conf->block_size > 0 ? conf->block_size
                                          : PBLOCK_DEFAULT_BLOCK_SIZE;

    if (pblock_mkdir_p(st->root) != 0 || pblock_mkdir_p(st->data_dir) != 0) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    snprintf(db, sizeof(db), "%s/catalog.db", conf->root);
    st->cat = pblock_catalog_open(db, conf->busy_timeout_ms);
    if (st->cat == NULL) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    /* The export root "/" always exists (a directory), like a POSIX mount point —
     * so stat("/")/opendir("/")/PROPFIND on the root succeed before anything is
     * written. Created once; harmless if a concurrent worker also creates it. */
    if (pblock_catalog_lookup(st->cat, "/", NULL) == 1) {
        pblock_meta root_meta;

        memset(&root_meta, 0, sizeof(root_meta));
        root_meta.is_dir = 1;
        root_meta.mtime  = root_meta.ctime = pblock_now();
        root_meta.mode   = S_IFDIR | 0755;
        (void) pblock_catalog_put(st->cat, "/", &root_meta);
    }

    inst->state = st;
    return NGX_OK;
}

static void
sd_pblock_cleanup(brix_sd_instance_t *inst)
{
    pblock_state_t *st = inst->state;

    if (st != NULL) {
        pblock_catalog_close(st->cat);
        free(st);
        inst->state = NULL;
    }
}

/* ---- object lifecycle ----------------------------------------------------- */

/* pblock_make_obj — wrap a block-0 fd + cached metadata in a heap object. On
 * failure the fd is closed and NULL/errno returned. */
static brix_sd_obj_t *
pblock_make_obj(brix_sd_instance_t *inst, const char *path, int fd,
    const pblock_meta *meta)
{
    brix_sd_obj_t *obj;
    pblock_obj_t    *os;

    obj = calloc(1, sizeof(*obj));
    os  = calloc(1, sizeof(*os));
    if (obj == NULL || os == NULL) {
        free(obj);
        free(os);
        if (fd >= 0) {
            close(fd);
        }
        errno = ENOMEM;
        return NULL;
    }

    os->st         = inst->state;
    os->meta       = *meta;
    os->block_size = meta->block_size;
    snprintf(os->path, sizeof(os->path), "%s", path);
    snprintf(os->blob_id, sizeof(os->blob_id), "%s", meta->blob_id);

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = fd >= 0 ? fd : NGX_INVALID_FILE;
    obj->state      = os;
    obj->heap_shell = 1;   /* malloc'd shell; a VFS adopter frees it after copy */

    /* Capture the open-time metadata snapshot the VFS reports to callers (file
     * size, mode, mtime) — without this the adopting handle would see a zeroed
     * snap and treat the file as empty (immediate EOF on read). */
    ngx_memzero(&obj->snap, sizeof(obj->snap));
    obj->snap.size   = meta->size;
    obj->snap.mtime  = meta->mtime;
    obj->snap.ctime  = meta->ctime;
    obj->snap.mode   = meta->mode;
    obj->snap.ino    = (ino_t) pblock_fnv(path);
    obj->snap.is_dir = meta->is_dir ? 1 : 0;
    obj->snap.is_reg = meta->is_dir ? 0 : 1;
    return obj;
}

/* pblock_open_create — create a brand-new file: a fresh per-object dir + block 0,
 * plus its catalog row. Returns the object or NULL/errno (*err_out set). */
static brix_sd_obj_t *
pblock_open_create(brix_sd_instance_t *inst, const char *path, mode_t mode,
    int *err_out)
{
    pblock_state_t  *st = inst->state;
    pblock_meta      meta;
    brix_sd_obj_t *obj;
    char             block0[PATH_MAX];
    int              fd;

    memset(&meta, 0, sizeof(meta));
    if (pblock_gen_blob_id(meta.blob_id) != 0
        || pblock_ensure_obj_dir(st, meta.blob_id) != 0
        || pblock_block_path(st, meta.blob_id, 0, block0, sizeof(block0)) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    fd = open(block0, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    meta.is_dir     = 0;
    meta.size       = 0;
    meta.block_size = st->block_size;
    meta.mtime      = meta.ctime = pblock_now();
    meta.mode       = S_IFREG | (mode & 0777);

    if (pblock_catalog_put(st->cat, path, &meta) != 0) {
        int err = errno;

        close(fd);
        pblock_remove_blocks(st, meta.blob_id, 0, st->block_size);
        if (err_out != NULL) { *err_out = err; }
        return NULL;
    }

    obj = pblock_make_obj(inst, path, fd, &meta);
    if (obj == NULL && err_out != NULL) {
        *err_out = errno;
    }
    return obj;
}

/* pblock_open_existing — open an existing file's block 0; honours O_TRUNC on
 * write via the block-aware truncate. Returns the object or NULL/errno. */
static brix_sd_obj_t *
pblock_open_existing(brix_sd_instance_t *inst, const char *path,
    pblock_meta *meta, int sd_flags, int *err_out)
{
    pblock_state_t  *st = inst->state;
    brix_sd_obj_t *obj;
    char             block0[PATH_MAX];
    int              want_write = sd_flags & BRIX_SD_O_WRITE;
    int              fd;

    if (pblock_block_path(st, meta->blob_id, 0, block0, sizeof(block0)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    fd = open(block0, want_write ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    obj = pblock_make_obj(inst, path, fd, meta);
    if (obj == NULL) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    if (want_write && (sd_flags & BRIX_SD_O_TRUNC) && meta->size > 0) {
        if (sd_pblock_ftruncate(obj, 0) != NGX_OK) {
            int err = errno;

            obj->driver->close(obj);   /* frees state + closes fd */
            free(obj);                 /* … and the malloc'd shell */
            if (err_out != NULL) { *err_out = err; }
            return NULL;
        }
    }
    return obj;
}

static brix_sd_obj_t *
sd_pblock_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    if (rc == 0 && meta.is_dir) {
        if (sd_flags & BRIX_SD_O_WRITE) {
            if (err_out != NULL) { *err_out = EISDIR; }
            return NULL;
        }
        return pblock_make_obj(inst, path, NGX_INVALID_FILE, &meta);
    }

    if (rc == 0) {   /* existing file */
        if ((sd_flags & BRIX_SD_O_CREATE) && (sd_flags & BRIX_SD_O_EXCL)) {
            if (err_out != NULL) { *err_out = EEXIST; }
            return NULL;
        }
        return pblock_open_existing(inst, path, &meta, sd_flags, err_out);
    }

    /* absent */
    if (!(sd_flags & BRIX_SD_O_CREATE)) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    return pblock_open_create(inst, path, mode, err_out);
}

static ngx_int_t
sd_pblock_close(brix_sd_obj_t *obj)
{
    pblock_obj_t *os;
    ngx_int_t     rc = NGX_OK;

    if (obj == NULL) {
        return NGX_OK;
    }
    os = obj->state;

    if (os != NULL && os->dirty) {
        if (pblock_catalog_touch(os->st->cat, os->path, os->meta.size,
                                 os->meta.mtime) != 0)
        {
            rc = NGX_ERROR;
        }
        os->dirty = 0;
    }
    if (obj->fd != NGX_INVALID_FILE) {
        if (close(obj->fd) != 0) {
            rc = NGX_ERROR;
        }
        obj->fd = NGX_INVALID_FILE;
    }
    free(os);
    obj->state = NULL;
    /* The obj shell is NOT freed here: it may be embedded in the adopter's
     * handle (the VFS copies *obj by value). Its owner — the VFS adopter (via
     * obj->heap_shell), the internal open-error paths, or the standalone test —
     * frees the malloc'd shell. */
    return rc;
}

/* ---- worker-safe raw byte I/O (block files; no SQLite on the hot path) ----- */

static ssize_t
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
    return pblock_read_blocks(os->st, os->blob_id, os->block_size, obj->fd,
                              buf, len, off);
}

static ssize_t
sd_pblock_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    pblock_obj_t *os = obj->state;
    ssize_t       n;

    if (len == 0) {
        return 0;
    }
    n = pblock_write_blocks(os->st, os->blob_id, os->block_size, obj->fd,
                            buf, len, off);
    if (n > 0) {
        os->meta.mtime = pblock_now();
        if ((int64_t) off + n > os->meta.size) {
            os->meta.size = (int64_t) off + n;
        }
        os->dirty = 1;
    }
    return n;
}

/* sd_pblock_preadv — vectored read as a loop of the block-aware pread (stops at
 * the first short/EOF segment); bytes read or -1. */
static ssize_t
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

static ssize_t
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
static ssize_t
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
    w = pblock_write_blocks(dos->st, dos->blob_id, dos->block_size, dst->fd,
                            buf, (size_t) r, dst_off);
    if (w > 0) {
        dos->meta.mtime = pblock_now();
        if ((int64_t) dst_off + w > dos->meta.size) {
            dos->meta.size = (int64_t) dst_off + w;
        }
        dos->dirty = 1;
    }
    return w;
}

/* sd_pblock_read_sendfile_fd — zero-copy only for an offset-0 range that lies
 * within block 0 (the persistently-open obj->fd): small files and the start of
 * large ones. Multi-block ranges return NGX_INVALID_FILE (served memory-backed)
 * until the VFS read path is block-aware. */
static ngx_fd_t
sd_pblock_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy)
{
    pblock_obj_t *os = obj->state;

    if (!want_zerocopy || obj->fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    if (off == 0 && (int64_t) len <= os->block_size) {
        return obj->fd;
    }
    return NGX_INVALID_FILE;
}

static ngx_int_t
sd_pblock_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    pblock_obj_t *os = obj->state;
    int64_t       bs = os->block_size;
    int64_t       old_last = pblock_last_block(os->meta.size, bs);
    int64_t       keep = pblock_last_block(len, bs);
    int64_t       boundary = (int64_t) len - keep * bs;   /* bytes kept in `keep` */
    int64_t       i;
    int           fd, transient = 0;

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
static ngx_int_t
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
        if (pblock_catalog_touch(os->st->cat, os->path, os->meta.size,
                                 os->meta.mtime) != 0)
        {
            return NGX_ERROR;
        }
        os->dirty = 0;
    }
    return NGX_OK;
}

static ngx_int_t
sd_pblock_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    pblock_obj_t *os = obj->state;

    pblock_fill_sd_stat(&os->meta, os->path, out);
    return NGX_OK;
}

/* ---- namespace ------------------------------------------------------------ */

static ngx_int_t
sd_pblock_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    pblock_fill_sd_stat(&meta, path, out);
    return NGX_OK;
}

static ngx_int_t
sd_pblock_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }

    if (is_dir) {
        int children;

        if (!meta.is_dir) {
            errno = ENOTDIR;
            return NGX_ERROR;
        }
        children = pblock_catalog_child_count(st->cat, path);
        if (children < 0) {
            return NGX_ERROR;
        }
        if (children > 0) {
            errno = ENOTEMPTY;
            return NGX_ERROR;
        }
    } else if (meta.is_dir) {
        errno = EISDIR;
        return NGX_ERROR;
    }

    if (!meta.is_dir) {
        pblock_remove_blocks(st, meta.blob_id, meta.size, meta.block_size);
    }
    return pblock_catalog_remove(st->cat, path) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_pblock_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;

    memset(&meta, 0, sizeof(meta));
    meta.is_dir = 1;
    meta.mtime  = meta.ctime = pblock_now();
    meta.mode   = S_IFDIR | (mode & 0777);
    /* One INSERT — the PRIMARY KEY constraint is the existence check (EEXIST),
     * so no separate lookup is needed. */
    return pblock_catalog_create(st->cat, path, &meta) == 0 ? NGX_OK : NGX_ERROR;
}

/* sd_pblock_setattr — apply kXR_chmod (mode) and/or kXR_setattr (times) to an
 * existing catalog row. The catalog records mode + mtime + ctime, so those are
 * honoured; it has no owner (uid/gid) or atime columns, so set_owner and atime
 * are accepted-and-ignored (object-store semantics) rather than failing — a chown
 * an export cannot represent should not break the op. ctime is bumped on any
 * change, matching POSIX. lookup→modify→put reuses the upsert path. */
static ngx_int_t
sd_pblock_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    pblock_state_t *st = inst->state;
    int             set_mtime = 0;
    int64_t         mtime = 0;

    if (attr->set_times && attr->mtime.tv_nsec != UTIME_OMIT) {
        set_mtime = 1;
        mtime = (attr->mtime.tv_nsec == UTIME_NOW)
                ? pblock_now() : (int64_t) attr->mtime.tv_sec;
    }

    /* One UPDATE — no read-modify-write. ENOENT (rc<0 with errno) when absent. */
    return pblock_catalog_setattr(st->cat, path, attr->set_mode ? 1 : 0,
               attr->mode & 0777, set_mtime, mtime, pblock_now()) == 0
           ? NGX_OK : NGX_ERROR;
}

/* sd_pblock_drop_dst — clear an existing rename/copy destination: reject a
 * non-empty directory, remove a file's blocks, then drop the catalog row. */
static ngx_int_t
sd_pblock_drop_dst(pblock_state_t *st, const char *dst,
    const pblock_meta *dmeta)
{
    if (dmeta->is_dir) {
        int children = pblock_catalog_child_count(st->cat, dst);

        if (children < 0) {
            return NGX_ERROR;
        }
        if (children > 0) {
            errno = ENOTEMPTY;
            return NGX_ERROR;
        }
    } else {
        pblock_remove_blocks(st, dmeta->blob_id, dmeta->size,
                             dmeta->block_size);
    }
    return pblock_catalog_remove(st->cat, dst) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_pblock_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    pblock_state_t *st = inst->state;
    pblock_meta     dmeta;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, src, NULL);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }

    rc = pblock_catalog_lookup(st->cat, dst, &dmeta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 0) {
        if (noreplace) {
            errno = EEXIST;
            return NGX_ERROR;
        }
        if (sd_pblock_drop_dst(st, dst, &dmeta) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Blocks are id-addressed, so moving the catalog row carries the content
     * with it (and reparents a directory subtree) without touching any bytes. */
    return pblock_catalog_rename(st->cat, src, dst) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_pblock_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    pblock_state_t *st = inst->state;
    pblock_meta     smeta, dmeta;
    int64_t         last, i;
    int             rc;

    rc = pblock_catalog_lookup(st->cat, src, &smeta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (smeta.is_dir) {
        errno = EISDIR;
        return NGX_ERROR;
    }

    memset(&dmeta, 0, sizeof(dmeta));
    if (pblock_gen_blob_id(dmeta.blob_id) != 0
        || pblock_ensure_obj_dir(st, dmeta.blob_id) != 0)
    {
        return NGX_ERROR;
    }

    last = pblock_last_block(smeta.size, smeta.block_size);
    for (i = 0; i <= last; i++) {
        char sp[PATH_MAX], dp[PATH_MAX];

        if (pblock_block_path(st, smeta.blob_id, i, sp, sizeof(sp)) != 0
            || pblock_block_path(st, dmeta.blob_id, i, dp, sizeof(dp)) != 0
            || pblock_copy_one_block(sp, dp) < 0)
        {
            int err = errno;

            pblock_remove_blocks(st, dmeta.blob_id, smeta.size,
                                 smeta.block_size);
            errno = err;
            return NGX_ERROR;
        }
    }

    dmeta.is_dir     = 0;
    dmeta.size       = smeta.size;
    dmeta.block_size = smeta.block_size;
    dmeta.mtime      = dmeta.ctime = pblock_now();
    dmeta.mode       = smeta.mode;

    if (pblock_catalog_put(st->cat, dst, &dmeta) != 0) {
        int err = errno;

        pblock_remove_blocks(st, dmeta.blob_id, smeta.size, smeta.block_size);
        errno = err;
        return NGX_ERROR;
    }
    if (bytes_out != NULL) {
        *bytes_out = (off_t) smeta.size;
    }
    return NGX_OK;
}

/* ---- directory iteration -------------------------------------------------- */

static brix_sd_dir_t *
sd_pblock_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    pblock_state_t  *st = inst->state;
    brix_sd_dir_t *dir;
    pblock_dir_t    *pd;
    pblock_meta      meta;
    int              rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (rc == 1) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    if (!meta.is_dir) {
        if (err_out != NULL) { *err_out = ENOTDIR; }
        return NULL;
    }

    dir = calloc(1, sizeof(*dir));
    pd  = calloc(1, sizeof(*pd));
    if (dir == NULL || pd == NULL) {
        free(dir);
        free(pd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    pd->it = pblock_catalog_opendir(st->cat, path);
    if (pd->it == NULL) {
        if (err_out != NULL) { *err_out = errno; }
        free(dir);
        free(pd);
        return NULL;
    }
    dir->inst  = inst;
    dir->state = pd;
    return dir;
}

static ngx_int_t
sd_pblock_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    pblock_dir_t *pd = d->state;
    int           rc = pblock_catalog_readdir(pd->it, out->name,
                                              sizeof(out->name));

    if (rc < 0) {
        return NGX_ERROR;
    }
    return rc == 1 ? NGX_DONE : NGX_OK;
}

static ngx_int_t
sd_pblock_closedir(brix_sd_dir_t *d)
{
    pblock_dir_t *pd = d->state;

    if (pd != NULL) {
        pblock_catalog_closedir(pd->it);
        free(pd);
    }
    free(d);
    return NGX_OK;
}

/* ---- xattr ---------------------------------------------------------------- */

static ssize_t
sd_pblock_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_getxattr(st->cat, path, name, buf, cap);
}

static ssize_t
sd_pblock_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_listxattr(st->cat, path, buf, cap);
}

static ngx_int_t
sd_pblock_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    pblock_state_t *st = inst->state;

    (void) flags;   /* XATTR_CREATE/REPLACE not distinguished by this backend */
    return pblock_catalog_setxattr(st->cat, path, name, val, len) == 0
               ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sd_pblock_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_removexattr(st->cat, path, name) == 0
               ? NGX_OK : NGX_ERROR;
}

/* ---- staged atomic publish ------------------------------------------------ */

static brix_sd_staged_t *
sd_pblock_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    pblock_state_t     *st = inst->state;
    brix_sd_staged_t *handle;
    pblock_staged_t    *ps;

    /* POSIX parity with the posix driver's staged temp (O_EXCL in the final
     * directory): a missing parent collection fails HERE — before any blob
     * is allocated or a single body byte is accepted — not at commit. */
    if (pblock_catalog_parent_ok(st->cat, final_path) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    handle = calloc(1, sizeof(*handle));
    ps     = calloc(1, sizeof(*ps));
    if (handle == NULL || ps == NULL) {
        free(handle);
        free(ps);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (pblock_gen_blob_id(ps->blob_id) != 0
        || pblock_ensure_obj_dir(st, ps->blob_id) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        free(handle);
        free(ps);
        return NULL;
    }

    ps->st         = st;
    ps->block_size = st->block_size;
    ps->size       = 0;
    ps->mode       = mode;
    snprintf(ps->final_path, sizeof(ps->final_path), "%s", final_path);
    handle->inst  = inst;
    handle->state = ps;
    return handle;
}

static ssize_t
sd_pblock_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    pblock_staged_t *ps = st->state;
    ssize_t          n;

    n = pblock_write_blocks(ps->st, ps->blob_id, ps->block_size, -1, buf, len,
                            off);
    if (n > 0 && (int64_t) off + n > ps->size) {
        ps->size = (int64_t) off + n;
    }
    return n;
}

/* sd_pblock_staged_commit — publish the staged blocks atomically by inserting
 * the final catalog row pointing at the staged blob id (the blocks simply become
 * the final object — no copy or rename). On success the handle is consumed; on
 * failure it stays valid and the caller must staged_abort to release it. */
static ngx_int_t
sd_pblock_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    pblock_staged_t *ps = st->state;
    pblock_state_t  *pst = ps->st;
    pblock_meta      meta, dmeta;
    int              rc;

    rc = pblock_catalog_lookup(pst->cat, ps->final_path, &dmeta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 0) {
        if (noreplace) {
            errno = EEXIST;
            return NGX_ERROR;
        }
        if (sd_pblock_drop_dst(pst, ps->final_path, &dmeta) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    memset(&meta, 0, sizeof(meta));
    meta.is_dir = 0;
    snprintf(meta.blob_id, sizeof(meta.blob_id), "%s", ps->blob_id);
    meta.size       = ps->size;
    meta.block_size = ps->block_size;
    meta.mtime      = meta.ctime = pblock_now();
    meta.mode       = S_IFREG | (ps->mode & 0777);

    if (pblock_catalog_put(pst->cat, ps->final_path, &meta) != 0) {
        return NGX_ERROR;
    }

    free(ps);
    free(st);
    return NGX_OK;
}

static void
sd_pblock_staged_abort(brix_sd_staged_t *st)
{
    pblock_staged_t *ps = st->state;

    if (ps != NULL) {
        pblock_remove_blocks(ps->st, ps->blob_id, ps->size, ps->block_size);
        free(ps);
    }
    free(st);
}

/* ---- the driver descriptor ------------------------------------------------ */

/* Full POSIX-parity capabilities: block 0 is a real kernel file, so the backend
 * is fd-backed, sendfile-able and io_uring-submittable; the catalog provides
 * atomic rename, real directories, server copy and object xattrs. */
const brix_sd_driver_t brix_sd_pblock_driver = {
    .name = "pblock",
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_SENDFILE
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_APPEND
          | BRIX_SD_CAP_IOURING | BRIX_SD_CAP_SERVER_COPY
          | BRIX_SD_CAP_XATTR | BRIX_SD_CAP_HARD_RENAME
          | BRIX_SD_CAP_DIRS,

    .init    = sd_pblock_init,
    .cleanup = sd_pblock_cleanup,
    .open    = sd_pblock_open,
    .close   = sd_pblock_close,

    .pread            = sd_pblock_pread,
    .pwrite           = sd_pblock_pwrite,
    .preadv           = sd_pblock_preadv,
    .preadv2          = sd_pblock_preadv2,
    .copy_range       = sd_pblock_copy_range,
    .read_sendfile_fd = sd_pblock_read_sendfile_fd,
    .ftruncate        = sd_pblock_ftruncate,
    .fsync            = sd_pblock_fsync,
    .fstat            = sd_pblock_fstat,

    .stat        = sd_pblock_stat,
    .unlink      = sd_pblock_unlink,
    .mkdir       = sd_pblock_mkdir,
    .rename      = sd_pblock_rename,
    .server_copy = sd_pblock_server_copy,
    .setattr     = sd_pblock_setattr,

    .opendir  = sd_pblock_opendir,
    .readdir  = sd_pblock_readdir,
    .closedir = sd_pblock_closedir,

    .getxattr    = sd_pblock_getxattr,
    .listxattr   = sd_pblock_listxattr,
    .setxattr    = sd_pblock_setxattr,
    .removexattr = sd_pblock_removexattr,

    .staged_open   = sd_pblock_staged_open,
    .staged_write  = sd_pblock_staged_write,
    .staged_commit = sd_pblock_staged_commit,
    .staged_abort  = sd_pblock_staged_abort,
};

#endif /* BRIX_HAVE_SQLITE */
