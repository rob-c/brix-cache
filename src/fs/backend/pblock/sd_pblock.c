/*
 * sd_pblock.c — the pblock ("pseudo-block") Storage Driver: a full-capability,
 * block-based drop-in for POSIX.
 *
 * WHAT: Implements brix_sd_pblock_driver, a complete backend that stores each
 *       object's bytes striped across fixed-size POSIX "block" files and the
 *       entire logical namespace + metadata in a SQLite catalog
 *       (sd_pblock_catalog.c). It advertises the same capabilities as the POSIX
 *       driver and implements every vtable slot. This file owns the instance and
 *       object lifecycle (init/cleanup, open/close and their helpers) and the
 *       driver descriptor; the byte I/O (sd_pblock_io.c), namespace/directory/
 *       xattr ops (sd_pblock_namespace.c) and staged atomic publish
 *       (sd_pblock_staged.c) live in siblings reached through
 *       sd_pblock_internal.h.
 *
 * WHY:  Striping bulk content into fixed-size blocks (default 64 MiB, set per
 *       file at creation and configurable per export) is the defining property
 *       of a block backend, and splitting that content from the namespace/
 *       metadata keeps the hot byte path free of any database work. SQLite is
 *       touched only at metadata boundaries. Split from a single 1111-line file
 *       (phase-79) to hold every pblock file under the ~500-line, one-concept cap.
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
#include "sd_pblock_internal.h"  /* shared obj state + split-out vtable slots */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/* The per-open object state (pblock_obj_t), the directory/staged state structs
 * and the split-out vtable-slot prototypes live in sd_pblock_internal.h; this
 * file keeps the instance + object lifecycle and the driver descriptor. */

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
     * written. Created once; harmless if a concurrent worker also creates it.
     * Sticky world-writable (/tmp semantics) so identity-enforced multi-user
     * exports work out of the box: anyone may create top-level entries, only
     * owners may remove them (pblock_ident_sticky_gate). Operators wanting a
     * stricter top level chmod "/" or pre-create VO directories. */
    if (pblock_catalog_lookup(st->cat, "/", NULL) == 1) {
        pblock_meta root_meta;

        memset(&root_meta, 0, sizeof(root_meta));
        root_meta.is_dir = 1;
        root_meta.mtime  = root_meta.ctime = pblock_now();
        root_meta.mode   = S_IFDIR | S_ISVTX | 0777;
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
    obj->snap.uid    = meta->uid;
    obj->snap.gid    = meta->gid;
    obj->snap.is_dir = meta->is_dir ? 1 : 0;
    obj->snap.is_reg = meta->is_dir ? 0 : 1;
    return obj;
}

/* pblock_open_create — create a brand-new file: a fresh per-object dir + block 0,
 * plus its catalog row owned by (uid, gid) — 0/0 for the service itself.
 * Returns the object or NULL/errno (*err_out set). */
static brix_sd_obj_t *
pblock_open_create(brix_sd_instance_t *inst, const char *path, mode_t mode,
    uint32_t uid, uint32_t gid, int *err_out)
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
    meta.uid        = uid;
    meta.gid        = gid;

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

/* sd_pblock_open_as — the open implementation, parameterized by the owner
 * (uid, gid) recorded on a CREATE. The plain vtable slot passes 0/0 (the
 * service); the identity-aware open_cred slot (sd_pblock_cred.c) passes the
 * requester's resolved catalog ids so new files are owned by their creator. */
brix_sd_obj_t *
sd_pblock_open_as(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
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
    return pblock_open_create(inst, path, mode, uid, gid, err_out);
}

static brix_sd_obj_t *
sd_pblock_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    /* No identity on the plain slot: creations belong to the service (0/0). */
    return sd_pblock_open_as(inst, path, sd_flags, mode, 0, 0, err_out);
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

/* ---- the driver descriptor ------------------------------------------------ */

/* Full POSIX-parity capabilities: block 0 is a real kernel file, so the backend
 * is fd-backed, sendfile-able and io_uring-submittable; the catalog provides
 * atomic rename, real directories, server copy and object xattrs. */
const brix_sd_driver_t brix_sd_pblock_driver = {
    .name = "pblock",
    /* pblock consumes the request IDENTITY (principal + VO list): the catalog
     * is its own identity registry, and the *_cred slots below enforce POSIX
     * mode bits against the catalog-internal synthetic uid/gids. */
    .cred_accept = BRIX_SD_CRED_IDENTITY,
    .caps = BRIX_SD_CAP_FD | BRIX_SD_CAP_SENDFILE
          | BRIX_SD_CAP_RANDOM_WRITE | BRIX_SD_CAP_RANGE_READ
          | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_APPEND
          | BRIX_SD_CAP_IOURING | BRIX_SD_CAP_SERVER_COPY
          | BRIX_SD_CAP_XATTR | BRIX_SD_CAP_XATTR_WRITE
          | BRIX_SD_CAP_HARD_RENAME
          | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE,

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

    /* identity-enforcing slots (sd_pblock_cred.c): POSIX mode-bit checks
     * against catalog ownership when the request carries an identity;
     * identity-less requests fall through to service semantics. */
    .open_cred        = sd_pblock_open_cred,
    .staged_open_cred = sd_pblock_staged_open_cred,
    .stat_cred        = sd_pblock_stat_cred,
    .unlink_cred      = sd_pblock_unlink_cred,
    .mkdir_cred       = sd_pblock_mkdir_cred,
    .rename_cred      = sd_pblock_rename_cred,
    .setattr_cred     = sd_pblock_setattr_cred,
    .getxattr_cred    = sd_pblock_getxattr_cred,
    .listxattr_cred   = sd_pblock_listxattr_cred,
    .setxattr_cred    = sd_pblock_setxattr_cred,
    .removexattr_cred = sd_pblock_removexattr_cred,
    .server_copy_cred = sd_pblock_server_copy_cred,
    .opendir_cred     = sd_pblock_opendir_cred,
};

#endif /* BRIX_HAVE_SQLITE */
