/*
 * sd_pblock_namespace.c — namespace, directory and xattr vtable slots for the
 * pblock storage driver.
 *
 * WHAT: Implements the metadata-plane vtable slots of brix_sd_pblock_driver:
 *       stat, unlink, mkdir, setattr, rename and server_copy over the SQLite
 *       catalog; directory iteration (opendir/readdir/closedir); and the object
 *       xattr CRUD (get/list/set/remove). server_copy duplicates a file's blocks
 *       under a fresh blob id; rename is a pure catalog row move (blocks are
 *       id-addressed, so no bytes are touched).
 *
 * WHY:  Split out of sd_pblock.c (phase-79) to keep every pblock file under the
 *       ~500-line, one-concept cap. These are the namespace mutations and reads,
 *       kept separate from the hot byte path (sd_pblock_io.c), the object
 *       lifecycle (sd_pblock.c) and the staged-publish path (sd_pblock_staged.c).
 *       The functions are non-static because the driver descriptor names them;
 *       sd_pblock_drop_dst is additionally reused by staged-commit's replace.
 *       Declarations live in sd_pblock_internal.h.
 *
 * HOW:  Every operation reaches the namespace through the catalog API
 *       (sd_pblock_catalog.h) and touches block files only through the packed-block
 *       engine (pblock_store.h) — no raw byte syscalls here. ngx-free (libc +
 *       catalog + engine) so the module and standalone unit test compile it
 *       identically. Gated by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* UTIME_OMIT / UTIME_NOW (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

/* Per-open directory state (dir->state); local to the iteration slots. */
typedef struct {
    pblock_catalog_iter *it;
} pblock_dir_t;

/* ---- namespace ------------------------------------------------------------ */

ngx_int_t
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

ngx_int_t
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

/* sd_pblock_mkdir_as — mkdir recording (uid, gid) as the new directory's
 * owner. The plain slot passes 0/0 (service); mkdir_cred (sd_pblock_cred.c)
 * passes the requester's resolved catalog ids. */
ngx_int_t
sd_pblock_mkdir_as(brix_sd_instance_t *inst, const char *path, mode_t mode,
    uint32_t uid, uint32_t gid)
{
    pblock_state_t *st = inst->state;
    pblock_meta     meta;

    memset(&meta, 0, sizeof(meta));
    meta.is_dir = 1;
    meta.mtime  = meta.ctime = pblock_now();
    meta.mode   = S_IFDIR | (mode & 0777);
    meta.uid    = uid;
    meta.gid    = gid;
    /* One INSERT — the PRIMARY KEY constraint is the existence check (EEXIST),
     * so no separate lookup is needed. */
    return pblock_catalog_create(st->cat, path, &meta) == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_pblock_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return sd_pblock_mkdir_as(inst, path, mode, 0, 0);
}

/* sd_pblock_setattr — apply kXR_chmod (mode), chown (owner) and/or kXR_setattr
 * (times) to an existing catalog row. The catalog records mode + owner (the
 * catalog-internal synthetic uid/gid) + mtime + ctime; atime has no column and
 * is accepted-and-ignored (object-store semantics) rather than failing — a
 * setattr an export cannot represent should not break the op. ctime is bumped
 * on any change, matching POSIX. This plain slot applies the caller's values
 * verbatim (service semantics); ownership POLICY (who may chown) lives in the
 * identity-aware setattr_cred slot. */
ngx_int_t
sd_pblock_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    pblock_state_t *st = inst->state;
    int             set_mtime = 0;
    int64_t         mtime = 0;
    int64_t         uid = -1, gid = -1;

    if (attr->set_times && attr->mtime.tv_nsec != UTIME_OMIT) {
        set_mtime = 1;
        mtime = (attr->mtime.tv_nsec == UTIME_NOW)
                ? pblock_now() : (int64_t) attr->mtime.tv_sec;
    }
    if (attr->set_owner) {
        /* (uid_t)-1 / (gid_t)-1 mean "keep" (chown(2)); map to the catalog's
         * signed -1 sentinel. */
        uid = attr->uid == (uid_t) -1 ? -1 : (int64_t) attr->uid;
        gid = attr->gid == (gid_t) -1 ? -1 : (int64_t) attr->gid;
    }

    /* One UPDATE — no read-modify-write. ENOENT (rc<0 with errno) when absent. */
    return pblock_catalog_setattr(st->cat, path, attr->set_mode ? 1 : 0,
               attr->mode & 0777, attr->set_owner ? 1 : 0, uid, gid,
               set_mtime, mtime, pblock_now()) == 0
           ? NGX_OK : NGX_ERROR;
}

/* sd_pblock_drop_dst — clear an existing rename/copy destination: reject a
 * non-empty directory, remove a file's blocks, then drop the catalog row. */
ngx_int_t
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

ngx_int_t
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

/* sd_pblock_server_copy_as — server-side copy whose destination row is owned
 * by (uid, gid): the copier, not the source's owner (POSIX cp semantics). The
 * plain slot passes 0/0 (service); server_copy_cred passes the requester. */
ngx_int_t
sd_pblock_server_copy_as(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, uint32_t uid, uint32_t gid)
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
    dmeta.uid        = uid;
    dmeta.gid        = gid;

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

ngx_int_t
sd_pblock_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_pblock_server_copy_as(inst, src, dst, bytes_out, 0, 0);
}

/* ---- directory iteration -------------------------------------------------- */

brix_sd_dir_t *
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

ngx_int_t
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

ngx_int_t
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

ssize_t
sd_pblock_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_getxattr(st->cat, path, name, buf, cap);
}

ssize_t
sd_pblock_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_listxattr(st->cat, path, buf, cap);
}

ngx_int_t
sd_pblock_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    pblock_state_t *st = inst->state;

    /* XATTR_CREATE/XATTR_REPLACE are enforced by the catalog (EEXIST/ENODATA),
     * as is the path-existence gate (ENOENT). */
    return pblock_catalog_setxattr(st->cat, path, name, val, len, flags) == 0
               ? NGX_OK : NGX_ERROR;
}

ngx_int_t
sd_pblock_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    pblock_state_t *st = inst->state;

    return pblock_catalog_removexattr(st->cat, path, name) == 0
               ? NGX_OK : NGX_ERROR;
}

#endif /* BRIX_HAVE_SQLITE */
