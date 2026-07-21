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
#include "pblock_fault.h"        /* F7 crash points */
#include "pblock_ctl.h"          /* F17 audit log */
#include "pblock_csi.h"          /* F3 per-block CRC32c integrity */
#include "pblock_quota.h"
#include "pblock_nearline.h"     /* Phase-83 F4 nearline residency rows */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "sd_pblock_internal.h"
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_snap.h"         /* Phase-83 F6 snapshots / fixture reset */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

/* Per-open directory state (dir->state); local to the iteration slots. The
 * dir path is kept for the F9 list-lag filter (entries hide by full path). */
typedef struct {
    pblock_catalog_iter *it;
    char                 dir[1024];
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
    /* F12/F13: an object recorded under a transform the current export is not
     * configured for is undecodable — refuse it at the metadata boundary (EIO)
     * so no read fast-path (sendfile/pread) ever serves its transformed bytes as
     * another kind. Directories carry no transform (xform stays ""). */
    if (!meta.is_dir
        && pblock_xform_kind_from_name(meta.xform) != st->xform.kind)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    /* F9: a fresh creation is invisible to stat for the visibility window
     * (S3 HEAD-after-PUT), and a fresh update may serve the pre-update row
     * for the stale window (S3 HEAD-after-overwrite). */
    if (st->lab != NULL) {
        if (pblock_anomaly_hidden(st, path)) {
            errno = ENOENT;
            return NGX_ERROR;
        }
        (void) pblock_anomaly_stale(st, path, &meta.size, &meta.mtime);
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

    /* F6: rmdir on the reserved control namespace drops a snapshot — handled
     * before any real catalog work (there is no such directory to remove). */
    if (st->snap && is_dir && pblock_snap_ctl_path(path)) {
        return pblock_snap_ctl_rmdir(st, path) == 0 ? NGX_OK : NGX_ERROR;
    }

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }

    /* F15: a live foreign lease must not be dissolvable by deleting the file
     * under it — EBUSY (kXR_FileLocked / 423) until it is released/expires.
     * The plain slot has no requester identity, so uid 0 (the service). */
    if (st->locks && pblock_locks_ns_check(st, path, 0) != 0) {
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
        /* F11: move the object into the trash BEFORE releasing it. trash_push
         * holds its blob, so the release below only decrements (a copy-on-write
         * transfer of the reference to the trash row). A failed push is
         * fail-open — the unlink just frees the blob as usual, no trash entry. */
        if (st->trash) {
            (void) pblock_hist_trash_push(st, path, &meta);
        }
        /* F10-aware release: the last reference removes blocks + csi rows
         * (byte-identical to the pre-F10 path with refs off); a still-shared
         * blob just loses one reference. */
        pblock_refs_release(st, meta.blob_id, meta.size, meta.block_size);
        if (st->nearline) {                  /* F4: residency dies with the file */
            pblock_nearline_drop(st, path);
        }
        if (st->lab != NULL) {               /* F9: event history dies with it */
            pblock_anomaly_drop(st, path);
        }
        if (st->locks) {                     /* F15: stale/own rows die with it */
            pblock_locks_drop(st, path);
        }
        /* F7: blocks are gone but the row still points at them — a crash here
         * leaves a dangling catalog row for pblock-fsck to flag and --gc. */
        pblock_lab_crash(st->lab, "before_unlink_row");
    }
    {
        ngx_int_t rc2 = pblock_catalog_remove(st->cat, path) == 0
                            ? NGX_OK : NGX_ERROR;

        if (st->audit) {                                 /* F17 */
            pblock_audit_log(st->cat, is_dir ? "rmdir" : "unlink", path, "",
                             meta.uid, meta.gid, rc2 == NGX_OK ? 0 : -1,
                             rc2 == NGX_OK ? 0 : errno);
        }
        return rc2;
    }
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

    /* F11: mkdir /.pblock/undelete/<path> pops <path> out of the trash — handled
     * before any real catalog work, and before the F6 dispatch since it owns a
     * distinct reserved sub-namespace. Service-only for the same reason as F6. */
    if (st->trash && pblock_hist_ctl_mkdir_match(path)) {
        return pblock_hist_ctl_mkdir(st, path) == 0 ? NGX_OK : NGX_ERROR;
    }

    /* F6: mkdir on the reserved control namespace takes/restores a snapshot —
     * handled before any real catalog work. Reached only through the inner
     * (service) mkdir path, so snapshot control is service-only. */
    if (st->snap && pblock_snap_ctl_path(path)) {
        return pblock_snap_ctl_mkdir(st, path) == 0 ? NGX_OK : NGX_ERROR;
    }

    if (pblock_quota_admit(st, uid, 0, 1) != 0) {        /* F5 */
        return NGX_ERROR;
    }

    memset(&meta, 0, sizeof(meta));
    meta.is_dir = 1;
    meta.mtime  = meta.ctime = pblock_now();
    meta.mode   = S_IFDIR | (mode & 0777);
    meta.uid    = uid;
    meta.gid    = gid;
    /* One INSERT — the PRIMARY KEY constraint is the existence check (EEXIST),
     * so no separate lookup is needed. */
    {
        ngx_int_t rc2 = pblock_catalog_create(st->cat, path, &meta) == 0
                            ? NGX_OK : NGX_ERROR;

        if (st->audit) {                                 /* F17 */
            pblock_audit_log(st->cat, "mkdir", path, "", uid, gid,
                             rc2 == NGX_OK ? 0 : -1, rc2 == NGX_OK ? 0 : errno);
        }
        return rc2;
    }
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
        /* F10-aware release (see sd_pblock_unlink). */
        pblock_refs_release(st, dmeta->blob_id, dmeta->size,
                            dmeta->block_size);
    }
    if (st->nearline) {                      /* F4: overwritten dst is replaced */
        pblock_nearline_drop(st, dst);
    }
    if (st->lab != NULL) {                   /* F9: replaced dst's history too */
        pblock_anomaly_drop(st, dst);
    }
    if (st->locks) {                         /* F15: replaced dst's rows too */
        pblock_locks_drop(st, dst);
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

    /* F15: renaming a leased src (or over a leased dst) is the classic lock
     * bypass — refuse while any live foreign lease exists on either name. */
    if (st->locks
        && (pblock_locks_ns_check(st, src, 0) != 0
            || pblock_locks_ns_check(st, dst, 0) != 0))
    {
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
    {
        ngx_int_t rc2 = pblock_catalog_rename(st->cat, src, dst) == 0
                            ? NGX_OK : NGX_ERROR;

        if (rc2 == NGX_OK && st->nearline) { /* F4: residency follows the path */
            pblock_nearline_rename(st, src, dst);
        }
        if (rc2 == NGX_OK && st->lab != NULL) {  /* F9: events follow the path */
            pblock_anomaly_rename(st, src, dst);
        }
        if (rc2 == NGX_OK && st->locks) {    /* F15: leases follow the path */
            pblock_locks_rename(st, src, dst);
        }
        if (st->audit) {                                 /* F17 */
            pblock_audit_log(st->cat, "rename", src, dst, 0, 0,
                             rc2 == NGX_OK ? 0 : -1, rc2 == NGX_OK ? 0 : errno);
        }
        return rc2;
    }
}

/* F10 CoW copy: dst shares src's blob — O(metadata), no bytes move; the first
 * write to either row breaks the share at open. The dst row is owned by
 * (uid, gid). Returns NGX_OK / NGX_ERROR. */
static ngx_int_t
pblock_copy_cow(pblock_state_t *st, const pblock_meta *smeta, const char *dst,
    uint32_t uid, uint32_t gid, off_t *bytes_out)
{
    pblock_meta dexist, dmeta;
    int         dhad = pblock_catalog_lookup(st->cat, dst, &dexist) == 0;

    if (pblock_refs_bump(st, smeta->blob_id, smeta->size,
                         smeta->block_size) != 0)
    {
        return NGX_ERROR;
    }
    memset(&dmeta, 0, sizeof(dmeta));
    memcpy(dmeta.blob_id, smeta->blob_id, sizeof(dmeta.blob_id));
    dmeta.is_dir     = 0;
    dmeta.size       = smeta->size;
    dmeta.block_size = smeta->block_size;
    dmeta.mtime      = dmeta.ctime = pblock_now();
    dmeta.mode       = smeta->mode;
    dmeta.uid        = uid;
    dmeta.gid        = gid;
    if (pblock_catalog_put(st->cat, dst, &dmeta) != 0) {
        int err = errno;

        pblock_refs_release(st, smeta->blob_id, smeta->size,
                            smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }
    if (dhad && !dexist.is_dir) {    /* the replaced dst's blob loses a ref */
        pblock_refs_release(st, dexist.blob_id, dexist.size,
                            dexist.block_size);
    }
    if (st->lab != NULL) {                           /* F9 */
        if (dhad) {
            pblock_anomaly_updated(st, dst, dexist.size, dexist.mtime);
        } else {
            pblock_anomaly_created(st, dst);
        }
    }
    if (bytes_out != NULL) {
        *bytes_out = (off_t) smeta->size;
    }
    /* No csi flush: the shared blob's integrity rows already exist. */
    if (st->audit) {                                 /* F17 */
        char aux[32];

        snprintf(aux, sizeof(aux), "cow=1 w=%lld", (long long) smeta->size);
        pblock_audit_log(st->cat, "copy", dst, aux, uid, gid, 0, 0);
    }
    return NGX_OK;
}

/* Physically copy every block of `src_blob` to `dst_blob`. Returns 0, or -1
 * with errno set from the failing call (the caller unwinds the partial dst). */
static int
pblock_copy_blocks(pblock_state_t *st, const char *src_blob,
    const char *dst_blob, int64_t size, int64_t block_size)
{
    int64_t last = pblock_last_block(size, block_size);
    int64_t i;

    for (i = 0; i <= last; i++) {
        char sp[PATH_MAX], dp[PATH_MAX];

        if (pblock_block_path(st, src_blob, i, sp, sizeof(sp)) != 0
            || pblock_block_path(st, dst_blob, i, dp, sizeof(dp)) != 0
            || pblock_copy_one_block(sp, dp) < 0)
        {
            return -1;
        }
    }
    return 0;
}

/* Full byte copy: allocate a fresh blob, copy every block, then publish the dst
 * row owned by (uid, gid). Returns NGX_OK / NGX_ERROR (partial blob unwound). */
static ngx_int_t
pblock_copy_physical(pblock_state_t *st, const pblock_meta *smeta,
    const char *dst, uint32_t uid, uint32_t gid, off_t *bytes_out)
{
    pblock_meta dmeta, dexist;
    int         dhad = 0;

    memset(&dmeta, 0, sizeof(dmeta));
    if (pblock_gen_blob_id(dmeta.blob_id) != 0
        || pblock_ensure_obj_dir(st, dmeta.blob_id) != 0)
    {
        return NGX_ERROR;
    }

    if (pblock_copy_blocks(st, smeta->blob_id, dmeta.blob_id, smeta->size,
                           smeta->block_size) != 0)
    {
        int err = errno;

        pblock_remove_blocks(st, dmeta.blob_id, smeta->size,
                             smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }

    dmeta.is_dir     = 0;
    dmeta.size       = smeta->size;
    dmeta.block_size = smeta->block_size;
    dmeta.mtime      = dmeta.ctime = pblock_now();
    dmeta.mode       = smeta->mode;
    dmeta.uid        = uid;
    dmeta.gid        = gid;

    /* F9: is this copy a create or an overwrite of dst? The pre-put row is what
     * a stale stat will serve. */
    if (st->lab != NULL) {
        dhad = pblock_catalog_lookup(st->cat, dst, &dexist) == 0;
    }
    if (pblock_catalog_put(st->cat, dst, &dmeta) != 0) {
        int err = errno;

        pblock_remove_blocks(st, dmeta.blob_id, smeta->size,
                             smeta->block_size);
        errno = err;
        return NGX_ERROR;
    }
    if (st->lab != NULL) {
        if (dhad) {
            pblock_anomaly_updated(st, dst, dexist.size, dexist.mtime);
        } else {
            pblock_anomaly_created(st, dst);
        }
    }
    if (bytes_out != NULL) {
        *bytes_out = (off_t) smeta->size;
    }
    if (st->csi) {                                       /* F3: tag the copy */
        (void) pblock_csi_flush(st, dmeta.blob_id, dmeta.size,
                                dmeta.block_size, 0, INT64_MAX);
    }
    if (st->audit) {                                     /* F17 */
        char aux[32];

        snprintf(aux, sizeof(aux), "w=%lld", (long long) smeta->size);
        pblock_audit_log(st->cat, "copy", dst, aux, uid, gid, 0, 0);
    }
    return NGX_OK;
}

/* sd_pblock_server_copy_as — server-side copy whose destination row is owned
 * by (uid, gid): the copier, not the source's owner (POSIX cp semantics). The
 * plain slot passes 0/0 (service); server_copy_cred passes the requester. */
ngx_int_t
sd_pblock_server_copy_as(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, uint32_t uid, uint32_t gid)
{
    pblock_state_t *st = inst->state;
    pblock_meta     smeta;
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

    if (st->quota) {                                     /* F5 */
        pblock_meta dexist;
        int         drc = pblock_catalog_lookup(st->cat, dst, &dexist);

        if (pblock_quota_admit(st, uid,
                (int64_t) smeta.size - (drc == 0 ? dexist.size : 0),
                drc == 0 ? 0 : 1) != 0)
        {
            return NGX_ERROR;
        }
    }

    if (st->refs) {                                      /* F10: CoW copy */
        return pblock_copy_cow(st, &smeta, dst, uid, gid, bytes_out);
    }
    return pblock_copy_physical(st, &smeta, dst, uid, gid, bytes_out);
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
    snprintf(pd->dir, sizeof(pd->dir), "%s", path);
    dir->inst  = inst;
    dir->state = pd;
    return dir;
}

ngx_int_t
sd_pblock_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    pblock_dir_t   *pd = d->state;
    pblock_state_t *st = d->inst->state;

    for ( ;; ) {
        int rc = pblock_catalog_readdir(pd->it, out->name, sizeof(out->name));

        if (rc < 0) {
            return NGX_ERROR;
        }
        if (rc == 1) {
            return NGX_DONE;
        }
        /* F9: list lag — a listing omits entries created within the armed
         * window (S3 LIST-after-PUT). */
        if (st->lab != NULL
            && pblock_anomaly_list_hidden(st, pd->dir, out->name))
        {
            continue;
        }
        return NGX_OK;
    }
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
