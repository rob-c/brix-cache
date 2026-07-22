/*
 * sd_pblock_open.c — the pblock storage-driver object lifecycle: opening and
 * closing a handle onto an object's block-0 fd + cached catalog metadata.
 *
 * WHAT: Owns sd_pblock_open / sd_pblock_open_as / sd_pblock_close (the .open /
 *       .close vtable slots named in the descriptor in sd_pblock.c, plus the
 *       identity-parameterised open_as boundary the *_cred slots call) and their
 *       private helpers (pblock_make_obj + the create/existing/absent open lanes).
 *
 * WHY:  Split from sd_pblock.c (phase-79/guard burndown) to hold every pblock
 *       file under the one-concept size cap; object open/close is the most
 *       self-contained slice of the former driver core. The instance init/cleanup
 *       lifecycle lives in sd_pblock_lifecycle.c, the descriptor + the
 *       enumerate/space/nearline slots stay in sd_pblock.c.
 *
 * HOW:  Same ngx-free (libc + sqlite, malloc-owned state) contract as the rest of
 *       the driver, compiled only when the build found libsqlite3
 *       (BRIX_HAVE_SQLITE) so a no-sqlite build stays empty.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* preadv2(2) (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"  /* shared obj state + split-out vtable slots */
#include "pblock_ctl.h"          /* Phase-83 lab control plane (opts + ctl table) */
#include "pblock_fault.h"        /* Phase-83 fault injection + I/O shaping */
#include "pblock_csi.h"          /* Phase-83 F3 per-block CRC32c integrity */
#include "pblock_quota.h"        /* Phase-83 F5 quotas + space accounting */
#include "pblock_nearline.h"     /* Phase-83 F4 nearline/tape simulation */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_snap.h"         /* Phase-83 F6 snapshots / fixture reset */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */
#include "core/compat/wverify.h" /* F10 whole-object CRC accumulator */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

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

    /* Phase-83: resolve any lab fault/shape rule for this handle ONCE, at open
     * (a metadata boundary). NULL when lab is off or no rule applies — the hot
     * byte path then skips the gate entirely. */
    os->lab = pblock_lab_snapshot(os->st->lab, path);

    /* F3: snapshot the at-rest per-block CRCs ONCE at open so the hot read path
     * verifies against memory (no DB). csi_dlo/dhi is the empty written extent
     * (dlo > dhi) until the first write widens it. */
    os->csi_dlo = INT64_MAX;
    os->csi_dhi = 0;
    if (os->st->csi && !meta->is_dir) {
        int64_t nblk = meta->size > 0
            ? pblock_last_block(meta->size, os->block_size) + 1 : 0;

        (void) pblock_csi_load(os->st->cat, os->blob_id, nblk,
                               &os->csi_crc, &os->csi_n);
    }

    /* F5: snapshot how far this handle may grow the file ONCE at open (quota
     * off ⇒ INT64_MAX) — pwrite/copy_range enforce it without touching the DB. */
    os->quota_max = pblock_quota_max_size(os->st, meta->uid, meta->size);

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

    /* F6: count live regular-file handles so a snapshot restore can refuse
     * (EBUSY) rather than swap the namespace out from under an open file.
     * Balanced by the matching decrement in sd_pblock_close. */
    if (os->st->snap && !meta->is_dir) {
        __atomic_add_fetch(&os->st->open_files, 1, __ATOMIC_RELEASE);
    }
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

    if (pblock_quota_admit(st, uid, 0, 1) != 0) {            /* F5 */
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

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
    snprintf(meta.xform, sizeof(meta.xform), "%s",   /* F12/F13: record kind */
             pblock_xform_name(st->xform.kind));

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
    if (obj != NULL && st->refs) {                            /* F10 */
        (void) pblock_refs_track(st, meta.blob_id, 0, meta.block_size, 0, 0);
        ((pblock_obj_t *) obj->state)->wv = brix_wverify_begin();
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

    /* F12/F13: refuse to serve a file whose recorded transform does not match the
     * export's configured one (wrong key/codec ⇒ garbage). A config error, not a
     * data error — fail the open rather than hand back undecodable bytes. */
    if (pblock_xform_kind_from_name(meta->xform) != st->xform.kind) {
        if (err_out != NULL) { *err_out = EIO; }
        return NULL;
    }

    /* F10: never write through a shared blob — a write-intent open first gives
     * this object a private copy (empty on O_TRUNC: the bytes are doomed). */
    if (st->refs && want_write
        && pblock_refs_break_share(st, path, meta,
                                   (sd_flags & BRIX_SD_O_TRUNC) != 0) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

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
    if (st->refs && want_write && (sd_flags & BRIX_SD_O_TRUNC)) {
        /* F10: content is being rewritten from scratch — this handle can grow
         * an honest whole-object CRC, making the blob a dedup candidate. */
        ((pblock_obj_t *) obj->state)->wv = brix_wverify_begin();
    }
    return obj;
}

/* F15: mandatory lease gate — before both the create and overwrite lanes, since
 * a whole-file lease guards the *name* (a create under a foreign lease is as much
 * a conflicting write as an overwrite). Live foreign 'X' refuses everyone; a live
 * foreign whole-file 'W' refuses write-intent opens. EBUSY maps to kXR_FileLocked
 * / HTTP 423 at the protocol edge. Returns 1 if the open must be refused (errno +
 * *err_out set), 0 to proceed. */
static int
pblock_open_locked(pblock_state_t *st, const char *path, int sd_flags,
    uint32_t uid, int *err_out)
{
    if (st->locks
        && pblock_locks_open_check(st, path,
               (sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                            | BRIX_SD_O_TRUNC | BRIX_SD_O_APPEND)) != 0,
               uid) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return 1;
    }
    return 0;
}

/* Existing-file open after the dir/lock gates: the F9 visibility-lag hide, the
 * O_CREATE|O_EXCL conflict, and the F4 nearline recall, then the real open. */
static brix_sd_obj_t *
pblock_open_existing_gated(brix_sd_instance_t *inst, pblock_state_t *st,
    const char *path, pblock_meta *meta, int sd_flags, int *err_out)
{
    /* F9: visibility lag — a freshly created path is ENOENT to other readers
     * for the armed window. Write-intent opens are exempt: the writer/overwriter
     * lane must never see its own phantom ENOENT (the S3 session monotonic-read
     * guarantee — a handle that wrote reads through its own open snapshot and is
     * untouched by design). */
    if (st->lab != NULL
        && !(sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                         | BRIX_SD_O_TRUNC))
        && pblock_anomaly_hidden(st, path))
    {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    if ((sd_flags & BRIX_SD_O_CREATE) && (sd_flags & BRIX_SD_O_EXCL)) {
        if (err_out != NULL) { *err_out = EEXIST; }
        return NULL;
    }
    /* F4: a demoted (nearline/offline) file must be recalled before it serves —
     * a bounded synchronous recall like sd_frm's, so a plain export exercises the
     * lane without a cache tier in front. A LOST object or failed recall errors
     * out (never silently serves the bytes a real tape system could not). O_TRUNC
     * replaces the content, so it skips the recall and comes back ONLINE below via
     * the write path. */
    if (st->nearline && !(sd_flags & BRIX_SD_O_TRUNC)
        && pblock_nearline_recall(st, path) != 0)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    return pblock_open_existing(inst, path, meta, sd_flags, err_out);
}

/* Absent path: create it when O_CREATE is set (recording the F9 anomaly on the
 * new name), else ENOENT. */
static brix_sd_obj_t *
pblock_open_absent(brix_sd_instance_t *inst, pblock_state_t *st,
    const char *path, mode_t mode, uint32_t uid, uint32_t gid,
    int sd_flags, int *err_out)
{
    brix_sd_obj_t *obj;

    if (!(sd_flags & BRIX_SD_O_CREATE)) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }
    obj = pblock_open_create(inst, path, mode, uid, gid, err_out);
    if (obj != NULL && st->lab != NULL) {
        pblock_anomaly_created(st, path);                     /* F9 */
    }
    return obj;
}

/* sd_pblock_open_as — the open implementation, parameterized by the owner
 * (uid, gid) recorded on a CREATE. The plain vtable slot passes 0/0 (the
 * service); the identity-aware open_cred slot (sd_pblock_cred.c) passes the
 * requester's resolved catalog ids so new files are owned by their creator. */
static brix_sd_obj_t *
pblock_open_as_inner(brix_sd_instance_t *inst, const char *path, int sd_flags,
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

    if (pblock_open_locked(st, path, sd_flags, uid, err_out)) {
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
        return pblock_open_existing_gated(inst, st, path, &meta, sd_flags,
                                          err_out);
    }

    return pblock_open_absent(inst, st, path, mode, uid, gid, sd_flags, err_out);
}

/* sd_pblock_open_as — the identity-parameterised open, wrapping the real
 * implementation with the F17 audit record. The wrapper (not the inner) is the
 * audit boundary so every terminal outcome — dir open, existing file, create,
 * or an error — is recorded exactly once with the actor identity and result. */
brix_sd_obj_t *
sd_pblock_open_as(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
{
    pblock_state_t *st = inst->state;
    brix_sd_obj_t  *obj;
    int             myerr = 0;

    obj = pblock_open_as_inner(inst, path, sd_flags, mode, uid, gid, &myerr);
    if (obj != NULL && st->locks) {
        /* F15: snapshot the foreign range leases into the handle — the pwrite
         * check is then a pure scan (per the phase design, a conflicting
         * later open is refused at *its* open, so no per-I/O DB hits). */
        pblock_locks_snapshot(st, obj->state, uid);
    }
    if (st->audit) {
        char aux[32];

        snprintf(aux, sizeof(aux), "flags=%d", sd_flags);
        pblock_audit_log(st->cat, "open", path, aux, uid, gid,
                         obj ? 0 : -1, obj ? 0 : myerr);
    }
    if (obj == NULL && err_out != NULL) {
        *err_out = myerr;
    }
    return obj;
}

brix_sd_obj_t *
sd_pblock_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    /* No identity on the plain slot: creations belong to the service (0/0). */
    return sd_pblock_open_as(inst, path, sd_flags, mode, 0, 0, err_out);
}

ngx_int_t
sd_pblock_close(brix_sd_obj_t *obj)
{
    pblock_obj_t *os;
    ngx_int_t     rc = NGX_OK;

    if (obj == NULL) {
        return NGX_OK;
    }
    os = obj->state;

    if (os != NULL && os->dirty) {
        pblock_meta old;
        int         have_old = 0;

        /* F9: the pre-update row is what a stale stat will serve — capture it
         * before the touch publishes the new size/mtime. */
        if (os->st->lab != NULL) {
            have_old = pblock_catalog_lookup(os->st->cat, os->path, &old) == 0;
        }
        pblock_lab_crash(os->st->lab, "before_catalog_update");   /* F7 */
        if (pblock_quota_touch_admit(os->st, os->path, os->meta.uid,
                                     os->meta.size) != 0             /* F5 */
            || pblock_catalog_touch(os->st->cat, os->path, os->meta.size,
                                 os->meta.mtime) != 0)
        {
            rc = NGX_ERROR;
        }
        pblock_lab_crash(os->st->lab, "after_catalog_update");    /* F7 */
        if (rc == NGX_OK && have_old) {
            pblock_anomaly_updated(os->st, os->path, old.size,
                                   old.mtime);                    /* F9 */
        }
        os->dirty = 0;
    }
    if (obj->fd != NGX_INVALID_FILE) {
        if (close(obj->fd) != 0) {
            rc = NGX_ERROR;
        }
        obj->fd = NGX_INVALID_FILE;
    }
    if (os != NULL) {
        if (os->st->audit) {                 /* F17: fold per-I/O totals here */
            char aux[64];

            snprintf(aux, sizeof(aux), "r=%lld w=%lld mb=%lld",
                     (long long) os->a_rbytes, (long long) os->a_wbytes,
                     (long long) os->a_maxblock);
            pblock_audit_log(os->st->cat, "close", os->path, aux,
                             os->meta.uid, os->meta.gid,
                             rc == NGX_OK ? 0 : -1, 0);
        }
        if (os->st->csi) {              /* F3: persist CRCs for written blocks */
            (void) pblock_csi_flush(os->st, os->blob_id, os->meta.size,
                                    os->block_size, os->csi_dlo, os->csi_dhi);
        }
        if (os->wv != NULL) {           /* F10: publish-time dedup fold */
            if (os->st->refs && rc == NGX_OK) {
                uint32_t crc   = 0;
                off_t    total = 0;
                int      ok;

                ok = brix_wverify_expected(os->wv, &crc, &total) == 0
                         && (int64_t) total == os->meta.size;
                (void) pblock_refs_dedup_publish(os->st, os->path, &os->meta,
                                                 crc, ok);
            }
            brix_wverify_free(os->wv);
        }
        if (os->st->snap && !os->meta.is_dir) {   /* F6: release the handle count */
            __atomic_sub_fetch(&os->st->open_files, 1, __ATOMIC_RELEASE);
        }
        free(os->csi_crc);
        free(os->lock_rng);             /* F15 per-open lease snapshot */
        pblock_lab_obj_free(os->lab);   /* Phase-83 per-open snapshot */
    }
    free(os);
    obj->state = NULL;
    /* The obj shell is NOT freed here: it may be embedded in the adopter's
     * handle (the VFS copies *obj by value). Its owner — the VFS adopter (via
     * obj->heap_shell), the internal open-error paths, or the standalone test —
     * frees the malloc'd shell. */
    return rc;
}

#endif /* BRIX_HAVE_SQLITE */
