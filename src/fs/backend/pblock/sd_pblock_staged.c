/*
 * sd_pblock_staged.c — staged atomic-publish vtable slots for the pblock driver.
 *
 * WHAT: Implements the staged-write path of brix_sd_pblock_driver:
 *       staged_open/write/commit/abort. Body bytes are written to a fresh blob id
 *       (no visible catalog row yet); commit publishes them atomically by
 *       inserting the final row that points at that blob (the staged blocks simply
 *       become the object — no copy or rename), while abort removes them.
 *
 * WHY:  Split out of sd_pblock.c (phase-79) to keep every pblock file under the
 *       ~500-line, one-concept cap. Atomic publish is its own concern, distinct
 *       from the object lifecycle (sd_pblock.c), the hot byte path (sd_pblock_io.c)
 *       and the namespace ops (sd_pblock_namespace.c). The functions are
 *       non-static because the driver descriptor names them; commit reuses
 *       sd_pblock_drop_dst from the namespace file. Declarations live in
 *       sd_pblock_internal.h.
 *
 * HOW:  staged_open gates the parent collection up front (POSIX parity with the
 *       POSIX driver's O_EXCL temp) before any blob is allocated, then reserves a
 *       blob id + object dir. staged_write appends through the packed-block engine
 *       with no persistent block-0 fd (blk0_fd = -1). commit does the replace/
 *       insert against the catalog and consumes the handle on success. ngx-free;
 *       gated by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "pblock_fault.h"        /* F7 crash points */
#include "pblock_ctl.h"          /* F17 audit log */
#include "pblock_csi.h"          /* F3 per-block CRC32c integrity */
#include "pblock_quota.h"        /* F5 quotas + space accounting */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "sd_pblock_internal.h"
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */
#include "core/compat/wverify.h" /* F10 whole-object CRC accumulator */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

/* Staged (atomic-publish) state (staged->state); local to this file. */
typedef struct {
    pblock_state_t *st;
    char            final_path[PATH_MAX];
    char            blob_id[PBLOCK_BLOB_ID_CAP];
    int64_t         block_size;
    int64_t         size;                 /* high-water mark of staged writes  */
    mode_t          mode;
    uint32_t        uid;                  /* owner recorded on the committed   */
    uint32_t        gid;                  /* row (0/0 = the service itself)    */
    void           *wv;                   /* F10: brix_wverify_t* — a staged
                                           * blob is always written whole, so
                                           * every staged handle can grow a
                                           * dedup-candidate CRC (refs only)   */
} pblock_staged_t;

/* ---- staged atomic publish ------------------------------------------------ */

/* sd_pblock_staged_open_as — staged open whose eventual committed row is owned
 * by (uid, gid). The plain slot passes 0/0 (service); staged_open_cred
 * (sd_pblock_cred.c) passes the requester's resolved catalog ids. */
brix_sd_staged_t *
sd_pblock_staged_open_as(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, uint32_t uid, uint32_t gid, int *err_out)
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

    /* F5: refuse an inode-quota-busting PUT before any body byte is accepted.
     * Byte admission happens at commit (the size is unknown here); an overwrite
     * of an existing row adds no inode, so admit 0 in that case. */
    if (st->quota
        && pblock_quota_admit(st, uid, 0,
               pblock_catalog_lookup(st->cat, final_path, NULL) == 0 ? 0 : 1)
           != 0)
    {
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
    ps->uid        = uid;
    ps->gid        = gid;
    snprintf(ps->final_path, sizeof(ps->final_path), "%s", final_path);
    if (st->refs) {                                      /* F10 */
        ps->wv = brix_wverify_begin();
    }
    if (st->snap) {                                      /* F6: block restore */
        __atomic_add_fetch(&st->open_files, 1, __ATOMIC_RELEASE);
    }
    handle->inst  = inst;
    handle->state = ps;
    if (st->audit) {                                     /* F17 */
        pblock_audit_log(st->cat, "staged_open", final_path, "", uid, gid, 0, 0);
    }
    return handle;
}

brix_sd_staged_t *
sd_pblock_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    return sd_pblock_staged_open_as(inst, final_path, mode, 0, 0, err_out);
}

ssize_t
sd_pblock_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    pblock_staged_t *ps = st->state;
    ssize_t          n;

    n = pblock_write_blocks(ps->st, ps->blob_id, ps->block_size, -1, buf, len,
                            off);
    if (n > 0) {
        if ((int64_t) off + n > ps->size) {
            ps->size = (int64_t) off + n;
        }
        if (ps->wv != NULL) {                        /* F10: grow the dedup CRC */
            (void) brix_wverify_update(ps->wv, buf, off, (size_t) n);
        }
    }
    return n;
}

/* sd_pblock_staged_commit — publish the staged blocks atomically by inserting
 * the final catalog row pointing at the staged blob id (the blocks simply become
 * the final object — no copy or rename). On success the handle is consumed; on
 * failure it stays valid and the caller must staged_abort to release it. */
ngx_int_t
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

    /* F15: publishing over a leased name is a write to it — refuse while a
     * live foreign lease exists (EBUSY; the handle stays valid for retry or
     * staged_abort, same contract as a refused quota). */
    if (pst->locks
        && pblock_locks_ns_check(pst, ps->final_path, ps->uid) != 0)
    {
        return NGX_ERROR;
    }

    /* F5: byte admission BEFORE the destructive drop_dst — a refused commit
     * must leave the existing object (and the usage rollup) untouched so the
     * caller's staged_abort releases only the staged blocks. */
    if (pblock_quota_admit(pst, ps->uid,
            ps->size - (rc == 0 ? dmeta.size : 0), rc == 0 ? 0 : 1) != 0)
    {
        return NGX_ERROR;
    }

    if (rc == 0) {
        if (noreplace) {
            errno = EEXIST;
            return NGX_ERROR;
        }
        /* F11: capture the prior object as a new version BEFORE the destructive
         * drop. version_push holds its blob, so drop_dst's release only
         * decrements (a copy-on-write transfer of the reference to the version
         * row). A failed push is fail-open — the overwrite just keeps no
         * history. */
        if (pst->versions > 0) {
            (void) pblock_hist_version_push(pst, ps->final_path, &dmeta);
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
    meta.uid        = ps->uid;
    meta.gid        = ps->gid;
    snprintf(meta.xform, sizeof(meta.xform), "%s",   /* F12/F13: record kind */
             pblock_xform_name(pst->xform.kind));

    /* F7: a crash here leaves the staged blocks on disk with no catalog row —
     * the canonical orphan-blob residue pblock-fsck must detect and --gc. */
    pblock_lab_crash(pst->lab, "mid_staged_commit");

    if (pblock_catalog_put(pst->cat, ps->final_path, &meta) != 0) {
        return NGX_ERROR;
    }

    if (pst->lab != NULL) {                              /* F9 */
        if (rc == 0) {
            pblock_anomaly_updated(pst, ps->final_path, dmeta.size,
                                   dmeta.mtime);
        } else {
            pblock_anomaly_created(pst, ps->final_path);
        }
    }

    if (pst->csi) {                                      /* F3: tag the blob */
        (void) pblock_csi_flush(pst, ps->blob_id, ps->size, ps->block_size,
                                0, INT64_MAX);
    }

    if (ps->wv != NULL) {                                /* F10: dedup fold */
        if (pst->refs) {
            uint32_t crc   = 0;
            off_t    total = 0;
            int      ok;

            ok = brix_wverify_expected(ps->wv, &crc, &total) == 0
                     && (int64_t) total == ps->size;
            (void) pblock_refs_dedup_publish(pst, ps->final_path, &meta,
                                             crc, ok);
        }
        brix_wverify_free(ps->wv);
    }

    if (pst->audit) {                                    /* F17 */
        char aux[32];

        snprintf(aux, sizeof(aux), "w=%lld", (long long) ps->size);
        pblock_audit_log(pst->cat, "commit", ps->final_path, aux,
                         ps->uid, ps->gid, 0, 0);
    }

    if (pst->snap) {                     /* F6: released — no longer blocks restore */
        __atomic_sub_fetch(&pst->open_files, 1, __ATOMIC_RELEASE);
    }
    free(ps);
    free(st);
    return NGX_OK;
}

void
sd_pblock_staged_abort(brix_sd_staged_t *st)
{
    pblock_staged_t *ps = st->state;

    if (ps != NULL) {
        /* Staged blobs are never tracked pre-publish, so an unconditional
         * remove is correct even with refs armed. */
        pblock_remove_blocks(ps->st, ps->blob_id, ps->size, ps->block_size);
        brix_wverify_free(ps->wv);       /* F10 (NULL-safe) */
        if (ps->st->snap) {              /* F6: released */
            __atomic_sub_fetch(&ps->st->open_files, 1, __ATOMIC_RELEASE);
        }
        free(ps);
    }
    free(st);
}

#endif /* BRIX_HAVE_SQLITE */
