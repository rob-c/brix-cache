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

/*
 * WHAT: Allocate a staged handle and its private pblock state together.
 * WHY:  A single failure path keeps staged-open admission easy to audit.
 * HOW:  Allocate both objects and report ENOMEM after releasing partial state.
 */
static brix_sd_staged_t *
pblock_staged_alloc(pblock_staged_t **state, int *err_out)
{
    brix_sd_staged_t *handle = calloc(1, sizeof(*handle));

    *state = calloc(1, sizeof(**state));
    if (handle != NULL && *state != NULL)
        return handle;
    free(handle);
    free(*state);
    *state = NULL;
    if (err_out != NULL)
        *err_out = ENOMEM;
    return NULL;
}

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

    handle = pblock_staged_alloc(&ps, err_out);
    if (handle == NULL) {
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

/*
 * WHAT: Validate and, when necessary, remove a staged commit destination.
 * WHY:  Lease, quota, no-replace, and history rules form one namespace gate.
 * HOW:  Lookup once, admit the delta, preserve history, then drop an overwrite.
 */
static int
pblock_staged_prepare_destination(pblock_state_t *pst, pblock_staged_t *ps,
    int noreplace, pblock_meta *previous, int *existed)
{
    int rc = pblock_catalog_lookup(pst->cat, ps->final_path, previous);

    if (rc < 0)
        return -1;
    if (pst->locks
        && pblock_locks_ns_check(pst, ps->final_path, ps->uid) != 0)
        return -1;
    if (pblock_quota_admit(pst, ps->uid,
            ps->size - (rc == 0 ? previous->size : 0), rc == 0 ? 0 : 1) != 0)
        return -1;
    *existed = rc == 0;
    if (!*existed)
        return 0;
    if (noreplace) {
        errno = EEXIST;
        return -1;
    }
    if (pst->versions > 0)
        (void) pblock_hist_version_push(pst, ps->final_path, previous);
    return sd_pblock_drop_dst(pst, ps->final_path, previous) == NGX_OK ? 0 : -1;
}

/*
 * WHAT: Fill the catalog metadata for a newly committed staged blob.
 * WHY:  Metadata construction is deterministic and independent of publication.
 * HOW:  Copy staged ownership and size, stamp time, mode, and transform kind.
 */
static void
pblock_staged_build_meta(const pblock_staged_t *ps, pblock_meta *meta)
{
    memset(meta, 0, sizeof(*meta));
    meta->is_dir = 0;
    snprintf(meta->blob_id, sizeof(meta->blob_id), "%s", ps->blob_id);
    meta->size = ps->size;
    meta->block_size = ps->block_size;
    meta->mtime = meta->ctime = pblock_now();
    meta->mode = S_IFREG | (ps->mode & 0777);
    meta->uid = ps->uid;
    meta->gid = ps->gid;
    snprintf(meta->xform, sizeof(meta->xform), "%s",
             pblock_xform_name(ps->st->xform.kind));
}

/*
 * WHAT: Record integrity, anomaly, and audit state after catalog publication.
 * WHY:  These observers must run only after the new row becomes authoritative.
 * HOW:  Update enabled facilities and consume the staged checksum accumulator.
 */
static void
pblock_staged_record_commit(pblock_state_t *pst, pblock_staged_t *ps,
    pblock_meta *meta, const pblock_meta *previous, int existed)
{
    if (pst->lab != NULL) {
        if (existed)
            pblock_anomaly_updated(pst, ps->final_path, previous->size,
                                   previous->mtime);
        else
            pblock_anomaly_created(pst, ps->final_path);
    }
    if (pst->csi)
        (void) pblock_csi_flush(pst, ps->blob_id, ps->size, ps->block_size,
                                0, INT64_MAX);
    if (ps->wv != NULL) {
        if (pst->refs) {
            uint32_t crc = 0;
            off_t total = 0;
            int ok = brix_wverify_expected(ps->wv, &crc, &total) == 0
                     && (int64_t) total == ps->size;

            (void) pblock_refs_dedup_publish(pst, ps->final_path, meta, crc, ok);
        }
        brix_wverify_free(ps->wv);
    }
    if (pst->audit) {
        char aux[32];

        snprintf(aux, sizeof(aux), "w=%lld", (long long) ps->size);
        pblock_audit_log(pst->cat, "commit", ps->final_path, aux,
                         ps->uid, ps->gid, 0, 0);
    }
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
    int              existed;

    if (pblock_staged_prepare_destination(pst, ps, noreplace, &dmeta,
                                          &existed) != 0)
        return NGX_ERROR;
    pblock_staged_build_meta(ps, &meta);

    /* F7: a crash here leaves the staged blocks on disk with no catalog row —
     * the canonical orphan-blob residue pblock-fsck must detect and --gc. */
    pblock_lab_crash(pst->lab, "mid_staged_commit");

    if (pblock_catalog_put(pst->cat, ps->final_path, &meta) != 0) {
        return NGX_ERROR;
    }

    pblock_staged_record_commit(pst, ps, &meta, &dmeta, existed);

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
