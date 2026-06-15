/*
 * reconcile.c — rebuild the SHM index from the durable file at master start.
 *
 * WHAT: frm_reconcile() validates the header, linearly scans every record slot,
 *   reclaims torn/cancelled slots, re-queues any STAGING request orphaned by a
 *   crash, repopulates the SHM index from the surviving active records, and
 *   bumps + publishes the generation. Runs ONCE in the master (from the index
 *   zone-init callback) before workers fork.
 *
 * WHY: "file = truth, SHM = cache." On every (re)start the index must be rebuilt
 *   from the file — a SHM zone does not survive a restart. A LINEAR scan (rather
 *   than chain-walking) is crash-robust: it never follows a possibly-garbage
 *   `next` pointer, and per-record CRC + self-offset checks make a torn write
 *   detectable so its slot is safely reclaimed rather than trusted.
 *
 * HOW: A record's `status` is authoritative — FREE/CANCELLED slots are free,
 *   QUEUED/ONLINE/FAILED are retained, STAGING is reset to QUEUED (the staging
 *   process died with the server, so the recall must restart). No on-disk chain
 *   is maintained; slot reuse is by FREE-slot scan (queue.c).
 */

#include "frm_internal.h"

#include <string.h>
#include <time.h>


ngx_int_t
frm_reconcile(frm_queue_t *q, ngx_log_t *log)
{
    frm_file_hdr_t     hdr;
    frm_record_t       rec;
    frm_index_table_t *tbl;
    int64_t            size, off;
    ngx_uint_t         active = 0, freed = 0, corrupt = 0, restaged = 0;

    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (frm_hdr_read(q, &hdr, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }

    frm_index_clear();

    size = frm_file_size(q);
    if (size < 0) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }

    for (off = FRM_REC_OFF(0);
         off + (int64_t) FRM_REC_SIZE <= size;
         off += (int64_t) FRM_REC_SIZE)
    {
        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            frm_file_unlock(q);
            return NGX_ERROR;
        }

        if (!frm_rec_valid(&rec, off)) {
            /* Torn/corrupt slot — unrecoverable; reclaim it as FREE. */
            ngx_memzero(&rec, sizeof(rec));
            rec.status = FRM_ST_FREE;
            (void) frm_rec_write(q, off, &rec, log);
            corrupt++;
            continue;
        }

        if (rec.status == FRM_ST_FREE) {
            freed++;
            continue;
        }
        if (rec.status == FRM_ST_CANCELLED) {
            rec.status = FRM_ST_FREE;
            (void) frm_rec_write(q, off, &rec, log);
            freed++;
            continue;
        }
        if (rec.status == FRM_ST_STAGING) {
            rec.status     = FRM_ST_QUEUED;
            rec.tod_status = (int64_t) time(NULL);
            (void) frm_rec_write(q, off, &rec, log);
            restaged++;
        }

        frm_index_insert(&rec);
        active++;
    }

    /* Publish a fresh generation so a worker can detect a stale index. */
    hdr.generation++;
    if (frm_hdr_write(q, &hdr, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    tbl = frm_index_table();
    if (tbl != NULL) {
        ngx_shmtx_lock(frm_index_mutex());
        tbl->generation = hdr.generation;
        ngx_shmtx_unlock(frm_index_mutex());
    }

    frm_file_unlock(q);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "frm: reconciled \"%V\": %ui active, %ui free, %ui re-queued, "
        "%ui corrupt-reclaimed (gen %uL)",
        &q->path, active, freed, restaged, corrupt, hdr.generation);

    if (frm_compact_needed(&hdr, size)) {
        (void) frm_compact(q, log);     /* best-effort; failure leaves file ok */
    }
    return NGX_OK;
}
