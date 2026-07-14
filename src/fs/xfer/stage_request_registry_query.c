/*
 * stage_request_registry_query.c — read/query ops of the durable stage-request
 * registry (split from stage_request_registry.c, phase-79).
 *
 * WHAT: The read side of the reqid-keyed durable request store — fetch a request
 *       by reqid, find the newest active request for a path, owner-check a reqid,
 *       enumerate active requests and a request's files, and translate a pin
 *       release into a cancel. Each op takes a SHARED whole-store lock (or none,
 *       for the compositions that delegate), scans fixed slots, and unlocks.
 * WHY:  The single 956-line registry owned three concerns; isolating the read
 *       ops here keeps every translation unit under the file-size cap and
 *       focused. The durable-store substrate (file I/O, locking, slot scan)
 *       stays in stage_request_registry.c and is reached only through the seam
 *       declared in stage_request_registry_internal.h — the lock/unlock
 *       boundaries and slot math are unchanged by the split.
 * HOW:  Each op is a flat early-return sequence over the substrate helpers:
 *       srq_lock(SHARE) -> srq_offset_by_reqid / slot scan -> srq_rec_read +
 *       srq_rec_valid -> srq_unlock -> srq_rec_to_view. The composite ops
 *       (owner_check, list_files, pin_release) reuse the public read ops rather
 *       than re-scanning.
 */

#include "stage_request_registry.h"
#include "stage_request_registry_internal.h"


/* read ops */

ngx_int_t
brix_stage_request_get(brix_stage_registry_t *reg, const char *reqid,
                         brix_stage_request_t *out, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_DECLINED;
    }
    srq_unlock(reg);
    srq_rec_to_view(&rec, out);
    return NGX_OK;
}

ngx_int_t
brix_stage_request_find_by_path(brix_stage_registry_t *reg, const char *lfn,
    char *reqid_out, size_t reqid_out_sz, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off, size, best_off = -1, best_tod = -1;
    char      best_reqid[SRQ_REQID_LEN];

    if (reg == NULL || reg->fd < 0 || lfn == NULL || reqid_out == NULL
        || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = srq_file_size(reg);
    for (off = SRQ_REC_OFF(0);
         size > 0 && off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            srq_unlock(reg);
            return NGX_ERROR;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE) {
            continue;
        }
        if (ngx_strcmp(rec.lfn, lfn) == 0 && rec.tod_added >= best_tod) {
            best_tod = rec.tod_added;
            best_off = off;
            ngx_cpystrn((u_char *) best_reqid, (u_char *) rec.reqid,
                        sizeof(best_reqid));
        }
    }
    srq_unlock(reg);
    if (best_off < 0) {
        return NGX_DECLINED;
    }
    ngx_cpystrn((u_char *) reqid_out, (u_char *) best_reqid, reqid_out_sz);
    return NGX_OK;
}

ngx_int_t
brix_stage_request_owner_check(brix_stage_registry_t *reg, const char *reqid,
    const char *requester_dn, ngx_log_t *log)
{
    brix_stage_request_t rec;

    if (requester_dn == NULL || requester_dn[0] == '\0') {
        return NGX_OK;                  /* anonymous caller: nothing to enforce */
    }
    if (brix_stage_request_get(reg, reqid, &rec, log) != NGX_OK) {
        return NGX_OK;                  /* absent/gone: idempotent, no oracle */
    }
    if (rec.requester_dn[0] == '\0'
        || ngx_strcmp(rec.requester_dn, requester_dn) == 0)
    {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "stage-req: cancel of reqid \"%s\" denied — owned by a "
                  "different principal", reqid);
    return NGX_DECLINED;
}

ngx_int_t
brix_stage_request_list_active(brix_stage_registry_t *reg,
    ngx_uint_t *cursor, brix_stage_request_t *out, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off, size;

    if (reg == NULL || reg->fd < 0 || cursor == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = srq_file_size(reg);
    for ( ;; ) {
        off = SRQ_REC_OFF(*cursor);
        if (size <= 0 || off + (int64_t) SRQ_REC_SIZE > size) {
            srq_unlock(reg);
            return NGX_DONE;
        }
        (*cursor)++;
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            srq_unlock(reg);
            return NGX_ERROR;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE) {
            continue;
        }
        srq_unlock(reg);
        srq_rec_to_view(&rec, out);
        return NGX_OK;
    }
}

ngx_int_t
brix_stage_request_list_files(brix_stage_registry_t *reg, const char *reqid,
    ngx_uint_t *cursor, brix_stage_request_t *out, ngx_log_t *log)
{
    /* One request id maps to exactly one lfn (bulk grouping deferred): yield the
     * single record on cursor 0, then NGX_DONE. */
    if (cursor == NULL) {
        return NGX_ERROR;
    }
    if (*cursor > 0) {
        return NGX_DONE;
    }
    (*cursor)++;
    return brix_stage_request_get(reg, reqid, out, log);
}

ngx_int_t
brix_stage_request_pin_release(brix_stage_registry_t *reg,
    const char *abs_path, ngx_log_t *log)
{
    char      reqid[SRQ_REQID_LEN];
    ngx_int_t rc;

    if (reg == NULL || abs_path == NULL) {
        return NGX_ERROR;
    }
    /* Record the release intent by cancelling any live request for the path; real
     * disk reclamation is delegated to the MSS/backend. */
    rc = brix_stage_request_find_by_path(reg, abs_path, reqid, sizeof(reqid), log);
    if (rc != NGX_OK) {
        return NGX_DECLINED;            /* not tracked / not pinned */
    }
    ngx_log_error(NGX_LOG_INFO, log, 0, "stage-req: pin released \"%s\"", abs_path);
    return brix_stage_request_cancel(reg, reqid, log);
}
