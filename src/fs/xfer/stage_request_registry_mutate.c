/*
 * stage_request_registry_mutate.c — mutating client ops of the durable
 * stage-request registry (split from stage_request_registry.c, phase-79).
 *
 * WHAT: The write side of the reqid-keyed durable request store — mint a reqid,
 *       admit a request, set its status, cancel/delete it, and reap expired
 *       records. Each op takes the whole-store lock, mutates a fixed slot with
 *       WAL ordering (record fdatasync then header fsync), and unlocks.
 * WHY:  The single 956-line registry owned three concerns; isolating the
 *       mutating ops here keeps every translation unit under the file-size cap
 *       and focused. The durable-store substrate (file I/O, locking, slot scan)
 *       stays in stage_request_registry.c and is reached only through the seam
 *       declared in stage_request_registry_internal.h — the lock/unlock
 *       boundaries and slot math are unchanged by the split.
 * HOW:  Every public op is a flat early-return sequence over the substrate
 *       helpers: srq_lock -> srq_hdr_read / srq_offset_by_reqid / srq_alloc_slot
 *       -> srq_rec_write + srq_hdr_write -> srq_unlock. The pure precondition and
 *       record-marshalling helpers for add() are kept local and side-effect-free.
 */

#include "stage_request_registry.h"
#include "stage_request_registry_internal.h"

#include <time.h>


/* reqid generation */

ngx_int_t
brix_stage_request_reqid_generate(brix_stage_registry_t *reg,
    char *reqid_out, size_t reqid_out_sz, ngx_log_t *log)
{
    srq_hdr_t hdr;
    uint64_t  seq;

    if (reg == NULL || reg->fd < 0 || reqid_out == NULL
        || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (srq_hdr_read(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;
    if (srq_hdr_write(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    srq_reqid_format(reg->host, seq, reqid_out, reqid_out_sz);
    return NGX_OK;
}


/* mutating ops */

/* ---- Validate the add-request arguments before any lock is taken ----
 *
 * WHAT: Return NGX_OK when every argument brix_stage_request_add needs is
 * usable, otherwise NGX_ERROR. Rejects null/closed registry, a missing view or
 * lfn, a too-small reqid_out buffer, and an lfn wider than the on-disk field
 * (the last logs the width violation).
 *
 * WHY: Keeps the mutating orchestrator flat and side-effect-honest by pulling
 * the pure precondition checks out of the locked critical section — none of
 * these touch the file, so they belong entirely before srq_lock.
 *
 * HOW:
 *   1. Reject any null/closed handle or too-small caller buffer.
 *   2. Reject an lfn that would not fit SRQ_LFN_LEN, logging the reason.
 *   3. Return NGX_OK when all checks pass.
 */
static ngx_int_t
srq_add_validate_args(brix_stage_registry_t *reg,
    const brix_stage_request_view_t *view, const char *reqid_out,
    size_t reqid_out_sz, ngx_log_t *log)
{
    if (reg == NULL || reg->fd < 0 || view == NULL || view->lfn == NULL
        || reqid_out == NULL || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (ngx_strlen(view->lfn) >= SRQ_LFN_LEN) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "stage-req: lfn exceeds %d bytes",
                      SRQ_LFN_LEN);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- Populate a blank on-disk record from a caller's request view ----
 *
 * WHAT: Zero-fill *rec and fill every field for a freshly QUEUED request from
 * *view, stamping the self-offset, timestamps, reqid, lfn and the optional
 * requester_dn/user/cs_value strings.
 *
 * WHY: This is pure record marshalling with no I/O and no lock interaction, so
 * isolating it keeps brix_stage_request_add a short, linear sequence and makes
 * the field mapping independently reviewable.
 *
 * HOW:
 *   1. Zero the record and set the fixed QUEUED-state scalar fields.
 *   2. Format the reqid from the host + durable seq and copy the mandatory lfn.
 *   3. Copy each optional string only when the view supplies it.
 */
static void
srq_rec_populate_from_view(srq_rec_t *rec,
    const brix_stage_request_view_t *view, const char *host, uint64_t seq,
    int64_t off, time_t now)
{
    ngx_memzero(rec, sizeof(*rec));
    rec->self        = off;
    rec->status      = SRQ_ST_QUEUED;
    rec->cs_type     = (uint8_t) view->cs_type;
    rec->tod_added   = (int64_t) now;
    rec->tod_status  = (int64_t) now;
    rec->tod_expire  = view->tod_expire;
    rec->opaque_off  = -1;
    rec->lfn_url_off = -1;
    srq_reqid_format(host, seq, rec->reqid, sizeof(rec->reqid));
    ngx_cpystrn((u_char *) rec->lfn, (u_char *) view->lfn, sizeof(rec->lfn));
    if (view->requester_dn) {
        ngx_cpystrn((u_char *) rec->requester_dn,
                    (u_char *) view->requester_dn, sizeof(rec->requester_dn));
    }
    if (view->user) {
        ngx_cpystrn((u_char *) rec->user, (u_char *) view->user,
                    sizeof(rec->user));
    }
    if (view->cs_value) {
        ngx_cpystrn((u_char *) rec->cs_value, (u_char *) view->cs_value,
                    sizeof(rec->cs_value));
    }
}

ngx_int_t
brix_stage_request_add(brix_stage_registry_t *reg,
    const brix_stage_request_view_t *view, char *reqid_out,
    size_t reqid_out_sz, ngx_log_t *log)
{
    srq_hdr_t hdr;
    srq_rec_t rec;
    int64_t   off;
    uint64_t  seq;
    time_t    now;

    if (srq_add_validate_args(reg, view, reqid_out, reqid_out_sz, log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    now = time(NULL);

    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (srq_hdr_read(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    off = srq_alloc_slot(reg, log);
    if (off < 0) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;

    srq_rec_populate_from_view(&rec, view, reg->host, seq, off, now);

    if (srq_rec_write(reg, off, &rec, log) != NGX_OK
        || srq_hdr_write(reg, &hdr, log) != NGX_OK)
    {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);

    ngx_cpystrn((u_char *) reqid_out, (u_char *) rec.reqid, reqid_out_sz);
    return NGX_OK;
}

ngx_int_t
brix_stage_request_set_status(brix_stage_registry_t *reg,
    const char *reqid, brix_stage_req_status_t status, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_DECLINED;
    }
    rec.status     = srq_status_on_disk(status);
    rec.tod_status = (int64_t) time(NULL);
    if (srq_rec_write(reg, off, &rec, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    return NGX_OK;
}

ngx_int_t
brix_stage_request_delete(brix_stage_registry_t *reg, const char *reqid,
                            ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_OK;                  /* already gone — idempotent */
    }
    ngx_memzero(&rec, sizeof(rec));
    rec.status = SRQ_ST_FREE;
    if (srq_rec_write(reg, off, &rec, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    return NGX_OK;
}

ngx_int_t
brix_stage_request_cancel(brix_stage_registry_t *reg, const char *reqid,
                            ngx_log_t *log)
{
    /* Mark CANCELLED (kept so a later status query reports it), not deleted. */
    ngx_int_t rc = brix_stage_request_set_status(reg, reqid,
                       BRIX_STAGE_REQ_CANCELLED, log);
    return (rc == NGX_DECLINED) ? NGX_OK : rc;   /* unknown reqid is idempotent */
}

ngx_uint_t
brix_stage_request_reap_expired(brix_stage_registry_t *reg, time_t now,
                                  ngx_log_t *log)
{
    srq_rec_t  rec;
    int64_t    off, size;
    ngx_uint_t reaped = 0;

    if (reg == NULL || reg->fd < 0) {
        return 0;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return 0;
    }
    size = srq_file_size(reg);
    for (off = SRQ_REC_OFF(0);
         size > 0 && off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            break;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE
            || rec.tod_expire == 0 || rec.tod_expire > (int64_t) now)
        {
            continue;
        }
        ngx_memzero(&rec, sizeof(rec));
        rec.status = SRQ_ST_FREE;
        if (srq_rec_write(reg, off, &rec, log) == NGX_OK) {
            reaped++;
        }
    }
    srq_unlock(reg);
    return reaped;
}
