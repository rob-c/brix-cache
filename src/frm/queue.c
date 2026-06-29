/*
 * queue.c — the FRM queue façade.
 *
 * WHAT: Lifecycle (frm_queue_get / frm_queue_init) plus the public mutating and
 *   read ops (frm_request_add/get/set_status/delete/find_by_path/list). Each
 *   mutating op commits to the durable file under the excl fcntl lock, then
 *   patches the SHM index; each read takes the shared lock so it never observes a
 *   half-written record.
 *
 * WHY: This is the single point that enforces "file = truth, SHM = cache" — the
 *   authority order (file first, index second) lives here so callers (prepare.c,
 *   the Tape REST endpoint, the open path) never see the split.
 *
 * Phase 0: one configured queue. Slot allocation reuses the first FREE slot (a
 * linear scan under the lock) before growing the file, so the file stays bounded
 * to the high-water-mark of concurrent requests; no on-disk chain is kept.
 */

#include "frm_internal.h"

#include <string.h>
#include <time.h>
#include <unistd.h>


static frm_queue_t  frm_q;
static int          frm_q_used;


frm_queue_t *
frm_singleton_queue(void)
{
    return frm_q_used ? &frm_q : NULL;
}

frm_queue_t *
frm_queue_get(ngx_conf_t *cf, const ngx_str_t *path, ngx_uint_t max_inflight,
              ngx_uint_t max_per_source)
{
    if (path == NULL || path->len == 0) {
        return NULL;
    }
    if (frm_q_used) {
        return &frm_q;                  /* Phase 0: single queue */
    }
    ngx_memzero(&frm_q, sizeof(frm_q));

    frm_q.path.data = ngx_pnalloc(cf->pool, path->len + 1);
    if (frm_q.path.data == NULL) {
        return NULL;
    }
    ngx_memcpy(frm_q.path.data, path->data, path->len);
    frm_q.path.data[path->len] = '\0';
    frm_q.path.len     = path->len;
    frm_q.fd             = -1;
    frm_q.lock_fd        = -1;
    frm_q.max_inflight   = max_inflight;
    frm_q.max_per_source = max_per_source;

    if (gethostname(frm_q.host, sizeof(frm_q.host)) != 0) {
        ngx_memcpy(frm_q.host, "localhost", sizeof("localhost"));
    }
    frm_q.host[sizeof(frm_q.host) - 1] = '\0';

    frm_q_used = 1;
    return &frm_q;
}

ngx_int_t
frm_queue_init(frm_queue_t *q, ngx_log_t *log)
{
    if (q == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_open(q, log) != NGX_OK) {
        return NGX_ERROR;
    }
    q->inited = 1;
    return NGX_OK;
}


/* internal helpers (caller holds the excl lock for alloc)*/
/* First reusable (FREE or torn) slot, else the EOF offset (grow). */
static int64_t
frm_alloc_slot(frm_queue_t *q, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      size = frm_file_size(q);
    int64_t      off;

    if (size < 0) {
        return -1;
    }
    for (off = FRM_REC_OFF(0);
         off + (int64_t) FRM_REC_SIZE <= size;
         off += (int64_t) FRM_REC_SIZE)
    {
        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            return -1;
        }
        if (!frm_rec_valid(&rec, off) || rec.status == FRM_ST_FREE) {
            return off;
        }
    }
    return (size < FRM_REC_OFF(0)) ? FRM_REC_OFF(0) : size;   /* grow @EOF */
}

/* Resolve a reqid → file offset: SHM index first, linear file scan on a miss. */
static int64_t
frm_offset_by_reqid(frm_queue_t *q, const char *reqid, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off = -1, size;

    if (frm_index_lookup(reqid, &off)) {
        return off;
    }
    /* Index miss (LRU-evicted or another worker's add not yet seen): scan. */
    size = frm_file_size(q);
    for (off = FRM_REC_OFF(0);
         size > 0 && off + (int64_t) FRM_REC_SIZE <= size;
         off += (int64_t) FRM_REC_SIZE)
    {
        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            return -1;
        }
        if (frm_rec_valid(&rec, off)
            && rec.status != FRM_ST_FREE
            && ngx_strcmp(rec.reqid, reqid) == 0)
        {
            frm_index_insert(&rec);     /* warm the cache */
            return off;
        }
    }
    return -1;
}


/* public mutating ops*/
ngx_int_t
frm_request_add(frm_queue_t *q, const frm_req_view_t *req,
                char *reqid_out, size_t reqid_out_sz, ngx_log_t *log)
{
    frm_file_hdr_t hdr;
    frm_record_t   rec;
    int64_t        off;
    uint64_t       seq;
    time_t         now;

    if (q == NULL || q->fd < 0 || req == NULL || req->lfn == NULL
        || reqid_out == NULL || reqid_out_sz < FRM_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (ngx_strlen(req->lfn) >= FRM_LFN_LEN) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "frm: lfn exceeds %d bytes",
                      FRM_LFN_LEN);
        return NGX_ERROR;
    }

    if (q->max_inflight > 0 && frm_index_count() >= q->max_inflight) {
        XROOTD_FRM_METRIC_INC(reject_inflight_total);
        return NGX_ABORT;
    }

    now = time(NULL);

    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Authoritative dedup UNDER THE LOCK: a live (QUEUED/STAGING) request for the
     * same lfn means N concurrent opens collapse to ONE recall. The linear scan
     * is O(slots) but admissions are rare; correctness beats the racy pre-lock
     * index hint it replaces.
     */
    {
        int64_t      scan, size = frm_file_size(q);
        frm_record_t ex;
        ngx_uint_t   src_live = 0;          /* F4: live records for this DN */
        int          count_src = (q->max_per_source > 0
                                  && req->requester_dn != NULL
                                  && req->requester_dn[0] != '\0');
        for (scan = FRM_REC_OFF(0);
             size > 0 && scan + (int64_t) FRM_REC_SIZE <= size;
             scan += (int64_t) FRM_REC_SIZE)
        {
            if (frm_rec_read(q, scan, &ex, log) != NGX_OK) {
                continue;
            }
            if (!frm_rec_valid(&ex, scan)
                || (ex.status != FRM_ST_QUEUED && ex.status != FRM_ST_STAGING))
            {
                continue;
            }
            if (ex.xfer_kind == req->xfer_kind
                && ngx_strcmp(ex.lfn, req->lfn) == 0)
            {
                /* dedup is per-kind: a live recall and a live write-through for
                 * the same path are distinct transfers and must not collapse. */
                ngx_cpystrn((u_char *) reqid_out, (u_char *) ex.reqid,
                            reqid_out_sz);
                frm_file_unlock(q);
                XROOTD_FRM_METRIC_INC(dedup_hits_total);
                return NGX_DECLINED;
            }
            if (count_src
                && ngx_strcmp(ex.requester_dn, req->requester_dn) == 0)
            {
                src_live++;
            }
        }
        /* F4 per-source quota: cap concurrent live recalls per requester DN. */
        if (count_src && src_live >= q->max_per_source) {
            frm_file_unlock(q);
            XROOTD_FRM_METRIC_INC(reject_inflight_total);
            return NGX_ABORT;
        }
    }

    if (frm_hdr_read(q, &hdr, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    off = frm_alloc_slot(q, log);
    if (off < 0) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;

    ngx_memzero(&rec, sizeof(rec));
    rec.self        = off;
    rec.status      = FRM_ST_QUEUED;
    rec.options     = req->options;
    rec.cs_type     = (uint8_t) req->cs_type;
    rec.priority    = req->priority;
    rec.queue       = req->queue;
    rec.tod_added   = (int64_t) now;
    rec.tod_status  = (int64_t) now;
    rec.tod_expire  = req->tod_expire;
    rec.opaque_off  = -1;
    rec.lfn_url_off = -1;
    rec.xfer_kind      = req->xfer_kind;       /* 0 = tape (default) */
    rec.xfer_mode_bits = req->xfer_mode_bits;
    frm_reqid_format(q->host, seq, rec.reqid, sizeof(rec.reqid));
    ngx_cpystrn((u_char *) rec.lfn, (u_char *) req->lfn, sizeof(rec.lfn));
    if (req->requester_dn) {
        ngx_cpystrn((u_char *) rec.requester_dn,
                    (u_char *) req->requester_dn, sizeof(rec.requester_dn));
    }
    if (req->user) {
        ngx_cpystrn((u_char *) rec.user, (u_char *) req->user, sizeof(rec.user));
    }
    if (req->notify) {
        ngx_cpystrn((u_char *) rec.notify, (u_char *) req->notify,
                    sizeof(rec.notify));
    }
    if (req->selector) {
        ngx_cpystrn((u_char *) rec.selector, (u_char *) req->selector,
                    sizeof(rec.selector));
    }
    if (req->cs_value) {
        ngx_cpystrn((u_char *) rec.cs_value, (u_char *) req->cs_value,
                    sizeof(rec.cs_value));
    }

    /* WAL: record body durable first, then the header publishes the new seq. */
    if (frm_rec_write(q, off, &rec, log) != NGX_OK
        || frm_hdr_write(q, &hdr, log) != NGX_OK)
    {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    frm_file_unlock(q);

    frm_index_insert(&rec);
    ngx_cpystrn((u_char *) reqid_out, (u_char *) rec.reqid, reqid_out_sz);
    XROOTD_FRM_METRIC_INC(requests_total);
    XROOTD_FRM_METRIC_INC(in_flight);       /* gauge: QUEUED+STAGING live count */
    return NGX_OK;
}

ngx_int_t
frm_request_set_status(frm_queue_t *q, const char *reqid,
                       frm_status_t status, int32_t fail_code, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off;

    if (q == NULL || q->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = frm_offset_by_reqid(q, reqid, log);
    if (off < 0
        || frm_rec_read(q, off, &rec, log) != NGX_OK
        || !frm_rec_valid(&rec, off)
        || rec.status == FRM_ST_FREE)
    {
        frm_file_unlock(q);
        return NGX_DECLINED;
    }
    {
        uint8_t old_status = rec.status;
        rec.status     = (uint8_t) status;
        rec.fail_code  = fail_code;
        rec.tod_status = (int64_t) time(NULL);
        if (frm_rec_write(q, off, &rec, log) != NGX_OK) {
            frm_file_unlock(q);
            return NGX_ERROR;
        }
        frm_file_unlock(q);

        frm_index_update(reqid, (uint8_t) status, rec.tod_expire);

        /* in_flight gauge: a record leaves "live" when it moves from
         * QUEUED/STAGING to a terminal state (ONLINE/FAILED/CANCELLED). Counting
         * the DEC here covers stage completion, dispatch-failure, and cancel in
         * one place — claim (QUEUED→STAGING) is not terminal, so no DEC. */
        if ((old_status == FRM_ST_QUEUED || old_status == FRM_ST_STAGING)
            && (status == FRM_ST_ONLINE || status == FRM_ST_FAILED
                || status == FRM_ST_CANCELLED))
        {
            XROOTD_FRM_METRIC_DEC(in_flight);
        }
    }
    return NGX_OK;
}

ngx_int_t
frm_request_delete(frm_queue_t *q, const char *reqid, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off;

    if (q == NULL || q->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = frm_offset_by_reqid(q, reqid, log);
    if (off < 0
        || frm_rec_read(q, off, &rec, log) != NGX_OK
        || !frm_rec_valid(&rec, off)
        || rec.status == FRM_ST_FREE)
    {
        frm_file_unlock(q);
        return NGX_DECLINED;            /* already gone — idempotent */
    }
    {
        uint8_t old_status = rec.status;
        ngx_memzero(&rec, sizeof(rec));
        rec.status = FRM_ST_FREE;
        if (frm_rec_write(q, off, &rec, log) != NGX_OK) {
            frm_file_unlock(q);
            return NGX_ERROR;
        }
        frm_file_unlock(q);

        frm_index_remove(reqid);
        /* deleting a still-live record (e.g. cancel before completion) drops it
         * from the in_flight gauge; a terminal record was already DEC'd. */
        if (old_status == FRM_ST_QUEUED || old_status == FRM_ST_STAGING) {
            XROOTD_FRM_METRIC_DEC(in_flight);
        }
    }
    return NGX_OK;
}

/*
 * WHAT: Authorization guard for a CLIENT-initiated cancel/evict of a stage
 *   request named by reqid. Returns NGX_OK when caller_dn is permitted to act on
 *   the request, NGX_DECLINED when the request is owned by a DIFFERENT
 *   authenticated principal.
 * WHY: Without it, any client could cancel/evict another tenant's recall by its
 *   guessable monotonic reqid (a cross-VO DoS). The owner DN is recorded on the
 *   record at enqueue (requester_dn); this re-checks it at cancel time.
 * HOW: Fail-OPEN by design so the check never breaks existing single-trust-domain
 *   deployments: an unauthenticated/anonymous caller, an absent/gone record
 *   (idempotent, no enumeration oracle), or a record with no recorded owner
 *   (anon-created) all pass. ONLY a concrete owner-DN vs caller-DN mismatch is
 *   denied. Internal callers (reaper expiry, dedup, completion) bypass this and
 *   call frm_request_delete/_set_status directly — only the two user-facing
 *   cancel/evict entry points consult this. The reqid→owner binding is immutable,
 *   so the get-then-act window is race-free for authorization purposes. */
ngx_int_t
frm_request_owner_check(frm_queue_t *q, const char *reqid,
                        const char *caller_dn, ngx_log_t *log)
{
    frm_record_t rec;

    if (caller_dn == NULL || caller_dn[0] == '\0') {
        return NGX_OK;            /* anonymous caller: no ownership to enforce */
    }
    if (frm_request_get(q, reqid, &rec, log) != NGX_OK) {
        return NGX_OK;            /* absent/gone: idempotent, no oracle */
    }
    if (rec.requester_dn[0] == '\0') {
        return NGX_OK;            /* record has no recorded owner (anon-created) */
    }
    if (ngx_strcmp(rec.requester_dn, caller_dn) == 0) {
        return NGX_OK;            /* owner match */
    }
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "frm: cancel/evict of reqid \"%s\" denied — request is owned "
                  "by a different principal", reqid);
    return NGX_DECLINED;
}

ngx_int_t
frm_request_claim(frm_queue_t *q, const char *reqid, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off;

    if (q == NULL || q->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = frm_offset_by_reqid(q, reqid, log);
    if (off < 0
        || frm_rec_read(q, off, &rec, log) != NGX_OK
        || !frm_rec_valid(&rec, off)
        || rec.status != FRM_ST_QUEUED)        /* only QUEUED → STAGING */
    {
        frm_file_unlock(q);
        return NGX_DECLINED;                    /* already claimed / gone */
    }
    rec.status     = FRM_ST_STAGING;
    rec.tod_status = (int64_t) time(NULL);
    rec.attempts++;
    if (frm_rec_write(q, off, &rec, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    frm_file_unlock(q);

    frm_index_update(reqid, FRM_ST_STAGING, rec.tod_expire);
    return NGX_OK;
}


/* public read ops (shared lock; never observe a torn record)*/
ngx_int_t
frm_request_get(frm_queue_t *q, const char *reqid, frm_record_t *out,
                ngx_log_t *log)
{
    int64_t off;

    if (q == NULL || q->fd < 0 || reqid == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    off = frm_offset_by_reqid(q, reqid, log);
    if (off < 0
        || frm_rec_read(q, off, out, log) != NGX_OK
        || !frm_rec_valid(out, off)
        || out->status == FRM_ST_FREE)
    {
        frm_file_unlock(q);
        return NGX_DECLINED;
    }
    frm_file_unlock(q);
    return NGX_OK;
}

ngx_int_t
frm_request_find_by_path(frm_queue_t *q, const char *lfn, frm_record_t *out,
                         ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off, size, best_off = -1, best_tod = -1;
    uint64_t     lfn_hash;

    if (q == NULL || q->fd < 0 || lfn == NULL || out == NULL) {
        return NGX_ERROR;
    }
    lfn_hash = frm_lfn_hash(lfn);

    if (frm_file_lock(q, FRM_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    /* Fast path: the index points at the newest live record for this hash. */
    if (frm_index_lookup_path(lfn_hash, 1, &off)
        && frm_rec_read(q, off, &rec, log) == NGX_OK
        && frm_rec_valid(&rec, off)
        && ngx_strcmp(rec.lfn, lfn) == 0)
    {
        *out = rec;
        frm_file_unlock(q);
        return NGX_OK;
    }
    /* Slow path: linear scan for the newest live record matching the lfn. */
    size = frm_file_size(q);
    for (off = FRM_REC_OFF(0);
         size > 0 && off + (int64_t) FRM_REC_SIZE <= size;
         off += (int64_t) FRM_REC_SIZE)
    {
        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            frm_file_unlock(q);
            return NGX_ERROR;
        }
        if (!frm_rec_valid(&rec, off) || rec.status == FRM_ST_FREE) {
            continue;
        }
        if (ngx_strcmp(rec.lfn, lfn) == 0 && rec.tod_added >= best_tod) {
            best_tod = rec.tod_added;
            best_off = off;
            *out = rec;
        }
    }
    frm_file_unlock(q);
    return (best_off >= 0) ? NGX_OK : NGX_DECLINED;
}

ngx_int_t
frm_request_list(frm_queue_t *q, ngx_uint_t *cursor, int status, int queue,
                 const char *dn_filter, frm_record_t *out, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off, size;

    if (q == NULL || q->fd < 0 || cursor == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = frm_file_size(q);

    for ( ;; ) {
        off = FRM_REC_OFF(*cursor);
        if (size <= 0 || off + (int64_t) FRM_REC_SIZE > size) {
            frm_file_unlock(q);
            return NGX_DONE;
        }
        (*cursor)++;

        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            frm_file_unlock(q);
            return NGX_ERROR;
        }
        if (!frm_rec_valid(&rec, off) || rec.status == FRM_ST_FREE) {
            continue;
        }
        if (status >= 0 && rec.status != (uint8_t) status) {
            continue;
        }
        if (queue != 0xff && rec.queue != (uint8_t) queue) {
            continue;
        }
        if (dn_filter != NULL && ngx_strcmp(rec.requester_dn, dn_filter) != 0) {
            continue;
        }
        *out = rec;
        frm_file_unlock(q);
        return NGX_OK;
    }
}


/* ===========================================================================
 * Phase 2 — HTTP WLCG Tape REST façade (thin wrappers over the store above).
 * ======================================================================== */

ngx_int_t
frm_file_locality(const char *full_path, frm_residency_t *out, ngx_log_t *log)
{
    if (full_path == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (frm_residency_probe(log, full_path, out) != NGX_OK) {
        return NGX_ERROR;
    }
    return (out->state == FRM_RES_LOST) ? NGX_DECLINED : NGX_OK;
}

ngx_int_t
frm_request_list_files(frm_queue_t *q, const char *reqid, frm_record_t *out,
                       ngx_log_t *log)
{
    /* Phase 0/1: a request id maps to exactly one lfn. Bulk grouping (one id,
     * many files) is deferred — see the §3.3 canonical-façade note. */
    return frm_request_get(q, reqid, out, log);
}

ngx_int_t
frm_request_list_active(frm_queue_t *q, ngx_uint_t *cursor,
                        const char *dn_filter, frm_record_t *out, ngx_log_t *log)
{
    return frm_request_list(q, cursor, -1, 0xff, dn_filter, out, log);
}

ngx_int_t
frm_request_cancel(frm_queue_t *q, const char *reqid, ngx_log_t *log)
{
    /* Mark CANCELLED (kept so a later status query can report it); the in_flight
     * gauge DEC and index update happen inside frm_request_set_status. */
    return frm_request_set_status(q, reqid, FRM_ST_CANCELLED, 0, log);
}

ngx_int_t
frm_pin_release(const char *full_path, ngx_log_t *log)
{
    frm_residency_t res;

    if (full_path == NULL) {
        return NGX_ERROR;
    }
    if (frm_residency_probe(log, full_path, &res) != NGX_OK
        || res.state == FRM_RES_LOST)
    {
        return NGX_DECLINED;
    }
    /* The staged copy may now be purged. Real disk reclamation is delegated to
     * the MSS (Category-2, Phase 4); here we only record the release intent. */
    XROOTD_FRM_METRIC_INC(evict_total);
    ngx_log_error(NGX_LOG_INFO, log, 0, "frm: pin released \"%s\"", full_path);
    return NGX_OK;
}
