/*
 * reaper.c — worker-0 timer that expires stale queue records.
 *
 * WHAT: frm_reap_expired() deletes records whose tod_expire has passed;
 *   frm_reaper_register() arms a periodic per-worker timer (worker 0 only) that
 *   drives it. Modeled on the CRL reload timer (src/config/process.c).
 *
 * WHY: Terminal records (ONLINE/FAILED) and abandoned requests must not
 *   accumulate forever. A single worker runs the reaper so the file lock is not
 *   contended N-ways; deletes are idempotent, so even if it ran on several
 *   workers the only cost would be wasted scans.
 */

#include "frm_internal.h"

#include <time.h>


#define FRM_REAP_INTERVAL_MS   60000
#define FRM_REAP_BATCH         64


ngx_int_t
frm_reap_expired(frm_queue_t *q, time_t now, ngx_log_t *log)
{
    frm_record_t rec;
    int64_t      off, size;
    char         expired[FRM_REAP_BATCH][FRM_REQID_LEN];
    int          n = 0, i;

    if (q == NULL || q->fd < 0) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = frm_file_size(q);
    for (off = FRM_REC_OFF(0);
         size > 0 && off + (int64_t) FRM_REC_SIZE <= size && n < FRM_REAP_BATCH;
         off += (int64_t) FRM_REC_SIZE)
    {
        if (frm_rec_read(q, off, &rec, log) != NGX_OK) {
            break;
        }
        if (!frm_rec_valid(&rec, off) || rec.status == FRM_ST_FREE) {
            continue;
        }
        if (rec.tod_expire > 0 && rec.tod_expire <= (int64_t) now) {
            ngx_cpystrn((u_char *) expired[n], (u_char *) rec.reqid,
                        FRM_REQID_LEN);
            n++;
        }
    }
    frm_file_unlock(q);

    for (i = 0; i < n; i++) {
        (void) frm_request_delete(q, expired[i], log);
    }
    if (n > 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "frm: reaped %d expired request(s)", n);
    }
    return NGX_OK;
}


/* the timer*/
static ngx_event_t   frm_reaper_ev;
static frm_queue_t  *frm_reaper_q;

static void
frm_reaper_handler(ngx_event_t *ev)
{
    if (frm_reaper_q != NULL) {
        (void) frm_reap_expired(frm_reaper_q, time(NULL), ev->log);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, FRM_REAP_INTERVAL_MS);
    }
}

void
frm_reaper_register(ngx_cycle_t *cycle)
{
    frm_queue_t *q = frm_singleton_queue();

    if (q == NULL || q->fd < 0) {
        return;
    }
    if (ngx_worker != 0) {              /* only worker 0 runs the reaper */
        return;
    }
    frm_reaper_q = q;
    ngx_memzero(&frm_reaper_ev, sizeof(frm_reaper_ev));
    frm_reaper_ev.handler = frm_reaper_handler;
    frm_reaper_ev.log     = cycle->log;
    frm_reaper_ev.data    = &frm_reaper_ev;
    ngx_add_timer(&frm_reaper_ev, FRM_REAP_INTERVAL_MS);
}
