/*
 * writethrough_replay.c — restart recovery for durable write-through flushes.
 *
 * WHAT: A per-worker scheduler that, after startup, re-drives write-through
 *   flushes recorded in the shared durable journal (the FRM queue) but left
 *   incomplete by a crash: it requeues FAILED `wt` records (bounded by attempts)
 *   and claims QUEUED `wt` records, posting each as a flush task. Completion
 *   (xrootd_wt_flush_done) deletes the record on success or marks it FAILED for a
 *   later bounded retry.
 *
 * WHY: WT async flush is fire-and-forget; before this, a worker/server crash mid
 *   flush silently lost the write-back (dirty cache data never reached the
 *   origin). The producer (writethrough_flush.c) now records each in-flight async
 *   flush in the journal; this is the consumer that turns that record into actual
 *   recovery — the origin receives the data after a restart. It reuses the proven
 *   FRM durable queue + the existing flush machinery rather than a parallel one
 *   (the journal is kind-aware: tape vs wt records coexist; the tape drain and
 *   this drain each claim only their own kind).
 *
 * HOW: master-side frm_reconcile resets crashed STAGING records to QUEUED; this
 *   worker timer then requeues FAILED `wt` records (attempts < cap) and claims +
 *   re-drives QUEUED `wt` records. frm_request_claim is atomic, so multiple
 *   workers replay distinct records safely. One effective pass recovers the
 *   backlog; the timer then idles, retrying periodically so a transiently-down
 *   origin is picked up later (bounded by the per-record attempt cap). No goto.
 */

#include "cache_internal.h"
#include "../frm/frm.h"
#include "../fs/xfer/xfer_reconcile.h"   /* the shared journal-recovery scan */

#define WT_REPLAY_START_DELAY    1500    /* ms after worker start: first pass    */
#define WT_REPLAY_RETRY_PERIOD   30000   /* ms between later retry passes         */
#define WT_REPLAY_MAX_ATTEMPTS   5       /* give up re-driving after this many    */

/* per-worker scheduler state (process-local) */
static ngx_event_t                    wt_replay_ev;
static ngx_stream_xrootd_srv_conf_t  *wt_replay_conf;
static ngx_thread_pool_t             *wt_replay_pool;
static ngx_log_t                     *wt_replay_log;
static ngx_uint_t                     wt_replay_ready;

/* A FAILED record is a flush that did not complete (crashed or the origin was
 * down). Requeue it for another attempt unless it has exhausted its retries. */
static void
wt_requeue_failed(const frm_record_t *rec, void *data)
{
    frm_queue_t *q = data;

    if (rec->attempts < WT_REPLAY_MAX_ATTEMPTS) {
        (void) frm_request_set_status(q, rec->reqid, FRM_ST_QUEUED, 0,
                                      wt_replay_log);
    }
}

/* Claim + re-drive a QUEUED wt record (claim is atomic across workers and bumps
 * attempts, so the retry cap is enforced). */
static void
wt_redrive_queued(const frm_record_t *rec, void *data)
{
    frm_queue_t *q = data;

    if (frm_request_claim(q, rec->reqid, wt_replay_log) != NGX_OK) {
        return;                              /* another worker took it */
    }
    if (xrootd_wt_flush_post_replay(wt_replay_conf, wt_replay_pool,
            (const char *) rec->lfn, (const char *) rec->reqid,
            rec->xfer_mode_bits, wt_replay_log) != NGX_OK)
    {
        /* could not post (bad origin path / OOM) → leave FAILED for a later
         * bounded pass rather than spin. */
        (void) frm_request_set_status(q, rec->reqid, FRM_ST_FAILED, -1,
                                      wt_replay_log);
    }
}

/* Requeue FAILED wt records (bounded), then claim + re-drive QUEUED ones — both
 * over the one shared journal scan (xfer_reconcile). */
static void
wt_replay_drain(void)
{
    frm_queue_t *q = frm_singleton_queue();

    if (!wt_replay_ready || q == NULL) {
        return;
    }
    (void) xrootd_xfer_journal_foreach(q, FRM_ST_FAILED, FRM_XFER_WT,
                                       wt_requeue_failed, q, wt_replay_log);
    (void) xrootd_xfer_journal_foreach(q, FRM_ST_QUEUED, FRM_XFER_WT,
                                       wt_redrive_queued, q, wt_replay_log);
}

static void
wt_replay_handler(ngx_event_t *ev)
{
    wt_replay_drain();
    if (!ngx_exiting) {
        ngx_add_timer(ev, WT_REPLAY_RETRY_PERIOD);
    }
}

void
xrootd_wt_replay_register(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_thread_pool_t *thread_pool)
{
    if (conf == NULL || !conf->wt_enable || thread_pool == NULL) {
        return;                          /* WT off or no pool → nothing to drive */
    }
    if (frm_singleton_queue() == NULL) {
        return;                          /* no journal → async stays best-effort */
    }

    wt_replay_conf = conf;
    wt_replay_pool = thread_pool;
    wt_replay_log  = cycle->log;
    wt_replay_ready = 1;

    ngx_memzero(&wt_replay_ev, sizeof(wt_replay_ev));
    wt_replay_ev.handler = wt_replay_handler;
    wt_replay_ev.log     = cycle->log;
    wt_replay_ev.data    = &wt_replay_ev;
    ngx_add_timer(&wt_replay_ev, WT_REPLAY_START_DELAY);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "wt: durable-flush replay scheduler armed");
}
