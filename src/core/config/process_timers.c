/*
 * process_timers.c — the self-arming per-worker maintenance timers.
 *
 * WHAT: Owns every maintenance-timer callback (CRL hot-reload, CMS
 *       pending-locate reaper, upload stage-out reaper, cache stale-dirty
 *       reaper, async stage-flush scheduler), their static ngx_event_t globals,
 *       and the three timer-arming entry points the init_process orchestrator
 *       calls. Each static timer event is co-located with BOTH its handler and
 *       its arming function so the global never crosses a file boundary.
 * WHY:  Split (phase-79 file-size cap) out of the former 925-line process.c.
 *       Grouping the timer machinery keeps the "arm -> fire -> re-arm" lifecycle
 *       of each maintenance timer reviewable in one place. brix_crl_reload_handler
 *       and brix_cache_reap_handler are non-static (declared in
 *       process_internal.h) because a server's init ladder in
 *       process_server_init.c arms those two per-server; the three arming
 *       functions are non-static because init_process (process.c) calls them.
 * HOW:  Every handler re-arms itself with ngx_add_timer unless ngx_exiting, and
 *       marks its timer cancelable so a draining worker is never held past its
 *       real work. No behaviour change from the split.
 */

#include "config.h"
#include "process_internal.h"
#include <sys/stat.h>                        /* struct stat, S_ISREG (CRL handler) */
#include "core/compat/log_diag.h"            /* BRIX_DIAG_CRIT */
#include "net/manager/pending.h"             /* brix_pending_reap_expired + interval */
#include "core/compat/staged_file.h"         /* brix_stage_reap_all, brix_stage_dir_count */
#include "fs/cache/cache_reap.h"             /* brix_cache_reap_dirty */
#include "fs/xfer/stage_engine.h"            /* brix_stage_scheduler_tick */
#include "fs/xfer/backend_async_queue.h"     /* brix_baq_tick */
#include "fs/backend/csi_scrub.h"            /* brix_csi_scrub_walk */
#include "observability/metrics/metrics.h"   /* ngx_brix_srv_metrics_t, shm zone */

/*
 * nginx's timer-expiry debug log (ngx_event_expire_timers, compiled in on a
 * --with-debug nginx and active when a server sets `error_log ... debug`) reads
 * ngx_event_ident(ev->data) == ((ngx_connection_t *) ev->data)->fd for EVERY
 * timer it fires.  Our worker-init maintenance timers are connection-less, so a
 * NULL ev->data made that log dereference NULL and SIGSEGV the worker — which
 * nginx respawns, so it crash-loops (a flood of core dumps that spiked system
 * load hard under the debug-logging test fleet).  Point such timers' ev->data at
 * this dummy connection (fd = -1) so the debug log has a valid fd to read; the
 * timer handlers themselves do not use ev->data.  Shared (non-static) so the
 * other connection-less maintenance timers (uring-panic, accesslog flush) point
 * at the same dummy — see extern declarations at their call sites.
 */
ngx_connection_t  brix_maint_timer_conn = { .fd = (ngx_socket_t) -1 };

/* Timer callback: rebuild the GSI X509_STORE from the configured CRL file at the
 * reload interval, then re-arm the timer. */
void
brix_crl_reload_handler(ngx_event_t *ev)
{
    ngx_stream_brix_srv_conf_t *xcf = ev->data;
    struct stat                   st;
    int                           is_reg_file;

    /*
     * E5: skip the CRL re-parse + store rebuild when the CRL source is an
     * unchanged regular file, so a large CRL on slow storage never stalls the
     * event loop on every interval.  A CApath DIRECTORY is always rebuilt — its
     * mtime does not reflect content changes of the CRL files inside it.
     */
    is_reg_file = (xcf->crl.len > 0
                   && stat((const char *) xcf->crl.data, &st) == 0
                   && S_ISREG(st.st_mode));

    if (is_reg_file && xcf->crl_mtime != 0 && st.st_mtime == xcf->crl_mtime) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: CRL \"%s\" unchanged — skipping reload",
                       xcf->crl.data);
        if (xcf->crl_reload > 0 && !ngx_exiting) {
            ngx_add_timer(ev, (ngx_msec_t) xcf->crl_reload * 1000);
        }
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "brix: CRL reload timer fired, rebuilding store "
                  "from \"%s\"", xcf->crl.data);

    /* NULL scope: the CRL hot-reload timer MUST rebuild from fresh CRLs on
     * disk, never reuse the memoised startup store. */
    if (brix_rebuild_gsi_store(xcf, ev->log, NULL) != NGX_OK) {
        BRIX_DIAG_CRIT(ev->log, 0,
            "brix: CRL reload failed for \"%s\" — keeping previous store",
            "the CRL file/dir is unreadable, malformed, or mid-rewrite",
            "check the path's permissions and that fetch-crl writes atomically; "
            "the server keeps serving with the LAST-GOOD CRLs, so a newly "
            "revoked cert may still be accepted until the next good reload",
            xcf->crl.data);
    } else if (is_reg_file) {
        /* Record mtime only on a successful rebuild so a failed load is retried
         * (not skipped) on the next interval. */
        xcf->crl_mtime = st.st_mtime;
    }

    /* Re-arm the timer (suppressed once the worker is exiting). */
    if (xcf->crl_reload > 0 && !ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) xcf->crl_reload * 1000);
    }
}

/*
 * A4: worker-0 periodic sweep of abandoned pending-locate slots.  Deadline-
 * rearmed (never self-rearms to 0ms) so it cannot busy-loop.  A cheap no-op when
 * no locates have expired or the zone is absent.
 */
static ngx_event_t  brix_pending_reap_timer;

/* Timer callback: reap expired slots from the CMS pending-locate registry
 * (brix_pending_reap_expired), then re-arm the timer. */
static void
brix_pending_reap_handler(ngx_event_t *ev)
{
    ngx_uint_t  reaped = brix_pending_reap_expired();

    if (reaped > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: pending-locate reaper freed %ui expired slot(s)",
                       reaped);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, BRIX_PENDING_REAP_INTERVAL_MS);
    }
}

/*
 * Upload stage-out reaper (worker 0).  Finishes any cache->storage commit that
 * was interrupted by a worker death: the first tick (soon after startup) recovers
 * complete-but-uncommitted files left from a previous run; periodic ticks retry
 * commits that failed at runtime (e.g. storage briefly unavailable).  No-op when
 * no stage dir is configured.  See src/compat/staged_file.c.
 */
#define BRIX_STAGE_REAP_FIRST_MS     1000
#define BRIX_STAGE_REAP_INTERVAL_MS  60000
static ngx_event_t  brix_stage_reap_timer;

/* Timer callback: complete/reap stale FRM stage-out commits
 * (brix_stage_reap_all), then re-arm the timer. */
static void
brix_stage_reap_handler(ngx_event_t *ev)
{
    ngx_uint_t n = brix_stage_reap_all(ev->log);
    if (n > 0) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: stage-out reaper completed %ui pending commit(s)",
                      n);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, BRIX_STAGE_REAP_INTERVAL_MS);
    }
}

/*
 * Unified cache-state engine: per-server stale-dirty reaper. Removes write-back
 * staging files dirty longer than brix_cache_dirty_max_age (the eviction guard
 * protects them, so without this an abandoned flush leaks disk forever). Runs on
 * a maintenance timer independent of occupancy. ev->data is the server conf.
 * (Cadence #defines BRIX_CACHE_REAP_FIRST_MS / _INTERVAL_MS live in
 * process_internal.h — the arming side is in process_server_init.c.)
 */
void
brix_cache_reap_handler(ngx_event_t *ev)
{
    ngx_stream_brix_srv_conf_t *xcf = ev->data;
    ngx_uint_t                    n = brix_cache_reap_dirty(xcf, ev->log);

    if (n > 0) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: cache stale-dirty reaper removed %ui file(s)", n);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, BRIX_CACHE_REAP_INTERVAL_MS);
    }
}

/*
 * Phase-59 W2b: per-server at-rest CSI scrub. Recomputes every recorded block
 * CRC of every tagged data file under the export root and surfaces at-rest rot
 * (metrics + error.log DIAG) that the hot read path — which only verifies the
 * blocks a read FULLY spans — would otherwise never notice. ev->data is the
 * server conf. The pacing IS the operator's brix_csi_scrub_interval: one full
 * walk per interval, re-armed at the same cadence.
 *
 * The engine (fs/backend/csi_scrub.c) is pure libc + xmeta + crc32c and is unit-
 * tested standalone (tests/c/test_csi_scrub.c); this handler is the thin nginx
 * caller that resolves the root, drives one walk, and folds the mismatch count
 * into the shared-memory metrics slot.
 */

/* The per-server SHM metrics slot for `xcf`, or NULL when metrics are
 * unconfigured (so the scrub degrades cleanly with no counter). Mirrors the slot
 * resolution in fs/cache/cache_reap.c::reap_metrics_slot + connection/handler.c. */
static ngx_brix_srv_metrics_t *
brix_csi_scrub_metrics_slot(const ngx_stream_brix_srv_conf_t *xcf)
{
    ngx_brix_metrics_t *shm;

    if (xcf->metrics_slot < 0
        || xcf->metrics_slot >= BRIX_METRICS_MAX_SERVERS
        || ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    shm = ngx_brix_shm_zone->data;
    return &shm->servers[xcf->metrics_slot];
}

/* Per-mismatch report sink: one DIAG line per corrupt block so an operator sees
 * the offending path + block, not just an opaque counter tick. */
static void
brix_csi_scrub_report(void *u, const char *path, uint64_t block,
    uint32_t want, uint32_t got)
{
    ngx_log_t *log = u;

    BRIX_DIAG_CRIT(log, 0,
        "brix: CSI scrub found at-rest corruption in \"%s\" block %uL "
        "(recorded crc32c %08xD, on-disk %08xD)",
        "a data block's on-disk bytes no longer match the checksum recorded "
        "when it was written — silent storage rot, a truncating restore, or an "
        "out-of-band edit that bypassed the gateway",
        "restore the file from a good replica; the gateway keeps serving it, so "
        "a spanning read will now fail closed for the affected client",
        path, block, want, got);
}

void
brix_csi_scrub_handler(ngx_event_t *ev)
{
    ngx_stream_brix_srv_conf_t *xcf = ev->data;
    brix_csi_scrub_stats_t        st;
    const char                   *root = (const char *) xcf->common.root_canon;

    ngx_memzero(&st, sizeof(st));
    (void) brix_csi_scrub_walk(root, &st, 0 /* unlimited: interval is the pace */,
                               brix_csi_scrub_report, ev->log);

    if (st.mismatches > 0) {
        ngx_brix_srv_metrics_t *m = brix_csi_scrub_metrics_slot(xcf);

        if (m != NULL) {
            (void) ngx_atomic_fetch_add(&m->csi_scrub_mismatch_total,
                                        (ngx_atomic_int_t) st.mismatches);
        }
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "brix: CSI scrub of \"%s\" found %uL corrupt block(s) "
                      "across %uL tagged file(s)",
                      root, st.mismatches, st.files_tagged);
    } else {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: CSI scrub of \"%s\" clean "
                       "(%uL files, %uL blocks verified)",
                       root, st.files_scanned, st.blocks_verified);
    }

    if (xcf->csi.scrub_interval > 0 && !ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) xcf->csi.scrub_interval * 1000);
    }
}

/* phase-64 SP4: drain the deferred (async) stage-flush queue every second. Armed
 * in every worker (the queue is per-worker); a no-op when empty. */
#define BRIX_STAGE_SCHED_MS  1000
static ngx_event_t  brix_stage_sched_timer;

static void
brix_stage_sched_handler(ngx_event_t *ev)
{
    brix_stage_scheduler_tick();
    /* Same per-worker cadence drains the durable async backend-op queue's TIME
     * trigger (the SIZE trigger posts its own deferred drain event). The wait_ms
     * cap is thus honoured at ~1s granularity — a coalescing backstop, not a
     * precise deadline. */
    brix_baq_tick();
    if (!ngx_exiting) {
        ngx_add_timer(ev, BRIX_STAGE_SCHED_MS);
    }
}

/* ---- Arm the per-worker async stage-flush scheduler timer ----
 *
 * WHAT: Installs and starts the 1s brix_stage_sched_timer that drains this
 * worker's deferred (async) stage-flush queue. No return value — timer arming
 * cannot fail.
 *
 * WHY: The deferred-flush queue is per-worker and protocol-agnostic, so the
 * timer must run in HTTP-only (WebDAV/S3) workers too; it is therefore armed
 * BEFORE the stream-config early-return in init_process. The tick is a no-op
 * when the queue is empty.
 *
 * HOW:
 *   1. Point the static timer event at brix_stage_sched_handler with the
 *      cycle log.
 *   2. Mark it cancelable so it never delays graceful shutdown.
 *   3. Arm it at BRIX_STAGE_SCHED_MS.
 */
void
brix_init_stage_sched_timer(ngx_cycle_t *cycle)
{
    brix_stage_sched_timer.handler = brix_stage_sched_handler;
    brix_stage_sched_timer.data    = &brix_maint_timer_conn;
    brix_stage_sched_timer.log     = cycle->log;
    /* cancelable: a background maintenance timer must NOT keep a gracefully
     * shutting-down worker alive until worker_shutdown_timeout — nginx's
     * ngx_event_no_timers_left() ignores cancelable timers, so the worker exits
     * as soon as its real work is done instead of lingering seconds on restart. */
    brix_stage_sched_timer.cancelable = 1;
    ngx_add_timer(&brix_stage_sched_timer, BRIX_STAGE_SCHED_MS);
}

/* ---- Arm the worker-0 pending-locate reaper timer (managers only) ----
 *
 * WHAT: Installs and starts the CMS pending-locate reaper timer when any
 * server block is a manager and this is worker 0. No return value — timer
 * arming cannot fail.
 *
 * WHY: A4 — abandoned in-flight locate slots must be reclaimed even when
 * traffic ceases. The registry is a single process-global SHM table, so one
 * worker suffices.
 *
 * HOW:
 *   1. Skip unless a manager was seen and ngx_worker == 0.
 *   2. Point the static timer event at brix_pending_reap_handler, mark
 *      cancelable, arm at BRIX_PENDING_REAP_INTERVAL_MS.
 */
void
brix_init_pending_reap_timer(ngx_cycle_t *cycle, ngx_uint_t manager_seen)
{
    if (!manager_seen || ngx_worker != 0) {
        return;
    }
    brix_pending_reap_timer.handler = brix_pending_reap_handler;
    brix_pending_reap_timer.data    = &brix_maint_timer_conn;
    brix_pending_reap_timer.log      = cycle->log;
    brix_pending_reap_timer.cancelable = 1;  /* don't delay graceful shutdown */
    ngx_add_timer(&brix_pending_reap_timer,
                  BRIX_PENDING_REAP_INTERVAL_MS);
}

/* ---- Arm the worker-0 upload stage-out reaper timer ----
 *
 * WHAT: Installs and starts the stage-out reaper timer on worker 0 when at
 * least one stage dir was registered at config time. No return value — timer
 * arming cannot fail.
 *
 * WHY: Finishes any interrupted cache->storage commit left by a previous run
 * (first tick is soon after startup for recovery), then sweeps periodically
 * for commits that failed at runtime. Covers both root:// and davs:// stage
 * dirs.
 *
 * HOW:
 *   1. Skip unless ngx_worker == 0 and brix_stage_dir_count() > 0.
 *   2. Point the static timer event at brix_stage_reap_handler, mark
 *      cancelable, arm at BRIX_STAGE_REAP_FIRST_MS.
 */
void
brix_init_stage_reap_timer(ngx_cycle_t *cycle)
{
    if (ngx_worker != 0 || brix_stage_dir_count() == 0) {
        return;
    }
    brix_stage_reap_timer.handler = brix_stage_reap_handler;
    brix_stage_reap_timer.data    = &brix_maint_timer_conn;
    brix_stage_reap_timer.log     = cycle->log;
    brix_stage_reap_timer.cancelable = 1;  /* don't delay graceful shutdown */
    ngx_add_timer(&brix_stage_reap_timer, BRIX_STAGE_REAP_FIRST_MS);
}
