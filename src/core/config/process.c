/*
 * process.c — per-worker process lifecycle: init/exit hooks and the self-arming
 * maintenance timers (CRL reload, pending-locate reaper, stage-out reaper).
 */

#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "net/proxy/proxy.h"
#include "net/proxy/proxy_internal.h"
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "protocols/root/write/chkpoint.h"
#include "core/compat/crypto.h"
#include "core/compat/log_diag.h"
#include "core/compat/lifecycle_timing.h"
#include "net/manager/health_check.h"
#include "net/manager/pending.h"
#include "fs/cache/origin/pelican_register.h"
#include "fs/cache/cache_internal.h"   /* brix_wt_replay_register (durable WT) */
#include "fs/cache/cache_reap.h"       /* stale-dirty reaper (cache-state engine) */
#include "fs/cache/reap_watermark.h"  /* proactive watermark LRU reaper */
#include "fs/xfer/stage_request_registry.h"  /* FRM-dissolution: composable registry */
#include "fs/cache/cache_storage.h"    /* per-role SD storage instances (exclusively-VFS) */
#include "fs/xfer/xfer.h"           /* brix_xfer_resume_sweep_register      */
#include "fs/xfer/stage_engine.h"   /* phase-64 SP4 async stage scheduler     */
#include "auth/gsi/keypool.h"
#include "auth/impersonate/lifecycle.h"
#include "core/aio/uring.h"
#include "fs/backend/sd.h"          /* SD registry: per-worker backend instance */
#include "fs/vfs/vfs_backend_registry.h" /* per-worker backend credential re-apply */
#include "core/config/credential_block.h" /* brix_credential_lookup (per-worker) */
#include "core/compat/cstr.h"       /* brix_str_cbuf */
#include "observability/sesslog/sesslog_ngx.h"

#if defined(__SANITIZE_ADDRESS__)   /* Phase 27 W6: explicit LSan check at exit */
#include <sanitizer/lsan_interface.h>
#endif

/* Timer callback: rebuild the GSI X509_STORE from the configured CRL file at the
 * reload interval, then re-arm the timer. */
static void
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
 */
#define BRIX_CACHE_REAP_FIRST_MS     5000
#define BRIX_CACHE_REAP_INTERVAL_MS  3600000   /* hourly */

static void
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

/* phase-64 SP4: drain the deferred (async) stage-flush queue every second. Armed
 * in every worker (the queue is per-worker); a no-op when empty. */
#define BRIX_STAGE_SCHED_MS  1000
static ngx_event_t  brix_stage_sched_timer;

static void
brix_stage_sched_handler(ngx_event_t *ev)
{
    brix_stage_scheduler_tick();
    if (!ngx_exiting) {
        ngx_add_timer(ev, BRIX_STAGE_SCHED_MS);
    }
}

/* ---- Bring up the durable stage engine (phase-64 SP4) for this worker ----
 *
 * WHAT: Initialises the stage journal and, on worker 0 only, replays staged
 * flushes interrupted by a crash and reaps orphaned direct-write temp files.
 * No return value — the engine degrades to in-memory when the journal dir is
 * unset and reconcile/reap are best-effort recovery.
 *
 * WHY: A crash can strand a staged FLUSH mid-flight and leave partial
 * "<final>.xrd-tmp.<dead-pid>.*" files in the export tree; without this the
 * write never reaches the backend and the partials leak disk forever.
 *
 * HOW:
 *   1. Init the stage engine with the opt-in $BRIX_STAGE_JOURNAL_DIR
 *      (unset = in-memory, no recovery).
 *   2. On worker 0: replay any journalled staged FLUSH (brix_stage_reconcile).
 *   3. On worker 0: reap orphaned non-staged direct-write temporaries — the
 *      broken write is discarded; the client retries (§11.3).
 */
static void
brix_init_stage_engine_worker(ngx_cycle_t *cycle)
{
    /* phase-64 SP4: durable stage journal + restart reconcile. The journal dir is
     * opt-in via $BRIX_STAGE_JOURNAL_DIR (unset = in-memory, no recovery). On a
     * restart worker 0 replays any staged FLUSH left in flight by a crash so the
     * write reaches the backend (only staged writes are recoverable - a non-staged
     * direct write's partial is reaped, not replayed; §11.3). */
    brix_stage_engine_init(getenv("BRIX_STAGE_JOURNAL_DIR"));
    if (ngx_worker == 0) {
        brix_stage_reconcile(NULL);
        /* Clean up the OTHER half: a NON-staged direct write interrupted by the
         * crash left an orphan "<final>.xrd-tmp.<dead-pid>.*" in the export tree -
         * reap it (the broken write is discarded; the client retries). */
        (void) brix_tmp_reap_all(cycle->log);
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
static void
brix_init_stage_sched_timer(ngx_cycle_t *cycle)
{
    brix_stage_sched_timer.handler = brix_stage_sched_handler;
    brix_stage_sched_timer.data    = NULL;
    brix_stage_sched_timer.log     = cycle->log;
    /* cancelable: a background maintenance timer must NOT keep a gracefully
     * shutting-down worker alive until worker_shutdown_timeout — nginx's
     * ngx_event_no_timers_left() ignores cancelable timers, so the worker exits
     * as soon as its real work is done instead of lingering seconds on restart. */
    brix_stage_sched_timer.cancelable = 1;
    ngx_add_timer(&brix_stage_sched_timer, BRIX_STAGE_SCHED_MS);
}

/* ---- Replay the remote-backend credential into this worker's VFS registry ----
 *
 * WHAT: Re-applies the server's configured storage credential to the
 * process-global VFS backend registry entry for its export root. No return
 * value — a missing credential/backend is a legitimate no-op.
 *
 * WHY: brix_vfs_backend_set_credential runs only at config parse, in the
 * throwaway config-load process; the serving master/workers do not inherit
 * that entry's credential, so their registry has the backend but an EMPTY
 * credential and the origin login fails with "no credential set". The srv
 * conf's fields ARE inherited reliably (nginx config), so replay them here,
 * per worker, before any request resolves + builds the backend instance.
 *
 * HOW:
 *   1. Skip unless both a storage credential name and an export root are set.
 *   2. NUL-terminate the credential name and look it up in the credential
 *      block table.
 *   3. Map the credential fields (proxy-or-cert, key, CA dir, SSS keytab)
 *      into a brix_vfs_backend_cred_t.
 *   4. Install it on the export root's registry entry; set_credential also
 *      resets e->inst so the instance rebuilds with the credential on first
 *      use.
 */
static void
brix_init_server_backend_credential(ngx_stream_brix_srv_conf_t *xcf)
{
    char                       credz[256];
    const brix_credential_t   *cred;
    brix_vfs_backend_cred_t    bcred;

    if (xcf->common.storage_credential.len == 0
        || xcf->common.root_canon[0] == '\0')
    {
        return;
    }

    ngx_cpystrn((u_char *) credz, xcf->common.storage_credential.data,
                ngx_min(xcf->common.storage_credential.len + 1,
                        sizeof(credz)));
    cred = brix_credential_lookup(credz);
    if (cred == NULL) {
        return;
    }

    ngx_memzero(&bcred, sizeof(bcred));
    bcred.x509_proxy = cred->x509_proxy.len > 0
        ? (const char *) cred->x509_proxy.data
        : (cred->x509_cert.len > 0
            ? (const char *) cred->x509_cert.data : NULL);
    bcred.x509_key = (cred->x509_proxy.len == 0
                      && cred->x509_key.len > 0)
        ? (const char *) cred->x509_key.data : NULL;
    bcred.ca_dir = cred->ca_dir.len > 0
        ? (const char *) cred->ca_dir.data : NULL;
    bcred.sss_keytab = cred->sss_keytab.len > 0
        ? (const char *) cred->sss_keytab.data : NULL;
    brix_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
}

/* ---- Open this worker's fds onto the staging registry + resume sweep ----
 *
 * WHAT: Initialises the composable stage request registry from the server's
 * (tape) control dir and registers the upload-resume TTL sweep for its stage
 * dir. No return value — both are best-effort, idempotent no-ops when the
 * respective dir is not configured.
 *
 * WHY: The migrated staging callers (prepare/tape_rest/open) record into the
 * registry, which needs per-worker fds; abandoned upload-resume partials in
 * the stage dir would otherwise leak disk. The legacy FRM
 * queue/scheduler/purge worker-init is retired — the recall is driven by the
 * sd_frm backend + the client poll model.
 *
 * HOW:
 *   1. When FRM is enabled with a control dir, NUL-terminate the dir for the
 *      C API and init the stage registry (journal dir = the control dir).
 *   2. When an upload stage dir is canonicalised, register the resume sweep
 *      (worker-0 only internally; the register itself is idempotent and arms
 *      a single timer for the first stage-dir server).
 */
static void
brix_init_server_stage_registry(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->frm.enable && xcf->frm.control_dir.len > 0) {
        char _jd[NGX_MAX_PATH];
        if (brix_str_cbuf(_jd, sizeof(_jd), &xcf->frm.control_dir) != NULL) {
            (void) brix_stage_registry_init(_jd, cycle->log);
        }
    }

    /* Phase 6 housekeeping: TTL-sweep abandoned upload-resume partials from
     * the stage dir (worker-0 only; the register itself is idempotent and
     * arms a single timer for the first stage-dir server). */
    if (xcf->upload_stage_dir_canon[0] != '\0') {
        brix_xfer_resume_sweep_register(cycle,
                                          xcf->upload_stage_dir_canon);
    }
}

/* ---- Open the confined export-root fd for a data server ----
 *
 * WHAT: Opens the server's export root as an O_PATH directory fd for
 * kernel-confined path operations. Returns NGX_OK on success or when no
 * local export root is configured; NGX_ERROR (with an EMERG log) when the
 * root cannot be opened.
 *
 * WHY: All confined path resolution (openat2 RESOLVE_IN_ROOT / O_NOFOLLOW
 * walks) anchors on this fd; a data server that cannot open its export root
 * must refuse to run rather than serve unconfined.
 *
 * HOW:
 *   1. Skip servers with an empty root_canon (proxy/manager/supervisor).
 *   2. open(root, O_PATH|O_DIRECTORY|O_CLOEXEC) into xcf->rootfd.
 *   3. On failure log EMERG with errno and return NGX_ERROR.
 */
static ngx_int_t
brix_init_server_rootfd(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *xcf)
{
    /* Only open rootfd for data servers with a local export root.
     * Proxy/manager/supervisor servers leave root_canon empty. */
    if (xcf->common.root_canon[0] == '\0') {
        return NGX_OK;
    }

    xcf->rootfd = open(xcf->common.root_canon,
                       O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (xcf->rootfd < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, errno,
                      "brix: cannot open export root \"%s\" for "
                      "kernel-confined path operations",
                      xcf->common.root_canon);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Arm the per-server stale-dirty cache reaper timer ----
 *
 * WHAT: Allocates and arms the hourly stale-dirty reaper timer for a server
 * whose cache-state engine is active. Returns NGX_OK (including the
 * not-configured no-op) or NGX_ERROR on allocation failure.
 *
 * WHY: The eviction guard protects dirty write-back staging files, so an
 * abandoned flush would leak disk forever without a reaper that runs on a
 * maintenance timer independent of occupancy.
 *
 * HOW:
 *   1. Skip unless brix_cache_dirty_max_age > 0 and a state root resolves.
 *   2. pcalloc the timer event from the cycle pool (NGX_ERROR on failure).
 *   3. Point it at brix_cache_reap_handler with the srv conf as ev->data,
 *      mark cancelable, arm at BRIX_CACHE_REAP_FIRST_MS.
 */
static ngx_int_t
brix_init_server_cache_reap_timer(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->cache_dirty_max_age <= 0
        || brix_cache_state_root(xcf) == NULL)
    {
        return NGX_OK;
    }

    xcf->cache_reap_timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (xcf->cache_reap_timer == NULL) {
        return NGX_ERROR;
    }
    xcf->cache_reap_timer->handler = brix_cache_reap_handler;
    xcf->cache_reap_timer->data    = xcf;
    xcf->cache_reap_timer->log     = cycle->log;
    xcf->cache_reap_timer->cancelable = 1;  /* don't delay graceful shutdown */
    ngx_add_timer(xcf->cache_reap_timer, BRIX_CACHE_REAP_FIRST_MS);

    return NGX_OK;
}

/* ---- Arm the per-server watermark-driven LRU reaper timer ----
 *
 * WHAT: Allocates and arms the proactive watermark LRU reaper timer for a
 * server with a cache and a valid HIGH watermark. Returns NGX_OK (including
 * the not-configured no-op) or NGX_ERROR on allocation failure.
 *
 * WHY: Waiting for occupancy-triggered eviction alone lets a busy cache
 * overshoot its watermark; a periodic proactive reap keeps it bounded. A
 * small per-worker jitter on the first tick keeps the workers from all
 * firing together.
 *
 * HOW:
 *   1. Skip unless a cache is configured, a state root resolves, and
 *      0 < high_watermark < 1000000.
 *   2. pcalloc the timer event from the cycle pool (NGX_ERROR on failure).
 *   3. Point it at brix_cache_watermark_timer_handler, mark cancelable, arm
 *      at BRIX_CACHE_REAP_FIRST_MS + (pid % 1000) jitter.
 */
static ngx_int_t
brix_init_server_watermark_timer(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if ((!xcf->cache && xcf->common.cache_store.len == 0)
        || brix_cache_state_root(xcf) == NULL
        || xcf->reaper.high_watermark <= 0
        || xcf->reaper.high_watermark >= 1000000)
    {
        return NGX_OK;
    }

    xcf->reaper.timer =
        ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (xcf->reaper.timer == NULL) {
        return NGX_ERROR;
    }
    xcf->reaper.timer->handler =
        brix_cache_watermark_timer_handler;
    xcf->reaper.timer->data = xcf;
    xcf->reaper.timer->log  = cycle->log;
    xcf->reaper.timer->cancelable = 1;  /* don't delay graceful shutdown */
    ngx_add_timer(xcf->reaper.timer,
                  BRIX_CACHE_REAP_FIRST_MS
                  + (ngx_msec_t) (ngx_pid % 1000));

    return NGX_OK;
}

/* ---- Arm the per-server CRL reload timer + schedule JWKS refresh ----
 *
 * WHAT: Starts the CRL hot-reload timer for GSI servers that configured
 * brix_crl_reload, and schedules the JWKS refresh in every case. Returns
 * NGX_OK, or NGX_ERROR when the timer event cannot be allocated.
 *
 * WHY: Timers are per-worker because each nginx worker process has its own
 * event loop and its own copy of the config pointers (but the X509_STORE*
 * is shared within a worker). JWKS refresh is orthogonal to CRLs and must be
 * scheduled whether or not a CRL timer is armed.
 *
 * HOW:
 *   1. When the server is not GSI/BOTH, or has no CRL path/interval: just
 *      schedule the JWKS refresh and return NGX_OK.
 *   2. Otherwise pcalloc the CRL timer event (NGX_ERROR on failure), point
 *      it at brix_crl_reload_handler, mark cancelable, arm at the configured
 *      interval and log a NOTICE.
 *   3. Schedule the JWKS refresh for the GSI/BOTH server too.
 */
static ngx_int_t
brix_init_server_crl_jwks(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *xcf)
{
    if ((xcf->auth != BRIX_AUTH_GSI && xcf->auth != BRIX_AUTH_BOTH)
        || xcf->crl.len == 0 || xcf->crl_reload == 0)
    {
        /* CRL timer not needed — but still check for JWKS refresh */
        brix_token_jwks_schedule_refresh(cycle, xcf);
        return NGX_OK;
    }

    /* Allocate and start the CRL reload timer */
    xcf->crl_timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (xcf->crl_timer == NULL) {
        return NGX_ERROR;
    }
    xcf->crl_timer->handler = brix_crl_reload_handler;
    xcf->crl_timer->data    = xcf;
    xcf->crl_timer->log     = cycle->log;
    xcf->crl_timer->cancelable = 1;  /* don't delay graceful shutdown */

    ngx_add_timer(xcf->crl_timer, (ngx_msec_t) xcf->crl_reload * 1000);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: CRL reload timer started - interval=%ds "
                  "path=\"%s\"",
                  (int) xcf->crl_reload, xcf->crl.data);

    /* Also check for JWKS refresh on GSI/BOTH servers */
    brix_token_jwks_schedule_refresh(cycle, xcf);

    return NGX_OK;
}

/* ---- Per-server worker initialization for one enabled brix server block ----
 *
 * WHAT: Runs every per-server init step for one enabled server conf, in the
 * frozen worker-init order: credential replay, log-fd capture, staging
 * registry, export rootfd, checkpoint recovery, cache storage, XrdAcc, CMS,
 * health-check, Pelican advertise, cache reaper timers, CRL/JWKS. Returns
 * NGX_OK, or NGX_ERROR to abort worker startup.
 *
 * WHY: Worker init is a flat sequence of independent subsystem
 * initializations; keeping each server's ladder in one orchestrator keeps
 * init_process itself a short loop while preserving the exact initialization
 * order the reload-semantics contract freezes.
 *
 * HOW:
 *   1. Replay the storage credential into the VFS backend registry.
 *   2. Capture the nginx-managed access/audit log fds.
 *   3. Init the staging registry + upload-resume sweep.
 *   4. Open the confined export rootfd (fatal on failure).
 *   5. Recover interrupted checkpoints, build cache SD storage instances,
 *      build XrdAcc tables — each fatal on failure.
 *   6. Start CMS handlers (when cms_addr set), health-check timer, Pelican
 *      cache advertisement — all internal no-ops when unconfigured.
 *   7. Arm the stale-dirty and watermark cache reaper timers (fatal on
 *      allocation failure).
 *   8. Arm the CRL reload timer / schedule JWKS refresh.
 */
static ngx_int_t
brix_init_one_server(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *xcf)
{
    brix_init_server_backend_credential(xcf);

    /*
     * Capture the nginx-managed log fds the master opened during
     * ngx_init_cycle.  We read file->fd here (not at config time, where it
     * is still NGX_INVALID_FILE) so the hot access-/audit-log write paths
     * keep using a plain int fd.  nginx dup2()s a reopened log onto the same
     * fd number on USR1, so this captured value stays valid for the worker's
     * lifetime.  A NULL handle means logging is disabled for this server.
     */
    xcf->access_log_fd = xcf->access_log_file != NULL
                         ? xcf->access_log_file->fd : NGX_INVALID_FILE;
    xcf->proxy.audit_log_fd = xcf->proxy.audit_log_file != NULL
                         ? xcf->proxy.audit_log_file->fd : NGX_INVALID_FILE;

    brix_init_server_stage_registry(cycle, xcf);

    if (brix_init_server_rootfd(cycle, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_chkpoint_recover_root(cycle->log, xcf->common.root_canon)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* The per-export storage backend (e.g. pblock) is registered at config
     * time and built per worker lazily by the VFS backend registry on first
     * use (brix_vfs_ctx_init → brix_vfs_backend_resolve); no per-server
     * init_process creation is needed here. */

    /* The cache performs all disk I/O through SD storage instances (POSIX
     * driver on a per-worker rootfd by default, or a configured backend) —
     * build them now. No-op unless a cache is configured. */
    if (brix_cache_storage_init(xcf, cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Build the per-worker XrdAcc tables + hot-reload timer (no-op unless
     * this server uses `brix_authdb_format xrdacc`). */
    if (brix_acc_init_server(xcf, cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xcf->cms.addr != NULL) {
        ngx_brix_cms_start(cycle, xcf);
    }

    /* Phase 22: start the active health-check timer (no-op if disabled). */
    brix_hc_manager_start(cycle, xcf);

    /* Pelican: start the cache advertisement timer (no-op unless
     * brix_cache_advertise is on with a key + data-url configured). */
    brix_cache_pelican_schedule_advertise(cycle, xcf);

    /* Unified cache-state engine: arm the per-worker stale-dirty reaper when
     * a state root resolves and a max age is set. Independent of occupancy. */
    if (brix_init_server_cache_reap_timer(cycle, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Watermark-driven LRU reaper: arm the proactive per-worker timer when a
     * cache is configured with a valid HIGH watermark. A small per-worker
     * jitter on the first tick keeps the workers from all firing together. */
    if (brix_init_server_watermark_timer(cycle, xcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return brix_init_server_crl_jwks(cycle, xcf);
}

/* ---- Warm the per-worker GSI ephemeral-DH key pool ----
 *
 * WHAT: Seeds the GSI DH key pool from the first GSI-enabled server block's
 * configuration. No return value — a config with no GSI server is a no-op
 * and pool warm-up failures degrade to on-demand keygen.
 *
 * WHY: Phase 33 — kXGC_certreq must never run keygen on the event thread
 * under a concurrent handshake burst. Only a small seed is generated
 * synchronously here; the pool fills to its configured size off the event
 * thread (via the GSI server's thread pool) so worker startup is not blocked
 * on the full warm-up.
 *
 * HOW:
 *   1. Skip unless the server scan found a GSI/BOTH block.
 *   2. Init the keypool with that block's thread pool, size, and seed count.
 */
static void
brix_init_gsi_keypool(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *gsi_xcf)
{
    if (gsi_xcf == NULL) {
        return;
    }
    brix_gsi_keypool_init(cycle, gsi_xcf->common.thread_pool,
                            gsi_xcf->gsi_keypool_size,
                            gsi_xcf->gsi_keypool_seed);
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
static void
brix_init_pending_reap_timer(ngx_cycle_t *cycle, ngx_uint_t manager_seen)
{
    if (!manager_seen || ngx_worker != 0) {
        return;
    }
    brix_pending_reap_timer.handler = brix_pending_reap_handler;
    brix_pending_reap_timer.data    = NULL;
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
static void
brix_init_stage_reap_timer(ngx_cycle_t *cycle)
{
    if (ngx_worker != 0 || brix_stage_dir_count() == 0) {
        return;
    }
    brix_stage_reap_timer.handler = brix_stage_reap_handler;
    brix_stage_reap_timer.data    = NULL;
    brix_stage_reap_timer.log     = cycle->log;
    brix_stage_reap_timer.cancelable = 1;  /* don't delay graceful shutdown */
    ngx_add_timer(&brix_stage_reap_timer, BRIX_STAGE_REAP_FIRST_MS);
}

/* ---- Warn once when openat2(2) confinement is unavailable ----
 *
 * WHAT: Emits a persistent startup WARN when the running kernel lacks
 * openat2(2). No return value — this is diagnostics only; the fallback path
 * still works.
 *
 * WHY: F-05 — without openat2 (kernel < 5.6 or built without the headers),
 * path confinement falls back to the O_NOFOLLOW segment-by-segment walk
 * which has a narrow TOCTOU window; operators must know confinement is
 * degraded so they can plan a kernel upgrade.
 *
 * HOW:
 *   1. Probe runtime availability (brix_openat2_runtime_available).
 *   2. Log the degraded-confinement warning when unavailable.
 */
static void
brix_warn_openat2_unavailable(ngx_cycle_t *cycle)
{
    if (!brix_openat2_runtime_available()) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "brix: openat2(2) is not available on this system "
                      "(requires Linux kernel 5.6+). Path confinement falls "
                      "back to O_NOFOLLOW traversal, which has a TOCTOU race "
                      "window on multi-tenant storage. Upgrade the kernel for "
                      "strongest path confinement.");
    }
}

/*
 * Worker process init: start CRL reload timers for every server block that
 * has brix_crl_reload configured. Timers are per-worker because each
 * nginx worker process has its own event loop and its own copy of the config
 * pointers (but the X509_STORE* is shared within a worker).
 */
/* ---- Per-worker init after fork: bring up all worker-scoped subsystems ----
 *
 * WHAT: Initialises crypto, the stage engine + scheduler, the proxy pool,
 * io_uring, every enabled server block (via brix_init_one_server), the GSI
 * keypool, the identity broker, and the worker-0 maintenance reapers.
 * Returns NGX_OK / NGX_ERROR (NGX_ERROR aborts the worker).
 *
 * WHY: nginx workers are forked from the master and inherit config but not
 * per-process resources (fds, timers, rings, key pools); everything a worker
 * owns must be (re)built here, in the frozen order the reload-semantics
 * contract documents.
 *
 * HOW:
 *   1. Start the boot-cost phase timer and init OpenSSL crypto (fatal).
 *   2. Bring up the stage engine and arm the per-worker stage-flush
 *      scheduler — BEFORE the stream-config early-return so HTTP-only
 *      (WebDAV/S3) workers get them too.
 *   3. Early-return NGX_OK when there is no stream config.
 *   4. Warn once when openat2(2) is unavailable (degraded confinement).
 *   5. Init the proxy pool and this worker's io_uring ring (fatal under
 *      `brix_io_uring on`).
 *   6. For each enabled server block: note GSI/manager presence, then run
 *      the per-server init ladder (fatal on error).
 *   7. Warm the GSI keypool, arm the pending-locate reaper, connect the
 *      identity broker, arm the stage-out reaper.
 *   8. Log the per-worker boot-cost breakdown and return NGX_OK.
 */
ngx_int_t
ngx_stream_brix_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    ngx_stream_brix_srv_conf_t  *gsi_xcf = NULL;  /* first GSI block: keypool cfg */
    ngx_uint_t                     manager_seen = 0;
    brix_phase_timer_t           pt;
    u_char                         ctx[64];

    /* Permanent per-worker boot-cost breakdown (one NOTICE line at the end). */
    brix_phase_timer_start(&pt);

    if (!brix_crypto_init()) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "brix: failed to initialise OpenSSL crypto primitives");
        return NGX_ERROR;
    }

    brix_init_stage_engine_worker(cycle);

    /* arm the per-worker async stage-flush scheduler. Done BEFORE the stream-config
     * early-return below so it runs in HTTP-only (WebDAV/S3) workers too - the
     * deferred-flush queue is per-worker and protocol-agnostic; the tick is a no-op
     * when the queue is empty. */
    brix_init_stage_sched_timer(cycle);

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    brix_warn_openat2_unavailable(cycle);

    cscfp = cmcf->servers.elts;

    brix_proxy_pool_init();

    /*
     * Phase 44: bring up this worker's optional io_uring ring (after the proxy
     * pool, same lifetime as every other per-worker async resource).  A no-op
     * unless a server block enabled it; under `brix_io_uring on` a bring-up
     * failure returns NGX_ERROR so the worker refuses to run on the thread pool
     * (§32.7 backstop).  Under `auto` it degrades silently.
     */
    if (brix_uring_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
    brix_phase_mark(&pt, "uring");

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_brix_module);

        if (!xcf->common.enable) {
            continue;
        }

        if ((xcf->auth == BRIX_AUTH_GSI || xcf->auth == BRIX_AUTH_BOTH)
            && gsi_xcf == NULL)
        {
            /* Phase 33: warm the GSI DH key pool below — keypool sizing +
             * thread pool come from the first GSI block. */
            gsi_xcf = xcf;
        }

        if (xcf->manager_mode) {
            manager_seen = 1;   /* A4: arm the pending-locate reaper below */
        }

        if (brix_init_one_server(cycle, xcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    brix_phase_mark(&pt, "servers");

    brix_init_gsi_keypool(cycle, gsi_xcf);
    brix_phase_mark(&pt, "keypool");

    brix_init_pending_reap_timer(cycle, manager_seen);

    /* Phase 40: connect this worker to the identity broker (no-op unless
     * brix_impersonation=map; lazily reconnects if the broker isn't up yet). */
    brix_imp_init_worker(cycle);

    brix_init_stage_reap_timer(cycle);

    ngx_snprintf(ctx, sizeof(ctx) - 1, "xrootd init_process[w%ui]%Z", ngx_worker);
    brix_phase_timer_log(&pt, cycle->log, (const char *) ctx);

    return NGX_OK;
}

/* Per-worker teardown at exit: release process-scoped resources. */
void
brix_exit_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    /*
     * Phase 27 W6: best-effort explicit LeakSanitizer check at worker exit.
     * nginx's daemon exit path does not reliably reach LSan's own atexit hook,
     * so a sanitizer build would otherwise never report leaks.  Placed before
     * any early return so it runs for http-only configs too.  Compiled out
     * entirely in normal builds — zero production effect.
     *
     * NOTE: whether this actually fires depends on nginx reaching exit_process
     * at shutdown, which is platform/signal-dependent (it was observed NOT to
     * run under WSL2 in dev).  See docs/03-configuration/build-guide.md.
     */
#if defined(__SANITIZE_ADDRESS__)
    __lsan_do_recoverable_leak_check();
#endif

    brix_sesslog_shutdown_flush();

    /* Fast teardown: drop any idle pooled upstream connections so this draining
     * worker releases authenticated upstream sockets immediately (with a clean
     * FIN) rather than leaving process-exit to reap them.  Idempotent and safe
     * when proxy mode was never used (the pool is simply empty). */
    brix_proxy_pool_shutdown();

    /* Phase 44: tear down this worker's io_uring ring (no-op if never up). */
    brix_uring_exit_worker(cycle);

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return;
    }

    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_brix_module);
        if (!xcf->common.enable) {
            continue;
        }
        if (xcf->rootfd >= 0) {
            close(xcf->rootfd);
            xcf->rootfd = -1;
        }
        brix_cache_storage_cleanup(xcf);
    }

    brix_crypto_cleanup();
}
