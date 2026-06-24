/* ------------------------------------------------------------------ */
/* Section: CRL Reload Timer Management                                 */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements worker process initialization for CRL (Certificate Revocation List) reload timers and CMS startup.
 *      Each timer callback rebuilds the GSI X509_STORE from the configured CRL file path at configurable intervals; worker init
 *      creates per-worker timers because each nginx worker has its own event loop and config copy. Also initializes proxy pool
 *      and starts CMS server handlers when cms_addr is configured.
 * WHY: CRL reload without full restart prevents certificate expiration or revocation from breaking operations mid-session — expired certificates are removed from trusted store at regular intervals rather than only during startup. Per-worker timer allocation prevents cross-worker event loop interference since each worker has independent event processing cycle and config copy. CMS server handlers enable bidirectional communication between nginx workers and CMS servers for cluster coordination when cms_addr is configured.
 * HOW: Two-phase lifecycle — (1) per-worker timer creation via ngx_pcalloc + ngx_add_timer with handler pointer set to xrootd_crl_reload_handler, (2) periodic callback execution: log INFO message → attempt store rebuild → keep previous store on failure → re-arm timer if interval > 0. CMS startup and proxy pool init run once during worker initialization phase. */

/* ------------------------------------------------------------------ */
/* Section: CRL Reload Timer Callback                                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_crl_reload_handler() is a static timer callback that rebuilds the GSI X509_STORE from the configured CRL file path
 *      at configurable intervals. Logs informational message on fire, attempts xrootd_rebuild_gsi_store(), keeps previous store on failure,
 *      re-arms timer if interval > 0. Called by nginx event loop when timer expires.
 * WHY: Periodic CRL reload ensures certificate revocation status is current without requiring full nginx restart — expired or revoked certificates are removed from trusted store at regular intervals rather than only during startup. Per-worker timer allocation prevents cross-worker event loop interference since each worker has its own independent event processing cycle and config copy. Graceful degradation: previous store retained on rebuild failure preventing session disruption.
 * HOW: Three-phase callback execution: (1) log INFO message with CRL path from ev->data (xcf reference), (2) attempt xrootd_rebuild_gsi_store() with NGX_OK/NGX_ERROR result logging, (3) re-arm timer via ngx_add_timer if interval > 0 converts seconds to milliseconds for nginx event loop. Static function — no public API exposure. */

/* ---- Function: xrootd_crl_reload_handler() (static) ----
 *
 * WHAT: Static timer callback that rebuilds the GSI X509_STORE from the configured CRL file path at configurable intervals. Logs
 *      informational message on fire, attempts xrootd_rebuild_gsi_store(), keeps previous store on failure, re-arms timer if interval > 0.
 *      Called by nginx event loop when timer expires — data pointer contains xcf reference for accessing crl and crl_reload fields. */

/* ---- WHY: CRL reload ensures certificate revocation status is current without requiring full nginx restart — expired or revoked
 *      certificates are removed from the trusted store at regular intervals rather than only during startup. Per-worker timer allocation
 *      prevents cross-worker event loop interference since each worker has its own independent event processing cycle and config copy. ---- */

#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "../proxy/proxy.h"
#include "../proxy/proxy_internal.h"
#include "../compat/staged_file.h"
#include "../write/chkpoint.h"
#include "../compat/crypto.h"
#include "../manager/health_check.h"
#include "../manager/pending.h"
#include "../gsi/keypool.h"
#include "../impersonate/lifecycle.h"
#include "../aio/uring.h"

#if defined(__SANITIZE_ADDRESS__)   /* Phase 27 W6: explicit LSan check at exit */
#include <sanitizer/lsan_interface.h>
#endif

static void
xrootd_crl_reload_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t *xcf = ev->data;
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
                       "xrootd: CRL \"%s\" unchanged — skipping reload",
                       xcf->crl.data);
        if (xcf->crl_reload > 0 && !ngx_exiting) {
            ngx_add_timer(ev, (ngx_msec_t) xcf->crl_reload * 1000);
        }
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "xrootd: CRL reload timer fired, rebuilding store "
                  "from \"%s\"", xcf->crl.data);

    if (xrootd_rebuild_gsi_store(xcf, ev->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "xrootd: CRL reload failed - keeping previous store");
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
static ngx_event_t  xrootd_pending_reap_timer;

static void
xrootd_pending_reap_handler(ngx_event_t *ev)
{
    ngx_uint_t  reaped = xrootd_pending_reap_expired();

    if (reaped > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "xrootd: pending-locate reaper freed %ui expired slot(s)",
                       reaped);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, XROOTD_PENDING_REAP_INTERVAL_MS);
    }
}

/*
 * Upload stage-out reaper (worker 0).  Finishes any cache->storage commit that
 * was interrupted by a worker death: the first tick (soon after startup) recovers
 * complete-but-uncommitted files left from a previous run; periodic ticks retry
 * commits that failed at runtime (e.g. storage briefly unavailable).  No-op when
 * no stage dir is configured.  See src/compat/staged_file.c.
 */
#define XROOTD_STAGE_REAP_FIRST_MS     1000
#define XROOTD_STAGE_REAP_INTERVAL_MS  60000
static ngx_event_t  xrootd_stage_reap_timer;

static void
xrootd_stage_reap_handler(ngx_event_t *ev)
{
    ngx_uint_t n = xrootd_stage_reap_all(ev->log);
    if (n > 0) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: stage-out reaper completed %ui pending commit(s)",
                      n);
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, XROOTD_STAGE_REAP_INTERVAL_MS);
    }
}

/* ------------------------------------------------------------------ */
/* Section: Worker Process Initialization                               */
/* ------------------------------------------------------------------ */
/*
 * WHAT: ngx_stream_xrootd_init_process() performs worker process initialization after nginx fork — initializes proxy pool, starts CMS
 *      server handlers when cms_addr is configured, creates per-worker CRL reload timers for servers with xrootd_crl_reload enabled. Timers
 *      are allocated per-worker because each nginx worker has its own event loop and config copy (X509_STORE* shared within a worker).
 * WHY: Worker initialization is critical because each forked worker has independent event loop, config copy, and memory space — timers must be allocated in the worker's pool rather than shared across processes. Proxy pool initialization enables upstream connection management for proxy mode operations. CMS server handlers enable bidirectional communication between nginx workers and CMS servers when cms_addr is configured. CRL reload ensures certificate revocation status is current without requiring full restart. Three-phase init order: (1) proxy pool → (2) CMS handlers → (3) CRL timers prevents dependency ordering issues.
 * HOW: Three-phase initialization: (1) xrootd_proxy_pool_init() enables upstream connection management, (2) iterate all server blocks starting ngx_xrootd_cms_start() when cms_addr configured, (3) conditional timer creation filtering by auth mode (GSI/BOTH required), crl path non-empty, and interval > 0 — allocates ngx_event_t via ngx_pcalloc, sets handler/data/log pointers, then ngx_add_timer converts seconds to milliseconds. Returns NGX_OK on success; NGX_ERROR on timer allocation failure. */

/* ---- Function: ngx_stream_xrootd_init_process() ----
 *
 * WHAT: Performs worker process initialization after nginx fork — initializes proxy pool, starts CMS server handlers when cms_addr is
 *      configured, creates per-worker CRL reload timers for servers with xrootd_crl_reload enabled (requires GSI auth or BOTH + crl path +
 *      interval). Returns NGX_OK on success; NGX_ERROR on timer allocation failure. Called once per worker process during startup. */

/* ---- WHY: Worker initialization is critical because each forked worker has independent event loop, config copy, and memory space — timers
 *      must be allocated in the worker's pool rather than shared across processes. Proxy pool initialization enables upstream connection
 *      management for proxy mode operations. CMS server handlers enable bidirectional communication between nginx workers and CMS servers
 *      when cms_addr is configured. CRL reload ensures certificate revocation status is current without requiring full restart. ---- */

/*
 * Worker process init: start CRL reload timers for every server block that
 * has xrootd_crl_reload configured. Timers are per-worker because each
 * nginx worker process has its own event loop and its own copy of the config
 * pointers (but the X509_STORE* is shared within a worker).
 */
ngx_int_t
ngx_stream_xrootd_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    ngx_uint_t                     gsi_seen = 0;
    ngx_uint_t                     manager_seen = 0;

    if (!xrootd_crypto_init()) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "xrootd: failed to initialise OpenSSL crypto primitives");
        return NGX_ERROR;
    }

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    /*
     * F-05: Probe openat2(2) availability.  When unavailable (kernel < 5.6 or
     * built without the openat2 headers), path confinement falls back to the
     * O_NOFOLLOW segment-by-segment walk which has a narrow TOCTOU window.
     * Emit a persistent startup warning so operators know confinement is
     * degraded and can plan a kernel upgrade.
     */
    if (!xrootd_openat2_runtime_available()) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "xrootd: openat2(2) is not available on this system "
                      "(requires Linux kernel 5.6+). Path confinement falls "
                      "back to O_NOFOLLOW traversal, which has a TOCTOU race "
                      "window on multi-tenant storage. Upgrade the kernel for "
                      "strongest path confinement.");
    }

    cscfp = cmcf->servers.elts;

    xrootd_proxy_pool_init();

    /*
     * Phase 44: bring up this worker's optional io_uring ring (after the proxy
     * pool, same lifetime as every other per-worker async resource).  A no-op
     * unless a server block enabled it; under `xrootd_io_uring on` a bring-up
     * failure returns NGX_ERROR so the worker refuses to run on the thread pool
     * (§32.7 backstop).  Under `auto` it degrades silently.
     */
    if (xrootd_uring_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->common.enable) {
            continue;
        }

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
        xcf->proxy_audit_log_fd = xcf->proxy_audit_log_file != NULL
                             ? xcf->proxy_audit_log_file->fd : NGX_INVALID_FILE;

        /* Phase 35: open this worker's own fds onto the FRM queue file (the
         * master reconciled file → SHM index before fork; workers lock/IO with
         * independent fds), then arm the per-worker stage scheduler. */
        if (xcf->frm.enable && xcf->frm.queue != NULL) {
            if (frm_queue_init(xcf->frm.queue, cycle->log) != NGX_OK) {
                return NGX_ERROR;
            }
            frm_stage_scheduler_register(cycle, &xcf->frm,
                                         xcf->common.thread_pool,
                                         xcf->manager_mode,
                                         (uint16_t) xcf->listen_port);
            /* Phase 4 F6: worker-0 Category-2 purge-watermark monitor (stub). */
            frm_migrate_purge_register(cycle, &xcf->frm);
        }

        if (xcf->auth == XROOTD_AUTH_GSI || xcf->auth == XROOTD_AUTH_BOTH) {
            gsi_seen = 1;   /* Phase 33: warm the GSI DH key pool below */
        }

        if (xcf->manager_mode) {
            manager_seen = 1;   /* A4: arm the pending-locate reaper below */
        }

        /* Only open rootfd for data servers with a local export root.
         * Proxy/manager/supervisor servers leave root_canon empty. */
        if (xcf->common.root_canon[0] != '\0') {
            xcf->rootfd = open(xcf->common.root_canon,
                               O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (xcf->rootfd < 0) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, errno,
                              "xrootd: cannot open export root \"%s\" for "
                              "kernel-confined path operations",
                              xcf->common.root_canon);
                return NGX_ERROR;
            }
        }

        if (xrootd_chkpoint_recover_root(cycle->log, xcf->common.root_canon)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Build the per-worker XrdAcc tables + hot-reload timer (no-op unless
         * this server uses `xrootd_authdb_format xrdacc`). */
        if (xrootd_acc_init_server(xcf, cycle) != NGX_OK) {
            return NGX_ERROR;
        }

        if (xcf->cms_addr != NULL) {
            ngx_xrootd_cms_start(cycle, xcf);
        }

        /* Phase 22: start the active health-check timer (no-op if disabled). */
        xrootd_hc_manager_start(cycle, xcf);

        if ((xcf->auth != XROOTD_AUTH_GSI && xcf->auth != XROOTD_AUTH_BOTH)
            || xcf->crl.len == 0 || xcf->crl_reload == 0)
        {
            /* CRL timer not needed — but still check for JWKS refresh */
            xrootd_token_jwks_schedule_refresh(cycle, xcf);
            continue;
        }

        /* Allocate and start the CRL reload timer */
        xcf->crl_timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (xcf->crl_timer == NULL) {
            return NGX_ERROR;
        }
        xcf->crl_timer->handler = xrootd_crl_reload_handler;
        xcf->crl_timer->data    = xcf;
        xcf->crl_timer->log     = cycle->log;

        ngx_add_timer(xcf->crl_timer, (ngx_msec_t) xcf->crl_reload * 1000);

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "xrootd: CRL reload timer started - interval=%ds "
                      "path=\"%s\"",
                      (int) xcf->crl_reload, xcf->crl.data);

        /* Also check for JWKS refresh on GSI/BOTH servers */
        xrootd_token_jwks_schedule_refresh(cycle, xcf);
    }

    /* Phase 33: warm the per-worker GSI ephemeral-DH key pool so kXGC_certreq
     * never runs keygen on the event thread under a concurrent handshake burst. */
    if (gsi_seen) {
        xrootd_gsi_keypool_init(cycle);
    }

    /* Phase 35: arm the FRM expiry reaper (worker 0 only; no-op when disabled). */
    frm_reaper_register(cycle);

    /* A4: arm the pending-locate reaper (worker 0 only) when any server is a
     * manager — reclaims abandoned in-flight locate slots even when traffic
     * ceases.  Single process-global SHM table, so one worker suffices. */
    if (manager_seen && ngx_worker == 0) {
        xrootd_pending_reap_timer.handler = xrootd_pending_reap_handler;
        xrootd_pending_reap_timer.data    = NULL;
        xrootd_pending_reap_timer.log      = cycle->log;
        ngx_add_timer(&xrootd_pending_reap_timer,
                      XROOTD_PENDING_REAP_INTERVAL_MS);
    }

    /* Phase 40: connect this worker to the identity broker (no-op unless
     * xrootd_impersonation=map; lazily reconnects if the broker isn't up yet). */
    xrootd_imp_init_worker(cycle);

    /* Upload stage-out reaper (worker 0): finish any interrupted cache->storage
     * commit left by a previous run, then sweep periodically.  Covers both
     * root:// and davs:// stage dirs (registered at config time).  The first tick
     * is soon (startup recovery); armed only when a stage dir is configured. */
    if (ngx_worker == 0 && xrootd_stage_dir_count() > 0) {
        xrootd_stage_reap_timer.handler = xrootd_stage_reap_handler;
        xrootd_stage_reap_timer.data    = NULL;
        xrootd_stage_reap_timer.log     = cycle->log;
        ngx_add_timer(&xrootd_stage_reap_timer, XROOTD_STAGE_REAP_FIRST_MS);
    }

    return NGX_OK;
}

void
xrootd_exit_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
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

    /* Fast teardown: drop any idle pooled upstream connections so this draining
     * worker releases authenticated upstream sockets immediately (with a clean
     * FIN) rather than leaving process-exit to reap them.  Idempotent and safe
     * when proxy mode was never used (the pool is simply empty). */
    xrootd_proxy_pool_shutdown();

    /* Phase 44: tear down this worker's io_uring ring (no-op if never up). */
    xrootd_uring_exit_worker(cycle);

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return;
    }

    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);
        if (!xcf->common.enable) {
            continue;
        }
        if (xcf->rootfd >= 0) {
            close(xcf->rootfd);
            xcf->rootfd = -1;
        }
    }

    xrootd_crypto_cleanup();
}
