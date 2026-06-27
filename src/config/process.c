/*
 * process.c — per-worker process lifecycle: init/exit hooks and the self-arming
 * maintenance timers (CRL reload, pending-locate reaper, stage-out reaper).
 */

#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "../proxy/proxy.h"
#include "../proxy/proxy_internal.h"
#include "../compat/staged_file.h"
#include "../write/chkpoint.h"
#include "../compat/crypto.h"
#include "../compat/log_diag.h"
#include "../compat/lifecycle_timing.h"
#include "../manager/health_check.h"
#include "../manager/pending.h"
#include "../cache/origin/pelican_register.h"
#include "../gsi/keypool.h"
#include "../impersonate/lifecycle.h"
#include "../aio/uring.h"

#if defined(__SANITIZE_ADDRESS__)   /* Phase 27 W6: explicit LSan check at exit */
#include <sanitizer/lsan_interface.h>
#endif

/* Timer callback: rebuild the GSI X509_STORE from the configured CRL file at the
 * reload interval, then re-arm the timer. */
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
        XROOTD_DIAG_CRIT(ev->log, 0,
            "xrootd: CRL reload failed for \"%s\" — keeping previous store",
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
static ngx_event_t  xrootd_pending_reap_timer;

/* Timer callback: reap expired slots from the CMS pending-locate registry
 * (xrootd_pending_reap_expired), then re-arm the timer. */
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

/* Timer callback: complete/reap stale FRM stage-out commits
 * (xrootd_stage_reap_all), then re-arm the timer. */
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

/*
 * Worker process init: start CRL reload timers for every server block that
 * has xrootd_crl_reload configured. Timers are per-worker because each
 * nginx worker process has its own event loop and its own copy of the config
 * pointers (but the X509_STORE* is shared within a worker).
 */
/* Per-worker init after fork: bring up the proxy pool, start the CMS server
 * handlers when cms_addr is set, and arm the CRL/pending/stage maintenance
 * timers.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t
ngx_stream_xrootd_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    ngx_uint_t                     gsi_seen = 0;
    ngx_stream_xrootd_srv_conf_t  *gsi_xcf = NULL;  /* first GSI block: keypool cfg */
    ngx_uint_t                     manager_seen = 0;
    xrootd_phase_timer_t           pt;
    u_char                         ctx[64];

    /* Permanent per-worker boot-cost breakdown (one NOTICE line at the end). */
    xrootd_phase_timer_start(&pt);

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
    xrootd_phase_mark(&pt, "uring");

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
            if (gsi_xcf == NULL) {
                gsi_xcf = xcf;   /* keypool sizing + thread pool come from here */
            }
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

        /* Pelican: start the cache advertisement timer (no-op unless
         * xrootd_cache_advertise is on with a key + data-url configured). */
        xrootd_cache_pelican_schedule_advertise(cycle, xcf);

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

    xrootd_phase_mark(&pt, "servers");

    /* Phase 33: warm the per-worker GSI ephemeral-DH key pool so kXGC_certreq
     * never runs keygen on the event thread under a concurrent handshake burst.
     * Only a small seed is generated synchronously here; the pool fills to its
     * configured size off the event thread (via the GSI server's thread pool) so
     * worker startup is not blocked on the full warm-up. */
    if (gsi_seen && gsi_xcf != NULL) {
        xrootd_gsi_keypool_init(cycle, gsi_xcf->common.thread_pool,
                                gsi_xcf->gsi_keypool_size,
                                gsi_xcf->gsi_keypool_seed);
    }
    xrootd_phase_mark(&pt, "keypool");

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

    ngx_snprintf(ctx, sizeof(ctx) - 1, "xrootd init_process[w%ui]%Z", ngx_worker);
    xrootd_phase_timer_log(&pt, cycle->log, (const char *) ctx);

    return NGX_OK;
}

/* Per-worker teardown at exit: release process-scoped resources. */
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
