/*
 * process.c — per-worker process lifecycle orchestration: the init/exit hooks.
 *
 * Phase-79 file-size split: the former 925-line process.c is now three focused
 * files in this directory. This file keeps the two nginx lifecycle hooks
 * (ngx_stream_brix_init_process / brix_exit_process) and the worker-scoped
 * bring-up helpers they call directly (stage engine, GSI keypool, openat2
 * warning). The self-arming maintenance timers moved to process_timers.c and
 * the per-server init ladder to process_server_init.c; their cross-file entry
 * points are declared in process_internal.h. Init ordering is unchanged.
 */

#include <unistd.h>
#include "config.h"
#include "process_internal.h"              /* cross-file timer + per-server entry points */
#include "net/proxy/proxy.h"
#include "net/proxy/proxy_internal.h"      /* brix_proxy_pool_init / _shutdown */
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "core/compat/crypto.h"            /* brix_crypto_init / _cleanup */
#include "core/compat/lifecycle_timing.h"  /* brix_phase_timer_* boot-cost breakdown */
#include "fs/cache/cache_storage.h"        /* brix_cache_storage_cleanup (exit) */
#include "fs/xfer/stage_engine.h"          /* phase-64 SP4 durable stage engine */
#include "fs/xfer/backend_async_queue.h"    /* durable async backend-op queue */
#include "auth/gsi/keypool.h"
#include "auth/impersonate/lifecycle.h"
#include "core/aio/uring.h"
#include "core/seccomp/seccomp.h"          /* D-3 per-worker syscall filter */
#include "observability/sesslog/sesslog_ngx.h"

#if defined(__SANITIZE_ADDRESS__)   /* Phase 27 W6: explicit LSan check at exit */
#include <sanitizer/lsan_interface.h>
#endif

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
    /* Durable async backend-op queue shares the same journal root (a private
     * backend/ subdir); init it right after so it inherits the same opt-in dir. */
    brix_baq_init();
    if (ngx_worker == 0) {
        brix_stage_reconcile(NULL);
        /* Replay any backend mutation (unlink/rmdir/rename/mkdir) a crash stranded
         * between "journalled" and "flushed" — the client was told to wait for it,
         * so it must reach the backend rather than vanish. Idempotent. */
        brix_baq_reconcile();
        /* Clean up the OTHER half: a NON-staged direct write interrupted by the
         * crash left an orphan "<final>.xrd-tmp.<dead-pid>.*" in the export tree -
         * reap it (the broken write is discarded; the client retries). */
        (void) brix_tmp_reap_all(cycle->log);
    }
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

    /* Shed ALL worker capabilities + set NO_NEW_PRIVS in EVERY worker, BEFORE the
     * stream-config early-return below, so HTTP-only (WebDAV/S3) workers are
     * hardened too — not just stream/root:// workers or `map` mode. A worker never
     * needs caps; a root-configured worker must not keep them (D-3 companion). */
    brix_imp_worker_harden(cycle->log);

    /* De-escalate a root-capable worker (root, or a non-root CAP_SETUID service
     * account) down to the confined brix_worker_user (default nobody) BEFORE any
     * backend init, broker connect, or the seccomp install below — so pre-auth
     * credential parsing never runs as a root-capable identity, in EVERY mode and
     * for HTTP-only (WebDAV/S3) workers too (they reach this before the early
     * return below; their seccomp install runs later in the WebDAV init_process).
     * Fail-closed: a worker that cannot reach a confined account refuses to run. */
    if (brix_imp_worker_deescalate(cycle->log) != NGX_OK) {
        return NGX_ERROR;
    }

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

    /* D-3: install the seccomp syscall filter LAST, once every one-shot setup
     * syscall above has run, so only the steady-state serving set must be on the
     * allowlist.  Idempotent + process-global (strictest across ALL brix servers,
     * stream + http): for an HTTP-only config this init_process early-returned
     * above and the install happens in the WebDAV init_process instead, so
     * WebDAV/S3-only workers are filtered too.  Fails the worker closed if an
     * audit/enforce filter cannot be loaded — never serve unfiltered. */
    if (brix_seccomp_install_once(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

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
