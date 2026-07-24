/*
 * process_server_init.c — the per-server worker-init ladder.
 *
 * WHAT: Owns brix_init_one_server() — every per-server init step for one
 *       enabled brix server block, in the frozen worker-init order (credential
 *       replay, log-fd capture, staging registry, export rootfd, checkpoint
 *       recovery, cache storage, XrdAcc, CMS, health-check, Pelican advertise,
 *       the two cache reaper timers, CRL/JWKS) — together with the file-local
 *       per-step helpers it delegates to.
 * WHY:  Split (phase-79 file-size cap) out of the former 925-line process.c.
 *       The per-server ladder is a self-contained concern: keeping it in one
 *       focused file leaves the init_process orchestrator (process.c) a short
 *       loop while preserving the EXACT initialization order the
 *       reload-semantics contract freezes. Only brix_init_one_server crosses
 *       the file boundary (declared in process_internal.h); every step helper
 *       stays file-local.
 * HOW:  brix_init_one_server runs the step helpers as a flat early-return
 *       sequence; a step returning NGX_ERROR aborts worker startup. The two
 *       reaper-timer arming helpers point their events at the callbacks defined
 *       in process_timers.c (brix_cache_reap_handler and, from
 *       reap_watermark.h, brix_cache_watermark_timer_handler). No behaviour
 *       change from the split.
 */

#include "config.h"
#include "process_internal.h"
#include <unistd.h>                           /* open() for the confined export rootfd */
#include "protocols/root/write/chkpoint.h"    /* brix_chkpoint_recover_root */
#include "net/manager/health_check.h"         /* brix_hc_manager_start */
#include "fs/cache/origin/pelican_register.h" /* brix_cache_pelican_schedule_advertise */
#include "fs/cache/reap_watermark.h"          /* brix_cache_watermark_timer_handler */
#include "fs/xfer/stage_request_registry.h"   /* brix_stage_registry_init */
#include "fs/cache/cache_storage.h"           /* brix_cache_storage_init, brix_cache_state_root */
#include "fs/xfer/xfer.h"                      /* brix_xfer_resume_sweep_register */
#include "fs/vfs/vfs_backend_registry.h"      /* brix_vfs_backend_set_credential */
#include "core/config/credential_block.h"     /* brix_credential_lookup (per-worker) */
#include "core/compat/cstr.h"                 /* brix_str_cbuf */

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
 *      block table; a miss is loud (error log) — a worker serving with a
 *      wiped credential must never be silent.
 *   3. Map the credential through brix_credential_to_backend_cred() — the
 *      ONE shared mapper (P80.1). Its earlier hand-copied twin here dropped
 *      bearer + all three s3 fields, and because set_credential overwrites
 *      all 8 registry slots unconditionally, every worker spawn wiped the
 *      parse-time S3 keys to "" (phase-80 finding 1.1).
 *   4. Install it on the export root's registry entry; set_credential also
 *      resets e->inst so the instance rebuilds with the credential on first
 *      use.
 */
static void
brix_init_server_backend_credential(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf)
{
    char                       credz[256];
    char                       bearer[4096];
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
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "brix: worker credential replay: no brix_credential \"%s\" "
            "for export \"%s\" — backend keeps its (empty) worker-side "
            "credential; upstream auth WILL fail", credz,
            xcf->common.root_canon);
        return;
    }

    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                          &bcred, cycle->log) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "brix: worker credential replay: cannot derive bearer for "
            "brix_credential \"%s\" (export \"%s\") — credential NOT "
            "installed; upstream auth WILL fail", credz,
            xcf->common.root_canon);
        return;
    }
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
 *   6. Start the health-check timer + Pelican cache advertisement — internal
 *      no-ops when unconfigured. (The outbound CMS client is started earlier,
 *      per-block and worker-0-gated, in brix_cms_role_worker_init.)
 *   7. Arm the stale-dirty and watermark cache reaper timers (fatal on
 *      allocation failure).
 *   8. Arm the CRL reload timer / schedule JWKS refresh.
 */
ngx_int_t
brix_init_one_server(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *xcf)
{
    brix_init_server_backend_credential(cycle, xcf);

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

    /*
     * The outbound CMS client is started in brix_cms_role_worker_init
     * (process.c), which runs for every server block (including cms-only
     * manager blocks with the data path disabled) and gates the client to
     * worker 0 so a stock upstream cmsd admits a single connection per node.
     * It must NOT be started here as well: this ladder runs on every worker,
     * which would resurrect the per-worker connection collision.
     */

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
