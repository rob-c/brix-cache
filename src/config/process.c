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

#include "config.h"
#include "../proxy/proxy.h"
#include "../proxy/proxy_internal.h"

static void
xrootd_crl_reload_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t *xcf = ev->data;

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "xrootd: CRL reload timer fired, rebuilding store "
                  "from \"%s\"", xcf->crl.data);

    if (xrootd_rebuild_gsi_store(xcf, ev->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "xrootd: CRL reload failed - keeping previous store");
    }

    /* Re-arm the timer */
    if (xcf->crl_reload > 0) {
        ngx_add_timer(ev, (ngx_msec_t) xcf->crl_reload * 1000);
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

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->common.enable) {
            continue;
        }

        if (xcf->cms_addr != NULL) {
            ngx_xrootd_cms_start(cycle, xcf);
        }

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

    return NGX_OK;
}
