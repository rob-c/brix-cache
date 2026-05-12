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

    cscfp = cmcf->servers.elts;

    xrootd_proxy_pool_init();

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xcf->cms_addr != NULL) {
            ngx_xrootd_cms_start(cycle, xcf);
        }

        if ((xcf->auth != XROOTD_AUTH_GSI && xcf->auth != XROOTD_AUTH_BOTH)
            || xcf->crl.len == 0 || xcf->crl_reload == 0)
        {
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
    }

    return NGX_OK;
}
