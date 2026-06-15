#include "server.h"
/*
 * server_handler.c — CMS server connection handler
 *
 * WHAT: Accepts TCP connections from the XRootD CMS manager and maintains a
 *       persistent heartbeat session. Each accepted connection is assigned a
 *       read/write handler pair that exchanges periodic load reports.
 *
 * WHY: The CMS manager needs to know which data servers are alive, how much
 *      free space they have, and their utilisation percentage so it can route
 *      client requests (kXR_locate / kXR_redirect) to the best server.
 *
 * HOW: On accept we allocate a cms_srv_ctx_t on the connection pool, set up
 *      ping_timer for periodic heartbeats, assign read/write handlers,
 *      and immediately arm the first read event. The read handler (recv.c)
 *      dispatches incoming frames; the write handler (send.c) fires load
 *      reports at conf->interval_ms intervals.
 */

void
xrootd_cms_srv_handler(ngx_stream_session_t *s)
/* ---- Function: xrootd_cms_srv_handler() -----------------------------------
 *
 * WHAT: Entry point for CMS server connections accepted by the stream module.
 *       Allocates context, sets up handlers and timer, arms first read.
 *
 * WHY: The CMS manager connects to this port as a data-server client. We need
 *      a per-connection state object (ctx) that tracks the connection pointer,
 *      how many bytes remain in the current frame header, the peer host string,
 *      and the heartbeat timer.
 *
 * HOW: 1. pcalloc ctx on c->pool (auto-cleaned on pool destruction).
 *      2. Initialise ctx fields: c pointer, hdr-in_need = CMS_HDR_LEN,
 *         host from ngx_sock_ntop, interval_ms from conf.
 *      3. Set ping_timer log/data, assign c->data = ctx.
 *      4. Replace default read/write handlers with cms_srv_read/cms_srv_write.
 *      5. Log debug line and arm first read.
 */

{
    ngx_connection_t                  *c;
    xrootd_cms_srv_ctx_t              *ctx;
    ngx_stream_xrootd_cms_srv_conf_t  *conf;
    size_t                             len;

    c = s->connection;

    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_cms_srv_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->c       = c;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    len = ngx_sock_ntop(c->sockaddr, c->socklen,
                        (u_char *) ctx->host, sizeof(ctx->host) - 1, 0);
    ctx->host[len] = '\0';

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_cms_srv_module);
    ctx->conf        = conf;
    ctx->interval_ms = (ngx_msec_t) conf->interval * 1000;
    if (ctx->interval_ms < 1000) {
        /* Never arm a 0/sub-1s self-rearming ping timer: interval 0 → 0ms timer
         * → epoll_wait(timeout=0) busy-loop pinning the worker. Floor at 1s. */
        ctx->interval_ms = 1000;
    }

    /*
     * W1b — accept-time CIDR allowlist gate.  Reject before installing any
     * frame handler so an unauthorised peer never reaches the LOGIN/registry
     * path.  When no allowlist is configured this passes (back-compat).
     */
    if (xrootd_cms_srv_check_peer(c, conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "xrootd: CMS server: registration denied from %s "
                      "(not in xrootd_cms_server_allow)", ctx->host);
        ngx_stream_finalize_session(s, NGX_STREAM_FORBIDDEN);
        return;
    }

    /* W1a — require the sss handshake before registration iff a keytab is set. */
    ctx->auth_state = (conf->sss_keys != NULL) ? CMS_AUTH_REQUESTED
                                               : CMS_AUTH_NONE;

    ctx->ping_timer.log  = c->log;
    ctx->ping_timer.data = ctx;

    c->data = ctx;
    c->read->handler  = xrootd_cms_srv_read;
    c->write->handler = xrootd_cms_srv_write;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: CMS server accepted from %s", ctx->host);

    xrootd_cms_srv_read(c->read);
}
