#include "server.h"


void
xrootd_cms_srv_handler(ngx_stream_session_t *s)
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
    ctx->interval_ms = (ngx_msec_t) conf->interval * 1000;

    ctx->ping_timer.log  = c->log;
    ctx->ping_timer.data = ctx;

    c->data = ctx;
    c->read->handler  = xrootd_cms_srv_read;
    c->write->handler = xrootd_cms_srv_write;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: CMS server accepted from %s", ctx->host);

    xrootd_cms_srv_read(c->read);
}
