#include "cms_internal.h"

#include <ngx_event_connect.h>


void
ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx, ngx_msec_t delay)
{
    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    ngx_add_timer(&ctx->timer, delay);
}


void
ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_msec_t  delay;

    delay = ctx->backoff;
    if (ctx->backoff < NGX_XROOTD_CMS_BACKOFF_MAX) {
        ctx->backoff *= 2;
        if (ctx->backoff > NGX_XROOTD_CMS_BACKOFF_MAX) {
            ctx->backoff = NGX_XROOTD_CMS_BACKOFF_MAX;
        }
    }

    ngx_xrootd_cms_schedule(ctx, delay);
}


void
ngx_xrootd_cms_disconnect(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->connection;
    if (c == NULL) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_close_connection(c);

    ctx->connection = NULL;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
}


static void
ngx_xrootd_cms_write_handler(ngx_event_t *ev)
{
    ngx_connection_t       *c;
    ngx_xrootd_cms_ctx_t   *ctx;

    c = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS connect/write timed out");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!ctx->logged_in) {
        if (ngx_xrootd_cms_send_login(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->logged_in = 1;
        ctx->backoff = NGX_XROOTD_CMS_BACKOFF_INITIAL;

        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS login sent to %V",
                      &ctx->conf->cms_manager);
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);
}


static void
ngx_xrootd_cms_connect(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    ngx_memzero(&ctx->peer, sizeof(ctx->peer));
    ctx->peer.sockaddr = ctx->conf->cms_addr->sockaddr;
    ctx->peer.socklen = ctx->conf->cms_addr->socklen;
    ctx->peer.name = &ctx->conf->cms_addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->cycle->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR || rc == NGX_DECLINED || ctx->peer.connection == NULL) {
        ngx_log_error(NGX_LOG_WARN, ctx->cycle->log, 0,
                      "xrootd: CMS connect to %V failed",
                      &ctx->conf->cms_manager);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    c = ctx->peer.connection;
    ctx->connection = c;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    c->data = ctx;
    c->read->handler = ngx_xrootd_cms_read_handler;
    c->write->handler = ngx_xrootd_cms_write_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, NGX_XROOTD_CMS_CONNECT_TIMEOUT);
        return;
    }

    ngx_xrootd_cms_write_handler(c->write);
}


static void
ngx_xrootd_cms_timer(ngx_event_t *ev)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    ctx = ev->data;

    if (ctx->connection == NULL) {
        ngx_xrootd_cms_connect(ctx);
        return;
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS load heartbeat failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);
}


void
ngx_xrootd_cms_start(ngx_cycle_t *cycle, ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    if (conf->cms_addr == NULL || conf->cms_ctx != NULL) {
        return;
    }

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_xrootd_cms_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "xrootd: CMS heartbeat allocation failed");
        return;
    }

    ctx->cycle = cycle;
    ctx->conf = conf;
    ctx->backoff = NGX_XROOTD_CMS_BACKOFF_INITIAL;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    ctx->timer.handler = ngx_xrootd_cms_timer;
    ctx->timer.data = ctx;
    ctx->timer.log = cycle->log;

    conf->cms_ctx = ctx;

    ngx_xrootd_cms_schedule(ctx, NGX_XROOTD_CMS_INITIAL_DELAY);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: CMS heartbeat starting for manager %V",
                  &conf->cms_manager);
}
