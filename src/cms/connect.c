#include "cms_internal.h"

#include <ngx_event_connect.h>

/* ---- ngx_xrootd_cms_schedule — set or replace the CMS timer with given delay ----
 *
 * WHAT: Arms or replaces the CMS heartbeat timer to fire after `delay` milliseconds. If a timer is already set, it's removed first before the new one is added. Used by connect lifecycle (initial connection retry, periodic heartbeat). */

void
ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx, ngx_msec_t delay)
{
    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    ngx_add_timer(&ctx->timer, delay);
}

/* ---- ngx_xrootd_cms_schedule_retry — exponential backoff reconnect scheduler ----
 *
 * WHAT: Doubles the current backoff delay (up to NGX_XROOTD_CMS_BACKOFF_MAX = 60s) and schedules a retry. Called after connection failure or disconnect to stagger reconnection attempts. Prevents hammering the CMS manager during transient failures. */

void
ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_msec_t  delay;
    ngx_msec_t  max_backoff;

    /* Cap max backoff at 10× the heartbeat interval so a short cms_interval
     * (e.g. 2s for tests) also gives short reconnect windows. */
    max_backoff = (ngx_msec_t) ctx->conf->cms_interval * 10000;
    if (max_backoff > NGX_XROOTD_CMS_BACKOFF_MAX) {
        max_backoff = NGX_XROOTD_CMS_BACKOFF_MAX;
    }

    delay = ctx->backoff;
    if (ctx->backoff < max_backoff) {
        ctx->backoff *= 2;
        if (ctx->backoff > max_backoff) {
            ctx->backoff = max_backoff;
        }
    }

    ngx_xrootd_cms_schedule(ctx, delay);
}

/* ---- ngx_xrootd_cms_disconnect — tear down active CMS connection and reset state ----
 *
 * WHAT: Closes the active TCP connection, removes read/write timers, resets ctx->connection to NULL. Also clears logged_in flag and resets inbuf position for next reconnection attempt. Called on I/O errors or timeouts. */

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

    ngx_log_error(NGX_LOG_WARN, c->write->log, 0,
                  "xrootd: CMS write handler called timedout=%d "
                  "c=%p ctx=%p logged_in=%d",
                  (int) ev->timedout, c, ctx,
                  ctx ? (int) ctx->logged_in : -1);

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
        ctx->backoff = ngx_min((ngx_msec_t) ctx->conf->cms_interval * 1000,
                               (ngx_msec_t) NGX_XROOTD_CMS_BACKOFF_INITIAL);

        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS login sent to %V",
                      &ctx->conf->cms_manager);

        /*
         * Announce traffic state (Resume|noStage) immediately after login so a
         * real cmsd manager marks this disk-only node active and eligible for
         * selection; without it the manager keeps us suspended and never
         * redirects clients here.
         */
        if (ngx_xrootd_cms_send_status(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }
    }

    ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                  "xrootd: CMS write handler: calling send_load");

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS write handler: send_load failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                  "xrootd: CMS write handler: send_load OK, calling handle_read_event");

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS write handler: handle_read_event failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                  "xrootd: CMS write handler: scheduling next heartbeat interval=%T",
                  ctx->conf->cms_interval);

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);

    ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                  "xrootd: CMS write handler: complete");
}

/* ---- ngx_xrootd_cms_connect — establish TCP connection to CMS manager ----
 *
 * WHAT: Configures an nginx peer connection to the CMS manager address and initiates TCP connect via ngx_event_connect_peer. On success, sets up read/write handlers and either fires immediately or waits for connect timeout (NGX_XROOTD_CMS_CONNECT_TIMEOUT = 5s). Called from timer handler when ctx->connection == NULL. */

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

/* ---- ngx_xrootd_cms_timer — periodic heartbeat or initial connect trigger ----
 *
 * WHAT: Timer handler for two purposes: (1) After initial connection success, fires periodically to send load heartbeat reports every `cms_interval` seconds. (2) When no active connection exists (ctx->connection == NULL), triggers reconnection attempt. Also handles load heartbeat failures by disconnecting and retrying with backoff. */

static void
ngx_xrootd_cms_timer(ngx_event_t *ev)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    ctx = ev->data;

    ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                  "xrootd: CMS timer fired connection=%p logged_in=%d",
                  ctx->connection,
                  ctx->connection ? (int) ctx->logged_in : -1);

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

/* ---- ngx_xrootd_cms_start — initialize and start CMS heartbeat client ----
 *
 * WHAT: Entry point called from config/process.c at worker init. Allocates the
 * CMS context, derives the initial reconnect backoff from cms_interval (capped
 * at NGX_XROOTD_CMS_BACKOFF_INITIAL), then schedules the first connection
 * attempt after NGX_XROOTD_CMS_INITIAL_DELAY (1s). Each nginx worker maintains
 * its own independent CMS connection to the parent manager. */

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
    ctx->backoff = ngx_min((ngx_msec_t) conf->cms_interval * 1000,
                           (ngx_msec_t) NGX_XROOTD_CMS_BACKOFF_INITIAL);
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
