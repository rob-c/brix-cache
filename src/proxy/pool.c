/*
 * pool.c — upstream connection pooling, health tracking, and keepalives.
 */

#include "proxy_internal.h"
#include <openssl/md5.h>

/* Worker-local pool of idle authenticated upstream connections. */
static ngx_queue_t  proxy_pool;
static ngx_uint_t   proxy_pool_count;

/* Worker-local health status for each upstream endpoint. */
xrootd_proxy_up_status_t *proxy_up_status;
static ngx_uint_t          proxy_up_status_count;

/* ---- health tracking ----------------------------------------------------- */

void
xrootd_proxy_up_status_init(ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_uint_t n = (conf->proxy_upstreams != NULL)
                   ? conf->proxy_upstreams->nelts : 1;

    if (proxy_up_status != NULL && proxy_up_status_count >= n) {
        return;
    }

    proxy_up_status = ngx_alloc(n * sizeof(xrootd_proxy_up_status_t),
                                ngx_cycle->log);
    if (proxy_up_status == NULL) {
        return;
    }

    ngx_memzero(proxy_up_status, n * sizeof(xrootd_proxy_up_status_t));
    proxy_up_status_count = n;
}

void
xrootd_proxy_up_mark_failed(xrootd_proxy_ctx_t *proxy)
{
    int idx = proxy->upstream_idx;
    if (idx < 0) idx = 0;

    if (proxy_up_status == NULL || (ngx_uint_t) idx >= proxy_up_status_count) {
        return;
    }

    proxy_up_status[idx].fails++;
    proxy_up_status[idx].checked = ngx_time();

    if (proxy_up_status[idx].fails >= XROOTD_PROXY_MAX_FAILS) {
        proxy_up_status[idx].down = 1;
        ngx_log_error(NGX_LOG_ERR, proxy->client_conn->log, 0,
                      "xrootd proxy: upstream #%d marked DOWN after %ui failures",
                      idx, proxy_up_status[idx].fails);
    }
}

void
xrootd_proxy_up_mark_ok(xrootd_proxy_ctx_t *proxy)
{
    int idx = proxy->upstream_idx;
    if (idx < 0) idx = 0;

    if (proxy_up_status == NULL || (ngx_uint_t) idx >= proxy_up_status_count) {
        return;
    }

    if (proxy_up_status[idx].down) {
        ngx_log_error(NGX_LOG_NOTICE, proxy->client_conn->log, 0,
                      "xrootd proxy: upstream #%d is UP again", idx);
    }

    proxy_up_status[idx].fails = 0;
    proxy_up_status[idx].down  = 0;
    proxy_up_status[idx].checked = ngx_time();
}

/* ---- keepalive ping timer ------------------------------------------------ */

static void
xrootd_proxy_pool_ping_handler(ngx_event_t *ev)
{
    xrootd_proxy_pooled_conn_t *pc = ev->data;
    ngx_connection_t           *c  = pc->conn;
    u_char                      ping[XRD_REQUEST_HDR_LEN];

    /* If the connection was already closed or taken from pool, ignore. */
    if (c == NULL) {
        return;
    }

    /* Check for idle timeout. */
    if (ngx_time() - pc->idle_since > XROOTD_PROXY_POOL_KEEPALIVE) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd proxy: pooled connection timed out");
        ngx_queue_remove(&pc->queue);
        proxy_pool_count--;
        ngx_close_connection(c);
        ngx_free(pc);
        return;
    }

    /* Build and send kXR_ping. */
    ngx_memzero(ping, sizeof(ping));
    {
        uint16_t rid = htons(kXR_ping);
        ngx_memcpy(ping + 2, &rid, 2);
    }

    if (c->send(c, ping, sizeof(ping)) < 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd proxy: pooled ping failed, closing");
        ngx_queue_remove(&pc->queue);
        proxy_pool_count--;
        ngx_close_connection(c);
        ngx_free(pc);
        return;
    }

    /* Re-arm the ping timer. */
    ngx_add_timer(ev, 15000); /* 15s pings */
}

/* ---- pool management ----------------------------------------------------- */

void
xrootd_proxy_pool_init(void)
{
    ngx_queue_init(&proxy_pool);
    proxy_pool_count = 0;
}

ngx_connection_t *
xrootd_proxy_pool_get(xrootd_proxy_ctx_t *proxy,
                      ngx_stream_xrootd_srv_conf_t *conf,
                      int *idx_out)
{
    ngx_queue_t                *q;
    xrootd_proxy_pooled_conn_t *pc;
    ngx_uint_t                  auth_type = conf->proxy_auth;
    u_char                      thash[16];
    ngx_uint_t                  tries, n_upstreams, start_idx;

    xrootd_proxy_up_status_init(conf);

    /* Selection logic with health awareness. */
    n_upstreams = (conf->proxy_upstreams != NULL) ? conf->proxy_upstreams->nelts : 1;
    start_idx   = (ngx_uint_t) ngx_random() % n_upstreams;

    /* Skip redirect for pool check for now; pooling is for primary upstreams. */
    if (proxy->redirect_host.len > 0) {
        return NULL;
    }

    /* Bearer token hash for matching authenticated connections. */
    if (auth_type == XROOTD_PROXY_AUTH_FORWARD && proxy->client_ctx->bearer_token[0]) {
        MD5((const u_char *) proxy->client_ctx->bearer_token,
            ngx_strlen(proxy->client_ctx->bearer_token), thash);
    } else {
        ngx_memzero(thash, 16);
    }

    for (tries = 0; tries < n_upstreams; tries++) {
        ngx_uint_t idx = (start_idx + tries) % n_upstreams;

        /* Skip down servers unless timeout passed. */
        if (proxy_up_status[idx].down) {
            if (ngx_time() - proxy_up_status[idx].checked < XROOTD_PROXY_FAIL_TIMEOUT) {
                continue;
            }
        }

        /* Search pool for a match. */
        for (q = ngx_queue_head(&proxy_pool);
             q != ngx_queue_sentinel(&proxy_pool);
             q = ngx_queue_next(q))
        {
            pc = ngx_queue_data(q, xrootd_proxy_pooled_conn_t, queue);

            if (pc->upstream_idx == idx && pc->auth_type == auth_type) {
                if (auth_type != XROOTD_PROXY_AUTH_FORWARD
                    || ngx_memcmp(pc->token_hash, thash, 16) == 0)
                {
                    ngx_connection_t *c = pc->conn;
                    ngx_queue_remove(q);
                    proxy_pool_count--;

                    if (pc->ping_ev.timer_set) {
                        ngx_del_timer(&pc->ping_ev);
                    }

                    ngx_free(pc);
                    *idx_out = (int) idx;

                    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                                   "xrootd proxy: reused connection from pool for upstream #%ui",
                                   idx);
                    return c;
                }
            }
        }
    }

    return NULL;
}

void
xrootd_proxy_pool_put(xrootd_proxy_ctx_t *proxy)
{
    xrootd_proxy_pooled_conn_t   *pc;
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;

    if (proxy->conn == NULL || proxy->state != XRD_PX_IDLE) {
        return;
    }

    /* Don't pool redirected connections (too transient). */
    if (proxy->redirect_host.len > 0) {
        return;
    }

    if (proxy_pool_count >= XROOTD_PROXY_POOL_SIZE) {
        /* Pool full — eject oldest. */
        ngx_queue_t *q = ngx_queue_last(&proxy_pool);
        pc = ngx_queue_data(q, xrootd_proxy_pooled_conn_t, queue);
        ngx_queue_remove(q);
        proxy_pool_count--;
        ngx_close_connection(pc->conn);
        ngx_free(pc);
    }

    pc = ngx_alloc(sizeof(xrootd_proxy_pooled_conn_t), proxy->client_conn->log);
    if (pc == NULL) {
        return;
    }

    pc->conn         = proxy->conn;
    pc->upstream_idx = (proxy->upstream_idx < 0) ? 0 : (ngx_uint_t) proxy->upstream_idx;
    pc->auth_type    = conf->proxy_auth;
    pc->idle_since   = ngx_time();

    if (pc->auth_type == XROOTD_PROXY_AUTH_FORWARD && proxy->client_ctx->bearer_token[0]) {
        MD5((const u_char *) proxy->client_ctx->bearer_token,
            ngx_strlen(proxy->client_ctx->bearer_token), pc->token_hash);
    } else {
        ngx_memzero(pc->token_hash, 16);
    }

    /* Detach connection from the client session. */
    proxy->conn = NULL;

    /* Configure keepalive ping timer. */
    ngx_memzero(&pc->ping_ev, sizeof(ngx_event_t));
    pc->ping_ev.handler = xrootd_proxy_pool_ping_handler;
    pc->ping_ev.data    = pc;
    pc->ping_ev.log     = pc->conn->log;
    ngx_add_timer(&pc->ping_ev, 15000);

    ngx_queue_insert_head(&proxy_pool, &pc->queue);
    proxy_pool_count++;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->conn->log, 0,
                   "xrootd proxy: connection returned to pool (pool size=%ui)",
                   proxy_pool_count);
}
