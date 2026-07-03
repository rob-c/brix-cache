/*
 * WHAT: Upstream connection pooling with health-aware selection, fail detection,
 *       and idle-timeout keepalive management. Maintains a worker-local queue of
 *       authenticated upstream connections that can be reused by subsequent client
 *       sessions matching auth type and bearer token hash.
 *
 * WHY:  Transparent proxy authentication (GSI/TLS) is expensive — reusing an already-
 *       authenticated connection avoids repeating handshake for every new client. Health
 *       tracking detects upstream failures and marks servers DOWN after BRIX_PROXY_MAX_FAILS,
 *       skipping them in pool selection until the fail timeout expires. Bearer token hashing
 *       ensures forwarded-token connections reuse only sessions authenticated with matching tokens.
 *       Keepalive timers prevent stale pooled connections from accumulating unread kXR_ok frames
 *       from previous pings (re-arm without ping to avoid buffer contamination).
 *
 * HOW:  brix_proxy_up_status_init() allocates per-upstream health status array on first call;
 *       reuses existing if count >= configured upstreams. up_mark_failed/up_mark_ok increment
 *       fail counters or reset them and log state transitions. pool_init creates the ngx_queue.
 *       pool_get performs random-start round-robin across upstreams, skipping DOWN servers within
 *       fail timeout, then scans pool for matching idx/auth_type/token_hash — returns connection
 *       on match, NULL otherwise. pool_put ejects oldest when pool full, allocates pooled_conn_t,
 *       detaches conn from proxy ctx, sets keepalive timer, inserts head of queue.
 */

#include "proxy_internal.h"
#include "core/compat/safe_size.h"   /* Phase 27 W1: overflow-checked size math */
#include <openssl/md5.h>

/* Worker-local pool of idle authenticated upstream connections. */
static ngx_queue_t  proxy_pool;
static ngx_uint_t   proxy_pool_count;

/* Worker-local health status for each upstream endpoint. */
brix_proxy_up_status_t *proxy_up_status;
static ngx_uint_t          proxy_up_status_count;

/* health tracking */

/* brix_proxy_up_status_init — allocate and zero the per-upstream health-status
 * array (worker-local singleton; reused if already sized for >= N upstreams). */
void
brix_proxy_up_status_init(ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t n = (conf->proxy_upstreams != NULL)
                   ? conf->proxy_upstreams->nelts : 1;

    if (proxy_up_status != NULL && proxy_up_status_count >= n) {
        return;
    }

    proxy_up_status = brix_alloc_array(ngx_cycle->log, n,
                                         sizeof(brix_proxy_up_status_t));
    if (proxy_up_status == NULL) {
        return;
    }

    ngx_memzero(proxy_up_status, n * sizeof(brix_proxy_up_status_t));
    proxy_up_status_count = n;
}

/* brix_proxy_up_mark_failed — increment the current upstream's fail counter (and
 * record the check time), marking it DOWN + logging after BRIX_PROXY_MAX_FAILS. */

void
brix_proxy_up_mark_failed(brix_proxy_ctx_t *proxy)
{
    int idx = proxy->upstream_idx;
    if (idx < 0) idx = 0;

    if (proxy_up_status == NULL || (ngx_uint_t) idx >= proxy_up_status_count) {
        return;
    }

    proxy_up_status[idx].fails++;
    proxy_up_status[idx].checked = ngx_time();

    if (proxy_up_status[idx].fails >= BRIX_PROXY_MAX_FAILS) {
        proxy_up_status[idx].down = 1;
        ngx_log_error(NGX_LOG_ERR, proxy->client_conn->log, 0,
                      "xrootd proxy: upstream #%d marked DOWN after %ui failures",
                      idx, proxy_up_status[idx].fails);
    }
}

/* brix_proxy_up_mark_ok — reset the current upstream's fail counter and clear its
 * DOWN flag (logging a notice on DOWN→UP), recording the check time. */

void
brix_proxy_up_mark_ok(brix_proxy_ctx_t *proxy)
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

/* pooled connection read handler.
 *
 * Fires when the upstream sends data or closes while its connection is idle
 * in the pool.  uconn->data has been set to pc (not proxy) by pool_put, so
 * dereferencing it as a proxy context would be a use-after-free.  Instead,
 * evict the connection and close it cleanly. */
static void
brix_proxy_pool_read_handler(ngx_event_t *rev)
{
    ngx_connection_t           *c  = rev->data;
    brix_proxy_pooled_conn_t *pc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd proxy: upstream closed while pooled — evicting");

    if (pc->ping_ev.timer_set) {
        ngx_del_timer(&pc->ping_ev);
    }

    ngx_queue_remove(&pc->queue);
    proxy_pool_count--;
    ngx_close_connection(c);
    ngx_free(pc);
}


/* keepalive ping timer */
static void
brix_proxy_pool_ping_handler(ngx_event_t *ev)
{
    brix_proxy_pooled_conn_t *pc = ev->data;
    ngx_connection_t           *c  = pc->conn;

    /* If the connection was already closed or taken from pool, ignore. */
    if (c == NULL) {
        return;
    }

    /* Check for idle timeout. */
    if (ngx_time() - pc->idle_since > BRIX_PROXY_POOL_KEEPALIVE) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd proxy: pooled connection timed out");
        ngx_queue_remove(&pc->queue);
        proxy_pool_count--;
        ngx_close_connection(c);
        ngx_free(pc);
        return;
    }

    /* Re-arm the idle-timeout timer without sending a ping.
     * Sending pings and not reading their responses leaves stale kXR_ok
     * frames in the socket buffer, which the next reused connection reads
     * as an unexpected response to its first real request.
     * Skip the re-arm while the worker is shutting down — the pool is drained
     * by brix_proxy_pool_shutdown() and the timer must not keep us alive. */
    if (!ngx_exiting) {
        ngx_add_timer(ev, pc->keepalive_interval);
    }
}

/* brix_proxy_pool_shutdown — close and free every idle pooled upstream connection
 * (same eviction sequence as the read-handler / idle-timeout path, keeping queue +
 * counter consistent) so a draining worker, once ngx_exiting is set, does not hold
 * authenticated sockets and keepalive timers until worker_shutdown_timeout. */
void
brix_proxy_pool_shutdown(void)
{
    /* proxy_pool is a zero-initialised BSS global. A worker that never ran
     * brix_proxy_pool_init() (e.g. an HTTP-only instance: the stream
     * init_process returns early when there is no stream main conf, before the
     * pool init) has a NULL sentinel, not the self-referential empty sentinel.
     * ngx_queue_empty() would then read NULL != &proxy_pool as "non-empty" and
     * the dequeue below would deref a NULL head (segfault at the ping_ev
     * offset). Treat a NULL sentinel as an uninitialised (empty) pool — this is
     * what makes the call genuinely "safe when proxy mode was never used". */
    if (proxy_pool.next == NULL) {
        return;
    }

    while (!ngx_queue_empty(&proxy_pool)) {
        ngx_queue_t                *q  = ngx_queue_head(&proxy_pool);
        brix_proxy_pooled_conn_t *pc =
            ngx_queue_data(q, brix_proxy_pooled_conn_t, queue);

        if (pc->ping_ev.timer_set) {
            ngx_del_timer(&pc->ping_ev);
        }
        ngx_queue_remove(&pc->queue);
        proxy_pool_count--;
        if (pc->conn != NULL) {
            ngx_close_connection(pc->conn);
        }
        ngx_free(pc);
    }
}

/* pool management */

/* brix_proxy_pool_init — initialize the worker-local idle-connection queue and
 * zero the pool counter (once at startup, before any get/put). */
void
brix_proxy_pool_init(void)
{
    ngx_queue_init(&proxy_pool);
    proxy_pool_count = 0;
}

/* brix_proxy_pool_get — pick an authenticated pooled upstream via health-aware
 * random-start round-robin (skipping DOWN servers within the fail timeout), matched
 * by upstream index, auth type (GSI/TLS/forwarded-token), and — in forwarded-token
 * mode — bearer-token MD5. Sets *idx_out; returns the connection, or NULL when the
 * caller must open a new one. */

ngx_connection_t *
brix_proxy_pool_get(brix_proxy_ctx_t *proxy,
                      ngx_stream_brix_srv_conf_t *conf,
                      int *idx_out)
{
    ngx_queue_t                *q;
    brix_proxy_pooled_conn_t *pc;
    ngx_uint_t                  auth_type = conf->proxy_auth;
    u_char                      thash[16];
    ngx_uint_t                  tries, n_upstreams, start_idx;

    brix_proxy_up_status_init(conf);

    /* Selection logic with health awareness. */
    n_upstreams = (conf->proxy_upstreams != NULL) ? conf->proxy_upstreams->nelts : 1;
    start_idx   = (ngx_uint_t) ngx_random() % n_upstreams;

    /* Skip redirect for pool check for now; pooling is for primary upstreams. */
    if (proxy->redirect_host.len > 0) {
        return NULL;
    }

    /* Bearer token hash for matching authenticated connections. */
    if (auth_type == BRIX_PROXY_AUTH_FORWARD && proxy->client_ctx->bearer_token[0]) {
        MD5((const u_char *) proxy->client_ctx->bearer_token,
            ngx_strlen(proxy->client_ctx->bearer_token), thash);
    } else {
        ngx_memzero(thash, 16);
    }

    for (tries = 0; tries < n_upstreams; tries++) {
        ngx_uint_t idx = (start_idx + tries) % n_upstreams;

        /* Skip down servers unless timeout passed. */
        if (proxy_up_status[idx].down) {
            if (ngx_time() - proxy_up_status[idx].checked < BRIX_PROXY_FAIL_TIMEOUT) {
                continue;
            }
        }

        /* Search pool for a match. */
        for (q = ngx_queue_head(&proxy_pool);
             q != ngx_queue_sentinel(&proxy_pool);
             q = ngx_queue_next(q))
        {
            pc = ngx_queue_data(q, brix_proxy_pooled_conn_t, queue);

            if (pc->upstream_idx == idx && pc->auth_type == auth_type) {
                if (auth_type != BRIX_PROXY_AUTH_FORWARD
                    || ngx_memcmp(pc->token_hash, thash, 16) == 0)
                {
                    ngx_connection_t *c = pc->conn;
                    ngx_queue_remove(q);
                    proxy_pool_count--;

                    if (pc->ping_ev.timer_set) {
                        ngx_del_timer(&pc->ping_ev);
                    }

                    /* Restore the upstream read handler before freeing pc.
                     * pool_put installed brix_proxy_pool_read_handler and
                     * set c->data = pc; the caller (connect_upstream.c) will
                     * set c->data = proxy immediately after we return. */
                    c->read->handler = brix_proxy_read_handler;

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

/* brix_proxy_pool_put — return an authenticated idle upstream to the worker-local
 * pool for reuse: detach it from the proxy ctx, wrap it in a pooled_conn_t (auth
 * type / upstream index / token hash / keepalive timer), and insert at the queue
 * head, ejecting the oldest when full (BRIX_PROXY_POOL_SIZE). Redirected
 * connections (too transient) are skipped. */

void
brix_proxy_pool_put(brix_proxy_ctx_t *proxy)
{
    brix_proxy_pooled_conn_t   *pc;
    ngx_stream_brix_srv_conf_t *conf = proxy->conf;

    if (proxy->conn == NULL || proxy->state != XRD_PX_IDLE) {
        return;
    }

    /* Don't pool redirected connections (too transient). */
    if (proxy->redirect_host.len > 0) {
        return;
    }

    if (proxy_pool_count >= BRIX_PROXY_POOL_SIZE) {
        /* Pool full — eject oldest. */
        ngx_queue_t *q = ngx_queue_last(&proxy_pool);
        pc = ngx_queue_data(q, brix_proxy_pooled_conn_t, queue);
        ngx_queue_remove(q);
        proxy_pool_count--;
        ngx_close_connection(pc->conn);
        ngx_free(pc);
    }

    pc = ngx_alloc(sizeof(brix_proxy_pooled_conn_t), proxy->client_conn->log);
    if (pc == NULL) {
        return;
    }

    pc->conn         = proxy->conn;
    pc->upstream_idx = (proxy->upstream_idx < 0) ? 0 : (ngx_uint_t) proxy->upstream_idx;
    pc->auth_type    = conf->proxy_auth;
    pc->idle_since         = ngx_time();
    pc->keepalive_interval = (conf->proxy_keepalive_interval > 0)
                             ? conf->proxy_keepalive_interval : 15000;

    if (pc->auth_type == BRIX_PROXY_AUTH_FORWARD && proxy->client_ctx->bearer_token[0]) {
        MD5((const u_char *) proxy->client_ctx->bearer_token,
            ngx_strlen(proxy->client_ctx->bearer_token), pc->token_hash);
    } else {
        ngx_memzero(pc->token_hash, 16);
    }

    /* Detach connection from the client session. */
    proxy->conn = NULL;

    /* Transfer connection ownership to pc and install a pool-safe read
     * handler.  brix_proxy_read_handler dereferences uconn->data as a
     * proxy ctx; that ctx lives in the client pool and is freed when the
     * session ends — so it must not be reached via a pooled connection.
     * brix_proxy_pool_read_handler evicts the entry cleanly instead. */
    pc->conn->data         = pc;
    pc->conn->read->handler = brix_proxy_pool_read_handler;

    /* Configure keepalive ping timer. */
    ngx_memzero(&pc->ping_ev, sizeof(ngx_event_t));
    pc->ping_ev.handler = brix_proxy_pool_ping_handler;
    pc->ping_ev.data    = pc;
    pc->ping_ev.log     = pc->conn->log;
    ngx_add_timer(&pc->ping_ev, pc->keepalive_interval);

    ngx_queue_insert_head(&proxy_pool, &pc->queue);
    proxy_pool_count++;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->conn->log, 0,
                   "xrootd proxy: connection returned to pool (pool size=%ui)",
                   proxy_pool_count);
}
