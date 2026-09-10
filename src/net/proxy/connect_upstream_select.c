/*
 * connect_upstream_select.c — upstream endpoint selection for the lazy connect.
 *
 * WHAT: Chooses where brix_proxy_connect() goes: a redirect target, a
 *       CMS-pinned data server (phase-115 W2.1), an already-authenticated
 *       pooled connection, a healthy member of the round-robin upstream array,
 *       or the single configured host.
 *
 * WHY: Selection is pure policy over the conf and per-session state — the one
 *      self-contained phase of connect_upstream.c. Splitting it keeps that
 *      file to the socket/resolve/TLS mechanics (and under the size gate).
 *
 * HOW: brix_proxy_select_endpoint() fills a brix_proxy_target_t (host + port)
 *      and returns NGX_DECLINED for "go resolve/connect", NGX_OK when a pooled
 *      connection was adopted (connect complete), NGX_ERROR when every
 *      upstream is down. pc_pick_healthy_upstream() walks the worker-local
 *      proxy_up_status health table from the shared round-robin cursor.
 */

#include "proxy_internal.h"

/* Round-robin counter for multiple upstream endpoints. */
static ngx_atomic_t  proxy_upstream_rr;


/*
 * WHAT: Picks a healthy upstream index from the round-robin array, honouring
 *       the lazily-allocated proxy_up_status health table.
 *
 * WHY: When every upstream is marked down (and none has aged past the retry
 *      window) we must fail the connect rather than fall through to a known-dead
 *      endpoint and hammer it in a tight loop.
 *
 * HOW: Advances the shared RR counter, then walks up to nelts entries from that
 *      start looking for one that is up (or stale enough to retry). A NULL
 *      health table means "all healthy" — the RR pick stands. Returns NGX_OK
 *      with *idx_out set, or NGX_ERROR when all are down.
 */
static ngx_int_t
pc_pick_healthy_upstream(ngx_stream_brix_srv_conf_t *conf,
                         ngx_uint_t *idx_out)
{
    ngx_uint_t  nelts = conf->proxy.upstreams->nelts;
    ngx_uint_t  idx;
    ngx_uint_t  i;
    int         found = 0;

    idx = ngx_atomic_fetch_add(&proxy_upstream_rr, 1) % nelts;

    /* proxy_up_status is lazily allocated by the health-tracking path and is
     * NULL until a failure marks an upstream down (the mark_fail/is_down
     * accessors are all NULL-tolerant no-ops). Treat a NULL table as "every
     * upstream healthy" so the round-robin pick stands — same semantics,
     * without dereferencing a NULL array. */
    for (i = 0; proxy_up_status != NULL && i < nelts; i++) {
        ngx_uint_t cur = (idx + i) % nelts;
        if (!proxy_up_status[cur].down ||
            ngx_time() - proxy_up_status[cur].checked >= BRIX_PROXY_FAIL_TIMEOUT)
        {
            idx = cur;
            found = 1;
            break;
        }
    }
    if (proxy_up_status == NULL) {
        found = 1;      /* no health table → RR pick is authoritative */
    }

    if (!found) {
        return NGX_ERROR;
    }

    *idx_out = idx;
    return NGX_OK;
}

/*
 * WHAT: Chooses the upstream endpoint into *tgt (host+port) with priority
 *       redirect > pooled connection > round-robin healthy array > single host.
 *
 * WHY: A pooled connection short-circuits the whole connect: it is already
 *      authenticated and bootstrapped, so we adopt it and either dispatch the
 *      saved request or resume the client read loop. GSI-as-user connections
 *      are per-user authenticated and must never reuse a pooled (foreign
 *      identity) connection.
 *
 * HOW: Returns NGX_OK when a pooled connection was adopted (caller returns OK to
 *      its own caller — connect is complete), NGX_DECLINED when *tgt was filled
 *      and the caller must proceed to resolve/connect, or NGX_ERROR when all
 *      upstreams are down.
 */
ngx_int_t
brix_proxy_select_endpoint(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
                   ngx_stream_brix_srv_conf_t *conf, brix_proxy_target_t *tgt)
{
    ngx_connection_t *uconn;
    int               pooled_idx = -1;
    ngx_uint_t        idx;

    if (proxy->redirect_host.len > 0) {
        tgt->host = &proxy->redirect_host;
        tgt->port = (ngx_int_t) proxy->redirect_port;
        /* upstream_idx stays what it was, or -1 if we started redirected */
        return NGX_DECLINED;
    }

    /* Phase-115 W2.1: a CMS-selected session goes to its pinned data server —
     * the configured upstream list (usually empty on a manager) and the shared
     * pool (keyed by that list) do not apply. */
    if (proxy->pinned_host.len > 0) {
        tgt->host = &proxy->pinned_host;
        tgt->port = (ngx_int_t) proxy->pinned_port;
        proxy->upstream_idx = -1;
        return NGX_DECLINED;
    }

    /* GSI-as-user connections are per-user authenticated — never reuse a
     * pooled connection (it carries a different identity). */
    uconn = (conf->proxy.auth == BRIX_PROXY_AUTH_GSI)
            ? NULL : brix_proxy_pool_get(proxy, conf, &pooled_idx);
    if (uconn != NULL) {
        proxy->conn         = uconn;
        proxy->upstream_idx = pooled_idx;
        proxy->state        = XRD_PX_IDLE;
        proxy->from_pool    = 1;
        uconn->data         = proxy;
        uconn->log          = client_conn->log;
        uconn->read->log    = client_conn->log;
        uconn->write->log   = client_conn->log;

        if (proxy->saved_req != NULL) {
            brix_proxy_dispatch_pending(proxy);
        } else {
            proxy->client_ctx->state = XRD_ST_REQ_HEADER;
            brix_schedule_read_resume(client_conn);
        }
        return NGX_OK;
    }

    if (conf->proxy.upstreams != NULL && conf->proxy.upstreams->nelts > 0) {
        brix_proxy_upstream_t *ups = conf->proxy.upstreams->elts;

        if (pc_pick_healthy_upstream(conf, &idx) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                          "xrootd proxy: all %ui upstream(s) down — "
                          "failing request",
                          (ngx_uint_t) conf->proxy.upstreams->nelts);
            return NGX_ERROR;
        }

        tgt->host = &ups[idx].host;
        tgt->port = (ngx_int_t) ups[idx].port;
        proxy->upstream_idx = (int) idx;
    } else {
        tgt->host = &conf->proxy.host;
        tgt->port = conf->proxy.port;
        proxy->upstream_idx = -1;
    }

    return NGX_DECLINED;
}
