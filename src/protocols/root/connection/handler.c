#include "core/ngx_brix_module.h"
#include <netinet/tcp.h>   /* Phase 39: TCP_USER_TIMEOUT / TCP_KEEPIDLE etc. */
#include "netopt.h"        /* Phase 50: shared dead-peer setsockopt helper */
#include "protocols/root/relay/relay.h"   /* transparent pass-through relay engage */

void
ngx_stream_brix_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    brix_ctx_t      *ctx;
    int                i;

    /* Pool allocation: ctx lives for the duration of the TCP connection. */
    ctx = ngx_pcalloc(c->pool, sizeof(brix_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->state = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;
    ctx->identity = brix_identity_alloc(c->pool);
    if (ctx->identity == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Protocol label and IP version — detected at connection time, immutable. */
    ngx_memcpy(ctx->protocol_label, "root", sizeof("root"));  /* "root\0" */
    if (c->sockaddr) {
        switch (c->sockaddr->sa_family) {
        case AF_INET6:
            ctx->ip_version = AF_INET6;
            break;
        default:
            ctx->ip_version = AF_INET;
            break;
        }
    } else {
        ctx->ip_version = 0; /* unknown */
    }
    if (c->addr_text.len > 0) {
        size_t n = c->addr_text.len;
        if (n >= sizeof(ctx->peer_ip)) {
            n = sizeof(ctx->peer_ip) - 1;
        }
        ngx_memcpy(ctx->peer_ip, c->addr_text.data, n);
        ctx->peer_ip[n] = '\0';
    }

    /* Sentinel value: fd < 0 means the slot is free. */
    for (i = 0; i < BRIX_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
        ctx->files[i].shared_handle_slot_hint = -1;  /* Phase 33 C2: no cache yet */
    }

    {
        /* Build a 16-byte opaque session ID. Not a CSPRNG value — just
         * unique enough to identify this connection within the process. */
        uint32_t parts[4];

        parts[0] = (uint32_t) ngx_time();
        parts[1] = (uint32_t) ngx_pid;
        parts[2] = (uint32_t) (uintptr_t) c;
        parts[3] = (uint32_t) ngx_random();
        ngx_memcpy(ctx->sessid, parts, BRIX_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_brix_module);

    {
        ngx_stream_brix_srv_conf_t *mconf;

        mconf = ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);

        /* Phase 39: cache the merged network-fault deadlines so the hot
         * recv/park paths never do a srv_conf lookup.  All default 0 = off. */
        ctx->read_timeout_ms      = mconf->read_timeout;
        ctx->handshake_timeout_ms = mconf->handshake_timeout;
        ctx->send_timeout_ms      = mconf->send_timeout;

        /*
         * Allocate the per-connection pipeline rings sized to the configured
         * depth (brix_pipeline_depth; merge-clamped to [MIN,MAX]).  A deeper
         * window absorbs more wire latency/jitter — a momentarily-slow drain no
         * longer empties the in-flight window and stalls the recv->send loop.
         * ctx->pipeline_depth is set LAST, so it stays 0 (and the teardown loops
         * that iterate to pipeline_depth are no-ops) until both rings exist.
         */
        {
            ngx_uint_t depth = mconf->pipeline_depth;

            ctx->out_ring = ngx_pcalloc(c->pool,
                                        depth * sizeof(brix_resp_slot_t));
            ctx->rd_pool  = ngx_pcalloc(c->pool,
                                        depth * sizeof(brix_read_slot_t));
            if (ctx->out_ring == NULL || ctx->rd_pool == NULL) {
                ngx_stream_finalize_session(s,
                    NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }
            ctx->pipeline_depth = depth;
        }

        /*
         * Phase 39 (WS3): OS-level dead-peer reaping, applied once at accept on
         * the control path.  Both default off (leave the kernel defaults), so a
         * stock deployment is byte-for-byte unchanged.  setsockopt failures are
         * deliberately non-fatal — a missing option must never abort a connection.
         */
        brix_apply_tcp_deadpeer_opts(c->fd, mconf->tcp_keepalive,
                                       mconf->tcp_user_timeout);

        /* Per-socket congestion control (e.g. "bbr"); empty = kernel default.
         * Best-effort — a missing algorithm leaves the default, never aborts. */
        brix_apply_tcp_congestion(c->fd, mconf->tcp_congestion);

        if (mconf->metrics_slot >= 0 && ngx_brix_shm_zone != NULL
            && ngx_brix_shm_zone->data != NULL
            && ngx_brix_shm_zone->data != (void *) 1)
        {
            ngx_brix_metrics_t     *shm = ngx_brix_shm_zone->data;
            ngx_brix_srv_metrics_t *srv = &shm->servers[mconf->metrics_slot];

            ctx->metrics = srv;

            srv->cache_enabled = mconf->cache ? 1 : 0;
            srv->cache_eviction_threshold = mconf->cache_eviction_threshold;
            if (mconf->cache && mconf->cache_root.len < sizeof(srv->cache_root)) {
                ngx_memcpy(srv->cache_root, mconf->cache_root.data,
                           mconf->cache_root.len);
                srv->cache_root[mconf->cache_root.len] = '\0';
            } else {
                srv->cache_root[0] = '\0';
            }

            if (!srv->in_use) {
                srv->in_use = 1;
                ngx_cpystrn((u_char *) srv->auth,
                            (u_char *) (mconf->auth == BRIX_AUTH_GSI
                                        ? "gsi"
                                        : mconf->auth == BRIX_AUTH_TOKEN
                                          ? "token"
                                          : mconf->auth == BRIX_AUTH_SSS
                                            ? "sss"
                                            : mconf->auth == BRIX_AUTH_UNIX
                                              ? "unix"
                                              : mconf->auth == BRIX_AUTH_KRB5
                                                ? "krb5" : "anon"),
                            sizeof(srv->auth));

                if (c->local_sockaddr) {
                    sa_family_t fam = c->local_sockaddr->sa_family;

                    if (fam == AF_INET) {
                        struct sockaddr_in *sin =
                            (struct sockaddr_in *) c->local_sockaddr;
                        srv->port = ntohs(sin->sin_port);

                    } else if (fam == AF_INET6) {
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *) c->local_sockaddr;
                        srv->port = ntohs(sin6->sin6_port);
                    }
                }

                /* Write per-upstream labels once (idempotent at first use). */
                if (mconf->proxy_upstreams != NULL) {
                    brix_proxy_upstream_t *ups = mconf->proxy_upstreams->elts;
                    ngx_uint_t               nu  = mconf->proxy_upstreams->nelts;
                    ngx_uint_t               ui;

                    if (nu > BRIX_PROXY_MAX_UPSTREAMS) {
                        nu = BRIX_PROXY_MAX_UPSTREAMS;
                    }
                    for (ui = 0; ui < nu; ui++) {
                        ngx_snprintf(
                            (u_char *) srv->proxy.upstreams[ui].label,
                            BRIX_PROXY_UPSTREAM_LABEL_LEN - 1,
                            "%V:%ui%Z",
                            &ups[ui].host, (ngx_uint_t) ups[ui].port);
                    }
                }
            }

            /*
             * Phase 39 (WS9): pre-identity admission cap.  Once the listener's
             * active-connection gauge is at brix_max_connections, refuse with a
             * plain TCP close — there is no streamid pre-login for a framed
             * kXR_wait, and combined with brix_handshake_timeout this bounds a
             * half-open / reconnect-storm flood.  Checked BEFORE the active++ so
             * a refused connection never perturbs the gauge.  0 = unlimited.
             */
            if (mconf->max_connections > 0
                && (ngx_uint_t) ngx_atomic_fetch_add(&srv->connections_active, 0)
                   >= mconf->max_connections)
            {
                ngx_atomic_fetch_add(&srv->connections_rejected_total, 1);
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "xrootd: connection refused — listener at "
                              "brix_max_connections (%ui)",
                              mconf->max_connections);
                ngx_stream_finalize_session(s, NGX_STREAM_OK);
                return;
            }

            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    /*
     * Transparent relay: if brix_transparent_proxy is configured, this port
     * relays verbatim to an upstream XRootD server (tapping the cleartext frames)
     * instead of terminating the protocol locally. Engages before any frame is
     * read; the relay owns the connection from here.
     */
    {
        ngx_stream_brix_srv_conf_t *rconf =
            ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);

        if (rconf->relay_addr != NULL) {
            if (brix_relay_start(s, c, rconf) != NGX_OK) {
                ngx_stream_finalize_session(s,
                                            NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }
    }

    c->read->handler = ngx_stream_brix_recv;
    c->write->handler = ngx_stream_brix_send;

    ngx_stream_brix_recv(c->read);
}
