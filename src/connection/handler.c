#include "../ngx_xrootd_module.h"

/*
 * Stream-module connection entry point.
 *
 * Called by nginx once per accepted TCP connection, before any data is
 * exchanged.  Responsibilities:
 *
 *   1. Allocate and zero-initialise the per-connection xrootd_ctx_t.
 *      Lifetime: c->pool — freed when the TCP connection closes.
 *      Do not cache pointers to ctx members beyond that lifetime.
 *
 *   2. Mark every file-handle slot as empty (fd = -1).
 *
 *   3. Generate a 16-byte session ID from time+pid+connection pointer+random.
 *      This is not a cryptographic secret; it is used as an opaque handle
 *      in kXR_bind and kXR_endsess.
 *
 *   4. Wire up the read/write event handlers and fire the first read.
 */

void
ngx_stream_xrootd_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    xrootd_ctx_t      *ctx;
    int                i;

    /* Pool allocation: ctx lives for the duration of the TCP connection. */
    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->state = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;

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

    /* Sentinel value: fd < 0 means the slot is free. */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
    }

    {
        /* Build a 16-byte opaque session ID. Not a CSPRNG value — just
         * unique enough to identify this connection within the process. */
        uint32_t parts[4];

        parts[0] = (uint32_t) ngx_time();
        parts[1] = (uint32_t) ngx_pid;
        parts[2] = (uint32_t) (uintptr_t) c;
        parts[3] = (uint32_t) ngx_random();
        ngx_memcpy(ctx->sessid, parts, XROOTD_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);

    {
        ngx_stream_xrootd_srv_conf_t *mconf;

        mconf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);
        if (mconf->metrics_slot >= 0 && ngx_xrootd_shm_zone != NULL
            && ngx_xrootd_shm_zone->data != NULL
            && ngx_xrootd_shm_zone->data != (void *) 1)
        {
            ngx_xrootd_metrics_t     *shm = ngx_xrootd_shm_zone->data;
            ngx_xrootd_srv_metrics_t *srv = &shm->servers[mconf->metrics_slot];

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
                            (u_char *) (mconf->auth == XROOTD_AUTH_GSI
                                        ? "gsi"
                                        : mconf->auth == XROOTD_AUTH_TOKEN
                                          ? "token"
                                          : mconf->auth == XROOTD_AUTH_SSS
                                            ? "sss" : "anon"),
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
                    xrootd_proxy_upstream_t *ups = mconf->proxy_upstreams->elts;
                    ngx_uint_t               nu  = mconf->proxy_upstreams->nelts;
                    ngx_uint_t               ui;

                    if (nu > XROOTD_PROXY_MAX_UPSTREAMS) {
                        nu = XROOTD_PROXY_MAX_UPSTREAMS;
                    }
                    for (ui = 0; ui < nu; ui++) {
                        ngx_snprintf(
                            (u_char *) srv->proxy.upstreams[ui].label,
                            XROOTD_PROXY_UPSTREAM_LABEL_LEN - 1,
                            "%V:%ui%Z",
                            &ups[ui].host, (ngx_uint_t) ups[ui].port);
                    }
                }
            }

            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    c->read->handler = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    ngx_stream_xrootd_recv(c->read);
}
