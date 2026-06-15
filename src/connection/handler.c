/* ------------------------------------------------------------------ */
/* Section: Connection Entry Point Initialization                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the nginx stream module connection handler that serves as the per-connection entry point for XRootD protocol processing. Called once per accepted TCP connection before any data exchange — performs four-phase initialization including ctx allocation, file-handle slot preparation, session ID generation, and event handler wiring. Also initializes metrics slot assignment (connections_active++) and auth method label on first use. */

/* ------------------------------------------------------------------ */
/* Section: Connection Handler Entry Point                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: ngx_stream_xrootd_handler() is the nginx stream module connection entry point called once per accepted TCP connection before any data exchange — performs four-phase initialization: (1) allocates and zero-initializes xrootd_ctx_t via ngx_pcalloc on c->pool lifetime; (2) marks all XROOTD_MAX_FILES file-handle slots as empty (fd=-1); (3) generates 16-byte opaque session ID from time+pid+c-pointer+random for kXR_bind/kXR_endsess identification; (4) wires up read/write event handlers and fires first recv loop. Also initializes protocol_label="root", ip_version detection, metrics slot assignment (connections_active++), and auth method label on first use. */

/* ---- Function: ngx_stream_xrootd_handler() ----
 *
 * WHAT: The nginx stream module connection entry point called once per accepted TCP connection before any data exchange — performs four-phase initialization: (1) allocates xrootd_ctx_t via ngx_pcalloc on c->pool lifetime; (2) marks all XROOTD_MAX_FILES file-handle slots as empty (fd=-1); (3) generates 16-byte opaque session ID from time+pid+c-pointer+random for kXR_bind/kXR_endsess identification; (4) wires up read/write event handlers and fires first recv loop. Also initializes protocol_label="root", ip_version detection, metrics slot assignment (connections_active++), auth method label on first use, cache configuration tracking per server metrics zone. Returns immediately if ctx allocation fails with NGX_STREAM_INTERNAL_SERVER_ERROR. */

/* ---- WHY: This handler is the critical entry point that transitions nginx from stream core default behavior to XRootD protocol processing — without it, incoming TCP connections would be processed as raw stream data rather than routed through XRootD session lifecycle (handshake → login → auth → read/write). Four-phase initialization ensures all resources are ready before any wire protocol exchange begins. Metrics slot assignment enables per-server tracking of connection counts and cache configuration across all worker processes using shared memory zones. ---- */

#include "../ngx_xrootd_module.h"
#include <netinet/tcp.h>   /* Phase 39: TCP_USER_TIMEOUT / TCP_KEEPIDLE etc. */

/* ---- ngx_stream_xrootd_handler — stream-module connection entry point (per-connection init) ----
 *
 * WHAT: Called by nginx once per accepted TCP connection before any data exchange. Performs four-phase initialization: (1) allocates and zero-initializes xrootd_ctx_t via ngx_pcalloc on c->pool lifetime; (2) marks all XROOTD_MAX_FILES file-handle slots as empty (fd=-1); (3) generates 16-byte opaque session ID from time+pid+c-pointer+random (not cryptographic, used for kXR_bind/kXR_endsess identification); (4) wires up read/write event handlers and fires first recv loop. Also initializes protocol_label="root", ip_version detection, metrics slot assignment (connections_active++), and auth method label on first use. */

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
    ctx->identity = xrootd_identity_alloc(c->pool);
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
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
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
        ngx_memcpy(ctx->sessid, parts, XROOTD_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);

    {
        ngx_stream_xrootd_srv_conf_t *mconf;

        mconf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

        /* Phase 39: cache the merged network-fault deadlines so the hot
         * recv/park paths never do a srv_conf lookup.  All default 0 = off. */
        ctx->read_timeout_ms      = mconf->read_timeout;
        ctx->handshake_timeout_ms = mconf->handshake_timeout;
        ctx->send_timeout_ms      = mconf->send_timeout;

        /*
         * Phase 39 (WS3): OS-level dead-peer reaping, applied once at accept on
         * the control path.  Both default off (leave the kernel defaults), so a
         * stock deployment is byte-for-byte unchanged.  setsockopt failures are
         * deliberately non-fatal — a missing option must never abort a connection.
         */
        if (mconf->tcp_keepalive) {
            int on = 1;
            (void) setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE,
                              (const void *) &on, sizeof(on));
#if defined(TCP_KEEPIDLE)
            { int v = 30;
              (void) setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPIDLE,
                                (const void *) &v, sizeof(v)); }
#endif
#if defined(TCP_KEEPINTVL)
            { int v = 10;
              (void) setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPINTVL,
                                (const void *) &v, sizeof(v)); }
#endif
#if defined(TCP_KEEPCNT)
            { int v = 3;
              (void) setsockopt(c->fd, IPPROTO_TCP, TCP_KEEPCNT,
                                (const void *) &v, sizeof(v)); }
#endif
        }
#if defined(TCP_USER_TIMEOUT)
        if (mconf->tcp_user_timeout > 0) {
            unsigned int ms = (unsigned int) mconf->tcp_user_timeout;
            (void) setsockopt(c->fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                              (const void *) &ms, sizeof(ms));
        }
#endif

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
                                            ? "sss"
                                            : mconf->auth == XROOTD_AUTH_UNIX
                                              ? "unix"
                                              : mconf->auth == XROOTD_AUTH_KRB5
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

            /*
             * Phase 39 (WS9): pre-identity admission cap.  Once the listener's
             * active-connection gauge is at xrootd_max_connections, refuse with a
             * plain TCP close — there is no streamid pre-login for a framed
             * kXR_wait, and combined with xrootd_handshake_timeout this bounds a
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
                              "xrootd_max_connections (%ui)",
                              mconf->max_connections);
                ngx_stream_finalize_session(s, NGX_STREAM_OK);
                return;
            }

            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    c->read->handler = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    ngx_stream_xrootd_recv(c->read);
}
/* ---- HOW: Allocates xrootd_ctx_t via ngx_pcalloc on c->pool lifetime — if NULL returns immediately with NGX_STREAM_INTERNAL_SERVER_ERROR. Sets ctx->session=s, state=XRD_ST_HANDSHAKE, hdr_pos=0. Copies "root" into protocol_label; detects ip_version from c->sockaddr (AF_INET6 or AF_INET); copies peer_ip from c->addr_text (bounded to sizeof(ctx->peer_ip)-1). Marks all XROOTD_MAX_FILES file-handle slots empty via fd=-1 loop. Builds 16-byte session ID from parts[0]=ngx_time(), parts[1]=ngx_pid, parts[2]=(uintptr_t)c, parts[3]=ngx_random() — memcpy into ctx->sessid. Sets ngx_stream_set_ctx(s,ctx,module). Retrieves mconf from srv_conf; if metrics_slot≥0 and shm_zone valid: sets ctx->metrics=srv; copies cache_enabled/eviction_threshold/cache_root into srv; on first use (srv->in_use==0): writes auth label (gsi/token/sss/anon), local port from sockaddr, proxy upstream labels into srv; increments connections_total+connections_active atomically. Arms c->read handler to ngx_stream_xrootd_recv and c->write handler to ngx_stream_xrootd_send — fires first recv loop via ngx_stream_xrootd_recv(c->read). */
