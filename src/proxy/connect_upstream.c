/*
 * connect_upstream.c — upstream TCP connect, XRootD bootstrap buffer,
 * TLS handshake callback, and lazy-connect lifecycle.
 *
 * WHAT: Builds the 68-byte bootstrap payload (client hello + kXR_protocol
 *       + kXR_login), resolves DNS, creates a non-blocking socket, connects
 *       to an upstream XRootD server, optionally performs TLS, then transitions
 *       into the bootstrap-read state.
 *
 * WHY: The proxy lazily opens backend connections on the first post-login opcode
 *      rather than at client login. This avoids idle upstream sockets during
 *      periods of low traffic and lets per-request auth decisions determine
 *      whether a backend connection is worth keeping.
 *
 * HOW: xrootd_proxy_connect() selects an endpoint from pool/rr/single,
 *      resolves via getaddrinfo(), creates non-blocking socket, arms write-event
 *      for async connect, optionally performs TLS, builds bootstrap buffer,
 *      then sets state to XRD_PX_BOOTSTRAP so read_handler parses responses.
 */

#include "proxy_internal.h"

#include <netdb.h>
#include <sys/socket.h>

/* ---- bootstrap frame builder -------------------------------------------- */

/*
 * Monotonically increasing counter mixed into the upstream login PID.
 * xrootd treats repeated logins from the same PID as session reconnects and
 * applies a backoff delay.  Using a unique virtual PID per upstream connection
 * prevents that stall.
 */
static ngx_atomic_t  proxy_upstream_seq;

/* Round-robin counter for multiple upstream endpoints. */
static ngx_atomic_t  proxy_upstream_rr;

/*
 * Builds the 68-byte bootstrap buffer:
 *   20  XRootD client hello
 *   24  kXR_protocol request
 *   24  kXR_login   request
 *
 * username: NUL-terminated string for kXR_login (max 8 chars).
 *           NULL or empty → default "xrd".
 */
static size_t
xrootd_proxy_build_bootstrap(u_char *buf, const char *username)
{
    u_char *cursor = buf;

    /* Client hello: 12 zero bytes + protocol version + ROOTD_PQ selector */
    ngx_memzero(cursor, 12);
    cursor += 12;
    {
        uint32_t v = htonl(4);
        ngx_memcpy(cursor, &v, 4); cursor += 4;
        v = htonl(ROOTD_PQ);
        ngx_memcpy(cursor, &v, 4); cursor += 4;
    }

    /* kXR_protocol */
    {
        ClientProtocolRequest *r = (ClientProtocolRequest *)(void *) cursor;
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_protocol);
        r->clientpv     = htonl(kXR_PROTOCOLVERSION);
        r->expect       = 0x03;
        cursor += sizeof(*r);
    }

    /* kXR_login */
    {
        ClientLoginRequest *r = (ClientLoginRequest *)(void *) cursor;
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_login);
        {
            ngx_atomic_uint_t seq = ngx_atomic_fetch_add(&proxy_upstream_seq, 1);
            r->pid = htonl((kXR_int32)((ngx_pid << 16) ^ (seq & 0xFFFF)));
        }
        if (username != NULL && username[0] != '\0') {
            size_t ulen = ngx_strlen(username);
            if (ulen > sizeof(r->username)) {
                ulen = sizeof(r->username);
            }
            ngx_memcpy(r->username, username, ulen);
        } else {
            r->username[0] = 'x';
            r->username[1] = 'r';
            r->username[2] = 'd';
        }
        r->capver       = kXR_ver005;
        cursor += sizeof(*r);
    }

    return (size_t)(cursor - buf);
}
/* ---- Function: xrootd_proxy_build_bootstrap() ---- */
/*
 * WHAT: Assembles a 68-byte bootstrap buffer containing three XRootD wire
 *       requests — client hello, kXR_protocol negotiation, and kXR_login.
 *
 * WHY: Every new upstream connection must send these three requests in sequence
 *      before the backend will accept further opcodes. The login PID is mixed
 *      with a monotonic counter to prevent xrootd from treating repeated logins
 *      as reconnects (which triggers backoff delay).
 *
 * HOW: Writes 12 zero bytes + protocol version + ROOTD_PQ selector, then fills
 *      ClientProtocolRequest and ClientLoginRequest structs via ngx_memzero
 *      followed by field assignment. Username defaults to "xrd" when NULL.
 */

/* ---- TLS handshake callback ----------------------------------------------- */

#if (NGX_SSL)
void
xrootd_proxy_tls_handshake_done(ngx_connection_t *uconn)
{
    xrootd_proxy_ctx_t *proxy = uconn->data;
    xrootd_ctx_t       *ctx   = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    if (!uconn->ssl->handshaked) {
        XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        xrootd_proxy_abort(proxy, "proxy: upstream TLS handshake failed");
        return;
    }

    /* Restore normal event handlers and transition to bootstrap */
    uconn->read->handler  = xrootd_proxy_read_handler;
    uconn->write->handler = xrootd_proxy_write_handler;
    proxy->state    = XRD_PX_BOOTSTRAP;
    proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
    proxy->rhdr_pos = 0;

    if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
        XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        xrootd_proxy_abort(proxy, "proxy: upstream write after TLS failed");
        return;
    }

    if (proxy->wbuf_pos < proxy->wbuf_len) {
        if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
            XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
            xrootd_proxy_abort(proxy, "proxy: write arm after TLS failed");
        }
        return;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        XROOTD_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        xrootd_proxy_abort(proxy, "proxy: read arm after TLS failed");
    }
}
/* ---- Function: xrootd_proxy_tls_handshake_done() ---- */
/*
 * WHAT: nginx SSL callback invoked after upstream TLS handshake completes.
 *       Restores normal read/write handlers, transitions state to BOOTSTRAP,
 *       flushes the bootstrap buffer, and arms both read and write events.
 *
 * WHY: TLS handshake runs asynchronously; when it finishes we must switch back
 *      from the SSL handler to xrootd_proxy_read_handler so the bootstrap
 *      response can be parsed. If the client session was destroyed during
 *      handshake we clean up immediately.
 *
 * HOW: Checks ctx validity and uconn->ssl->handshaked, increments error metrics
 *      on failure, restores read/write handlers, sets state to XRD_PX_BOOTSTRAP,
 *      calls xrootd_proxy_flush() to send bootstrap data, then arms write event
 *      if unsent bytes remain and read event for upstream response parsing.
 */

#endif /* NGX_SSL */

/* ---- public: connect and start bootstrap ---------------------------------- */

ngx_int_t
xrootd_proxy_connect(xrootd_proxy_ctx_t *proxy,
                     ngx_connection_t   *client_conn,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    struct sockaddr_storage  chosen_addr;
    socklen_t                chosen_addrlen;
    int                      fd;
    ngx_connection_t        *uconn;
    u_char                  *bsbuf;
    size_t                   bslen;
    ngx_int_t                rc;
    ngx_str_t               *use_host;
    ngx_int_t                use_port;
    int                      pooled_idx = -1;

    /* Select upstream: redirected host > pool > round-robin array > single host */
    if (proxy->redirect_host.len > 0) {
        use_host = &proxy->redirect_host;
        use_port = (ngx_int_t) proxy->redirect_port;
        /* upstream_idx stays what it was, or -1 if we started redirected */
    } else {
        uconn = xrootd_proxy_pool_get(proxy, conf, &pooled_idx);
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
                xrootd_proxy_dispatch_pending(proxy);
            } else {
                proxy->client_ctx->state = XRD_ST_REQ_HEADER;
                xrootd_schedule_read_resume(client_conn);
            }
            return NGX_OK;
        }

        if (conf->proxy_upstreams != NULL && conf->proxy_upstreams->nelts > 0) {
            xrootd_proxy_upstream_t *ups = conf->proxy_upstreams->elts;
            ngx_atomic_uint_t        idx, i;

            /* Select a healthy upstream.  If EVERY upstream is currently marked
             * down (and none has aged past the retry window) do NOT fall through
             * to a known-dead endpoint — fail the connect so the caller returns a
             * clean error instead of hammering a dead upstream in a tight loop. */
            int found = 0;
            idx = ngx_atomic_fetch_add(&proxy_upstream_rr, 1) % conf->proxy_upstreams->nelts;
            for (i = 0; i < conf->proxy_upstreams->nelts; i++) {
                ngx_uint_t cur = (idx + i) % conf->proxy_upstreams->nelts;
                if (!proxy_up_status[cur].down ||
                    ngx_time() - proxy_up_status[cur].checked >= XROOTD_PROXY_FAIL_TIMEOUT)
                {
                    idx = cur;
                    found = 1;
                    break;
                }
            }

            if (!found) {
                ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                              "xrootd proxy: all %ui upstream(s) down — "
                              "failing request",
                              (ngx_uint_t) conf->proxy_upstreams->nelts);
                return NGX_ERROR;
            }

            use_host = &ups[idx].host;
            use_port = (ngx_int_t) ups[idx].port;
            proxy->upstream_idx = (int) idx;
        } else {
            use_host = &conf->proxy_host;
            use_port = conf->proxy_port;
            proxy->upstream_idx = -1;
        }
    }

    {
        struct addrinfo  hints_ai, *res_ai, *rp_ai;
        char             port_str[16];

        ngx_memzero(&hints_ai, sizeof(hints_ai));
        hints_ai.ai_socktype = SOCK_STREAM;
        hints_ai.ai_family   = AF_UNSPEC;
        snprintf(port_str, sizeof(port_str), "%u", (unsigned) use_port);

        if (getaddrinfo((const char *) use_host->data,
                        port_str, &hints_ai, &res_ai) != 0) {
            ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                          "xrootd proxy: cannot resolve \"%s\"",
                          use_host->data);
            return NGX_ERROR;
        }

        fd = (int) NGX_INVALID_FILE;
        for (rp_ai = res_ai; rp_ai != NULL; rp_ai = rp_ai->ai_next) {
            fd = ngx_socket(rp_ai->ai_family, rp_ai->ai_socktype,
                            rp_ai->ai_protocol);
            if (fd == (int) NGX_INVALID_FILE) {
                continue;
            }
            if (ngx_nonblocking(fd) == NGX_ERROR) {
                ngx_close_socket(fd);
                fd = (int) NGX_INVALID_FILE;
                continue;
            }
            ngx_memcpy(&chosen_addr, rp_ai->ai_addr, rp_ai->ai_addrlen);
            chosen_addrlen = rp_ai->ai_addrlen;
            break;
        }
        freeaddrinfo(res_ai);
    }

    if (fd == (int) NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                      "xrootd proxy: no usable address for \"%s\"",
                      use_host->data);
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        return NGX_ERROR;
    }

    uconn = ngx_get_connection(fd, client_conn->log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    uconn->pool = ngx_create_pool(512, client_conn->log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    /* Build bootstrap buffer in the upstream connection pool */
    bsbuf = ngx_palloc(uconn->pool,
                       XRD_HANDSHAKE_LEN
                       + sizeof(ClientProtocolRequest)
                       + sizeof(ClientLoginRequest));
    if (bsbuf == NULL) {
        ngx_destroy_pool(uconn->pool);
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        return NGX_ERROR;
    }
    /* Resolve the upstream login username from the configured policy. */
    {
        char upstream_user[9];

        switch (conf->proxy_login_user) {
        case XROOTD_PROXY_LOGIN_PASSTHROUGH:
            if (proxy->client_ctx != NULL
                && proxy->client_ctx->login_user[0] != '\0')
            {
                ngx_cpystrn((u_char *) upstream_user,
                            (u_char *) proxy->client_ctx->login_user,
                            sizeof(upstream_user));
            } else {
                upstream_user[0] = '\0'; /* no client username → fall back to "xrd" */
            }
            break;
        case XROOTD_PROXY_LOGIN_FIXED:
            ngx_cpystrn((u_char *) upstream_user,
                        (u_char *) conf->proxy_login_user_name,
                        sizeof(upstream_user));
            break;
        default: /* XROOTD_PROXY_LOGIN_ANONYMOUS */
            upstream_user[0] = '\0';
            break;
        }

        bslen = xrootd_proxy_build_bootstrap(bsbuf, upstream_user);
    }

    uconn->data                = proxy;
    uconn->recv                = ngx_recv;
    uconn->send                = ngx_send;
    uconn->recv_chain          = ngx_recv_chain;
    uconn->send_chain          = ngx_send_chain;
    uconn->log                 = client_conn->log;
    uconn->read->handler       = xrootd_proxy_read_handler;
    uconn->write->handler      = xrootd_proxy_write_handler;
    uconn->read->log           = client_conn->log;
    uconn->write->log          = client_conn->log;

    proxy->conn       = uconn;
    proxy->wbuf       = bsbuf;
    proxy->wbuf_len   = bslen;
    proxy->wbuf_pos   = 0;
    proxy->wbuf_owned = 0;   /* Phase 39: bsbuf is pool-allocated — pool owns it */
    proxy->state      = XRD_PX_CONNECTING;

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, client_conn->log, 0,
                  "xrootd proxy: connect() to %s:%d",
                  use_host->data, (int) use_port);

    rc = connect(fd, (struct sockaddr *)(void *) &chosen_addr,
                 chosen_addrlen);
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, client_conn->log, ngx_socket_errno,
                      "xrootd proxy: connect to %s:%d failed",
                      use_host->data, (int) use_port);
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        xrootd_proxy_cleanup(proxy);
        return NGX_ERROR;
    }

    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
        xrootd_proxy_cleanup(proxy);
        return NGX_ERROR;
    }

    /* Arm connect timeout: fires in write_handler as wev->timedout */
    if (rc == -1 && conf->proxy_connect_timeout > 0) {
        ngx_add_timer(uconn->write, conf->proxy_connect_timeout);
    }

    if (rc == 0) {
        /* Immediate connect (local loopback etc.) */
#if (NGX_SSL)
        if (conf->proxy_upstream_tls && conf->proxy_tls_ctx != NULL) {
            if (ngx_ssl_create_connection(conf->proxy_tls_ctx, uconn,
                                          NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
            {
                XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
                XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
                xrootd_proxy_cleanup(proxy);
                return NGX_ERROR;
            }
            /* SNI: prefer explicit name directive, fall back to configured host */
            {
                const char *sni = (conf->proxy_upstream_tls_name.len > 0)
                                  ? (const char *) conf->proxy_upstream_tls_name.data
                                  : (const char *) conf->proxy_host.data;
                SSL_set_tlsext_host_name(uconn->ssl->connection, sni);
            }
            uconn->ssl->handler = xrootd_proxy_tls_handshake_done;
            proxy->state = XRD_PX_TLS_HANDSHAKE;
            if (ngx_ssl_handshake(uconn) == NGX_AGAIN) {
                return NGX_OK; /* TLS callback will continue */
            }
            xrootd_proxy_tls_handshake_done(uconn);
            return NGX_OK;
        }
#endif
        proxy->state    = XRD_PX_BOOTSTRAP;
        proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
        proxy->rhdr_pos = 0;

        if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
            XROOTD_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
            XROOTD_PROXY_UP_INC(proxy, upstream_connect_errors);
            xrootd_proxy_cleanup(proxy);
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, client_conn->log, 0,
                   "xrootd proxy: connecting to %s:%d",
                   use_host->data, (int) use_port);
    return NGX_OK;
}
/* ---- Function: xrootd_proxy_connect() ---- */
/*
 * WHAT: Selects an upstream endpoint, resolves DNS, creates a non-blocking
 *       socket, connects asynchronously, optionally performs TLS, builds the
 *       bootstrap buffer, and transitions into the bootstrap-read state.
 *
 * WHY: The proxy lazily opens backend connections on the first post-login opcode
 *      rather than at client login. Endpoint selection follows priority:
 *      redirected host > pooled connection > round-robin healthy upstreams >
 *      single configured host. This avoids idle sockets and distributes load.
 *
 * HOW: Selects endpoint from redirect/pool/rr/single, resolves via getaddrinfo()
 *      loop (tries each address until a socket succeeds), creates non-blocking
 *      socket with ngx_nonblocking(), arms write event for async connect,
 *      optionally performs TLS via ngx_ssl_create_connection + ngx_ssl_handshake,
 *      builds bootstrap buffer in upstream pool, sets proxy state to
 *      XRD_PX_CONNECTING or XRD_PX_BOOTSTRAP depending on TLS status.
 */

