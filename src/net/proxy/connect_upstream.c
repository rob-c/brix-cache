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
 * HOW: brix_proxy_connect() selects an endpoint from pool/rr/single,
 *      resolves via getaddrinfo(), creates non-blocking socket, arms write-event
 *      for async connect, optionally performs TLS, builds bootstrap buffer,
 *      then sets state to XRD_PX_BOOTSTRAP so read_handler parses responses.
 */

#include "proxy_internal.h"
#include "protocols/root/connection/netconnect.h"   /* shared outbound resolve/connect helper */

#include <netdb.h>
#include <sys/socket.h>

/* bootstrap frame builder */
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
brix_proxy_build_bootstrap(u_char *buf, const char *username)
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
        xrdw_protocol_req_t    b = { .clientpv = kXR_PROTOCOLVERSION,
                                     .expect = 0x03 };
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_protocol);
        xrdw_protocol_req_pack(&b, ((ClientRequestHdr *) (void *) cursor)->body);
        cursor += sizeof(*r);
    }

    /* kXR_login */
    {
        ClientLoginRequest *r = (ClientLoginRequest *)(void *) cursor;
        xrdw_login_req_t     b = { .capver = kXR_ver005 };
        ngx_atomic_uint_t    seq = ngx_atomic_fetch_add(&proxy_upstream_seq, 1);

        b.pid = (int32_t) ((ngx_pid << 16) ^ (seq & 0xFFFF));
        if (username != NULL && username[0] != '\0') {
            size_t ulen = ngx_strlen(username);
            if (ulen > sizeof(b.username)) {
                ulen = sizeof(b.username);
            }
            ngx_memcpy(b.username, username, ulen);
        } else {
            b.username[0] = 'x';
            b.username[1] = 'r';
            b.username[2] = 'd';
        }

        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0; r->streamid[1] = 1;
        r->requestid    = htons(kXR_login);
        xrdw_login_req_pack(&b, ((ClientRequestHdr *) (void *) cursor)->body);
        cursor += sizeof(*r);
    }

    return (size_t)(cursor - buf);
}
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

/* TLS handshake callback */
#if (NGX_SSL)
void
brix_proxy_tls_handshake_done(ngx_connection_t *uconn)
{
    brix_proxy_ctx_t *proxy = uconn->data;
    brix_ctx_t       *ctx   = proxy->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        brix_proxy_cleanup(proxy);
        return;
    }

    if (!uconn->ssl->handshaked) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: upstream TLS handshake failed");
        return;
    }

    /* Restore normal event handlers and transition to bootstrap */
    uconn->read->handler  = brix_proxy_read_handler;
    uconn->write->handler = brix_proxy_write_handler;
    proxy->state    = XRD_PX_BOOTSTRAP;
    proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
    proxy->rhdr_pos = 0;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: upstream write after TLS failed");
        return;
    }

    if (proxy->wbuf_pos < proxy->wbuf_len) {
        if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
            BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
            BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
            brix_proxy_abort(proxy, "proxy: write arm after TLS failed");
        }
        return;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        BRIX_PROXY_METRIC_INC(ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_abort(proxy, "proxy: read arm after TLS failed");
    }
}
/*
 * WHAT: nginx SSL callback invoked after upstream TLS handshake completes.
 *       Restores normal read/write handlers, transitions state to BOOTSTRAP,
 *       flushes the bootstrap buffer, and arms both read and write events.
 *
 * WHY: TLS handshake runs asynchronously; when it finishes we must switch back
 *      from the SSL handler to brix_proxy_read_handler so the bootstrap
 *      response can be parsed. If the client session was destroyed during
 *      handshake we clean up immediately.
 *
 * HOW: Checks ctx validity and uconn->ssl->handshaked, increments error metrics
 *      on failure, restores read/write handlers, sets state to XRD_PX_BOOTSTRAP,
 *      calls brix_proxy_flush() to send bootstrap data, then arms write event
 *      if unsent bytes remain and read event for upstream response parsing.
 */

#endif /* NGX_SSL */

/* upstream connect phases */

/*
 * Chosen upstream target: host/port plus the resolved sockaddr that the
 * async connect() will use.  Purely a value carrier passed between the
 * endpoint-selection, resolve, and arm-events phases — it holds NO ngx_log_t
 * pointer, so it is safe to stack-allocate per connect (see the stale-handler
 * SIGSEGV postmortem: never park a c->log in a long-lived struct).
 */
typedef struct {
    ngx_str_t               *host;      /* borrowed: conf / redirect / ups elt */
    ngx_int_t                port;
    struct sockaddr_storage  addr;
    socklen_t                addrlen;
    int                      fd;        /* resolved socket for this target */
} pc_target_t;

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
static ngx_int_t
pc_select_endpoint(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
                   ngx_stream_brix_srv_conf_t *conf, pc_target_t *tgt)
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

/*
 * WHAT: Resolves tgt->host:port (AF policy) into a non-blocking socket fd and
 *       records the chosen sockaddr in tgt->addr/addrlen.
 *
 * WHY: Endpoint selection yields a host string; the async connect() needs a
 *      concrete socket and address. AF selection is BRIX_AF_AUTO (try every
 *      family) here — the proxy does not constrain the upstream family.
 *
 * HOW: Delegates to brix_resolve_connect_socket() and maps its status to the
 *      proxy's own log message (DNS failure vs no-usable-socket, the latter
 *      also bumping connect-error metrics). Stores the fd in tgt->fd and
 *      returns NGX_OK, or NGX_ERROR on failure (nothing left open).
 */
static ngx_int_t
pc_resolve_target(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
                  pc_target_t *tgt)
{
    brix_resolve_status_t rstatus = BRIX_RESOLVE_OK;

    tgt->fd = brix_resolve_connect_socket((const char *) tgt->host->data,
                                           (unsigned) tgt->port,
                                           BRIX_AF_AUTO,
                                           &tgt->addr, &tgt->addrlen,
                                           &rstatus);
    if (tgt->fd == (int) NGX_INVALID_FILE) {
        if (rstatus == BRIX_RESOLVE_ERR_DNS) {
            ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                          "xrootd proxy: cannot resolve \"%s\"",
                          tgt->host->data);
            return NGX_ERROR;
        }
        ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                      "xrootd proxy: no usable address for \"%s\"",
                      tgt->host->data);
        BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Resolves the upstream login username from the configured policy into
 *       user_out (a >= 9-byte buffer).
 *
 * WHY: The kXR_login bootstrap request carries a username; policy decides
 *      whether it passes through the client's login name, uses a fixed
 *      configured name, or stays anonymous (empty → "xrd" default downstream).
 *
 * HOW: Switches on conf->proxy.login_user; ngx_cpystrn truncates to the buffer
 *      size. Passthrough with no client username falls back to empty.
 */
static void
pc_resolve_login_user(brix_proxy_ctx_t *proxy,
                      ngx_stream_brix_srv_conf_t *conf, char *user_out)
{
    switch (conf->proxy.login_user) {
    case BRIX_PROXY_LOGIN_PASSTHROUGH:
        if (proxy->client_ctx != NULL
            && proxy->client_ctx->login.user[0] != '\0')
        {
            ngx_cpystrn((u_char *) user_out,
                        (u_char *) proxy->client_ctx->login.user, 9);
        } else {
            user_out[0] = '\0'; /* no client username → fall back to "xrd" */
        }
        break;
    case BRIX_PROXY_LOGIN_FIXED:
        ngx_cpystrn((u_char *) user_out,
                    (u_char *) conf->proxy.login_user_name, 9);
        break;
    default: /* BRIX_PROXY_LOGIN_ANONYMOUS */
        user_out[0] = '\0';
        break;
    }
}

/*
 * WHAT: Wraps a connected-ready fd in an nginx connection with its own pool,
 *       builds the bootstrap buffer, and wires up the proxy send/recv handlers.
 *
 * WHY: Every upstream connection needs a dedicated pool (for the bootstrap
 *      frames), the standard ngx send/recv vtable, and the proxy read/write
 *      handlers before connect() is armed.
 *
 * HOW: ngx_get_connection + ngx_create_pool + ngx_palloc for the 68-byte
 *      bootstrap; fills it via pc_resolve_login_user + brix_proxy_build_bootstrap;
 *      points proxy->wbuf at the pool-owned buffer (wbuf_owned=0). Returns the
 *      connection, or NULL after closing the fd / freeing partial state.
 */
static ngx_connection_t *
pc_open_socket(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
               ngx_stream_brix_srv_conf_t *conf, int fd)
{
    ngx_connection_t *uconn;
    u_char           *bsbuf;
    char              upstream_user[9] = { 0 };

    uconn = ngx_get_connection(fd, client_conn->log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uconn->pool = ngx_create_pool(512, client_conn->log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        return NULL;
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
        return NULL;
    }

    pc_resolve_login_user(proxy, conf, upstream_user);

    uconn->data                = proxy;
    uconn->recv                = ngx_recv;
    uconn->send                = ngx_send;
    uconn->recv_chain          = ngx_recv_chain;
    uconn->send_chain          = ngx_send_chain;
    uconn->log                 = client_conn->log;
    uconn->read->handler       = brix_proxy_read_handler;
    uconn->write->handler      = brix_proxy_write_handler;
    uconn->read->log           = client_conn->log;
    uconn->write->log          = client_conn->log;

    proxy->conn       = uconn;
    proxy->wbuf       = bsbuf;
    proxy->wbuf_len   = brix_proxy_build_bootstrap(bsbuf, upstream_user);
    proxy->wbuf_pos   = 0;
    proxy->wbuf_owned = 0;   /* Phase 39: bsbuf is pool-allocated — pool owns it */
    proxy->state      = XRD_PX_CONNECTING;

    return uconn;
}

#if (NGX_SSL)
/*
 * WHAT: Starts the upstream TLS handshake on an already-connected socket.
 *
 * WHY: On an immediate (rc==0) connect to a TLS upstream we begin the client
 *      TLS handshake right away; the async callback finishes the bootstrap.
 *
 * HOW: ngx_ssl_create_connection + SNI (explicit name directive, else host) +
 *      ngx_ssl_handshake. NGX_AGAIN leaves the callback to continue; a synchronous
 *      completion invokes brix_proxy_tls_handshake_done() inline. Returns NGX_OK
 *      on success (connect continues via callback/inline), NGX_ERROR after
 *      cleanup on failure.
 */
static ngx_int_t
pc_start_tls(brix_proxy_ctx_t *proxy, ngx_stream_brix_srv_conf_t *conf,
             ngx_connection_t *uconn)
{
    const char *sni;

    if (ngx_ssl_create_connection(conf->proxy.tls_ctx, uconn,
                                  NGX_SSL_BUFFER | NGX_SSL_CLIENT)
        != NGX_OK)
    {
        BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_cleanup(proxy);
        return NGX_ERROR;
    }

    /* SNI: prefer explicit name directive, fall back to configured host */
    sni = (conf->proxy.upstream_tls_name.len > 0)
          ? (const char *) conf->proxy.upstream_tls_name.data
          : (const char *) conf->proxy.host.data;
    SSL_set_tlsext_host_name(uconn->ssl->connection, sni);

    uconn->ssl->handler = brix_proxy_tls_handshake_done;
    proxy->state = XRD_PX_TLS_HANDSHAKE;
    if (ngx_ssl_handshake(uconn) == NGX_AGAIN) {
        return NGX_OK; /* TLS callback will continue */
    }
    brix_proxy_tls_handshake_done(uconn);
    return NGX_OK;
}
#endif /* NGX_SSL */

/*
 * WHAT: Fires the async connect() on fd, arms the write event / connect timer,
 *       and — on an immediate connect — either starts TLS or flushes bootstrap.
 *
 * WHY: nginx drives outbound connects under the event loop: connect() returns
 *      EINPROGRESS and the write_handler completes it, unless the peer is local
 *      (rc==0) in which case we proceed to TLS or bootstrap flush immediately.
 *
 * HOW: connect() (EINPROGRESS is expected/OK), ngx_handle_write_event, optional
 *      connect timer; on rc==0 dispatches to pc_start_tls (TLS upstreams) or sets
 *      BOOTSTRAP state + brix_proxy_flush. Any failure cleans up. Returns NGX_OK
 *      or NGX_ERROR.
 */
static ngx_int_t
pc_arm_events(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
              ngx_stream_brix_srv_conf_t *conf, ngx_connection_t *uconn,
              pc_target_t *tgt)
{
    ngx_int_t rc;

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, client_conn->log, 0,
                  "xrootd proxy: connect() to %s:%d",
                  tgt->host->data, (int) tgt->port);

    rc = connect(tgt->fd, (struct sockaddr *)(void *) &tgt->addr,
                 tgt->addrlen);
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, client_conn->log, ngx_socket_errno,
                      "xrootd proxy: connect to %s:%d failed",
                      tgt->host->data, (int) tgt->port);
        BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_cleanup(proxy);
        return NGX_ERROR;
    }

    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        brix_proxy_cleanup(proxy);
        return NGX_ERROR;
    }

    /* Arm connect timeout: fires in write_handler as wev->timedout */
    if (rc == -1 && conf->proxy.connect_timeout > 0) {
        ngx_add_timer(uconn->write, conf->proxy.connect_timeout);
    }

    if (rc == 0) {
        /* Immediate connect (local loopback etc.) */
#if (NGX_SSL)
        if (conf->proxy.upstream_tls && conf->proxy.tls_ctx != NULL) {
            return pc_start_tls(proxy, conf, uconn);
        }
#endif
        proxy->state    = XRD_PX_BOOTSTRAP;
        proxy->bs_phase = XRD_PX_BS_HANDSHAKE;
        proxy->rhdr_pos = 0;

        if (brix_proxy_flush(proxy) == NGX_ERROR) {
            BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
            BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
            brix_proxy_cleanup(proxy);
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, client_conn->log, 0,
                   "xrootd proxy: connecting to %s:%d",
                   tgt->host->data, (int) tgt->port);
    return NGX_OK;
}

/* public: connect and start bootstrap */
ngx_int_t
brix_proxy_connect(brix_proxy_ctx_t *proxy,
                     ngx_connection_t   *client_conn,
                     ngx_stream_brix_srv_conf_t *conf)
{
    pc_target_t       tgt;
    ngx_connection_t *uconn;
    ngx_int_t         rc;

    ngx_memzero(&tgt, sizeof(tgt));

    /* Select upstream: redirected host > pool > round-robin array > single host.
     * NGX_OK = a pooled connection was adopted (connect complete). */
    rc = pc_select_endpoint(proxy, client_conn, conf, &tgt);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* GSI delegation: log in to the upstream AS THE USER in a thread (the blocking
     * in-process GSI client), then hand the authenticated fd to the relay. */
    if (conf->proxy.auth == BRIX_PROXY_AUTH_GSI) {
        return brix_proxy_gsi_connect_async(proxy, conf, tgt.host,
                                              (uint16_t) tgt.port);
    }

    if (pc_resolve_target(proxy, client_conn, &tgt) != NGX_OK) {
        return NGX_ERROR;
    }

    uconn = pc_open_socket(proxy, client_conn, conf, tgt.fd);
    if (uconn == NULL) {
        return NGX_ERROR;
    }

    return pc_arm_events(proxy, client_conn, conf, uconn, &tgt);
}
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
 * HOW: Orchestrates the connect phases in sequence — pc_select_endpoint (which
 *      may short-circuit on a pooled connection), pc_resolve_target (AF policy),
 *      pc_open_socket (connection + pool + bootstrap buffer), and pc_arm_events
 *      (async connect + optional TLS via pc_start_tls). GSI-delegated connects
 *      hand off to brix_proxy_gsi_connect_async before the socket phases.
 */

