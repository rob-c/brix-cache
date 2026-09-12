/*
 * connect_upstream.c — upstream TCP connect, XRootD bootstrap buffer,
 * TLS handshake callback, and lazy-connect lifecycle.
 *
 * WHAT: Builds the 68-byte bootstrap payload (client hello + kXR_protocol
 *       + kXR_login), resolves the upstream through the brix DNS driver,
 *       creates a non-blocking socket, connects to an upstream XRootD server,
 *       optionally performs TLS, then transitions into the bootstrap-read
 *       state.
 *
 * WHY: The proxy lazily opens backend connections on the first post-login opcode
 *      rather than at client login. This avoids idle upstream sockets during
 *      periods of low traffic and lets per-request auth decisions determine
 *      whether a backend connection is worth keeping.
 *
 * HOW: brix_proxy_connect() selects an endpoint from pool/rr/single and starts
 *      an async brix_dns_resolve() under the server block's brix_resolver
 *      policy (phase-116: never getaddrinfo on the event loop).  The answer
 *      arrives inline for a literal or a cache hit, otherwise later on the
 *      event loop; either way pc_dns_done() creates the non-blocking socket,
 *      arms the write-event for the async connect, optionally performs TLS,
 *      builds the bootstrap buffer, then sets state to XRD_PX_BOOTSTRAP so
 *      read_handler parses responses.  A resolve that fails after
 *      brix_proxy_connect() returned goes through brix_proxy_abort() exactly
 *      like a failed async connect().
 */

#include "proxy_internal.h"
#include "net/dns/dns.h"

#include <sys/socket.h>

/* The bootstrap frame builder (brix_proxy_build_bootstrap) lives in
 * connect_upstream_bootstrap.c; the TLS handshake completion callback
 * (brix_proxy_tls_handshake_done) lives in connect_upstream_tls.c; endpoint
 * selection (brix_proxy_select_endpoint) in connect_upstream_select.c. All are
 * declared in proxy_internal.h. */

/* upstream connect phases */

/*
 * WHAT: Creates a non-blocking SOCK_STREAM socket for one resolved answer and
 *       records the answer's sockaddr in tgt->addr/addrlen.
 *
 * WHY: The resolver returns every family the policy allows; the first family
 *      this host can open a socket for is the one the async connect() uses.
 *
 * HOW: ngx_socket + ngx_nonblocking; returns the fd, or NGX_INVALID_FILE with
 *      nothing left open so the caller tries the next answer.
 */
static int
pc_socket_for(const brix_dns_addr_t *answer, brix_proxy_target_t *tgt)
{
    int  fd = ngx_socket(answer->ss.ss_family, SOCK_STREAM, 0);

    if (fd == (int) NGX_INVALID_FILE) {
        return fd;
    }
    if (ngx_nonblocking(fd) == NGX_ERROR) {
        ngx_close_socket(fd);
        return (int) NGX_INVALID_FILE;
    }
    ngx_memcpy(&tgt->addr, &answer->ss, answer->len);
    tgt->addrlen = answer->len;
    return fd;
}

static ngx_int_t pc_connect_resolved(brix_proxy_ctx_t *proxy);

/*
 * WHAT: Completion handler of the upstream resolve started by
 *       pc_start_resolve(); runs on the event loop, inline or later.
 *
 * WHY: brix_proxy_connect() must report an inline outcome to its caller
 *      (which relays a redirect or fails the request itself), while a later
 *      outcome has no caller left to report to and takes the same path as a
 *      failed async connect(): brix_proxy_abort().
 *
 * HOW: Clears dns_inflight FIRST so the cleanup that a failed socket phase
 *      triggers does not cancel a request that already completed, drives the
 *      socket phases, then routes the result by dns_inline.
 */
static void
pc_dns_done(brix_dns_req_t *req)
{
    brix_proxy_ctx_t  *proxy = req->data;
    ngx_int_t          rc;

    proxy->dns_inflight = 0;
    rc = pc_connect_resolved(proxy);
    if (proxy->dns_inline) {
        proxy->dns_rc = rc;
        return;
    }
    if (rc != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: upstream resolve failed");
    }
}

/*
 * WHAT: Starts resolving tgt->host:port through the brix DNS driver under the
 *       server block's policy (phase-116 I-DNS-1: nothing on the event loop
 *       calls getaddrinfo).
 *
 * WHY: Endpoint selection yields a host string; the async connect() needs a
 *      concrete address, and a name whose answer is not cached must not stall
 *      every other session on this worker while the resolver answers. AF
 *      selection is BRIX_AF_AUTO (every family) — the proxy does not
 *      constrain the upstream family.
 *
 * HOW: Fills proxy->dns_req (the name is borrowed from conf / the redirect /
 *      the pin, all of which outlive the request because cleanup cancels it)
 *      and calls brix_dns_resolve(). dns_inline is set across the call so a
 *      handler that runs before it returns stores its outcome in dns_rc
 *      instead of aborting; NGX_AGAIN in dns_rc afterwards means the answer
 *      is still in flight and the connect completes (or aborts) later.
 *      Returns NGX_OK (in flight or connected), else NGX_ERROR with nothing
 *      left open.
 */
static ngx_int_t
pc_start_resolve(brix_proxy_ctx_t *proxy, ngx_connection_t *client_conn,
                 ngx_stream_brix_srv_conf_t *conf, const brix_proxy_target_t *tgt)
{
    brix_dns_req_t  *req = &proxy->dns_req;

    brix_proxy_cleanup_dns(proxy);
    ngx_memzero(req, sizeof(*req));
    req->name     = *tgt->host;
    req->port     = (in_port_t) tgt->port;
    req->af       = BRIX_AF_AUTO;
    req->socktype = SOCK_STREAM;
    req->policy   = conf->common.dns.policy;
    req->log      = client_conn->log;
    req->handler  = pc_dns_done;
    req->data     = proxy;

    proxy->dns_rc       = NGX_AGAIN;
    proxy->dns_inflight = 1;
    proxy->dns_inline   = 1;

    if (brix_dns_resolve(req) != NGX_OK) {
        proxy->dns_inflight = 0;
        proxy->dns_inline   = 0;
        ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                      "xrootd proxy: cannot start resolving \"%V\"",
                      tgt->host);
        return NGX_ERROR;
    }
    proxy->dns_inline = 0;

    return proxy->dns_rc == NGX_AGAIN ? NGX_OK : proxy->dns_rc;
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

    uconn->pool = ngx_create_pool(BRIX_PROXY_POOL_SIZE, client_conn->log);
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
              brix_proxy_target_t *tgt)
{
    ngx_int_t rc;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, client_conn->log, 0,
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

/*
 * WHAT: Turns the finished resolve in proxy->dns_req into a non-blocking
 *       socket + chosen sockaddr and runs the socket phases (open + arm).
 *
 * WHY: The resolve completes on the event loop either inline or later; the
 *      socket phases are the same either way, so they live behind the
 *      completion handler rather than in brix_proxy_connect().
 *
 * HOW: A resolver failure logs the proxy's own message (nothing is open yet);
 *      the answers are tried in resolver order and the first family that
 *      yields a socket wins, none bumping the connect-error metrics. Then
 *      pc_open_socket + pc_arm_events as before (the latter cleans up on its
 *      own failures). Returns NGX_OK once the connect is in flight.
 */
static ngx_int_t
pc_connect_resolved(brix_proxy_ctx_t *proxy)
{
    brix_dns_req_t              *req = &proxy->dns_req;
    ngx_connection_t            *client_conn = proxy->client_conn;
    ngx_stream_brix_srv_conf_t  *conf = proxy->conf;
    ngx_connection_t            *uconn;
    brix_proxy_target_t                  tgt;
    ngx_uint_t                   i;

    ngx_memzero(&tgt, sizeof(tgt));
    tgt.host = &req->name;
    tgt.port = (ngx_int_t) req->port;
    tgt.fd   = (int) NGX_INVALID_FILE;

    if (req->rc != NGX_OK || req->naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                      "xrootd proxy: cannot resolve \"%V\": %s", &req->name,
                      req->error != NULL ? req->error : "no address");
        return NGX_ERROR;
    }

    for (i = 0; i < req->naddrs && tgt.fd == (int) NGX_INVALID_FILE; i++) {
        tgt.fd = pc_socket_for(&req->addrs[i], &tgt);
    }
    if (tgt.fd == (int) NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, client_conn->log, 0,
                      "xrootd proxy: no usable address for \"%V\"",
                      &req->name);
        BRIX_PROXY_METRIC_INC(proxy->client_ctx, upstream_connect_errors);
        BRIX_PROXY_UP_INC(proxy, upstream_connect_errors);
        return NGX_ERROR;
    }

    uconn = pc_open_socket(proxy, client_conn, conf, tgt.fd);
    if (uconn == NULL) {
        return NGX_ERROR;
    }

    return pc_arm_events(proxy, client_conn, conf, uconn, &tgt);
}

/* public: connect and start bootstrap */
ngx_int_t
brix_proxy_connect(brix_proxy_ctx_t *proxy,
                     ngx_connection_t   *client_conn,
                     ngx_stream_brix_srv_conf_t *conf)
{
    brix_proxy_target_t       tgt;
    ngx_int_t         rc;

    ngx_memzero(&tgt, sizeof(tgt));

    /* Select upstream: redirected host > pool > round-robin array > single host.
     * NGX_OK = a pooled connection was adopted (connect complete). */
    rc = brix_proxy_select_endpoint(proxy, client_conn, conf, &tgt);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* GSI delegation: log in to the upstream AS THE USER in a thread (the blocking
     * in-process GSI client), then hand the authenticated fd to the relay. */
    if (conf->proxy.auth == BRIX_PROXY_AUTH_GSI) {
        return brix_proxy_gsi_connect_async(proxy, conf, tgt.host,
                                              (uint16_t) tgt.port);
    }

    return pc_start_resolve(proxy, client_conn, conf, &tgt);
}
/*
 * WHAT: Selects an upstream endpoint, resolves it asynchronously, creates a
 *       non-blocking socket, connects asynchronously, optionally performs TLS,
 *       builds the bootstrap buffer, and transitions into the bootstrap-read
 *       state.
 *
 * WHY: The proxy lazily opens backend connections on the first post-login opcode
 *      rather than at client login. Endpoint selection follows priority:
 *      redirected host > pooled connection > round-robin healthy upstreams >
 *      single configured host. This avoids idle sockets and distributes load.
 *
 * HOW: Orchestrates the connect phases in sequence — brix_proxy_select_endpoint (which
 *      may short-circuit on a pooled connection), pc_start_resolve (async brix
 *      DNS under the server block's policy), then from pc_dns_done:
 *      pc_connect_resolved → pc_open_socket (connection + pool + bootstrap
 *      buffer) → pc_arm_events (async connect + optional TLS via pc_start_tls).
 *      GSI-delegated connects hand off to brix_proxy_gsi_connect_async before
 *      the resolve (its thread resolves under the same policy).
 */
