#include "upstream_internal.h"
#include "../connection/netconnect.h"   /* shared outbound resolve/connect helper */

/*
 * WHAT: Start an upstream XRootD connection — context allocation, DNS/TCP setup, bootstrap buffer build,
 *      and connect initiation for transparent proxy mode.
 * WHY: When a client connects in proxy mode, nginx must lazily open a backend XRootD server connection
 *      on the first post-login opcode. This file owns that startup sequence: allocating upstream context,
 *      resolving the upstream address (pre-configured or per-request DNS), creating a non-blocking socket,
 *      arming event handlers, and building the initial handshake/protocol/login bootstrap bytes.
 * HOW: Two-path address resolution — fast path uses pre-resolved sockaddr from config (no DNS on event loop);
 *      fallback path calls getaddrinfo() per-request with warning logged at startup. Non-blocking socket +
 *      ngx_get_connection + pool setup + read/write handler assignment + timer for kXR_wait retry. Bootstrap
 *      buffer contains handshake zeros, protocol request, and login request concatenated in wire order.
 */

#include <netdb.h>
#include <sys/socket.h>

/*
 * WHAT: Lazily open the backend XRootD connection for the in-flight client opcode and
 *      kick off the async connect. Returns NGX_OK once the connect is armed/initiated;
 *      NGX_ERROR (after cleanup) on any setup failure.
 * WHY: In proxy mode the upstream socket is created on demand at the first post-login
 *      opcode, so this captures the opcode/streamid/path/options that triggered it —
 *      they must be replayed to the backend once bootstrap completes.
 * HOW: alloc+link the upstream ctx, snapshot the request, resolve the address (config
 *      fast path or per-request DNS), create a non-blocking socket + nginx connection,
 *      build the handshake/protocol/login bootstrap into the write buffer, then connect().
 *      On EINPROGRESS the write handler finishes the connect; on immediate success (rc==0)
 *      we flush the bootstrap here. Any failure path rolls ctx->state back to REQ_HEADER.
 */
ngx_int_t
xrootd_upstream_start(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_upstream_t       *up;
    ngx_connection_t        *uconn;
    int                      fd;
    struct sockaddr_storage  chosen_addr;
    socklen_t                chosen_addrlen;
    ngx_int_t                rc;
    size_t                   bslen;
    u_char                  *bsbuf;

    up = ngx_pcalloc(c->pool, sizeof(xrootd_upstream_t));
    if (up == NULL) {
        return NGX_ERROR;
    }

    up->client_ctx = ctx;
    up->client_conn = c;
    ctx->upstream = up;

    /* Snapshot the opcode/streamid that triggered the open — these are replayed to the
     * backend verbatim after bootstrap so the server's reply matches the client's. */
    up->req_opcode = ctx->cur_reqid;
    up->req_streamid[0] = ctx->cur_streamid[0];
    up->req_streamid[1] = ctx->cur_streamid[1];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             up->req_path, sizeof(up->req_path), 1))
    {
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    /* Preserve opcode-specific request fields straight off the wire header (network
     * byte order) so the replayed request to the backend is byte-identical to the
     * client's. Only locate/open carry options we must reproduce; open also carries mode. */
    if (ctx->cur_reqid == kXR_locate) {
        xrdw_locate_req_t lr;

        xrdw_locate_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &lr);
        up->req_options = lr.options;
    } else if (ctx->cur_reqid == kXR_open) {
        xrdw_open_req_t oreq;

        xrdw_open_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &oreq);
        up->req_options = oreq.options;
        up->req_open_mode = oreq.mode;
    }

    fd = (int) NGX_INVALID_FILE;

    if (conf->upstream_addr != NULL) {
        /* fast path: address pre-resolved at config time — no DNS on event loop */
        struct sockaddr *sa = conf->upstream_addr->sockaddr;

        fd = ngx_socket(sa->sa_family, SOCK_STREAM, 0);
        if (fd != (int) NGX_INVALID_FILE) {
            if (ngx_nonblocking(fd) == NGX_ERROR) {
                ngx_close_socket(fd);
                fd = (int) NGX_INVALID_FILE;
            } else {
                ngx_memcpy(&chosen_addr, sa, conf->upstream_addr->socklen);
                chosen_addrlen = conf->upstream_addr->socklen;
            }
        }
    } else {
        /* fallback: resolve per-request (blocks event loop; logged as warning at startup).
         * The first family yielding a non-blocking socket wins; a no-usable-socket
         * result falls through to the shared `if (fd == INVALID)` check below. */
        xrootd_resolve_status_t rstatus;

        fd = xrootd_resolve_connect_socket((char *) conf->upstream_host.data,
                                           (unsigned) conf->upstream_port,
                                           &chosen_addr, &chosen_addrlen,
                                           &rstatus);
        if (fd == (int) NGX_INVALID_FILE
            && rstatus == XROOTD_RESOLVE_ERR_DNS)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd: upstream: cannot resolve \"%s\"",
                          (char *) conf->upstream_host.data);
            xrootd_upstream_cleanup(up);
            return NGX_ERROR;
        }
    }

    if (fd == (int) NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: upstream: no usable address for \"%s\"",
                      (char *) conf->upstream_host.data);
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    /* Wrap the raw fd in an nginx connection so it participates in the event loop.
     * From here failures must ngx_free_connection() in addition to closing the socket. */
    uconn = ngx_get_connection(fd, c->log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    /* Per-connection pool: response bodies and TLS scratch are allocated here so they
     * are reclaimed when the upstream connection is destroyed. */
    uconn->pool = ngx_create_pool(512, c->log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    uconn->data = up;
    uconn->recv = ngx_recv;
    uconn->send = ngx_send;
    uconn->recv_chain = ngx_recv_chain;
    uconn->send_chain = ngx_send_chain;
    uconn->log = c->log;
    uconn->read->handler = xrootd_upstream_read_handler;
    uconn->write->handler = xrootd_upstream_write_handler;
    uconn->read->log = c->log;
    uconn->write->log = c->log;

    up->conn = uconn;
    up->state = XRD_UP_CONNECTING;

    /* Build the bootstrap write buffer: the three opening wire messages concatenated in
     * send order — handshake (fixed-size zero/init bytes) + protocol request + login
     * request. This is sent before any client opcode is replayed. wbuf_pos tracks how
     * much has drained across partial writes. */
    bslen = XRD_HANDSHAKE_LEN
            + sizeof(ClientProtocolRequest)
            + sizeof(ClientLoginRequest);
    bsbuf = ngx_palloc(uconn->pool, bslen);
    if (bsbuf == NULL) {
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }
    xrootd_upstream_build_bootstrap(bsbuf);
    up->wbuf = bsbuf;
    up->wbuf_len = bslen;
    up->wbuf_pos = 0;

    /* Mark the client session as proxied; client-side reads now route to upstream. */
    ctx->state = XRD_ST_UPSTREAM;

    /* Non-blocking connect: EINPROGRESS is the normal async case (write handler finishes
     * it via SO_ERROR); rc==0 is an immediate local connect; anything else is a hard fail. */
    rc = connect(fd, (struct sockaddr *)(void *) &chosen_addr,
                 chosen_addrlen);
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "xrootd: upstream connect to %s:%d failed",
                      (char *) conf->upstream_host.data,
                      (int) conf->upstream_port);
        xrootd_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    /* Arm the write event in both cases: EINPROGRESS needs it to learn of connect
     * completion; rc==0 needs it to drain any bootstrap bytes that block on this write. */
    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        xrootd_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    /* Immediate connect: skip the CONNECTING wait and start bootstrap now — advance to
     * BOOTSTRAP/HANDSHAKE, reset the response-header accumulator, and flush bootstrap. */
    if (rc == 0) {
        ngx_int_t frc;

        up->state = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;

        frc = xrootd_upstream_flush(up);
        if (frc == NGX_ERROR) {
            xrootd_upstream_cleanup(up);
            ctx->state = XRD_ST_REQ_HEADER;
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: upstream connecting to %s:%d",
                   (char *) conf->upstream_host.data,
                   (int) conf->upstream_port);

    return NGX_OK;
}

