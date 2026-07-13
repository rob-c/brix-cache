#include "upstream_internal.h"
#include "protocols/root/connection/netconnect.h"   /* shared outbound resolve/connect helper */

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
 * WHAT: Allocate the upstream context, link it to the client, and snapshot the
 *      in-flight opcode/streamid/path plus opcode-specific option fields.
 *      Returns NGX_OK once `up->req_*` is fully populated; NGX_ERROR (after cleanup
 *      where an `up` exists) on alloc failure, missing payload, or path extraction.
 * WHY: The socket is opened on the first post-login opcode, so the request that
 *      triggered it must be captured verbatim — it is replayed to the backend after
 *      bootstrap so the server's reply matches the client's request byte-for-byte.
 * HOW: pcalloc the ctx from the client pool, link it both ways, copy the streamid;
 *      extract the confined path from the payload; then, for locate/open only,
 *      unpack the wire header body (network byte order) to preserve options (and
 *      open's mode). *out_up is set once allocation succeeds so the caller can
 *      report failure without re-cleaning.
 */
static ngx_int_t
brix_upstream_start_snapshot_request(brix_ctx_t *ctx, ngx_connection_t *c,
                                     brix_upstream_t **out_up)
{
    brix_upstream_t *up;

    up = ngx_pcalloc(c->pool, sizeof(brix_upstream_t));
    if (up == NULL) {
        return NGX_ERROR;
    }

    up->client_ctx = ctx;
    up->client_conn = c;
    ctx->upstream = up;
    *out_up = up;

    /* Snapshot the opcode/streamid that triggered the open — these are replayed to the
     * backend verbatim after bootstrap so the server's reply matches the client's. */
    up->req_opcode = ctx->recv.cur_reqid;
    up->req_streamid[0] = ctx->recv.cur_streamid[0];
    up->req_streamid[1] = ctx->recv.cur_streamid[1];

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return NGX_ERROR;
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             up->req_path, sizeof(up->req_path), 1))
    {
        return NGX_ERROR;
    }

    /* Preserve opcode-specific request fields straight off the wire header (network
     * byte order) so the replayed request to the backend is byte-identical to the
     * client's. Only locate/open carry options we must reproduce; open also carries mode. */
    if (ctx->recv.cur_reqid == kXR_locate) {
        xrdw_locate_req_t lr;

        xrdw_locate_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &lr);
        up->req_options = lr.options;
    } else if (ctx->recv.cur_reqid == kXR_open) {
        xrdw_open_req_t oreq;

        xrdw_open_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &oreq);
        up->req_options = oreq.options;
        up->req_open_mode = oreq.mode;
    }

    return NGX_OK;
}

/*
 * WHAT: Produce a connectable, non-blocking upstream socket and the sockaddr to
 *      connect it to. Returns the fd (>=0) and fills *addr and *addrlen on success;
 *      returns NGX_INVALID_FILE and sets *dns_failed on a hard DNS error.
 * WHY: Two address-resolution paths must be tried in a fixed order without touching
 *      the event loop when avoidable — config pre-resolution first, per-request DNS
 *      only as a fallback — and the caller distinguishes "cannot resolve" from
 *      "no usable address" for logging.
 * HOW: Fast path uses conf->upstream_addr (resolved at config time): open a socket
 *      of the address family, set non-blocking, and copy the sockaddr. Fallback path
 *      calls brix_resolve_connect_socket (blocking getaddrinfo, first family that
 *      yields a non-blocking socket wins) and reports BRIX_RESOLVE_ERR_DNS via
 *      *dns_failed. *addrlen stays 0 only on the failure paths.
 */
static int
brix_upstream_start_resolve_socket(ngx_stream_brix_srv_conf_t *conf,
                                   struct sockaddr_storage *addr,
                                   socklen_t *addrlen, ngx_int_t *dns_failed)
{
    int fd;

    *dns_failed = 0;

    if (conf->upstream_addr != NULL) {
        /* fast path: address pre-resolved at config time — no DNS on event loop */
        struct sockaddr *sa = conf->upstream_addr->sockaddr;

        fd = ngx_socket(sa->sa_family, SOCK_STREAM, 0);
        if (fd != (int) NGX_INVALID_FILE) {
            if (ngx_nonblocking(fd) == NGX_ERROR) {
                ngx_close_socket(fd);
                fd = (int) NGX_INVALID_FILE;
            } else {
                ngx_memcpy(addr, sa, conf->upstream_addr->socklen);
                *addrlen = conf->upstream_addr->socklen;
            }
        }
        return fd;
    }

    /* fallback: resolve per-request (blocks event loop; logged as warning at startup).
     * The first family yielding a non-blocking socket wins; a no-usable-socket
     * result falls through to the shared `fd == INVALID` check in the caller. */
    brix_resolve_status_t rstatus;

    fd = brix_resolve_connect_socket((char *) conf->upstream_host.data,
                                       (unsigned) conf->upstream_port,
                                       BRIX_AF_AUTO,
                                       addr, addrlen, &rstatus);
    if (fd == (int) NGX_INVALID_FILE && rstatus == BRIX_RESOLVE_ERR_DNS) {
        *dns_failed = 1;
    }
    return fd;
}

/*
 * WHAT: Wrap a connected-to-be socket fd in an nginx connection with its own pool
 *      and the upstream read/write handlers armed. Returns the connection, or NULL
 *      (after closing the fd and any half-built connection) on failure.
 * WHY: The raw fd must participate in the event loop; from the moment ngx_get_connection
 *      succeeds, teardown must also ngx_free_connection — this helper keeps that
 *      ordering in one place so its failure paths never leak.
 * HOW: ngx_get_connection, then create a small per-connection pool (response bodies
 *      and TLS scratch live here so they are reclaimed with the connection), then wire
 *      the recv/send vtable, log, and read/write handlers. On any failure the fd (and
 *      connection, if obtained) are released before returning NULL.
 */
static ngx_connection_t *
brix_upstream_start_wrap_conn(int fd, brix_upstream_t *up, ngx_log_t *log)
{
    ngx_connection_t *uconn;

    /* Wrap the raw fd in an nginx connection so it participates in the event loop.
     * From here failures must ngx_free_connection() in addition to closing the socket. */
    uconn = ngx_get_connection(fd, log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    /* Per-connection pool: response bodies and TLS scratch are allocated here so they
     * are reclaimed when the upstream connection is destroyed. */
    uconn->pool = ngx_create_pool(512, log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        return NULL;
    }

    uconn->data = up;
    uconn->recv = ngx_recv;
    uconn->send = ngx_send;
    uconn->recv_chain = ngx_recv_chain;
    uconn->send_chain = ngx_send_chain;
    uconn->log = log;
    uconn->read->handler = brix_upstream_read_handler;
    uconn->write->handler = brix_upstream_write_handler;
    uconn->read->log = log;
    uconn->write->log = log;

    return uconn;
}

/*
 * WHAT: Build the three-message bootstrap into the upstream connection's pool and
 *      install it as the write buffer. Returns NGX_OK, or NGX_ERROR on alloc failure.
 * WHY: The opening handshake + protocol + login bytes are sent before any client
 *      opcode is replayed; staging them as a single wbuf lets the flush loop drain
 *      them across partial writes with wbuf_pos as the cursor.
 * HOW: Size for the fixed handshake plus one ClientProtocolRequest and one
 *      ClientLoginRequest, palloc from uconn->pool, serialize via
 *      brix_upstream_build_bootstrap, then point up->wbuf at it with pos = 0.
 */
static ngx_int_t
brix_upstream_start_build_wbuf(brix_upstream_t *up, ngx_connection_t *uconn)
{
    size_t   bslen;
    u_char  *bsbuf;

    /* Build the bootstrap write buffer: the three opening wire messages concatenated in
     * send order — handshake (fixed-size zero/init bytes) + protocol request + login
     * request. This is sent before any client opcode is replayed. wbuf_pos tracks how
     * much has drained across partial writes. */
    bslen = XRD_HANDSHAKE_LEN
            + sizeof(ClientProtocolRequest)
            + sizeof(ClientLoginRequest);
    bsbuf = ngx_palloc(uconn->pool, bslen);
    if (bsbuf == NULL) {
        return NGX_ERROR;
    }
    brix_upstream_build_bootstrap(bsbuf);
    up->wbuf = bsbuf;
    up->wbuf_len = bslen;
    up->wbuf_pos = 0;

    return NGX_OK;
}

/*
 * WHAT: Kick off the non-blocking connect, arm the write event, and — on an immediate
 *      local connect — start the bootstrap by flushing it. Returns NGX_OK once the
 *      connect is armed/initiated; NGX_ERROR on connect, event-arm, or flush failure.
 * WHY: This is the final commit step; every failure here must roll the client session
 *      state back to REQ_HEADER so the client can retry, which the caller does on the
 *      NGX_ERROR return.
 * HOW: connect() — EINPROGRESS is the normal async case (write handler finishes via
 *      SO_ERROR), rc==0 is an immediate connect, anything else is a hard fail.
 *      ngx_handle_write_event arms the write side in both good cases. For rc==0 only,
 *      advance to BOOTSTRAP/HANDSHAKE, reset the response accumulator, and flush.
 *      The socket fd is taken from uconn->fd (set by ngx_get_connection).
 */
static ngx_int_t
brix_upstream_start_connect(brix_upstream_t *up, ngx_connection_t *uconn,
                            ngx_stream_brix_srv_conf_t *conf,
                            const struct sockaddr_storage *addr,
                            socklen_t addrlen)
{
    ngx_int_t rc;

    /* Non-blocking connect: EINPROGRESS is the normal async case (write handler finishes
     * it via SO_ERROR); rc==0 is an immediate local connect; anything else is a hard fail. */
    rc = connect(uconn->fd, (const struct sockaddr *)(const void *) addr, addrlen);
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, uconn->log, ngx_socket_errno,
                      "brix: upstream connect to %s:%d failed",
                      (char *) conf->upstream_host.data,
                      (int) conf->upstream_port);
        return NGX_ERROR;
    }

    /* Arm the write event in both cases: EINPROGRESS needs it to learn of connect
     * completion; rc==0 needs it to drain any bootstrap bytes that block on this write. */
    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Immediate connect: skip the CONNECTING wait and start bootstrap now — advance to
     * BOOTSTRAP/HANDSHAKE, reset the response-header accumulator, and flush bootstrap. */
    if (rc == 0) {
        up->state = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;

        if (brix_upstream_flush(up) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

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
brix_upstream_start(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf)
{
    brix_upstream_t         *up = NULL;
    ngx_connection_t        *uconn;
    int                      fd;
    struct sockaddr_storage  chosen_addr;
    socklen_t                chosen_addrlen = 0;   /* set whenever fd is valid;
                                                      0 only on the (rejected)
                                                      fd==INVALID paths */
    ngx_int_t                dns_failed;

    if (brix_upstream_start_snapshot_request(ctx, c, &up) != NGX_OK) {
        if (up != NULL) {
            brix_upstream_cleanup(up);
        }
        return NGX_ERROR;
    }

    fd = brix_upstream_start_resolve_socket(conf, &chosen_addr,
                                            &chosen_addrlen, &dns_failed);
    if (dns_failed) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: upstream: cannot resolve \"%s\"",
                      (char *) conf->upstream_host.data);
        brix_upstream_cleanup(up);
        return NGX_ERROR;
    }

    if (fd == (int) NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: upstream: no usable address for \"%s\"",
                      (char *) conf->upstream_host.data);
        brix_upstream_cleanup(up);
        return NGX_ERROR;
    }

    uconn = brix_upstream_start_wrap_conn(fd, up, c->log);
    if (uconn == NULL) {
        brix_upstream_cleanup(up);
        return NGX_ERROR;
    }

    up->conn = uconn;
    up->state = XRD_UP_CONNECTING;

    if (brix_upstream_start_build_wbuf(up, uconn) != NGX_OK) {
        brix_upstream_cleanup(up);
        return NGX_ERROR;
    }

    /* Mark the client session as proxied; client-side reads now route to upstream. */
    ctx->state = XRD_ST_UPSTREAM;

    if (brix_upstream_start_connect(up, uconn, conf,
                                    &chosen_addr, chosen_addrlen) != NGX_OK)
    {
        brix_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: upstream connecting to %s:%d",
                   (char *) conf->upstream_host.data,
                   (int) conf->upstream_port);

    return NGX_OK;
}

