#include "upstream_internal.h"

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

    if (ctx->cur_reqid == kXR_locate) {
        ClientLocateRequest *lr;

        lr = (ClientLocateRequest *) (void *) ctx->hdr_buf;
        up->req_options = ntohs(lr->options);
    } else if (ctx->cur_reqid == kXR_open) {
        ClientOpenRequest *oreq;

        oreq = (ClientOpenRequest *) (void *) ctx->hdr_buf;
        up->req_options = ntohs(oreq->options);
        up->req_open_mode = ntohs(oreq->mode);
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
        /* fallback: resolve per-request (blocks event loop; logged as warning at startup) */
        struct addrinfo  hints_ai, *res_ai, *rp_ai;
        char             port_str[16];

        ngx_memzero(&hints_ai, sizeof(hints_ai));
        hints_ai.ai_socktype = SOCK_STREAM;
        hints_ai.ai_family   = AF_UNSPEC;
        snprintf(port_str, sizeof(port_str), "%u",
                 (unsigned) conf->upstream_port);

        if (getaddrinfo((char *) conf->upstream_host.data,
                        port_str, &hints_ai, &res_ai) != 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd: upstream: cannot resolve \"%s\"",
                          (char *) conf->upstream_host.data);
            xrootd_upstream_cleanup(up);
            return NGX_ERROR;
        }

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
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: upstream: no usable address for \"%s\"",
                      (char *) conf->upstream_host.data);
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

    uconn = ngx_get_connection(fd, c->log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }

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

    ctx->state = XRD_ST_UPSTREAM;

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

    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        xrootd_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

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

