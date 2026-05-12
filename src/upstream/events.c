#include "upstream_internal.h"

#include <sys/socket.h>

void
xrootd_upstream_wait_timer_handler(ngx_event_t *ev)
{
    xrootd_upstream_t *up = ev->data;
    xrootd_ctx_t      *ctx = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, up->client_conn->log, 0,
                  "xrootd: upstream kXR_wait expired; retrying");

    if (xrootd_upstream_send_request(up) != NGX_OK && up->conn != NULL) {
        xrootd_upstream_abort(up, "upstream retry failed");
    }
}

void
xrootd_upstream_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *uconn = wev->data;
    xrootd_upstream_t *up = uconn->data;
    xrootd_ctx_t      *ctx = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (wev->timedout) {
        xrootd_upstream_abort(up, "upstream connect/write timeout");
        return;
    }

    if (up->state == XRD_UP_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err)
        {
            ngx_log_error(NGX_LOG_ERR, up->client_conn->log,
                          err ? err : ngx_socket_errno,
                          "xrootd: upstream TCP connect failed");
            xrootd_upstream_abort(up, "upstream TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "xrootd: upstream TCP connected");

        up->state = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;
    }

    if (up->wbuf_pos < up->wbuf_len) {
        ngx_int_t rc = xrootd_upstream_flush(up);

        if (rc == NGX_ERROR) {
            xrootd_upstream_abort(up, "upstream write error");
        }
        return;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream read arm failed in write handler");
    }
}

void
xrootd_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *uconn = rev->data;
    xrootd_upstream_t *up = uconn->data;
    xrootd_ctx_t      *ctx = up->client_ctx;
    ssize_t            n;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (rev->timedout) {
        xrootd_upstream_abort(up, "upstream read timeout");
        return;
    }

    for (;;) {
        if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            size_t need = XRD_RESPONSE_HDR_LEN - up->rhdr_pos;

            n = uconn->recv(uconn, up->rhdr + up->rhdr_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up, "upstream read arm failed (hdr)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed");
                return;
            }

            up->rhdr_pos += (size_t) n;
            if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
                continue;
            }

            {
                ServerResponseHdr *hdr;

                hdr = (ServerResponseHdr *) (void *) up->rhdr;
                up->resp_status = ntohs(hdr->status);
                up->resp_dlen = ntohl(hdr->dlen);
            }

            if (up->resp_dlen > 0) {
                if (up->resp_dlen > XROOTD_MAX_PATH + 256) {
                    xrootd_upstream_abort(up,
                                          "upstream response body too large");
                    return;
                }
                up->resp_body = ngx_palloc(uconn->pool, up->resp_dlen + 1);
                if (up->resp_body == NULL) {
                    xrootd_upstream_abort(up, "upstream pool alloc failed");
                    return;
                }
                up->resp_body[up->resp_dlen] = '\0';
                up->resp_body_pos = 0;
            }
        }

        if (up->resp_body_pos < up->resp_dlen) {
            size_t need = up->resp_dlen - up->resp_body_pos;

            n = uconn->recv(uconn, up->resp_body + up->resp_body_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up,
                                          "upstream read arm failed (body)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed (body)");
                return;
            }

            up->resp_body_pos += (size_t) n;
            if (up->resp_body_pos < up->resp_dlen) {
                continue;
            }
        }

        if (up->state == XRD_UP_BOOTSTRAP) {
            xrootd_upstream_handle_bootstrap_response(up);
            return;
        }

        if (up->state == XRD_UP_REQUEST || up->state == XRD_UP_ASYNC) {
            xrootd_upstream_forward_response(up);
            return;
        }

        xrootd_upstream_abort(up, "upstream: unexpected state in read handler");
        return;
    }
}

