#include "upstream_internal.h"

#include <string.h>

ngx_int_t
xrootd_upstream_send_request(xrootd_upstream_t *up)
{
    ngx_pool_t *pool = up->conn->pool;
    size_t      pathlen = strlen(up->req_path);
    size_t      hdrlen = XRD_REQUEST_HDR_LEN;
    size_t      total = hdrlen + pathlen;
    u_char     *buf;

    buf = ngx_palloc(pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(buf, total);

    switch (up->req_opcode) {

    case kXR_locate: {
        ClientLocateRequest *r = (ClientLocateRequest *) (void *) buf;

        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid = htons(kXR_locate);
        r->options = htons(up->req_options);
        r->dlen = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    case kXR_open: {
        ClientOpenRequest *r = (ClientOpenRequest *) (void *) buf;

        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid = htons(kXR_open);
        r->mode = htons(up->req_open_mode);
        r->options = htons(up->req_options);
        r->dlen = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    case kXR_stat: {
        ClientStatRequest *r = (ClientStatRequest *) (void *) buf;

        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid = htons(kXR_stat);
        r->dlen = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    default:
        ngx_log_error(NGX_LOG_ERR, up->client_conn->log, 0,
                      "xrootd: upstream: unsupported opcode %d",
                      (int) up->req_opcode);
        return NGX_ERROR;
    }

    up->wbuf = buf;
    up->wbuf_len = total;
    up->wbuf_pos = 0;

    up->rhdr_pos = 0;
    up->resp_dlen = 0;
    up->resp_body = NULL;
    up->resp_body_pos = 0;
    up->state = XRD_UP_REQUEST;

    return xrootd_upstream_flush(up);
}

ngx_int_t
xrootd_upstream_flush(xrootd_upstream_t *up)
{
    ngx_connection_t *uconn = up->conn;
    ssize_t           n;

    while (up->wbuf_pos < up->wbuf_len) {
        n = uconn->send(uconn, up->wbuf + up->wbuf_pos,
                        up->wbuf_len - up->wbuf_pos);
        if (n > 0) {
            up->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

