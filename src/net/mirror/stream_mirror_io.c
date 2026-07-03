/*
 * stream_mirror_io.c — shared shadow-socket framing primitives.
 *
 * WHAT: Implements brix_mirror_io_flush() and brix_mirror_io_recv_frame(),
 *       the non-blocking write-drain and resumable response-frame reader shared
 *       by stream_mirror.c (reads) and stream_wmirror.c (writes). See the header
 *       for the contract.
 *
 * WHY:  These two routines were duplicated verbatim in both mirrors. The body
 *       length is attacker-supplied, so the single capped allocation here is the
 *       one place that bound is enforced.
 *
 * HOW:  Both operate on caller-supplied field pointers and the caller's
 *       connection; they re-arm the relevant nginx event on NGX_AGAIN and never
 *       touch the caller's dispatch/teardown state.
 */
#include "stream_mirror_io.h"

ngx_int_t
brix_mirror_io_flush(ngx_connection_t *c, const u_char *wbuf,
    size_t wbuf_len, size_t *wbuf_pos)
{
    ssize_t n;

    while (*wbuf_pos < wbuf_len) {
        n = c->send(c, (u_char *) wbuf + *wbuf_pos, wbuf_len - *wbuf_pos);
        if (n > 0) {
            *wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_mirror_io_recv_frame(ngx_connection_t *c, u_char *rhdr,
    size_t *rhdr_pos, uint16_t *resp_status, uint32_t *resp_dlen,
    u_char **resp_body, size_t *resp_body_pos)
{
    ssize_t n;

    if (*rhdr_pos < XRD_RESPONSE_HDR_LEN) {
        size_t need = XRD_RESPONSE_HDR_LEN - *rhdr_pos;
        n = c->recv(c, rhdr + *rhdr_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }
        *rhdr_pos += (size_t) n;
        if (*rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            return NGX_AGAIN;
        }
        /* Header fully buffered: latch status + body length (network order). */
        {
            ServerResponseHdr *h = (ServerResponseHdr *) (void *) rhdr;
            *resp_status = ntohs(h->status);
            *resp_dlen   = ntohl((uint32_t) h->dlen);
        }
        if (*resp_dlen > 0) {
            if (*resp_dlen > BRIX_MIRROR_MAX_RESP_BODY) {
                return NGX_ERROR;
            }
            *resp_body = ngx_palloc(c->pool, *resp_dlen);
            if (*resp_body == NULL) { return NGX_ERROR; }
            *resp_body_pos = 0;
        }
    }

    while (*resp_body_pos < *resp_dlen) {
        size_t need = *resp_dlen - *resp_body_pos;
        n = c->recv(c, *resp_body + *resp_body_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }
        *resp_body_pos += (size_t) n;
    }
    return NGX_OK;
}
