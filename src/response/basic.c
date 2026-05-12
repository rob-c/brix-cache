#include "ngx_xrootd_module.h"

/*
 * Basic XRootD response framing helpers.
 *
 * All wire responses eventually go through xrootd_queue_response(), which
 * handles partial writes and EAGAIN buffering for the connection.
 */

void
xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out)
{
    out->streamid[0] = streamid[0];
    out->streamid[1] = streamid[1];
    out->status      = htons(status);
    out->dlen        = htonl(dlen);
}


ngx_int_t
xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen)
{
    size_t   total;
    u_char  *buf;

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, bodylen,
        (ServerResponseHdr *) buf);

    if (bodylen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, bodylen);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}


ngx_int_t
xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg)
{
    size_t    msglen, bodylen, total;
    uint32_t  ecode;
    u_char   *buf;

    /*
     * kXR_error bodies are [errnum:4B BE][errmsg:NUL-terminated text].
     * The trailing NUL matters because several clients treat the text as a C string.
     */
    msglen = strlen(msg) + 1;
    bodylen = sizeof(kXR_int32) + msglen;
    total = XRD_RESPONSE_HDR_LEN + bodylen;

    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_error, (uint32_t) bodylen,
        (ServerResponseHdr *) buf);

    ecode = htonl(errcode);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &ecode, sizeof(ecode));
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ecode), msg, msglen);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending error %d: %s", (int) errcode, msg);

    return xrootd_queue_response(ctx, c, buf, total);
}
