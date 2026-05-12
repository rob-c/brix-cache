#include "server.h"


static ngx_int_t
xrootd_cms_srv_send_all(xrootd_cms_srv_ctx_t *ctx, const u_char *buf,
    size_t len)
{
    ngx_connection_t  *c;
    ssize_t            n;
    size_t             sent;

    c = ctx->c;
    sent = 0;

    while (sent < len) {
        n = c->send(c, (u_char *) buf + sent, len - sent);

        if (n == NGX_AGAIN || n == 0) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        sent += (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
xrootd_cms_srv_send_frame(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    u_char  hdr[NGX_XROOTD_CMS_HDR_LEN];

    if (payload_len > 65535) {
        return NGX_ERROR;
    }

    ngx_xrootd_cms_put32(hdr, streamid);
    hdr[4] = code;
    hdr[5] = modifier;
    ngx_xrootd_cms_put16(hdr + 6, (uint16_t) payload_len);

    if (xrootd_cms_srv_send_all(ctx, hdr, sizeof(hdr)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (payload_len > 0
        && xrootd_cms_srv_send_all(ctx, payload, payload_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
xrootd_cms_srv_send_ping(xrootd_cms_srv_ctx_t *ctx)
{
    return xrootd_cms_srv_send_frame(ctx, 0, CMS_RR_PING, 0, NULL, 0);
}
