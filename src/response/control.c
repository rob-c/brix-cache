#include "ngx_xrootd_module.h"
#include "../compat/host_format.h"  /* xrootd_format_host — IPv6 bracketing */
#include "../compat/alloc_guard.h"

/*
 * Control-flow responses: redirects and asynchronous retry hints.
 */

ngx_int_t
xrootd_send_redirect(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port)
{
    size_t    hostlen;
    uint32_t  bodylen, pbe;
    size_t    total;
    u_char   *buf;
    char      hostbuf[288];

    /* Bracket an IPv6 literal host ("[::1]" not bare "::1") so the client does
     * not mis-read the colons; the port is a separate 4-byte field, so the host
     * string is host-only. IPv4/hostname/already-bracketed pass through. */
    hostlen = xrootd_format_host(host, hostbuf, sizeof(hostbuf));
    bodylen = (uint32_t) (sizeof(uint32_t) + hostlen);
    total = XRD_RESPONSE_HDR_LEN + bodylen;

    XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_redirect, bodylen,
        (ServerResponseHdr *) buf);

    pbe = htonl((uint32_t) port);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &pbe, sizeof(pbe));
    if (hostlen > 0) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(pbe), hostbuf, hostlen);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending redirect to %s:%d", host ? host : "", (int) port);

    return xrootd_queue_response(ctx, c, buf, total);
}

/*
 * xrootd_send_redirect_tpc — redirect with a TPC key appended as opaque.
 *
 * The redirect body is: [port: 4 bytes][host string][?tpc.key=<key>]
 * which the XRootD client parses as an opaque-qualified host.  Passing a
 * NULL or empty key falls back to a plain redirect (no opaque appended).
 */
ngx_int_t
xrootd_send_redirect_tpc(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port, const char *tpc_key)
{
    size_t    hostlen, opaquelen, bodylen, total;
    uint32_t  pbe;
    u_char   *buf, *p;
    char      opaque[160];
    char      hostbuf[288];

    if (tpc_key == NULL || tpc_key[0] == '\0') {
        return xrootd_send_redirect(ctx, c, host, port);
    }

    /* Bracket an IPv6 literal host before the [host][?tpc.key=…] body. */
    hostlen   = xrootd_format_host(host, hostbuf, sizeof(hostbuf));
    opaquelen = (size_t) snprintf(opaque, sizeof(opaque), "?tpc.key=%s", tpc_key);
    bodylen   = sizeof(uint32_t) + hostlen + opaquelen;
    total     = XRD_RESPONSE_HDR_LEN + bodylen;

    XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_redirect, (uint32_t) bodylen,
        (ServerResponseHdr *) buf);

    p   = buf + XRD_RESPONSE_HDR_LEN;
    pbe = htonl((uint32_t) port);
    ngx_memcpy(p, &pbe, sizeof(pbe));
    p += sizeof(pbe);

    if (hostlen > 0) {
        ngx_memcpy(p, hostbuf, hostlen);
        p += hostlen;
    }
    ngx_memcpy(p, opaque, opaquelen);

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending TPC redirect to %s:%d key=%s",
        host ? host : "", (int) port, tpc_key);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* Send kXR_wait telling the client to retry after `seconds` (backpressure /
 * staging). */
ngx_int_t
xrootd_send_wait(xrootd_ctx_t *ctx, ngx_connection_t *c, uint32_t seconds)
{
    size_t    total;
    uint32_t  sbe;
    u_char   *buf;

    total = XRD_RESPONSE_HDR_LEN + sizeof(uint32_t);
    buf = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_wait,
        (uint32_t) sizeof(uint32_t), (ServerResponseHdr *) buf);

    sbe = htonl(seconds);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &sbe, sizeof(sbe));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending kXR_wait %u seconds", (unsigned) seconds);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* Send kXR_waitresp asking the client to await an async response the server will
 * push later. */
ngx_int_t
xrootd_send_waitresp(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    u_char *buf;

    XROOTD_PALLOC_OR_RETURN(buf, c->pool, XRD_RESPONSE_HDR_LEN, NGX_ERROR);

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_waitresp, 0,
        (ServerResponseHdr *) buf);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending kXR_waitresp");

    return xrootd_queue_response(ctx, c, buf, XRD_RESPONSE_HDR_LEN);
}
