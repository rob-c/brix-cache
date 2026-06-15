#include "ngx_xrootd_module.h"
#include "../compat/host_format.h"  /* xrootd_format_host — IPv6 bracketing */

/* ------------------------------------------------------------------ */
/* Control Flow Responses — Redirects and Wait Hints                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements four control-flow response functions used during session lifecycle management. xrootd_send_redirect() sends kXR_redirect response body containing server port + hostname telling the client to reconnect to a different location (used for CMS locate redirects or manager mode delegation); xrootd_send_redirect_tpc() extends redirect with TPC key appended as opaque query parameter "?tpc.key=<key>" enabling third-party copy transfer context preservation across redirection; xrootd_send_wait() sends kXR_wait response with uint32_t seconds telling the client to pause and retry after specified duration (used for overloaded server backpressure); xrootd_send_waitresp() sends minimal kXR_waitresp acknowledgment confirming wait period elapsed.
 *
 * WHY: Control flow responses enable session lifecycle management beyond simple request/reply — redirects allow CMS/manager mode delegation to data servers without client awareness; wait hints provide graceful overload handling instead of immediate rejection; TPC redirect preserves transfer context across server boundaries ensuring native third-party copy continues seamlessly when source/destination server changes. These are critical for cluster-mode operation and high-load scenarios. */

/* ------------------------------------------------------------------ */
/* Section: Server Redirect                                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_send_redirect() sends kXR_redirect response body containing [port: 4 bytes BE][host string] telling the client to reconnect to a different server location. Called during CMS locate operation when manager redirects request to appropriate data server, or during manager mode delegation for workload distribution. Host may be NULL/empty for port-only redirect (same host, different port).
 *
 * WHY: Enables transparent workload redistribution without requiring client reconfiguration — CMS locate returns correct data server address based on file location; manager mode delegates heavy requests to available data servers maintaining operational balance. Client receives kXR_redirect and automatically reconnects using the provided hostname/port without manual intervention. */

/* ------------------------------------------------------------------ */
/* Section: TPC-Aware Redirect                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_send_redirect_tpc() extends plain redirect with TPC key appended as opaque query parameter "?tpc.key=<key>" telling the client to reconnect while preserving third-party copy transfer context. The redirect body is [port: 4 bytes][host string][?tpc.key=<key>] which XRootD client parses as an opaque-qualified host. Passing NULL or empty tpc_key falls back to plain redirect (no opaque appended).
 *
 * WHY: Native TPC transfers require key registry coordination between source and destination servers — when redirecting a TPC operation, the transfer context must be preserved across server boundaries ensuring the destination can retrieve the key from SHM registry. Without opaque key appending, TPC transfers would fail after redirection because the destination server lacks the required key to authenticate the incoming stream. */

/* ------------------------------------------------------------------ */
/* Section: Client Wait Hints                                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_send_wait() sends kXR_wait response with uint32_t seconds telling the client to pause and retry after specified duration — used for overloaded server backpressure handling instead of immediate rejection. The body contains [seconds: 4 bytes BE] specifying minimum wait time before retry attempt. xrootd_send_waitresp() sends minimal kXR_waitresp acknowledgment confirming wait period elapsed — response header only with no body payload indicating the client should proceed now.
 *
 * WHY: Graceful overload handling prevents resource exhaustion during high-load scenarios — instead of immediately rejecting requests (kXR_Overloaded), the server provides a specific retry window allowing clients to back off without losing session context or requiring reconnect. This maintains operational stability during traffic spikes while eventually serving all queued requests once capacity returns. */

/* ---- Function: xrootd_send_redirect() ----
 *
 * WHAT: Sends kXR_redirect response body containing [port: 4 bytes BE][host string] telling the client to reconnect to a different server location. Called during CMS locate operation when manager redirects request to appropriate data server, or during manager mode delegation for workload distribution. Host may be NULL/empty for port-only redirect (same host, different port).
 *
 * WHY: Enables transparent workload redistribution without requiring client reconfiguration — CMS locate returns correct data server address based on file location; manager mode delegates heavy requests to available data servers maintaining operational balance. Client receives kXR_redirect and automatically reconnects using the provided hostname/port without manual intervention.
 *
 * HOW: Two-phase response → calculate body length (sizeof(uint32_t) + hostlen) — build response header with kXR_redirect opcode and body length — encode port as big-endian uint32_t at offset 0 of body — memcpy host string at offset sizeof(uint32_t) if host non-empty — queue response via xrootd_queue_response(). */

/* ---- Function: xrootd_send_redirect_tpc() ----
 *
 * WHAT: Extends plain redirect with TPC key appended as opaque query parameter "?tpc.key=<key>" telling the client to reconnect while preserving third-party copy transfer context. The redirect body is [port: 4 bytes][host string][?tpc.key=<key>] which XRootD client parses as an opaque-qualified host. Passing NULL or empty tpc_key falls back to plain redirect (no opaque appended).
 *
 * WHY: Native TPC transfers require key registry coordination between source and destination servers — when redirecting a TPC operation, the transfer context must be preserved across server boundaries ensuring the destination can retrieve the key from SHM registry. Without opaque key appending, TPC transfers would fail after redirection because the destination server lacks the required key to authenticate the incoming stream.
 *
 * HOW: Three-phase response → check tpc_key (fall back to plain redirect if NULL/empty) — calculate body length (sizeof(uint32_t) + hostlen + opaquelen where opaque = "?tpc.key=<key>") — build response header with kXR_redirect opcode and body length — encode port as big-endian uint32_t at offset 0 of body — memcpy host string at offset sizeof(uint32_t) if host non-empty — append opaque key parameter after host — queue response via xrootd_queue_response(). */

/* ---- Function: xrootd_send_wait() ----
 *
 * WHAT: Sends kXR_wait response with uint32_t seconds telling the client to pause and retry after specified duration — used for overloaded server backpressure handling instead of immediate rejection. The body contains [seconds: 4 bytes BE] specifying minimum wait time before retry attempt. Returns NGX_OK on success; NGX_ERROR on allocation failure.
 *
 * WHY: Graceful overload handling prevents resource exhaustion during high-load scenarios — instead of immediately rejecting requests (kXR_Overloaded), the server provides a specific retry window allowing clients to back off without losing session context or requiring reconnect. This maintains operational stability during traffic spikes while eventually serving all queued requests once capacity returns.
 *
 * HOW: One-phase response → calculate body length sizeof(uint32_t) — build response header with kXR_wait opcode and body length — encode seconds as big-endian uint32_t at offset 0 of body — queue response via xrootd_queue_response(). */

/* ---- Function: xrootd_send_waitresp() ----
 *
 * WHAT: Sends minimal kXR_waitresp acknowledgment confirming wait period elapsed — response header only with no body payload indicating the client should proceed now. Used after server capacity returns from overloaded state to signal clients that previous wait condition has resolved and requests may resume immediately.
 *
 * WHY: Provides explicit confirmation that overload condition has cleared without requiring additional protocol negotiation — clients waiting on kXR_wait receive this response when server capacity returns, allowing immediate retry without guessing appropriate wait duration. This eliminates uncertainty about retry timing while maintaining clean state transition from overloaded to normal operation.
 *
 * HOW: One-phase response → calculate body length XRD_RESPONSE_HDR_LEN (no body payload) — build response header with kXR_waitresp opcode and zero body length — queue response via xrootd_queue_response(). */

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

    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

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

    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

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

ngx_int_t
xrootd_send_waitresp(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    u_char *buf;

    buf = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_waitresp, 0,
        (ServerResponseHdr *) buf);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending kXR_waitresp");

    return xrootd_queue_response(ctx, c, buf, XRD_RESPONSE_HDR_LEN);
}
