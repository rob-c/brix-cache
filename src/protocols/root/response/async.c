/*
 * src/response/async.c — Native kXR_attn generation and deprecated async handlers.
 *
 * WHAT: Implements native kXR_attn (4001) server-push frames for two active
 *       action codes: kXR_asyncms (5002) for unsolicited text notifications and
 *       kXR_asynresp (5008) for deferred response delivery after kXR_waitresp.
 *       Also provides a generic brix_send_attn() wrapper.
 *       Deprecated action codes 5000-5007 (except 5002 and 5008) all return
 *       kXR_Unsupported per the v5.2.0 spec ("No longer supported").
 *
 * WHY: kXR_attn is the XRootD server-push mechanism. The proxy relay path
 *      already forwards upstream kXR_attn frames transparently (events_read.c).
 *      This module provides the native generation path so the server itself can
 *      push notifications — required for kXR_notify on kXR_prepare and as the
 *      foundation for kXR_recoverWrts write-journal recovery.
 *
 * Wire layout for kXR_asyncms / kXR_asynresp:
 *
 *   [outer ServerResponseHdr: 8B]
 *       streamid[2]  — {0,0} for asyncms; deferred streamid for asynresp
 *       status[2]    — kXR_attn (4001)
 *       dlen[4]      — 4 + 4 + 8 + payload_len = 16 + payload_len
 *   [actnum: 4B BE]  — kXR_asyncms (5002) or kXR_asynresp (5008)
 *   [reserved: 4B]   — zeroes
 *   [inner ServerResponseHdr: 8B]
 *       streamid[2]  — {0,0} for asyncms; deferred streamid for asynresp
 *       status[2]    — kXR_ok (asyncms) or actual resp status (asynresp)
 *       dlen[4]      — payload length
 *   [payload: variable]
 */

#include "core/ngx_brix_module.h"
#include "async.h"
#include "core/compat/alloc_guard.h"


static const u_char kAttnZeroStreamid[2] = {0, 0};

/* Minimum body size shared by asyncms and asynresp:
 *   actnum[4] + reserved[4] + inner_hdr[8] = 16 bytes */
#define ATTN_BODY_OVERHEAD  16


size_t
brix_attn_asyncms_frame_len(size_t msglen)
{
    return XRD_RESPONSE_HDR_LEN + ATTN_BODY_OVERHEAD + msglen;
}

void
brix_build_attn_asyncms_frame(u_char *buf, const char *msg, size_t msglen)
{
    uint32_t  outer_bodylen = (uint32_t)(ATTN_BODY_OVERHEAD + msglen);
    uint32_t  act_be        = htonl((uint32_t) kXR_asyncms);
    u_char   *p             = buf;

    /* Outer kXR_attn header: streamid={0,0} */
    brix_build_resp_hdr(kAttnZeroStreamid, kXR_attn, outer_bodylen,
                          (ServerResponseHdr *) p);
    p += XRD_RESPONSE_HDR_LEN;

    /* actnum = kXR_asyncms */
    ngx_memcpy(p, &act_be, 4);
    p += 4;

    /* reserved[4] */
    ngx_memset(p, 0, 4);
    p += 4;

    /* Inner ServerResponseHdr: streamid={0,0}, status=kXR_ok, dlen=msglen */
    brix_build_resp_hdr(kAttnZeroStreamid, kXR_ok, (uint32_t) msglen,
                          (ServerResponseHdr *) p);
    p += XRD_RESPONSE_HDR_LEN;

    /* Notification text */
    if (msglen > 0 && msg != NULL) {
        ngx_memcpy(p, msg, msglen);
    }
}


ngx_int_t
brix_send_attn_asyncms(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *msg, size_t msglen)
{
    size_t   total;
    u_char  *buf;

    total = brix_attn_asyncms_frame_len(msglen);
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_attn_asyncms_frame(buf, msg, msglen);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending kXR_attn asyncms (%uz bytes)", msglen);

    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_send_attn_asynresp(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char *deferred_streamid,
    uint16_t resp_status,
    const void *body, uint32_t bodylen)
{
    uint32_t  outer_bodylen = (uint32_t) ATTN_BODY_OVERHEAD + bodylen;
    size_t    total         = XRD_RESPONSE_HDR_LEN + outer_bodylen;
    uint32_t  act_be        = htonl((uint32_t) kXR_asynresp);
    u_char   *buf, *p;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    p = buf;

    /* Outer kXR_attn header: use the deferred request's stream ID */
    brix_build_resp_hdr(deferred_streamid, kXR_attn, outer_bodylen,
                          (ServerResponseHdr *) p);
    p += XRD_RESPONSE_HDR_LEN;

    /* actnum = kXR_asynresp */
    ngx_memcpy(p, &act_be, 4);
    p += 4;

    /* reserved[4] */
    ngx_memset(p, 0, 4);
    p += 4;

    /* Inner ServerResponseHdr: deferred streamid, actual status, body length */
    brix_build_resp_hdr(deferred_streamid, resp_status, bodylen,
                          (ServerResponseHdr *) p);
    p += XRD_RESPONSE_HDR_LEN;

    /* Response body */
    if (bodylen > 0 && body != NULL) {
        ngx_memcpy(p, body, bodylen);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "xrootd: sending kXR_attn asynresp status=%d bodylen=%u",
        (int) resp_status, bodylen);

    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_send_attn(brix_ctx_t *ctx, ngx_connection_t *c,
    int actnum, const char *msg, size_t msglen)
{
    uint32_t  bodylen = (uint32_t)(4 + msglen);
    size_t    total   = XRD_RESPONSE_HDR_LEN + bodylen;
    uint32_t  act_be  = htonl((uint32_t) actnum);
    u_char   *buf;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->cur_streamid, kXR_attn, bodylen,
                          (ServerResponseHdr *) buf);

    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &act_be, 4);
    if (msglen > 0 && msg != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + 4, msg, msglen);
    }

    return brix_queue_response(ctx, c, buf, total);
}


ngx_int_t
brix_handle_async_ab(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncab (5000) is no longer supported");
}

ngx_int_t
brix_handle_async_di(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncdi (5001) is no longer supported");
}

ngx_int_t
brix_handle_async_ms(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncms (5002) is no longer supported");
}

ngx_int_t
brix_handle_async_rd(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncrd (5003) is no longer supported");
}

ngx_int_t
brix_handle_async_wt(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncwt (5004) is no longer supported");
}

ngx_int_t
brix_handle_async_av(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncav (5005) is no longer supported");
}

ngx_int_t
brix_handle_async_unav(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncunav (5006) is no longer supported");
}

ngx_int_t
brix_handle_async_go(brix_ctx_t *ctx, ngx_connection_t *c)
{
    return brix_send_error(ctx, c, kXR_Unsupported,
                            "kXR_asyncgo (5007) is no longer supported");
}
