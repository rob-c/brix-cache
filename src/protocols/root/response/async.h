/*
 * src/response/async.h — Native kXR_attn generation and deprecated async handlers.
 */

#ifndef BRIX_RESPONSE_ASYNC_H
#define BRIX_RESPONSE_ASYNC_H

#include "core/ngx_brix_module.h"

/* ------------------------------------------------------------------ */
/* Native kXR_attn generation                                          */
/* ------------------------------------------------------------------ */

/*
 * brix_attn_asyncms_frame_len — size in bytes of a complete kXR_attn +
 * kXR_asyncms wire frame for a notification message of msglen bytes.
 *
 * Use this to pre-calculate buffer sizes when combining a primary response
 * frame with an asyncms notification in a single allocation.
 */
size_t brix_attn_asyncms_frame_len(size_t msglen);

/*
 * brix_build_attn_asyncms_frame — write a kXR_attn + kXR_asyncms frame
 * into buf.  Caller must have allocated at least
 * brix_attn_asyncms_frame_len(msglen) bytes at buf.
 *
 * Wire layout:
 *   [outer ServerResponseHdr: 8B]  streamid={0,0}, status=kXR_attn, dlen=16+msglen
 *   [actnum: 4B BE]                kXR_asyncms (5002)
 *   [reserved: 4B]                 zeroes
 *   [inner ServerResponseHdr: 8B]  streamid={0,0}, status=kXR_ok, dlen=msglen
 *   [message: msglen bytes]
 */
void brix_build_attn_asyncms_frame(u_char *buf,
    const char *msg, size_t msglen);

/*
 * brix_send_attn_asyncms — allocate and send an unsolicited kXR_attn +
 * kXR_asyncms notification frame.  The outer stream ID is {0,0} (unsolicited).
 */
ngx_int_t brix_send_attn_asyncms(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *msg, size_t msglen);

/*
 * brix_send_attn_asynresp — send a deferred response via kXR_attn +
 * kXR_asynresp.  Used when the server previously sent kXR_waitresp to
 * acknowledge a request and is now delivering the actual response.
 *
 * deferred_streamid: the streamid of the original deferred request (2 bytes).
 * resp_status:       the inner response status (kXR_ok, kXR_error, etc.)
 * body / bodylen:    the inner response payload (may be NULL/0 for empty body).
 */
ngx_int_t brix_send_attn_asynresp(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char *deferred_streamid,
    uint16_t resp_status,
    const void *body, uint32_t bodylen);

/*
 * brix_send_attn — generic kXR_attn frame.
 * outer streamid = ctx->cur_streamid, body = actnum[4] + parms[msglen].
 * Prefer the structured helpers above for active action codes.
 */
ngx_int_t brix_send_attn(brix_ctx_t *ctx, ngx_connection_t *c,
    int actnum, const char *msg, size_t msglen);

/* ------------------------------------------------------------------ */
/* Deprecated async operation handlers (5000-5007)                     */
/* ------------------------------------------------------------------ */
/* All return kXR_Unsupported — these opcodes are retired in v5.       */
/*
 * Each handler queues a single kXR_error(kXR_Unsupported) response naming its
 * own retired opcode and performs no other work. Common to all:
 *   ctx->cur_streamid is echoed into the error frame; the body is allocated
 *   from c->pool and queued on ctx via brix_send_error.
 *   Returns NGX_OK once the error frame is queued, NGX_ERROR on alloc failure.
 */

/* kXR_asyncab (5000) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_ab(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncdi (5001) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_di(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncms (5002) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_ms(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncrd (5003) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_rd(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncwt (5004) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_wt(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncav (5005) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_av(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncunav (5006) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_unav(brix_ctx_t *ctx, ngx_connection_t *c);
/* kXR_asyncgo (5007) — retired; always replies kXR_Unsupported. */
ngx_int_t brix_handle_async_go(brix_ctx_t *ctx, ngx_connection_t *c);

#endif /* BRIX_RESPONSE_ASYNC_H */
