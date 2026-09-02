#include "recv_frame.h"

/*
 * recv_payload_buf.c — the reusable heap payload buffer for the recv framing
 * loop (split from recv_process.c to keep it under the size cap).  Two ways
 * to size it: _ensure at request start (the buffer is empty, so a resize may
 * free-then-alloc) and _grow mid-request (the kXR_writev / kXR_chkpoint body
 * extension raises the expected length after bytes have landed, so a resize
 * must copy the payload_pos bytes already received).  Both NUL-terminate at
 * dlen so string-parsing handlers can treat the payload as a C string.
 */

static ngx_int_t
brix_payload_buffer_size(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen, ngx_flag_t preserve)
{
    u_char  *buf;
    size_t   need;

    if (dlen > (uint32_t) (SIZE_MAX - 1)) {
        return NGX_ERROR;
    }
    need = (size_t) dlen + 1;

    if (ctx->recv.payload_buf != NULL && ctx->recv.payload_buf_size >= need) {
        ctx->recv.payload = ctx->recv.payload_buf;
        ctx->recv.payload[dlen] = '\0';
        return NGX_OK;
    }

    buf = ngx_alloc(need, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->recv.payload_buf != NULL) {
        if (preserve) {
            ngx_memcpy(buf, ctx->recv.payload_buf, ctx->recv.payload_pos);
        }
        ngx_free(ctx->recv.payload_buf);
    }

    ctx->recv.payload_buf = buf;
    ctx->recv.payload_buf_size = need;
    ctx->recv.payload = buf;
    ctx->recv.payload[dlen] = '\0';

    return NGX_OK;
}

/* brix_ensure_payload_buffer: ensure payload_buf holds dlen (+1 NUL) bytes at
 * request start (the buffer is empty here, so a resize need not copy). */
ngx_int_t
brix_ensure_payload_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    return brix_payload_buffer_size(ctx, c, dlen, 0);
}

/* brix_grow_payload_buffer — enlarge payload_buf PRESERVING the received bytes
 * (payload_pos of them), for the mid-request kXR_writev / kXR_chkpoint body
 * extension that raises the expected body length after data has landed. */
ngx_int_t
brix_grow_payload_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    return brix_payload_buffer_size(ctx, c, dlen, 1);
}
