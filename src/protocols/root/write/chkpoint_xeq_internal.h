#ifndef BRIX_WRITE_CHKPOINT_XEQ_INTERNAL_H
#define BRIX_WRITE_CHKPOINT_XEQ_INTERNAL_H

#include "chkpoint_xeq.h"

/* WHAT: The embedded sub-request a kXR_ckpXeq frame carries: its 24-byte
 *      ClientRequestHdr, the streamed body that follows, and the body length
 *      declared by that header.
 * WHY: Every write-family sub-handler needs the same three fields; bundling
 *      them keeps each handler's param list at (ctx, c, idx, desc) — below the
 *      ≤5 cap — while these handlers stay file-local to ckp_xeq's dispatch.
 * HOW: ckp_xeq fills one descriptor from ctx->recv.payload and passes it down;
 *      the fields are read-only to the handlers. */
typedef struct {
    const u_char  *sub_hdr;
    const u_char  *sub_payload;
    uint32_t       sub_dlen;
} ckp_write_desc_t;

/* Write-family ckpXeq sub-handlers — defined in chkpoint_xeq_write.c, dispatched
 * from chkpoint_xeq.c.  Each targets the checkpointed handle idx. */
ngx_int_t ckp_xeq_write(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d);
ngx_int_t ckp_xeq_pgwrite(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d);
ngx_int_t ckp_xeq_truncate(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr);
ngx_int_t ckp_xeq_writev(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d, uint32_t data_len);

#endif /* BRIX_WRITE_CHKPOINT_XEQ_INTERNAL_H */
