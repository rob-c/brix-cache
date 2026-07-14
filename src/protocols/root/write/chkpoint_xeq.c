#include "chkpoint_xeq.h"
#include "chkpoint_xeq_internal.h"

#include <string.h>

/* brix_ckpxeq_body_extra — trailing sub-body length for kXR_ckpXeq
 * WHAT: Computes how many more bytes the client will stream after the ckpXeq
 * frame, staged on `have` (body bytes received so far).  have == 24: the
 * embedded sub-header just landed — the sub-request's own dlen bytes follow
 * (write/pgwrite data, or the writev descriptor block).  have == 24 +
 * sub_dlen: an embedded writev's descriptors landed — sum(wlen) data bytes
 * follow, delegated to brix_writev_body_extra (the SAME contract as a
 * standalone kXR_writev).  *final = 0 tells the recv framing to call again
 * after the current extension completes.
 * WHY: Stock wire contract (do_ChkPntXeq + XrdCl MessageUtils): the outer
 * chkpoint dlen frames ONLY the embedded 24-byte header; everything else is
 * raw body streamed behind the frame.  Shared by the recv framing so the
 * whole sub-request lands contiguously in payload_buf before dispatch.
 * HOW: Bound every stage by BRIX_MAX_WRITE_PAYLOAD (and the writev vector
 * cap) and return NGX_DECLINED on any violation — the framing then does NOT
 * extend, the auth gates still run, and ckp_xeq detects the un-read trailing
 * bytes (count mismatch) and drops the link. */
ngx_int_t
brix_ckpxeq_body_extra(const u_char *body, uint32_t have,
    uint32_t *extra, unsigned *final)
{
    uint16_t  sub_reqid;
    uint32_t  sub_dlen;

    *extra = 0;
    *final = 1;

    if (body == NULL || have < 24) {
        return NGX_DECLINED;
    }

    sub_reqid = (uint16_t) ntohs(*(const uint16_t *) (body + 2));
    sub_dlen  = (uint32_t) ntohl(*(const uint32_t *) (body + 20));

    if (have == 24) {
        if (sub_dlen == 0) {
            return NGX_OK;               /* nothing streams (e.g. truncate) */
        }

        switch (sub_reqid) {

        case kXR_write:
        case kXR_pgwrite:
            if (sub_dlen > BRIX_MAX_WRITE_PAYLOAD) {
                return NGX_DECLINED;
            }
            *extra = sub_dlen;
            return NGX_OK;

        case kXR_writev:
            /* Descriptor block first; the segment data extends in stage 2
             * once the descriptors can be summed. */
            if (sub_dlen % BRIX_WRITEV_SEGSIZE != 0
                || sub_dlen > BRIX_WRITEV_MAXSEGS * BRIX_WRITEV_SEGSIZE)
            {
                return NGX_DECLINED;
            }
            *extra = sub_dlen;
            *final = 0;
            return NGX_OK;

        default:
            /* Invalid embed (chkpoint-in-chkpoint, truncate with data, or
             * garbage) — no extension; ckp_xeq rejects and drops. */
            return NGX_DECLINED;
        }
    }

    /* Stage 2: the embedded writev descriptor block is in at body[24..). */
    if (sub_reqid == kXR_writev && have == 24 + sub_dlen) {
        return brix_writev_body_extra(body + 24, sub_dlen, extra);
    }

    return NGX_DECLINED;
}

/* WHAT: Unwraps the embedded sub-request carried by a kXR_ckpXeq frame and
 *      routes it to the matching write/pgwrite/truncate/writev handler for
 *      the checkpointed handle idx.
 * WHY: kXR_ckpXeq tunnels an ordinary write op "inside" an active checkpoint
 *      so the op can be rolled back.  Requiring an active checkpoint
 *      (ckp_path) guards against executing a tentative op with no rollback
 *      anchor.  Stock wire contract (do_ChkPntXeq): the frame's dlen is
 *      EXACTLY 24 — the embedded ClientRequestHdr — and the sub-request body
 *      (sub_dlen bytes per the embedded header; for writev, descriptors then
 *      data, see ckp_xeq_writev) streams after the frame.  The recv framing
 *      (brix_ckpxeq_body_extra) has already appended those streamed bytes
 *      to ctx->recv.payload (ctx->recv.cur_body_extra of them), so the sub-request is
 *      contiguous here.
 * HOW: Stock-parity validation, then dispatch: 1) embedded streamid must
 *      match the outer header's. 2) dlen must be 24. 3) An embedded chkpoint,
 *      or a truncate carrying data, is invalid.  All three reject + drop the
 *      link exactly like stock (do_ChkPntXeq returns -1) — for 1 and 3 the
 *      trailing bytes may not have been read, so no resync is possible.
 *      4) Per-type byte-count cross-check against cur_body_extra (defensive:
 *      detects a declined extension) — also error + drop.  5) Only then the
 *      checkpoint-active check (error, link kept: the sub-body is safely
 *      buffered by that point), and the switch to the sub-handler. */
/* WHAT: Runs every stock-parity wire-shape check a kXR_ckpXeq frame must pass
 *      before its embedded op is dispatched — streamid match, dlen == 24,
 *      no embedded chkpoint / data-bearing truncate, and the per-type
 *      trailing-byte cross-check.
 * WHY: These four checks contribute the bulk of ckp_xeq's branching; hoisting
 *      them keeps the dispatcher small and the ordering (all wire-shape checks
 *      before the checkpoint-active check) explicit and unchanged.  Each
 *      violation emits the SAME error + counts the SAME op-error as before and
 *      signals the caller to drop the link.
 * HOW: On the first failing check, send the matching kXR_ArgInvalid and return
 *      NGX_ERROR; return NGX_OK when the frame is well-formed.  sub_reqid /
 *      sub_dlen have already been decoded by the caller.  The streamid check
 *      runs in ckp_xeq itself so its original before-dlen-check ordering (and
 *      NULL/short-payload guard) is preserved verbatim. */
static ngx_int_t
ckp_xeq_validate_frame(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t sub_reqid, uint32_t sub_dlen)
{
    /* Stock parity: a chkpoint may not embed a chkpoint, and an embedded
     * truncate carries no data (its length rides in the offset field). */
    if (sub_reqid == kXR_chkpoint
        || (sub_reqid == kXR_truncate && sub_dlen != 0))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "chkpoint request is invalid");
        return NGX_ERROR;
    }

    /* Defensive byte-count cross-check: the recv framing extended the body
     * by exactly sub_dlen (write/pgwrite data; writev descriptors).  A
     * shortfall means the extension was declined (oversized sub_dlen or a
     * malformed descriptor block) — the trailing bytes were never read, so
     * no resync is possible: error + drop.  Runs BEFORE the checkpoint-
     * active check so a framing violation always takes the link-drop path. */
    if (((sub_reqid == kXR_write || sub_reqid == kXR_pgwrite)
         && ctx->recv.cur_body_extra != sub_dlen)
        || (sub_reqid == kXR_writev && ctx->recv.cur_body_extra < sub_dlen))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq: sub-request length invalid");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* WHAT: Routes a validated ckpXeq sub-request to the matching write-family
 *      handler for the checkpointed handle idx.
 * WHY: Isolating the type switch from the wire-shape validation keeps each
 *      function single-purpose and under the CCN cap; behaviour (handler
 *      selection, default reject) is identical to the inline switch it replaces.
 * HOW: Dispatch on sub_reqid; the default path logs, counts an op-error, and
 *      sends kXR_ArgInvalid while keeping the link (stock second-pass default). */
static ngx_int_t
ckp_xeq_dispatch(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    uint16_t sub_reqid, const ckp_write_desc_t *d)
{
    switch (sub_reqid) {

    case kXR_write:
        return ckp_xeq_write(ctx, c, idx, d);

    case kXR_pgwrite:
        return ckp_xeq_pgwrite(ctx, c, idx, d);

    case kXR_truncate:
        return ckp_xeq_truncate(ctx, c, idx, d->sub_hdr);

    case kXR_writev:
        return ckp_xeq_writev(ctx, c, idx, d,
                              ctx->recv.cur_body_extra - d->sub_dlen);

    default:
        /* Stock parity: unknown embedded op — error, keep the link (stock's
         * second-pass default does not drop). */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: ckpXeq unsupported sub-reqid=%d",
                       (int) sub_reqid);
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "chkpoint request is invalid");
    }
}

ngx_int_t
ckp_xeq(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t       *f = &ctx->files[idx];
    ckp_write_desc_t   d;
    uint16_t           sub_reqid;

    /* Stock parity: the embedded request must carry the outer streamid.  Kept
     * ahead of the dlen check (and behind its own NULL/short-payload guard) so
     * a streamid mismatch reports before a length mismatch, exactly as before. */
    if (ctx->recv.payload != NULL && ctx->recv.cur_dlen >= 2
        && (ctx->recv.payload[0] != ctx->recv.cur_streamid[0]
            || ctx->recv.payload[1] != ctx->recv.cur_streamid[1]))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Request streamid mismatch");
        return NGX_ERROR;
    }

    /* Stock parity: the frame is EXACTLY the embedded 24-byte header — the
     * sub-request body streams after it.  This also rejects the legacy
     * private layout (header + body counted inside dlen) the way a stock
     * server does.  Guards the payload deref for every check below. */
    if (ctx->recv.cur_dlen != 24 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Request length invalid");
        return NGX_ERROR;
    }

    /* Wire layout as buffered by the recv framing:
     *   [0 .. 24)                 embedded ClientRequestHdr
     *   [24 .. 24+cur_body_extra) streamed sub-request body
     * requestid at header offset 2, dlen at offset 20, both big-endian. */
    d.sub_hdr     = ctx->recv.payload;
    sub_reqid     = (uint16_t) ntohs(*(const uint16_t *) (d.sub_hdr + 2));
    d.sub_dlen    = (uint32_t) ntohl(*(const uint32_t *) (d.sub_hdr + 20));
    d.sub_payload = ctx->recv.payload + 24;

    if (ckp_xeq_validate_frame(ctx, c, sub_reqid, d.sub_dlen) != NGX_OK) {
        return NGX_ERROR;
    }

    /* A ckpXeq with no open checkpoint has nothing to make tentative — reject
     * so a write can never masquerade as checkpointed when it is not.  Runs
     * AFTER the wire-shape checks above so a framing violation always takes
     * the link-drop path even when no checkpoint is open. */
    if (f->ckp_path == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "xeq",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    return ckp_xeq_dispatch(ctx, c, idx, sub_reqid, &d);
}
