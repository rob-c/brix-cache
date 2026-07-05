/*
 * signing.c — kXR_sigver opcode handler (request-signature verification).
 */

#include "core/ngx_brix_module.h"

/*
 * brix_handle_sigver - XRootD request signing (kXR_sigver).
 *
 * Protocol flow:
 *   1. Client sends kXR_sigver with HMAC-SHA256(signing_key, seqno || next_hdr
 *      [|| next_payload]) as the body, and expectrid = opcode of the next request.
 *   2. We save the HMAC and seqno in pending state on ctx.
 *   3. brix_dispatch() verifies the HMAC before routing the following request.
 *
 * For GSI sessions signing_active is 1 and signing_key = SHA-256(DH secret).
 * For token/anonymous sessions we accept sigver without verification; legitimate
 * clients should not send it unsolicited, but some do (e.g. when connecting to an
 * unknown server type).
 *
 * Only HMAC-SHA256 without RSA (kXR_SHA256, kXR_rsaKey unset) is verified.
 * RSA-signed requests are accepted without checking the asymmetric signature.
 */
/* Handle kXR_sigver — store the expected HMAC-SHA256 signature and monotonic
 * sequence number for verifying the NEXT signed request (the seqno blocks
 * replay). */
ngx_int_t
brix_handle_sigver(brix_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_sigver_req_t    req;
    uint16_t             expectrid;
    uint64_t             seqno;

    xrdw_sigver_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    expectrid = req.expectrid;
    seqno     = req.seqno;

    if (ctx->sigver.signing_active) {
        /* Reject replays: seqno must strictly increase across the session. */
        if (seqno <= ctx->sigver.last_seqno) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: sigver replay (seqno=%llu <= last=%llu)",
                          (unsigned long long) seqno,
                          (unsigned long long) ctx->sigver.last_seqno);
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "sigver replay detected");
        }
        ctx->sigver.last_seqno = seqno;

        if ((req.crypto & kXR_HashMask_sig) == kXR_SHA256_sig
            && !(req.crypto & kXR_rsaKey_sig))
        {
            /* Need exactly 32 bytes of HMAC in the body. */
            if (ctx->recv.cur_dlen < 32 || ctx->recv.payload == NULL) {
                return brix_send_error(ctx, c, kXR_ArgInvalid,
                                         "sigver body too short");
            }

            ctx->sigver.pending = 1;
            ctx->sigver.expectrid = expectrid;
            ctx->sigver.seqno = seqno;
            ctx->sigver.nodata = (req.flags & kXR_nodata_sig) ? 1 : 0;
            ngx_memcpy(ctx->sigver.hmac, ctx->recv.payload, 32);

            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "brix: sigver pending expectrid=%d seqno=%llu",
                           (int) expectrid, (unsigned long long) seqno);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "brix: sigver crypto=0x%02xd not verified (RSA path)",
                           (unsigned) req.crypto);
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: sigver accepted without verification (no GSI key)");
    }

    brix_log_access(ctx, c, "SIGVER", "-", "-", 1, 0, NULL, 0);
    /*
     * kXR_sigver is a request PREFIX, not a standalone request: per the XRootD
     * protocol (XrdXrootdProtocol::ProcSig) the server sends NO response on
     * success — the single response belongs to the signed request that follows,
     * which brix_verify_pending_sigver() validates at the top of its dispatch.
     * Returning NGX_OK without queuing a frame lets the recv loop read that next
     * request. Emitting a kXR_ok here desynchronised every stock-protocol client
     * (go-hep, official XrdCl): they read the ack as the signed request's reply
     * (e.g. go-hep stat → statinfo "" parse error). The error paths above still
     * reply, since a sigver failure aborts the exchange.
     */
    return NGX_OK;
}
