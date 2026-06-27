/*
 * signing.c — kXR_sigver opcode handler (request-signature verification).
 */

#include "../ngx_xrootd_module.h"

/*
 * xrootd_handle_sigver - XRootD request signing (kXR_sigver).
 *
 * Protocol flow:
 *   1. Client sends kXR_sigver with HMAC-SHA256(signing_key, seqno || next_hdr
 *      [|| next_payload]) as the body, and expectrid = opcode of the next request.
 *   2. We save the HMAC and seqno in pending state on ctx.
 *   3. xrootd_dispatch() verifies the HMAC before routing the following request.
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
xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_sigver_req_t    req;
    uint16_t             expectrid;
    uint64_t             seqno;

    xrdw_sigver_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    expectrid = req.expectrid;
    seqno     = req.seqno;

    if (ctx->signing_active) {
        /* Reject replays: seqno must strictly increase across the session. */
        if (seqno <= ctx->last_seqno) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: sigver replay (seqno=%llu <= last=%llu)",
                          (unsigned long long) seqno,
                          (unsigned long long) ctx->last_seqno);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "sigver replay detected");
        }
        ctx->last_seqno = seqno;

        if ((req.crypto & kXR_HashMask_sig) == kXR_SHA256_sig
            && !(req.crypto & kXR_rsaKey_sig))
        {
            /* Need exactly 32 bytes of HMAC in the body. */
            if (ctx->cur_dlen < 32 || ctx->payload == NULL) {
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "sigver body too short");
            }

            ctx->sigver_pending = 1;
            ctx->sigver_expectrid = expectrid;
            ctx->sigver_seqno = seqno;
            ctx->sigver_nodata = (req.flags & kXR_nodata_sig) ? 1 : 0;
            ngx_memcpy(ctx->sigver_hmac, ctx->payload, 32);

            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver pending expectrid=%d seqno=%llu",
                           (int) expectrid, (unsigned long long) seqno);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver crypto=0x%02xd not verified (RSA path)",
                           (unsigned) req.crypto);
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: sigver accepted without verification (no GSI key)");
    }

    xrootd_log_access(ctx, c, "SIGVER", "-", "-", 1, 0, NULL, 0);
    /*
     * kXR_sigver is a request PREFIX, not a standalone request: per the XRootD
     * protocol (XrdXrootdProtocol::ProcSig) the server sends NO response on
     * success — the single response belongs to the signed request that follows,
     * which xrootd_verify_pending_sigver() validates at the top of its dispatch.
     * Returning NGX_OK without queuing a frame lets the recv loop read that next
     * request. Emitting a kXR_ok here desynchronised every stock-protocol client
     * (go-hep, official XrdCl): they read the ack as the signed request's reply
     * (e.g. go-hep stat → statinfo "" parse error). The error paths above still
     * reply, since a sigver failure aborts the exchange.
     */
    return NGX_OK;
}
