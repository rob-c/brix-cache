#include "../ngx_xrootd_module.h"

/* ------------------------------------------------------------------ */
/* Request Signing — kXR_sigver handler                                  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_sigver opcode — XRootD request signing mechanism.
 *       When enabled, clients must provide an HMAC-SHA256 signature for every subsequent
 *       request after this opcode. The server stores the expected HMAC (pending state) and
 *       verifies it in xrootd_dispatch() before processing each covered request. This prevents
 *       request forgery and replay attacks on GSI sessions.
 *
 * WHY: GSI sessions use a Diffie-Hellman shared secret as their signing key. Without sigver,
 *      an attacker could inject fake requests into the session stream — signatures ensure every
 *      opcode (read/write/stat/etc.) is cryptographically verified before execution. This is a
 *      critical security invariant for GSI deployments.
 *
 * HOW: Two-phase mechanism:
 *      Phase 1 (sigver handler): client sends HMAC + seqno + expectrid → server stores pending state,
 *         rejects replays (seqno must strictly increase), only verifies HMAC-SHA256 (not RSA)
 *      Phase 2 (dispatch verification): xrootd_verify_pending_sigver() computes HMAC of next request
 *         and compares against stored pending value — mismatch returns kXR_NotAuthorized */

/* ------------------------------------------------------------------ */
/* Section: Sigver Replay Protection                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Sequential number tracking prevents replay attacks. Each sigver uses a monotonically
 *       increasing seqno; if the server sees a seqno that is <= its last recorded value, it rejects
 *      as a potential replay attack. This ensures signatures cannot be reused across requests.
 *
 * WHY: Without seqno tracking, an attacker could capture a valid sigver response and inject it into
 *      subsequent requests — the HMAC would still match but the request content would differ. Seqno
 *      provides cryptographic binding between signature and specific request context.
 *
 * HOW: On each sigver update: compare new seqno against ctx->last_seqno → reject if <= (replay) →
 *      update last_seqno = new seqno for future comparisons. */

/* ---- Function: xrootd_handle_sigver() ----
 *
 * WHAT: Handles the kXR_sigver opcode — stores an expected HMAC-SHA256 signature for verification of the next
 *       request. Validates seqno monotonicity (rejects replays), stores pending state including expectrid,
 *      seqno, hmac bytes, and nodata flag. Only verifies HMAC-SHA256 signatures; RSA paths are accepted without check.
 *
 * WHY: Critical security mechanism for GSI sessions — prevents request forgery by ensuring every subsequent opcode
 *      is cryptographically verified before processing. In token/anonymous modes sigver is accepted but not enforced,
 *      accommodating clients that may send it unsolicited when connecting to unknown server types.
 *
 * HOW: Two-phase flow → parse expectrid (uint16) + seqno (uint64 BE) from wire format → GSI signing check (reject replay if
 *      seqno <= last_seqno, only verify HMAC-SHA256 not RSA) → store pending state (sigver_pending=1, sigver_hmac[32],
 *      sigver_expectrid, sigver_seqno, sigver_nodata flag) → return kXR_ok with access-log entry. */

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
ngx_int_t
xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientSigverRequest *req = (ClientSigverRequest *) ctx->hdr_buf;
    uint16_t             expectrid;
    uint64_t             seqno;

    ngx_memcpy(&expectrid, &req->expectrid, 2);
    expectrid = ntohs(expectrid);

    ngx_memcpy(&seqno, &req->seqno, 8);
    seqno = be64toh(seqno);

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

        if ((req->crypto & kXR_HashMask_sig) == kXR_SHA256_sig
            && !(req->crypto & kXR_rsaKey_sig))
        {
            /* Need exactly 32 bytes of HMAC in the body. */
            if (ctx->cur_dlen < 32 || ctx->payload == NULL) {
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "sigver body too short");
            }

            ctx->sigver_pending = 1;
            ctx->sigver_expectrid = expectrid;
            ctx->sigver_seqno = seqno;
            ctx->sigver_nodata = (req->flags & kXR_nodata_sig) ? 1 : 0;
            ngx_memcpy(ctx->sigver_hmac, ctx->payload, 32);

            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver pending expectrid=%d seqno=%llu",
                           (int) expectrid, (unsigned long long) seqno);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver crypto=0x%02xd not verified (RSA path)",
                           (unsigned) req->crypto);
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: sigver accepted without verification (no GSI key)");
    }

    xrootd_log_access(ctx, c, "SIGVER", "-", "-", 1, 0, NULL, 0);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
