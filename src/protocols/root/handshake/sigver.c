#include "handshake.h"
#include "auth/gsi/gsi_core.h"   /* brix_gsi_sigver_required (shared policy) */

/* sigver.c — request signature verification (kXR_sigver, stock XrdSecProtect
 * secver 0) and security-level enforcement.
 * WHAT: Owns the "verify" half of XRootD request signing. Three entry points:
 *       brix_verify_pending_sigver() consumes the sigver state recorded when a
 *       kXR_sigver request arrived and validates that the immediately-following
 *       covered request matches the expected opcode, streamid, and signature;
 *       the static brix_verify_sigver_sig() decrypts the client's signature
 *       blob with the negotiated GSI session cipher and compares it against
 *       SHA-256(seqno || header || payload-unless-nodata) in constant time; and
 *       brix_signing_enforce_level() rejects opcodes that the configured
 *       brix_security_level requires to be signed but were not.
 *
 * WHY:  XRootD signs requests so a passive observer cannot inject or tamper with
 *       mutating operations once a session is authenticated. This file enforces
 *       that contract on the server side: a mismatched/absent signature must fail
 *       closed (kXR_NotAuthorized) rather than silently passing the request to the
 *       read/write dispatchers. Splitting verify (here) from the kXR_sigver request
 *       handler (src/session/signing.c, which records the pending state) keeps the
 *       "record intent" and "check intent against next request" responsibilities
 *       in separate, single-purpose files.
 *
 * HOW:  kXR_sigver records pending state (expected reqid, streamid, signature
 *       blob, nodata flag, seqno) elsewhere; dispatch then calls
 *       brix_verify_pending_sigver() on the next request, which gates on
 *       ctx->sigver.signing_active, matches expectrid + streamid against the
 *       covered request, and delegates the cryptographic check to
 *       brix_verify_sigver_sig() using the sigver-owned copy of the session
 *       cipher (ctx->sigver.sig_cipher/sig_key — armed by
 *       gsi_arm_request_signing(), surviving the §F6 delegation cleanse). On
 *       success it sets ctx->sigver.verified; brix_signing_enforce_level()
 *       later consults that flag plus brix_sigver_opcode_requires() (a level
 *       0-4 policy table) to decide whether an unsigned opcode is permitted. */

/*
 * Decrypt and compare the signature over the covered request (stock
 * XrdSecProtect secver 0: the blob is the session-cipher encryption of the
 * plain SHA-256 over seqno_be(8) || request header(24) || payload — payload
 * omitted when the nodata flag was set).  brix_gsi_sigver_verify() decrypts
 * with the sigver-owned session key (IV-stripped on the signed-DH path) and
 * CRYPTO_memcmp's the 32-byte hash. Returns BRIX_DISPATCH_CONTINUE on a match;
 * otherwise sends kXR_ServerError when the armed cipher cannot be resolved or
 * kXR_NotAuthorized on a signature mismatch and returns that send's result.
 */
static ngx_int_t
brix_verify_sigver_sig(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_gsi_cipher_t cipher;

    if (!brix_gsi_cipher_lookup(ctx->sigver.sig_cipher, &cipher)) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: sigver session cipher \"%s\" unavailable for reqid=%d",
                      ctx->sigver.sig_cipher, (int) ctx->recv.cur_reqid);
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "signature verification failed");
    }

    /* Shared kernel (libxrdproto gsi_core) — decrypts the blob and recomputes
     * over the SAME covered bytes the client signs. Single source of the
     * covered-byte layout with the native client's signer. */
    if (!brix_gsi_sigver_verify(&cipher, ctx->sigver.sig_key,
                                  ctx->sigver.sig_use_iv,
                                  ctx->sigver.sig, (size_t) ctx->sigver.sig_len,
                                  ctx->sigver.seqno, ctx->recv.hdr_buf,
                                  ctx->recv.payload, ctx->recv.cur_dlen,
                                  ctx->sigver.nodata))
    {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: sigver signature mismatch for reqid=%d",
                      (int) ctx->recv.cur_reqid);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "signature verification failed");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: sigver verified reqid=%d",
                   (int) ctx->recv.cur_reqid);

    return BRIX_DISPATCH_CONTINUE;
}

/*
 * Verify the pending kXR_sigver signature against the next request.
 *
 * kXR_sigver itself lives in src/session/signing.c because that request records
 * pending state. This file owns the other half: checking that pending state
 * before the covered request is routed.
 */
ngx_int_t
brix_verify_pending_sigver(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_int_t rc;

    ctx->sigver.verified = 0;

    if (ctx->sigver.pending && ctx->recv.cur_reqid != kXR_sigver) {
        ctx->sigver.pending = 0;

        if (ctx->sigver.signing_active) {
            if (ctx->sigver.expectrid != ctx->recv.cur_reqid) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "brix: sigver expectrid=%d but got reqid=%d",
                              (int) ctx->sigver.expectrid,
                              (int) ctx->recv.cur_reqid);
                /* kXR_InvalidRequest: the request is malformed or not allowed now */
                return brix_send_error(ctx, c, kXR_InvalidRequest,
                                         "signed request opcode mismatch");
            }

            /* Stock parity (XrdSecProtect::Verify): the sigver frame and the
             * covered request must share a streamid — the hash covers the
             * header as sent, so a stream mismatch can never verify anyway;
             * failing early gives a precise diagnostic. */
            if (ctx->sigver.sid[0] != ctx->recv.hdr_buf[0]
                || ctx->sigver.sid[1] != ctx->recv.hdr_buf[1])
            {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "brix: sigver streamid mismatch for reqid=%d",
                              (int) ctx->recv.cur_reqid);
                return brix_send_error(ctx, c, kXR_InvalidRequest,
                                         "signed request streamid mismatch");
            }

            rc = brix_verify_sigver_sig(ctx, c);
            if (rc != BRIX_DISPATCH_CONTINUE) {
                return rc;
            }

            ctx->sigver.verified = 1;
        }
    } else if (ctx->recv.cur_reqid == kXR_sigver) {
        ctx->sigver.pending = 0;
    }

    return BRIX_DISPATCH_CONTINUE;
}

/*
 * Policy table mapping (opcode, security_level) → whether a signature is required.
 * Levels mirror XRootD's brix_security_level: 0=none, 1=compatible (nothing
 * required), 2=standard (mutations + kXR_open), 3=intense (everything post-login),
 * 4=pedantic (everything). Session/auth state-machine opcodes (login, protocol,
 * auth, endsess, ping, sigver, bind) are always exempt. Returns non-zero when the
 * opcode must be signed at the given level.
 */
static int
brix_sigver_opcode_requires(uint16_t opcode, ngx_uint_t level)
{
    /* Policy table now lives in the shared gsi_core.c (single source with the
     * native client's signer). Level 4 (pedantic) folds into "everything". */
    return brix_gsi_sigver_required(opcode, (int) level);
}

/*
 * brix_signing_enforce_level — enforce the configured brix_security_level.
 *
 * Checks whether the current opcode requires a signature at the configured
 * security level.  If it does and the request was not signed (verified_signing=0),
 * rejects the request with kXR_NotAuthorized.
 */
ngx_int_t
brix_signing_enforce_level(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    if (!ctx->sigver.signing_active || conf->security_level == 0) {
        return BRIX_DISPATCH_CONTINUE;
    }

    if (brix_sigver_opcode_requires(ctx->recv.cur_reqid, conf->security_level)) {
        if (!ctx->sigver.verified) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: unsigned request %d rejected by security_level=%d",
                          (int) ctx->recv.cur_reqid, (int) conf->security_level);
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "request signing required for this opcode");
        }

        /* Pedantic mode: also enforce that the signature covered the payload. */
        if (conf->security_level >= 4 && ctx->sigver.nodata && ctx->recv.cur_dlen > 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: pedantic signing rejection: sigver nodata flag set but payload present");
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "payload signing required in pedantic mode");
        }
    }

    return BRIX_DISPATCH_CONTINUE;
}
