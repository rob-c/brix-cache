#include "handshake.h"
#include "../gsi/gsi_core.h"   /* xrootd_gsi_sigver_required (shared policy) */

/* sigver.c — request signature verification (kXR_sigver HMAC-SHA256) and security-level enforcement
 * WHAT: Owns the "verify" half of XRootD request signing. Three entry points:
 *       xrootd_verify_pending_sigver() consumes the sigver state recorded when a
 *       kXR_sigver request arrived and validates that the immediately-following
 *       covered request matches the expected opcode and HMAC; the static
 *       xrootd_verify_sigver_hmac() recomputes the HMAC-SHA256 over the seqno,
 *       request header, and (unless sigver_nodata) the payload, comparing it in
 *       constant time against the client-supplied ctx->sigver_hmac; and
 *       xrootd_signing_enforce_level() rejects opcodes that the configured
 *       xrootd_security_level requires to be signed but were not.
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
 * HOW:  kXR_sigver records pending state (expected reqid, supplied HMAC, nodata
 *       flag, seqno) elsewhere; dispatch then calls xrootd_verify_pending_sigver()
 *       on the next request, which gates on ctx->signing_active, matches
 *       sigver_expectrid against cur_reqid, and delegates the cryptographic check
 *       to xrootd_verify_sigver_hmac() using ctx->signing_key via OpenSSL EVP_MAC
 *       (HMAC/SHA256, MAC + ctx cached on ctx for reuse). On success it sets
 *       ctx->verified_signing; xrootd_signing_enforce_level() later consults that
 *       flag plus xrootd_sigver_opcode_requires() (a level 0-4 policy table) to
 *       decide whether an unsigned opcode is permitted. */

/*
 * Recompute and compare the HMAC-SHA256 over the covered request. Lazily fetches
 * the OpenSSL "HMAC" EVP_MAC and allocates an EVP_MAC_CTX (both cached on ctx for
 * reuse across requests), keys it with the 32-byte ctx->signing_key, and updates
 * it with the big-endian seqno, the request header (ctx->hdr_buf,
 * XRD_REQUEST_HDR_LEN), and — unless ctx->sigver_nodata or there is no payload —
 * the request payload. The digest is compared against ctx->sigver_hmac with
 * CRYPTO_memcmp (constant time). Returns XROOTD_DISPATCH_CONTINUE on a match;
 * otherwise sends kXR_ServerError on a computation failure or kXR_NotAuthorized
 * on a digest mismatch and returns that send's result.
 */
static ngx_int_t
xrootd_verify_sigver_hmac(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    u_char computed[32];

    /* Shared HMAC (libxrdproto gsi_core) — recomputes over the SAME covered bytes
     * the client signs: seqno_be(8) || request header(24) || (payload unless the
     * nodata flag). Single source of the covered-byte layout. */
    if (!xrootd_gsi_sigver_hmac(ctx->signing_key, ctx->sigver_seqno,
                                ctx->hdr_buf, ctx->payload, ctx->cur_dlen,
                                ctx->sigver_nodata, computed))
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: sigver HMAC calculation failed for reqid=%d",
                      (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "signature verification failed");
    }

    if (CRYPTO_memcmp(computed, ctx->sigver_hmac, 32) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: sigver HMAC mismatch for reqid=%d",
                      (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "signature verification failed");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: sigver verified reqid=%d",
                   (int) ctx->cur_reqid);

    return XROOTD_DISPATCH_CONTINUE;
}

/*
 * Verify the pending kXR_sigver signature against the next request.
 *
 * kXR_sigver itself lives in src/session/signing.c because that request records
 * pending state. This file owns the other half: checking that pending state
 * before the covered request is routed.
 */
ngx_int_t
xrootd_verify_pending_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_int_t rc;

    ctx->verified_signing = 0;

    if (ctx->sigver_pending && ctx->cur_reqid != kXR_sigver) {
        ctx->sigver_pending = 0;

        if (ctx->signing_active) {
            if (ctx->sigver_expectrid != ctx->cur_reqid) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: sigver expectrid=%d but got reqid=%d",
                              (int) ctx->sigver_expectrid,
                              (int) ctx->cur_reqid);
                /* kXR_InvalidRequest: the request is malformed or not allowed now */
                return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                         "signed request opcode mismatch");
            }

            rc = xrootd_verify_sigver_hmac(ctx, c);
            if (rc != XROOTD_DISPATCH_CONTINUE) {
                return rc;
            }

            ctx->verified_signing = 1;
        }
    } else if (ctx->cur_reqid == kXR_sigver) {
        ctx->sigver_pending = 0;
    }

    return XROOTD_DISPATCH_CONTINUE;
}

/*
 * Policy table mapping (opcode, security_level) → whether a signature is required.
 * Levels mirror XRootD's xrootd_security_level: 0=none, 1=compatible (nothing
 * required), 2=standard (mutations + kXR_open), 3=intense (everything post-login),
 * 4=pedantic (everything). Session/auth state-machine opcodes (login, protocol,
 * auth, endsess, ping, sigver, bind) are always exempt. Returns non-zero when the
 * opcode must be signed at the given level.
 */
static int
xrootd_sigver_opcode_requires(uint16_t opcode, ngx_uint_t level)
{
    /* Policy table now lives in the shared gsi_core.c (single source with the
     * native client's signer). Level 4 (pedantic) folds into "everything". */
    return xrootd_gsi_sigver_required(opcode, (int) level);
}

/*
 * xrootd_signing_enforce_level — enforce the configured xrootd_security_level.
 *
 * Checks whether the current opcode requires a signature at the configured
 * security level.  If it does and the request was not signed (verified_signing=0),
 * rejects the request with kXR_NotAuthorized.
 */
ngx_int_t
xrootd_signing_enforce_level(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    if (!ctx->signing_active || conf->security_level == 0) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    if (xrootd_sigver_opcode_requires(ctx->cur_reqid, conf->security_level)) {
        if (!ctx->verified_signing) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: unsigned request %d rejected by security_level=%d",
                          (int) ctx->cur_reqid, (int) conf->security_level);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "request signing required for this opcode");
        }

        /* Pedantic mode: also enforce that the signature covered the payload. */
        if (conf->security_level >= 4 && ctx->sigver_nodata && ctx->cur_dlen > 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: pedantic signing rejection: sigver nodata flag set but payload present");
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "payload signing required in pedantic mode");
        }
    }

    return XROOTD_DISPATCH_CONTINUE;
}
