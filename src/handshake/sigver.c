#include "handshake.h"

static void
xrootd_sigver_seqno_be(uint64_t seq, u_char out[8])
{
    out[0] = (u_char) (seq >> 56);
    out[1] = (u_char) (seq >> 48);
    out[2] = (u_char) (seq >> 40);
    out[3] = (u_char) (seq >> 32);
    out[4] = (u_char) (seq >> 24);
    out[5] = (u_char) (seq >> 16);
    out[6] = (u_char) (seq >> 8);
    out[7] = (u_char) seq;
}

static ngx_int_t
xrootd_verify_sigver_hmac(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    u_char        seqno_be[8];
    u_char        computed[32];
    OSSL_PARAM    params[2];
    size_t        clen;
    int           ok;

    xrootd_sigver_seqno_be(ctx->sigver_seqno, seqno_be);

    if (ctx->sigver_mac == NULL) {
        ctx->sigver_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (ctx->sigver_mac == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd: sigver HMAC provider unavailable");
            return xrootd_send_error(ctx, c, kXR_ServerError,
                                     "signature verification unavailable");
        }
    }

    if (ctx->sigver_mac_ctx == NULL) {
        ctx->sigver_mac_ctx = EVP_MAC_CTX_new(ctx->sigver_mac);
        if (ctx->sigver_mac_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd: sigver HMAC context allocation failed");
            return xrootd_send_error(ctx, c, kXR_ServerError,
                                     "signature verification unavailable");
        }
    }

    clen = sizeof(computed);
    ok = 0;

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx->sigver_mac_ctx, ctx->signing_key, 32, params) == 1
        && EVP_MAC_update(ctx->sigver_mac_ctx, seqno_be, 8) == 1
        && EVP_MAC_update(ctx->sigver_mac_ctx, ctx->hdr_buf,
                          XRD_REQUEST_HDR_LEN) == 1)
    {
        if (ctx->sigver_nodata
            || ctx->payload == NULL
            || ctx->cur_dlen == 0
            || EVP_MAC_update(ctx->sigver_mac_ctx, ctx->payload,
                              ctx->cur_dlen) == 1)
        {
            ok = (EVP_MAC_final(ctx->sigver_mac_ctx, computed, &clen,
                                sizeof(computed)) == 1);
        }
    }

    if (!ok || clen != sizeof(computed)) {
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

    if (ctx->sigver_pending && ctx->cur_reqid != kXR_sigver) {
        ctx->sigver_pending = 0;

        if (ctx->signing_active) {
            if (ctx->sigver_expectrid != ctx->cur_reqid) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: sigver expectrid=%d but got reqid=%d",
                              (int) ctx->sigver_expectrid,
                              (int) ctx->cur_reqid);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "signed request opcode mismatch");
            }

            rc = xrootd_verify_sigver_hmac(ctx, c);
            if (rc != XROOTD_DISPATCH_CONTINUE) {
                return rc;
            }
        }
    } else if (ctx->cur_reqid == kXR_sigver) {
        ctx->sigver_pending = 0;
    }

    return XROOTD_DISPATCH_CONTINUE;
}
