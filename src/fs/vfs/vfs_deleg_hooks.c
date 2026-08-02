/*
 * vfs_deleg_hooks.c — call-ready S3-STS and krb5 delegation hooks
 * (phase-70 §5.5, §5.7). Split verbatim from vfs_deleg.c (P90-70.9 made room
 * there for the exchange-cache integration).
 *
 * WHAT: The two origin-leg delegation seams that compile and are call-ready
 *       but are NOT yet driven from brix_vfs_deleg_live_cred:
 *       brix_vfs_deleg_sts_cred()   — S3 STS assume-role → sd_remote cred form.
 *       brix_vfs_deleg_krb5_token() — first GSSAPI leg AS the inbound user.
 *
 * WHY:  Both wait on capture-site/config work owned elsewhere (see each DEFERRED
 *       note); keeping them out of the hot materialiser file keeps that file
 *       within the size budget while the hooks stay buildable and unit-linkable.
 */
#include "vfs_internal.h"
#include "auth/s3/sts.h"                 /* brix_s3_sts_assume  (§5.5) */
#include "auth/krb5/forward.h"           /* brix_krb5_deleg_to_origin (§5.7) */

/* ---- brix_vfs_deleg_sts_cred (call-ready hook, §5.5) -----------------------
 *
 * WHAT: Exchange the node's S3 service credential for temporary credentials
 *       scoped to the inbound identity via brix_s3_sts_assume(), and stamp the
 *       result onto cred->s3_ak/s3_sk/s3_region (mode EXCHANGE).
 *
 * WHY:  An S3 SigV4 secret is never transmitted, so the origin cannot be handed
 *       the caller's key; STS is the EXCHANGE path (§5.5). This helper is the
 *       single seam where the STS result becomes the sd_remote-consumable cred
 *       form, mirroring brix_vfs_deleg_exchange for bearers.
 *
 * HOW:  Calls brix_s3_sts_assume() with the ctx identity and the caller-supplied
 *       conf; on NGX_OK borrows the pool-copied ak/sk/region onto *cred. On
 *       failure → deny (never the service cred under fallback-deny). Secrets are
 *       never logged.
 *
 * DRIVEN (phase-70 §5.5 origin leg closed): both prerequisites are now wired.
 *       (a) The STS conf source exists — brix_backend_s3_sts_access_key/
 *       _secret_key/_region/_ttl (+ the pre-existing _endpoint/_role) are stamped
 *       onto the live-cred bag by brix_proto_deleg_stamp_conf (deleg_wire.c) via
 *       brix_vfs_deleg_set_sts, reachable from every front-door capture site.
 *       (b) sd_remote's cred path threads s3_ak/sk/region/session through to the
 *       origin keys, and sd_s3_sign_ex folds the STS session token into
 *       x-amz-security-token + the SigV4 signature. brix_vfs_deleg_live_cred now
 *       calls this from the no-forwardable-bytes branch when the leaf backend
 *       accepts BRIX_SD_CRED_S3. */
ngx_int_t
brix_vfs_deleg_sts_cred(brix_vfs_ctx_t *ctx, const brix_s3_sts_conf_t *cf,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    ngx_str_t ak = ngx_null_string;
    ngx_str_t sk = ngx_null_string;
    ngx_str_t session = ngx_null_string;
    brix_s3_sts_out_t out = { &ak, &sk, &session };

    *use_cred = 0;

    if (ctx == NULL || cf == NULL) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_MISSING);
    }

    if (brix_s3_sts_assume(ctx->pool, ctx->identity, cf, &out, ctx->log)
        != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: S3 STS exchange failed - denying (no service-cred fallback "
            "for EXCHANGE)");
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_EXCHANGE);
    }

    cred->s3_ak     = (const char *) ak.data;
    cred->s3_sk     = (const char *) sk.data;
    cred->s3_region = (cf->region.len > 0) ? (const char *) cf->region.data
                                           : NULL;
    /* STS temporary credentials are unusable without their session token: it
     * must ride in x-amz-security-token AND the SigV4 signature on every origin
     * request (sd_s3_sign_ex folds it in). GetSessionToken/AssumeRole always
     * return one; an empty session (defensive) leaves it NULL. */
    cred->s3_session = (session.len > 0) ? (const char *) session.data : NULL;
    cred->mode       = BRIX_CRED_EXCHANGE;
    *use_cred        = 1;

    return NGX_OK;
}

/* ---- brix_vfs_deleg_krb5_token (call-ready hook, §5.7) ---------------------
 *
 * WHAT: Initiate the first GSSAPI leg to the origin AS the inbound user, using a
 *       forwardable delegated GSS credential, via brix_krb5_deleg_to_origin().
 *
 * WHY:  krb5 is only backend-usable by GSSAPI forwarding (§5.7); this seam turns
 *       the captured delegated cred + origin service principal into the first-leg
 *       token the origin-auth caller then drives to completion.
 *
 * HOW:  Guarded by brix_krb5_forward_available() so a build without krb5, or a
 *       request without a forwardable ticket, cleanly reports unavailable (the
 *       caller falls back to SELECT). On success *out_token holds the first-leg
 *       GSS token (pool-copied).
 *
 * RETAINED REFERENCE DIALECT — SUPERSEDED, not on the production path. The live
 *       krb5 origin leg is the RAW AP-REQ path (brix_cache_origin_auth_krb5_raw,
 *       driven from origin_protocol_bootstrap.c), because stock XRootD krb5
 *       speaks raw krb5_rd_req, NOT a GSSAPI gss_init_sec_context init-token
 *       exchange (phase-88 UPDATE (iv); phase-92 §5). This GSSAPI-init hook has
 *       zero production callers and is kept only as a reference implementation of
 *       the GSSAPI dialect (compiles, exercised by its own unit). Do NOT read the
 *       absence of a caller as INFRA-BLOCKED — it is deliberately retained-unused. */
ngx_int_t
brix_vfs_deleg_krb5_token(brix_vfs_ctx_t *ctx, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token)
{
    if (ctx == NULL || out_token == NULL) {
        return NGX_ERROR;
    }

    if (!brix_krb5_forward_available()) {
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "brix: krb5 credential forwarding unavailable - falling back to "
            "SELECT");
        return NGX_ERROR;
    }

    return brix_krb5_deleg_to_origin(ctx->pool, deleg_gss_cred,
        origin_service_princ, out_token, ctx->log);
}
