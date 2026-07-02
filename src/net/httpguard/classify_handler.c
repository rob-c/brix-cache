/*
 * classify_handler.c — ACCESS-phase pre-backend bounce.
 *
 * WHAT: runs guard_classify_pre on every guarded request before proxy_pass;
 *   bounces signature/grammar hits with the configured status so junk never
 *   reaches the ARC / XrdHttp backend.
 * WHY:  the ACCESS phase is the last hook before the content phase hands the
 *   request to the upstream — the one place a pre-backend verdict can act.
 * HOW:  build guard_request_t (guard_http_req.c), classify, and on BOUNCE
 *   record the reason in the request ctx (the LOG handler skips those),
 *   write the audit line immediately, and return 403/444.
 */

#include "guard_http.h"

/* ---- ACCESS-phase handler: bounce junk pre-backend ----
 *
 * WHAT: returns NGX_DECLINED for clean/unguarded/internal requests
 *   (proxy_pass runs), or the configured bounce status (403/444) after
 *   auditing a signature or grammar hit.
 *
 * WHY: keeps scanner noise off the backend and gives fail2ban its
 *   pre-backend signals. 444 maps to nginx's close-without-response —
 *   ideal for scanners; 403 sends a normal error page.
 *
 * HOW: 1. Skip when the location has no guard or the request is internal.
 *      2. Ensure the per-request ctx exists (LOG phase reads it).
 *      3. Normalize into guard_request_t (stack scratch) + classify_pre.
 *      4. On BOUNCE: record the reason, audit immediately (guaranteed even
 *         if the request never reaches the LOG phase), return the bounce
 *         status.
 */
ngx_int_t
ngx_http_xrootd_guard_access_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_guard_loc_conf_t *lcf;
    ngx_http_xrootd_guard_ctx_t      *ctx;
    guard_request_t                   req;
    guard_reason_t                    why = GUARD_R_NONE;
    char                              pathbuf[XROOTD_GUARD_PATH_BUF];
    char                              ipbuf[XROOTD_GUARD_IP_BUF];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_guard_module);
    if (!lcf->enable || r->internal) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_guard_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_guard_module);
    }

    ngx_http_xrootd_guard_build_request(r, lcf, &req,
        pathbuf, sizeof(pathbuf), ipbuf, sizeof(ipbuf));

    if (guard_classify_pre(&lcf->ruleset, &req, &why) == GUARD_BOUNCE) {
        ctx->pre_reason = why;
        ctx->bounced    = 1;
        req.status_code = (int) lcf->bounce_status;
        ngx_http_xrootd_guard_write_audit(r, lcf, &req, why);
        return lcf->bounce_status;      /* 403 or 444 (NGX_HTTP_CLOSE) */
    }

    return NGX_DECLINED;                /* clean -> proxy_pass runs */
}
