/*
 * audit_handler.c — LOG-phase outcome classification + audit line.
 *
 * WHAT: after the response went out, maps the final status to a guard
 *   outcome (404 -> notfound, 401/403 -> authfail), runs guard_classify_post,
 *   and appends one audit line per flagged request.
 * WHY:  post-response signals (not-found storms, repeated auth failures) only
 *   exist once the backend has answered — the LOG phase is where the status
 *   is final and every request passes through exactly once.
 * HOW:  skip requests already audited by the ACCESS bounce (request ctx flag),
 *   rebuild guard_request_t with outcome fields, classify, write.
 */

#include "guard_http.h"

/* ---- Final HTTP status -> guard outcome ----
 *
 * WHAT: maps the response status to the guard's outcome classes: 404 ->
 *   NOTFOUND, 401/403 -> AUTHFAIL, other 4xx/5xx -> ERROR, else OK.
 *
 * WHY: classify_post keys on outcomes, not raw statuses, so the same
 *   thresholds mean the same thing across HTTP and root://.
 *
 * HOW: 1. Compare against the nginx status constants in signal order.
 */
static guard_outcome_t
status_to_outcome(ngx_uint_t status)
{
    if (status == NGX_HTTP_NOT_FOUND) {
        return OUTCOME_NOTFOUND;                        /* 404 */
    }
    if (status == NGX_HTTP_UNAUTHORIZED || status == NGX_HTTP_FORBIDDEN) {
        return OUTCOME_AUTHFAIL;                        /* 401 / 403 */
    }
    if (status >= NGX_HTTP_BAD_REQUEST) {
        return OUTCOME_ERROR;
    }
    return OUTCOME_OK;
}

/* ---- LOG-phase handler: audit post-response signals ----
 *
 * WHAT: always returns NGX_OK (LOG handlers cannot affect the response);
 *   appends an audit line when classify_post flags the final outcome.
 *
 * WHY: one line per notfound/authfail is the raw material for fail2ban's
 *   threshold jails; requests the ACCESS phase already bounced were audited
 *   there and must not double-log.
 *
 * HOW: 1. Skip unguarded locations and ACCESS-bounced requests (ctx flag).
 *      2. Rebuild guard_request_t and stamp the final status/outcome.
 *      3. classify_post; write the audit line only on a flagged reason.
 */
ngx_int_t
ngx_http_brix_guard_log_handler(ngx_http_request_t *r)
{
    ngx_http_brix_guard_loc_conf_t *lcf;
    ngx_http_brix_guard_ctx_t      *ctx;
    guard_request_t                   req;
    guard_reason_t                    reason;
    char                              pathbuf[BRIX_GUARD_PATH_BUF];
    char                              ipbuf[BRIX_GUARD_IP_BUF];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_guard_module);
    if (!lcf->enable) {
        return NGX_OK;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_guard_module);
    if (ctx != NULL && ctx->bounced) {
        return NGX_OK;   /* already logged at ACCESS phase (pre-reason) */
    }

    ngx_http_brix_guard_build_request(r, lcf, &req,
        pathbuf, sizeof(pathbuf), ipbuf, sizeof(ipbuf));
    req.status_code = (int) r->headers_out.status;
    req.outcome     = status_to_outcome(r->headers_out.status);

    reason = guard_classify_post(&lcf->ruleset, &req);
    if (reason != GUARD_R_NONE) {
        ngx_http_brix_guard_write_audit(r, lcf, &req, reason);
    }
    return NGX_OK;
}
