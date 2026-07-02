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

/* ---- LOG-phase handler: audit post-response signals ----
 *
 * WHAT: always returns NGX_OK (LOG handlers cannot affect the response);
 *   appends an audit line when classify_post flags the outcome.
 *   (Implementation lands with the audit writer — this stub is a no-op.)
 *
 * WHY: one line per notfound/authfail is the raw material for fail2ban's
 *   threshold jails.
 *
 * HOW: 1. Stub: no-op.
 */
ngx_int_t
ngx_http_xrootd_guard_log_handler(ngx_http_request_t *r)
{
    (void) r;
    return NGX_OK;
}
