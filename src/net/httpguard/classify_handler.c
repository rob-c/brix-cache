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
 * WHAT: returns NGX_DECLINED for clean/unguarded requests (proxy_pass runs),
 *   or the configured bounce status (403/444) after auditing a signature or
 *   grammar hit. (Implementation lands with the request builder — this stub
 *   declines everything.)
 *
 * WHY: keeps scanner noise off the backend and gives fail2ban its
 *   pre-backend signals.
 *
 * HOW: 1. Stub: decline.
 */
ngx_int_t
ngx_http_xrootd_guard_access_handler(ngx_http_request_t *r)
{
    (void) r;
    return NGX_DECLINED;
}
