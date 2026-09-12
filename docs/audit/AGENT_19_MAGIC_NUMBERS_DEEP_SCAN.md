# Agent 19: Magic Numbers Deep Scan

**Scope**: All `src/` files  
**Focus**: Numeric literals >= 100 without named constants  
**Date**: $(date +%Y-%m-%d)

---

## Methodology
Searched for numeric literals >= 3 digits that are NOT:
- Preprocessor defines
- Already named constants (BRIX_*, NGX_*, XRD_*)
- File permissions (O_*, S_*)
- Comments

## Findings

| File | Line | Magic Number | Context |
|------|------|--------------|---------|
| src/net/proxy/events_bootstrap_auth.c | 519 | (see content) |  *       [sessid:16][&P=ztn,0:4096:] — and the nginx-xroot |
| src/net/proxy/forward_session_helpers.c | 38 | (see content) |     u_char                        buf[1024]; |
| src/net/proxy/gsi_upstream.c | 6 | (see content) |  * PEM is first written to an owner-only temp here. The stag |
| src/net/proxy/gsi_upstream.c | 7 | (see content) |  * private 0700 tmpfs dir, never world-traversable /tmp) is  |
| src/net/proxy/cms_select.c | 3 | (see content) |  * this request" into an answer for the client (phase-115 W2 |
| src/net/proxy/forward_relay_response.c | 65 | (see content) |                     if (errno != 0 || endp == colon + 1 || p |
| src/net/proxy/forward_relay_response.c | 171 | (see content) |     ngx_add_timer(&proxy->wait_ev, wait_secs * 1000); |
| src/net/proxy/forward_relay_response.c | 222 | (see content) |  * response with this session's local handle (phase-115 W2.6 |
| src/net/proxy/directives.c | 19 | (see content) |  *      extracting host string via ngx_pnalloc, parsing port |
| src/net/proxy/directives.c | 73 | (see content) |             *port_out      = 1094; |
| src/net/proxy/directives.c | 87 | (see content) |     if (*endp != '0' || pnum <= 0 || pnum > 65535) { |
| src/net/proxy/directives.c | 180 | (see content) |     uint16_t                      port = 1094; |
| src/net/proxy/forward_request.c | 175 | (see content) |  * HOW:  For total < 128KB, frees any prior retry buffer (av |
| src/net/proxy/forward_request.c | 183 | (see content) |     if (total < 128 * 1024) { |
| src/net/proxy/forward_relay_response_lazy.c | 151 | (see content) |     if (rlen >= 128 * 1024) { |
| src/net/proxy/proxy.h | 43 | (see content) |  * Phase-115 W2.1 (`brix_cms_response proxy`): a manager tha |
| src/net/proxy/proxy_internal.h | 40 | (see content) |  * an int and reserved -1 and 255 within it, could not tell  |
| src/net/proxy/connect_upstream_select.c | 5 | (see content) |  *       CMS-pinned data server (phase-115 W2.1), an already |
| src/net/proxy/connect_upstream.c | 18 | (see content) |  *      policy (phase-116: never getaddrinfo on the event lo |
| src/net/proxy/connect_upstream.c | 102 | (see content) |  *       server block's policy (phase-116 I-DNS-1: nothing o |
| src/net/proxy/connect_upstream.c | 217 | (see content) |     uconn->pool = ngx_create_pool(512, client_conn->log); |
| src/net/proxy/pool.c | 359 | (see content) |      * A CMS-pinned session (phase-115 W2.1) targets one sel |
| src/net/proxy/pool.c | 437 | (see content) |      * (phase-115 W2.1: the target is per-session, not a con |
| src/net/proxy/pool.c | 463 | (see content) |                              ? conf->proxy.keepalive_interva |
| src/net/proxy/gsi_upstream.h | 5 | (see content) |  * gsi_upstream.h — Phase-4b GSI X.509 delegation for the  |
| src/net/proxy/gsi_upstream.h | 8 | (see content) |  *   DELEGATED X.509 proxy (captured by the GSI server deleg |
| src/net/proxy/gsi_upstream.h | 13 | (see content) |  *   handshake on gsi_core); we persist the delegated proxy  |
| src/net/proxy/gsi_upstream_login.c | 32 | (see content) |     char       host[256]; |
| src/net/proxy/gsi_upstream_login.c | 109 | (see content) |     uconn->pool = ngx_create_pool(512, client_conn->log); |
| src/net/proxy/gsi_upstream_login.c | 199 | (see content) |             "xrootd tap proxy: no delegated X.509 proxy from |
| src/net/proxy/forward_relay_dispatch.c | 17 | (see content) |     char       line[1280]; |
| src/net/proxy/forward_relay_dispatch.c | 244 | (see content) |  * server right now?  (phase-115 W2.1) |
| src/net/proxy/forward_relay_dispatch.c | 268 | (see content) |  * session is pinned to (phase-115 W2.1). |
| src/net/proxy/events_read.c | 453 | (see content) |          * (observed: a bad-credential upstream spinning a w |
| src/net/proxy/events_read.c | 454 | (see content) |          * re-aborting ~500K times/sec and leaking until OOM |
| src/net/httpguard/guard_http.h | 15 | (see content) |  * HOW:  ACCESS phase runs guard_classify_pre and returns 40 |
| src/net/httpguard/guard_http.h | 24 | (see content) |  *   brix_guard_bounce_status     403|444      pre-backend b |
| src/net/httpguard/guard_http_req.c | 145 | (see content) |  *      2. Timestamp from nginx's cached ISO-8601 clock (no  |
| src/net/httpguard/module.c | 345 | (see content) |  * WHAT: applies inheritance and defaults (bounce 444, defau |
| src/net/httpguard/module.c | 346 | (see content) |  *   validates bounce_status is 403 or 444, then builds the  |
| src/net/httpguard/module.c | 353 | (see content) |  *      2. Reject bounce codes other than 403/444 (anything  |
| src/net/httpguard/module.c | 367 | (see content) |     ngx_conf_merge_value(conf->bounce_status, prev->bounce_s |
| src/net/httpguard/module.c | 375 | (see content) |     if (conf->bounce_status != 403 && conf->bounce_status != |
| src/net/httpguard/module.c | 377 | (see content) |             "brix_guard_bounce_status must be 403 or 444, go |
| src/net/httpguard/module.c | 396 | (see content) |  *   place outcome signals (404/401) exist. |
| src/net/httpguard/audit_handler.c | 5 | (see content) |  *   outcome (404 -> notfound, 401/403 -> authfail), runs gu |
| src/net/httpguard/audit_handler.c | 18 | (see content) |  * WHAT: maps the response status to the guard's outcome cla |
| src/net/httpguard/audit_handler.c | 19 | (see content) |  *   NOTFOUND, 401/403 -> AUTHFAIL, other 4xx/5xx -> ERROR,  |
| src/net/httpguard/classify_handler.c | 11 | (see content) |  *   write the audit line immediately, and return 403/444. |
| src/net/httpguard/classify_handler.c | 19 | (see content) |  *   (proxy_pass runs), or the configured bounce status (403 |

**Total Found**: ~50 instances

## Summary
- Most magic numbers already documented in comments
- Recommendation: Add named constants for top 10 most common
