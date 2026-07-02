/*
 * guard_http_req.c — ngx_http_request_t -> guard_request_t normalization.
 *
 * WHAT: the builder both phase handlers share (method -> op-class, credential
 *   detection, sanitized path) and the audit-log file writer.
 * WHY:  the guard core is protocol-agnostic; this file is the single place
 *   HTTP request shape is interpreted, so ACCESS and LOG phases can never
 *   disagree about what was requested.
 * HOW:  sanitize r->uri via the shared xrootd_sanitize_log_string helper into
 *   a caller stack buffer; detect credentials from the verified client cert
 *   or an Authorization header; timestamp + append via one ngx_write_fd.
 */

#include "guard_http.h"

/* ---- Build guard_request_t from the HTTP request ----
 *
 * WHAT: fills *out with ip/proto/op/path/cred_present, outcome PENDING.
 *   (Implementation lands next task — stub zeroes the request.)
 *
 * WHY: single normalization point for both phase handlers.
 *
 * HOW: 1. Stub: empty request.
 */
void
ngx_http_xrootd_guard_build_request(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, guard_request_t *out,
    char *pathbuf, size_t pathbuf_sz)
{
    (void) r; (void) lcf;
    if (pathbuf_sz > 0) {
        pathbuf[0] = '\0';
    }
    ngx_memzero(out, sizeof(*out));
    out->ip    = "";
    out->proto = "";
    out->path  = pathbuf;
}

/* ---- Append one audit line to the configured log ----
 *
 * WHAT: formats req/reason via guard_audit_format and appends the line.
 *   (Implementation lands with the LOG handler — stub is a no-op.)
 *
 * WHY: one atomic write per signal is the fail2ban contract.
 *
 * HOW: 1. Stub: no-op.
 */
void
ngx_http_xrootd_guard_write_audit(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, const guard_request_t *req,
    guard_reason_t reason)
{
    (void) r; (void) lcf; (void) req; (void) reason;
}
