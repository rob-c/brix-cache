/*
 * guard_audit_http.c — see guard_audit_http.h.
 *
 * The one place an HTTP request becomes a guard_request_t. Everything here is
 * bounded stack work: no allocation, no request-lifetime references escaping,
 * and the URI is copied out of the request buffer before it is sanitized
 * (r->uri.data is NOT NUL-terminated — sanitizing in place would read past
 * the span and leak adjacent header bytes into the audit line).
 */
#include "guard_audit_http.h"

#include "core/http/http_headers.h"
#include "fs/path/path.h"                  /* brix_sanitize_log_string */

void
brix_http_guard_audit(ngx_http_request_t *r, const char *proto,
    guard_reason_t reason, guard_op_class_t op, ngx_uint_t status)
{
    guard_request_t  req;
    char             ipbuf[64];
    char             rawbuf[256];
    char             san[256];
    char             line[512];
    char             ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    size_t           n, ts_len;

    n = ngx_min(r->connection->addr_text.len, sizeof(ipbuf) - 1);
    ngx_memcpy(ipbuf, r->connection->addr_text.data, n);
    ipbuf[n] = '\0';

    n = ngx_min(r->uri.len, sizeof(rawbuf) - 1);
    ngx_memcpy(rawbuf, r->uri.data, n);
    rawbuf[n] = '\0';

    req.ip           = ipbuf;
    req.proto        = proto;
    req.op           = op;
    req.path         = san;
    req.path_len     = brix_sanitize_log_string(rawbuf, san, sizeof(san));
    req.cred_present = (brix_http_get_header(r, "authorization").len > 0);
    req.outcome      = OUTCOME_PENDING;
    req.status_code  = (int) status;

    ts_len = ngx_cached_http_log_iso8601.len;
    if (ts_len >= sizeof(ts)) {
        ts_len = sizeof(ts) - 1;
    }
    ngx_memcpy(ts, ngx_cached_http_log_iso8601.data, ts_len);
    ts[ts_len] = '\0';

    if (guard_audit_format(&req, reason, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "%s", line);
    }
}
