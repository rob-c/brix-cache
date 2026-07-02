/*
 * guard_http_req.c — ngx_http_request_t -> guard_request_t normalization.
 *
 * WHAT: the builder both phase handlers share (method -> op-class, credential
 *   detection, sanitized path/ip) and the audit-log file writer.
 * WHY:  the guard core is protocol-agnostic; this file is the single place
 *   HTTP request shape is interpreted, so ACCESS and LOG phases can never
 *   disagree about what was requested.
 * HOW:  NUL-terminate r->uri into stack scratch, sanitize it via the shared
 *   xrootd_sanitize_log_string helper; copy addr_text (not NUL-terminated by
 *   nginx) likewise; detect credentials from the verified client cert or an
 *   Authorization header; timestamp + append via one ngx_write_fd.
 */

#include "guard_http.h"

/* ---- HTTP method -> guard op-class ----
 *
 * WHAT: maps the nginx method flag to the guard's protocol-agnostic op-class
 *   (profile-independent baseline); anything unlisted is GUARD_OP_UNKNOWN.
 *
 * WHY: grammar rules are written against op-classes, not HTTP verbs, so the
 *   same ruleset semantics serve ARC, WebDAV, and root://.
 *
 * HOW: 1. switch on r->method's flag value.
 */
static guard_op_class_t
method_to_op(ngx_uint_t method)
{
    switch (method) {
    case NGX_HTTP_GET:
    case NGX_HTTP_HEAD:      return GUARD_OP_READ;
    case NGX_HTTP_PUT:
    case NGX_HTTP_POST:      return GUARD_OP_WRITE;
    case NGX_HTTP_DELETE:    return GUARD_OP_DELETE;
    case NGX_HTTP_PROPFIND:  return GUARD_OP_LIST;
    case NGX_HTTP_OPTIONS:   return GUARD_OP_INFO;
    default:                 return GUARD_OP_UNKNOWN;
    }
}

/* ---- Detect a presented credential ----
 *
 * WHAT: returns 1 if the client presented a verified TLS client certificate
 *   or a non-empty Authorization header, else 0.
 *
 * WHY: cred_present separates anonymous scanner noise from failing-but-
 *   authenticated users in the audit trail (and future signal tuning).
 *
 * HOW: 1. Under SSL, ask nginx for the client-verify result and accept
 *         exactly "SUCCESS" (the ngx_ssl_get_client_verify token — covers
 *         ssl_verify_client optional/optional_no_ca setups).
 *      2. Otherwise any non-empty Authorization header counts (bearer,
 *         basic — scheme is the backend's concern).
 */
static int
cred_present(ngx_http_request_t *r)
{
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        ngx_str_t verify;

        if (ngx_ssl_get_client_verify(r->connection, r->pool, &verify)
                == NGX_OK
            && verify.len == sizeof("SUCCESS") - 1
            && ngx_strncmp(verify.data, "SUCCESS", verify.len) == 0)
        {
            return 1;
        }
    }
#endif
    return r->headers_in.authorization != NULL
        && r->headers_in.authorization->value.len > 0;
}

/* ---- NUL-terminate an ngx_str_t into a fixed buffer ----
 *
 * WHAT: copies up to bufsz-1 bytes of src into buf and NUL-terminates;
 *   returns the copied length.
 *
 * WHY: both r->uri and addr_text are counted strings while the pure-C guard
 *   core takes C strings; truncation (never overflow) is the failure mode.
 *
 * HOW: 1. Clamp, ngx_memcpy, terminate.
 */
static size_t
copy_str_z(const ngx_str_t *src, char *buf, size_t bufsz)
{
    size_t copy_len = src->len < bufsz - 1 ? src->len : bufsz - 1;

    ngx_memcpy(buf, src->data, copy_len);
    buf[copy_len] = '\0';
    return copy_len;
}

/* ---- Build guard_request_t from the HTTP request ----
 *
 * WHAT: fills *out with ip/proto/op/path/cred_present; outcome starts
 *   PENDING with status 0 (the LOG handler overwrites both). pathbuf/ipbuf
 *   are caller-owned scratch that must outlive the classify call.
 *
 * WHY: single normalization point for both phase handlers, and the one place
 *   the wire-derived URI is sanitized (INVARIANT: every logged wire string
 *   goes through xrootd_sanitize_log_string).
 *
 * HOW: 1. NUL-terminate r->uri into local scratch (ngx_str_t is counted).
 *      2. Sanitize into pathbuf — control/quote/backslash/non-ASCII bytes
 *         become \xNN so the audit line can never be split or forged.
 *      3. Copy addr_text into ipbuf (nginx does not NUL-terminate it).
 *      4. proto = configured profile token; "http" when no profile is set
 *         (the audit line's proto= field must never be empty for fail2ban).
 */
void
ngx_http_xrootd_guard_build_request(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, guard_request_t *out,
    char *pathbuf, size_t pathbuf_sz, char *ipbuf, size_t ipbuf_sz)
{
    char uri_z[XROOTD_GUARD_PATH_BUF];

    copy_str_z(&r->uri, uri_z, sizeof(uri_z));
    out->path_len = xrootd_sanitize_log_string(uri_z, pathbuf, pathbuf_sz);
    out->path     = pathbuf;

    copy_str_z(&r->connection->addr_text, ipbuf, ipbuf_sz);
    out->ip = ipbuf;

    out->proto = lcf->profile.len ? (const char *) lcf->profile.data : "http";
    out->op           = method_to_op(r->method);
    out->cred_present = cred_present(r);
    out->outcome      = OUTCOME_PENDING;
    out->status_code  = 0;
}

/* ---- Append one audit line to the configured log ----
 *
 * WHAT: formats req/reason via guard_audit_format and appends the line to
 *   the location's audit log; silently a no-op when no log is configured or
 *   the line does not fit.
 *
 * WHY: one atomic write per signal is the fail2ban contract — the file is
 *   opened O_APPEND by ngx_conf_open_file, and a single sub-PIPE_BUF
 *   write(2) never interleaves across workers.
 *
 * HOW: 1. Bail without a usable log fd.
 *      2. Timestamp from nginx's cached ISO-8601 clock (no syscall,
 *         refreshed by the event loop; adapters own the clock per the
 *         guard-core contract).
 *      3. guard_audit_format into a stack line; append '\n'; one
 *         ngx_write_fd. A failed write is reported once per request on the
 *         connection log (fail2ban silently losing lines would be worse).
 */
void
ngx_http_xrootd_guard_write_audit(ngx_http_request_t *r,
    ngx_http_xrootd_guard_loc_conf_t *lcf, const guard_request_t *req,
    guard_reason_t reason)
{
    char    line[XROOTD_GUARD_PATH_BUF + 256];
    char    ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    size_t  ts_len;
    size_t  line_len;

    if (lcf->audit_log == NULL || lcf->audit_log->fd == NGX_INVALID_FILE) {
        return;
    }

    ts_len = ngx_cached_http_log_iso8601.len;
    if (ts_len >= sizeof(ts)) {
        ts_len = sizeof(ts) - 1;
    }
    ngx_memcpy(ts, ngx_cached_http_log_iso8601.data, ts_len);
    ts[ts_len] = '\0';

    line_len = guard_audit_format(req, reason, ts, line, sizeof(line) - 1);
    if (line_len == 0) {
        return;
    }
    line[line_len++] = '\n';

    if (ngx_write_fd(lcf->audit_log->fd, line, line_len)
        != (ssize_t) line_len)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      "xrootd_guard: audit log write failed");
    }
}
