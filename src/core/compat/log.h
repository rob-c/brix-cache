#ifndef XROOTD_COMPAT_LOG_H
#define XROOTD_COMPAT_LOG_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_log_safe_path — sanitize path and emit via ngx_log_error.
 *
 * Escapes control bytes, quotes, backslashes, and non-ASCII in path before
 * substituting it into fmt (which must contain exactly one %s placeholder).
 */
void xrootd_log_safe_path(ngx_log_t *log, ngx_uint_t level, ngx_err_t err,
    const char *fmt, const char *path)
    __attribute__((format(printf, 4, 0)));

#endif /* XROOTD_COMPAT_LOG_H */
