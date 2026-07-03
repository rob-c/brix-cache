/*
 * log.c - sanitized path logging helper shared across all protocols.
 */

#include "log.h"

/* forward — defined in src/path/path.c */
size_t brix_sanitize_log_string(const char *in, char *out, size_t outsz);

void
brix_log_safe_path(ngx_log_t *log, ngx_uint_t level, ngx_err_t err,
    const char *fmt, const char *path)
{
    char safe_path[512];

    brix_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(level, log, err, fmt, safe_path);
}
