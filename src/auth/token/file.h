#ifndef BRIX_TOKEN_FILE_H
#define BRIX_TOKEN_FILE_H

#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t brix_token_read_file(const ngx_str_t *path, u_char *buf,
/* Reads a bearer token from a file with bounded size limit. Strips trailing
 * whitespace and NUL-terminates the result.
 * path:   ngx_str_t containing the file path to read
 * buf:    destination buffer for the token string
 * buf_sz: capacity of buf (must be >= 2)
 * out_len: optional pointer set to token length on success
 * log:    nginx log context for error messages
 * label:  prefix string used in error log messages (e.g. "token" or "s3")
 * Returns: NGX_OK on success, NGX_ERROR on any failure (path missing/empty,
 *          open/read error, empty file). */
    size_t buf_sz, size_t *out_len, ngx_log_t *log, const char *label);

#endif /* BRIX_TOKEN_FILE_H */
