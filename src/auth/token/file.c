/*
 * file.c - shared bounded bearer-token file reader.
 *
 * WHAT: Reads a bearer token from a file with configurable size limits. Opens the
 *       specified path, reads up to buf_sz-1 bytes into caller-provided buffer,
 *       strips trailing whitespace (CR/LF/space), and NUL-terminates the result.
 *      Returns token length via out_len pointer when provided.
 *
 * WHY: Token endpoints often write tokens to files for credential caching or
 *      service-account integration. This helper provides a safe bounded read that
 *      handles common file-format issues (trailing newlines, oversized content)
 *      without requiring callers to implement size limits and whitespace stripping.
 *      Used by token/validate.c for bearer-token validation from files and s3/auth.c
 *      for S3 credential retrieval. The label parameter enables callers to prefix
 *      error log messages with context (e.g., "token" vs "s3").
 *
 * HOW: Validates path non-empty, fits in NGX_MAX_PATH buffer, buf non-null with
 *      capacity >= 2 bytes. Copies path string via ngx_memcpy + NUL terminator. Opens
 *      file with fopen("rb") — sets FD_CLOEXEC to prevent inheritance across exec().
 *      Reads up to buf_sz-1 bytes via fread() (leaves room for NUL). Checks ferror()
 *      after read, saves errno before close. Strips trailing whitespace via isspace() loop.
 *      Rejects empty files (n==0) with EINVAL. Sets out_len on success if pointer non-null.
 *      Returns NGX_OK on success, NGX_ERROR on any failure with log message populated.
 */

#include "file.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

ngx_int_t
brix_token_read_file(const ngx_str_t *path, u_char *buf, size_t buf_sz,
    size_t *out_len, ngx_log_t *log, const char *label)
{
    char   pathz[NGX_MAX_PATH];
    FILE  *fp;
    size_t n;

    if (out_len != NULL) {
        *out_len = 0;
    }

    if (path == NULL || path->len == 0 || path->len >= sizeof(pathz)
        || buf == NULL || buf_sz < 2)
    {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "%s token file path missing or too long",
                          label ? label : "xrootd");
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memcpy(pathz, path->data, path->len);
    pathz[path->len] = '\0';

    fp = fopen(pathz, "rb");
    if (fp == NULL) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "%s cannot open token file \"%s\"",
                          label ? label : "xrootd", pathz);
        }
        return NGX_ERROR;
    }
    (void) fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    n = fread(buf, 1, buf_sz - 1, fp);
    if (ferror(fp)) {
        int saved = errno;
        fclose(fp);
        errno = saved;
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "%s cannot read token file \"%s\"",
                          label ? label : "xrootd", pathz);
        }
        return NGX_ERROR;
    }
    fclose(fp);

    buf[n] = '\0';
    while (n > 0 && isspace((unsigned char) buf[n - 1])) {
        buf[--n] = '\0';
    }

    if (n == 0) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "%s token file \"%s\" is empty",
                          label ? label : "xrootd", pathz);
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (out_len != NULL) {
        *out_len = n;
    }

    return NGX_OK;
}
