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

/*
 * brix_token_diag_t - diagnostic context bundling the log sink and its label.
 *
 * WHAT: Pairs the optional ngx_log_t and the caller's context label so every
 *       stage receives error-reporting state as a single argument.
 * WHY:  log and label travel together to every failure path; bundling them
 *       keeps each helper at or below the five-parameter limit without adding
 *       a global or duplicating the NULL-label fallback per call site.
 * HOW:  Plain-old-data value; callers pass it by const pointer.
 */
typedef struct {
    ngx_log_t  *log;
    const char *label;
} brix_token_diag_t;

/*
 * brix_token_label - resolve the diagnostic label with a default.
 *
 * WHAT: Returns diag->label, or "xrootd" when the caller left it NULL.
 * WHY:  Every error path prefixes its message with the caller's context; a
 *       single resolver keeps the fallback identical across all call sites.
 * HOW:  Ternary select — no allocation, no side effects.
 */
static const char *
brix_token_label(const brix_token_diag_t *diag)
{
    return diag->label ? diag->label : "xrootd";
}

/*
 * brix_token_validate_args - reject malformed arguments and build a C path.
 *
 * WHAT: Validates path/buffer arguments and copies path into a NUL-terminated
 *       pathz buffer (size NGX_MAX_PATH) on success.
 * WHY:  Bounds must be checked before any file access; concentrating the guard
 *       in one helper keeps the reader loop free of validation branches while
 *       preserving the original EINVAL semantics and log message.
 * HOW:  Rejects NULL/empty/over-long path, NULL buf, or capacity < 2 bytes.
 *       On rejection logs (when log != NULL), sets errno=EINVAL, returns
 *       NGX_ERROR. On success copies path->data + NUL terminator into pathz
 *       (a fixed NGX_MAX_PATH-byte buffer owned by the caller).
 */
static ngx_int_t
brix_token_validate_args(const ngx_str_t *path, const u_char *buf,
    size_t buf_sz, char *pathz, const brix_token_diag_t *diag)
{
    if (path == NULL || path->len == 0 || path->len >= NGX_MAX_PATH
        || buf == NULL || buf_sz < 2)
    {
        if (diag->log != NULL) {
            ngx_log_error(NGX_LOG_ERR, diag->log, 0,
                          "%s token file path missing or too long",
                          brix_token_label(diag));
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memcpy(pathz, path->data, path->len);
    pathz[path->len] = '\0';
    return NGX_OK;
}

/*
 * brix_token_slurp - bounded read of a token file into buf.
 *
 * WHAT: Opens pathz, reads up to buf_sz-1 bytes into buf, and returns the byte
 *       count via *n_out. Does not NUL-terminate or trim (caller's job).
 * WHY:  Isolates all stdio + errno handling (open failure, read error with
 *       errno preservation across fclose) so the top-level flow stays linear.
 * HOW:  fopen("rb"), set FD_CLOEXEC, fread. On ferror, saves errno across
 *       fclose, logs, returns NGX_ERROR. On success closes and reports count.
 *       Read-only stream: fclose status cannot affect already-consumed data.
 */
static ngx_int_t
brix_token_slurp(const char *pathz, u_char *buf, size_t buf_sz, size_t *n_out,
    const brix_token_diag_t *diag)
{
    FILE  *fp;
    size_t n;

    fp = fopen(pathz, "rb");
    if (fp == NULL) {
        if (diag->log != NULL) {
            ngx_log_error(NGX_LOG_ERR, diag->log, ngx_errno,
                          "%s cannot open token file \"%s\"",
                          brix_token_label(diag), pathz);
        }
        return NGX_ERROR;
    }
    (void) fcntl(fileno(fp), F_SETFD, FD_CLOEXEC);

    n = fread(buf, 1, buf_sz - 1, fp);
    if (ferror(fp)) {
        int saved = errno;
        (void) fclose(fp); /* phase74-fp: read-only stream, ferror already latched the read failure being reported */
        errno = saved;
        if (diag->log != NULL) {
            ngx_log_error(NGX_LOG_ERR, diag->log, ngx_errno,
                          "%s cannot read token file \"%s\"",
                          brix_token_label(diag), pathz);
        }
        return NGX_ERROR;
    }
    (void) fclose(fp); /* phase74-fp: read-only stream fully consumed, ferror checked above — close status cannot affect the data */

    *n_out = n;
    return NGX_OK;
}

/*
 * brix_token_trim - NUL-terminate and strip trailing whitespace in place.
 *
 * WHAT: NUL-terminates buf at n, then removes trailing isspace() bytes,
 *       returning the trimmed length.
 * WHY:  Token files commonly carry trailing CR/LF/space; trimming is a pure
 *       string transform best kept out of the I/O and validation stages.
 * HOW:  Terminates at n, then walks back over isspace() bytes, NUL-terminating
 *       as it shrinks. Returns the resulting length.
 */
static size_t
brix_token_trim(u_char *buf, size_t n)
{
    buf[n] = '\0';
    while (n > 0 && isspace((unsigned char) buf[n - 1])) {
        buf[--n] = '\0';
    }
    return n;
}

ngx_int_t
brix_token_read_file(const ngx_str_t *path, u_char *buf, size_t buf_sz,
    size_t *out_len, ngx_log_t *log, const char *label)
{
    char              pathz[NGX_MAX_PATH];
    size_t            n = 0;
    brix_token_diag_t diag;

    diag.log = log;
    diag.label = label;

    if (out_len != NULL) {
        *out_len = 0;
    }

    if (brix_token_validate_args(path, buf, buf_sz, pathz, &diag) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_token_slurp(pathz, buf, buf_sz, &n, &diag) != NGX_OK) {
        return NGX_ERROR;
    }

    n = brix_token_trim(buf, n);

    if (n == 0) {
        if (diag.log != NULL) {
            ngx_log_error(NGX_LOG_ERR, diag.log, 0,
                          "%s token file \"%s\" is empty",
                          brix_token_label(&diag), pathz);
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (out_len != NULL) {
        *out_len = n;
    }

    return NGX_OK;
}
