/* ------------------------------------------------------------------ */
/* Path Validation — Configuration Pre-flight Checks                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements configuration validation helpers that verify paths exist and have correct
 *      attributes during nginx startup. xrootd_validate_path() checks path existence, type (file vs directory),
 *      and access permissions with emerg-level logging on failure; xrootd_copy_conf_string() safely copies ngx_str_t
 *      values into null-terminated buffers for string parsing operations that require C-string semantics.
 *
 * WHY: These helpers are called during postconfiguration phase to validate that all configured paths (pki directories,
 *      cache roots, voms directories) exist before accepting client connections. Failure at this stage prevents
 *      runtime crashes when nginx attempts to access non-existent configuration resources under load. String copy helper
 *      ensures safe conversion from ngx_str_t (non-null-terminated) to C-string for operations like strtol parsing. */

/* ------------------------------------------------------------------ */
/* Section: Path Validation                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_validate_path() performs three-level validation on a configured path during nginx startup:
 *      existence check via stat(2), type verification (regular file vs directory vs either), and access permission
 *      check via access(2). Returns NGX_OK if all checks pass; returns NGX_ERROR with emerg-level log on any failure.
 *      NULL/empty paths are treated as optional — validation is skipped without error when path parameter is absent.
 *
 * WHY: Configuration validation prevents runtime failures where nginx would attempt to open non-existent files or
 *      directories under load, causing crashes that disrupt client sessions. Type verification ensures the configured
 *      resource matches expected semantics (e.g., vomsdir must be a directory not a file). Access mode check validates
 *      permission level required for the operation (read-only access for certificate loading vs read+execute for directory traversal). */

/* ------------------------------------------------------------------ */
/* Section: String Copy Helper                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_copy_conf_string() converts an ngx_str_t into a null-terminated C-string buffer allocated from nginx pool.
 *      Copies src->len bytes via ngx_memcpy, appends NUL terminator, and sets dst.len = src->len for consistency with
 *      the original string representation. Returns NGX_CONF_ERROR on allocation failure; NGX_CONF_OK otherwise.
 *
 * WHY: nginx uses ngx_str_t (length + data pointer) rather than C-strings throughout its codebase — operations like strtol(),
 *      strchr(), and strcmp() require null-terminated buffers. This helper provides safe conversion without using strlen/strcpy
 *      on ngx_str_t (which would be incorrect since ngx_str_t is not guaranteed to be null-terminated). Pool allocation ensures
 *      memory is reclaimed when configuration reloads or worker processes exit. */

/* ---- Function: xrootd_validate_path() ----
 *
 * WHAT: Validates a configured path during nginx startup performing three checks: existence (stat), type verification
 *      (regular file vs directory vs either), and access permission (R_OK/W_OK/X_OK). NULL/empty paths are optional —
 *      skipped without error. Returns NGX_OK on success; NGX_ERROR with emerg-level log describing the specific failure.
 *
 * WHY: Prevents runtime failures where nginx attempts to open non-existent configuration resources under load, causing
 *      crashes that disrupt client sessions. Type verification ensures configured resource matches expected semantics (e.g.,
 *      vomsdir must be a directory not a file). Access mode check validates permission level required for the operation. */

/* ---- Function: xrootd_copy_conf_string() ----
 *
 * WHAT: Converts an ngx_str_t into a null-terminated C-string buffer allocated from nginx pool, copying src->len bytes
 *      via ngx_memcpy and appending NUL terminator. Returns NGX_CONF_ERROR on allocation failure; NGX_CONF_OK otherwise.
 *
 * WHY: nginx uses ngx_str_t (length + data pointer) rather than C-strings throughout its codebase — operations like strtol(),
 *      strchr(), and strcmp() require null-terminated buffers. This helper provides safe conversion without using strlen/strcpy
 *      on ngx_str_t (which would be incorrect since ngx_str_t is not guaranteed to be null-terminated). Pool allocation ensures
 *      memory is reclaimed when configuration reloads or worker processes exit. */

#include "config.h"

ngx_int_t
xrootd_validate_path(ngx_conf_t *cf, const char *label, const ngx_str_t *path,
    xrootd_path_kind_t kind, int access_mode)
{
    struct stat st;

    if (path == NULL || path->len == 0 || path->data == NULL) {
        return NGX_OK;
    }

    if (stat((char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: %s path \"%s\" is not accessible",
                           label, path->data);
        return NGX_ERROR;
    }

    switch (kind) {
    case XROOTD_PATH_REGULAR_FILE:
        if (!S_ISREG(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a regular file",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case XROOTD_PATH_DIRECTORY:
        if (!S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case XROOTD_PATH_FILE_OR_DIRECTORY:
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a file or directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;
    }

    if (access_mode != 0 && access((char *) path->data, access_mode) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: %s path \"%s\" failed permission check",
                           label, path->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

char *
xrootd_copy_conf_string(ngx_conf_t *cf, const ngx_str_t *src, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return NGX_CONF_OK;
}
