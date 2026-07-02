/*
 * helpers.c — startup config-validation helpers (path checks + ngx_str_t copy).
 * Each function is documented at its definition below.
 */

#include "config.h"

/* Validate a configured path at startup: existence (stat), type
 * (file/dir/either), and access mode (R/W/X_OK).  A NULL/empty path is
 * optional and skipped.  Returns NGX_OK, or NGX_ERROR with an emerg log
 * naming the failure. */
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

/* Copy an ngx_str_t into a NUL-terminated C string in cf->pool (ngx_str_t is
 * not NUL-terminated, so strtol/strchr/etc. need this).  Returns NGX_CONF_OK,
 * or NGX_CONF_ERROR on allocation failure. */
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
