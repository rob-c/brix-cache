#include "vfs_internal.h"

xrootd_vfs_dir_t *
xrootd_vfs_opendir(xrootd_vfs_ctx_t *ctx, int *err_out)
{
    xrootd_vfs_dir_t *dh;
    const char       *path;
    ngx_msec_t        start;
    int               saved_errno;

    start = ngx_current_msec;

    if (err_out != NULL) {
        *err_out = 0;
    }

    if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, xrootd_vfs_ctx_path(ctx),
                                  XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    path = xrootd_vfs_ctx_path(ctx);
    dh = ngx_pcalloc(ctx->pool, sizeof(*dh));
    if (dh == NULL) {
        errno = ENOMEM;
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    dh->path = xrootd_vfs_copy_path(ctx->pool, path);
    if (dh->path == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    dh->dir = opendir(path);
    if (dh->dir == NULL) {
        saved_errno = errno;
        if (err_out != NULL) {
            *err_out = errno;
        }
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NULL;
    }

    dh->pool = ctx->pool;
    dh->log = ctx->log;

    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_DIRLIST, NULL, 0,
                              NGX_OK, 0, start);
    return dh;
}

ngx_int_t
xrootd_vfs_readdir(xrootd_vfs_dir_t *dh, ngx_str_t *name_out,
    xrootd_vfs_stat_t *stat_out)
{
    struct dirent *de;

    if (dh == NULL || dh->dir == NULL || name_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    for ( ;; ) {
        errno = 0;
        de = readdir(dh->dir);
        if (de == NULL) {
            return errno == 0 ? NGX_DONE : NGX_ERROR;
        }

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        break;
    }

    name_out->len = strlen(de->d_name);
    name_out->data = ngx_pnalloc(dh->pool, name_out->len + 1);
    if (name_out->data == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    ngx_memcpy(name_out->data, de->d_name, name_out->len);
    name_out->data[name_out->len] = '\0';

    if (stat_out != NULL) {
        char         child[PATH_MAX];
        struct stat  st;
        int          n;

        n = snprintf(child, sizeof(child), "%s/%s", dh->path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }

        if (lstat(child, &st) != 0) {
            return NGX_ERROR;
        }

        xrootd_vfs_fill_stat(&st, stat_out);
    }

    return NGX_OK;
}

ngx_int_t
xrootd_vfs_closedir(xrootd_vfs_dir_t *dh, ngx_log_t *log)
{
    if (dh == NULL || dh->dir == NULL) {
        return NGX_OK;
    }

    if (closedir(dh->dir) != 0) {
        ngx_log_error(NGX_LOG_ERR, log != NULL ? log : dh->log, errno,
                      "xrootd_vfs: closedir failed for \"%s\"",
                      dh->path != NULL ? dh->path : "-");
        dh->dir = NULL;
        return NGX_ERROR;
    }

    dh->dir = NULL;
    return NGX_OK;
}
