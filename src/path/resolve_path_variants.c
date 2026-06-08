#include "../ngx_xrootd_module.h"

#include <limits.h>

#include "path_internal.h"
#include "unified.h"

static int
xrootd_resolve_with_opts(ngx_log_t *log, const ngx_str_t *root,
                         const char *reqpath, xrootd_path_opts_t opts,
                         char *resolved, size_t resolvsz)
{
    char                  root_canon[PATH_MAX];
    xrootd_path_status_t  rc;

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    rc = xrootd_path_resolve_cstr(log, root_canon, reqpath, opts,
                                  resolved, resolvsz, NULL);
    if (rc == XROOTD_PATH_STATUS_TOO_LONG) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
    }

    return rc == XROOTD_PATH_STATUS_OK;
}

int
xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
                            const char *reqpath, char *resolved,
                            size_t resolvsz)
{
    xrootd_path_opts_t opts;

    opts = (xrootd_path_opts_t) { 0 };
    opts.allow_missing_parents = 1;
    opts.is_write_operation = 1;

    return xrootd_resolve_with_opts(log, root, reqpath, opts,
                                    resolved, resolvsz);
}

int
xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
                    const char *reqpath, char *resolved, size_t resolvsz)
{
    xrootd_path_opts_t opts;

    opts = (xrootd_path_opts_t) { 0 };
    opts.allow_root = 1;

    return xrootd_resolve_with_opts(log, root, reqpath, opts,
                                    resolved, resolvsz);
}

int
xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
                          const char *reqpath, char *resolved,
                          size_t resolvsz)
{
    xrootd_path_opts_t opts;

    opts = (xrootd_path_opts_t) { 0 };
    opts.allow_missing_tail = 1;
    opts.is_write_operation = 1;

    return xrootd_resolve_with_opts(log, root, reqpath, opts,
                                    resolved, resolvsz);
}
