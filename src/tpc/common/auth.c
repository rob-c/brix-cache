#include "auth.h"

#include <limits.h>

static ngx_int_t
xrootd_tpc_check_scope_path(const xrootd_identity_t *identity,
    const ngx_str_t *path, int need_write, ngx_log_t *log)
{
    char local_path[PATH_MAX];

    if (path == NULL || path->data == NULL || path->len == 0) {
        return NGX_OK;
    }

    if (path->len >= sizeof(local_path)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: authorization path is too long");
        return NGX_DECLINED;
    }

    ngx_memcpy(local_path, path->data, path->len);
    local_path[path->len] = '\0';

    if (xrootd_identity_check_token_scope(identity, local_path, need_write)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: token scope denied %s access to \"%s\"",
                      need_write ? "write" : "read", local_path);
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_tpc_check_authz(const xrootd_identity_t *identity,
    const ngx_str_t *src_path, const ngx_str_t *dst_path, ngx_log_t *log)
{
    if (identity != NULL && (identity->auth_method & XROOTD_AUTHN_S3KEY)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: S3 SigV4 identities cannot initiate TPC");
        return NGX_DECLINED;
    }

    if (xrootd_tpc_check_scope_path(identity, src_path, 0, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (xrootd_tpc_check_scope_path(identity, dst_path, 1, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
