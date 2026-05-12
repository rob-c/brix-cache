#include "stat.h"
#include <string.h>

/* Return kXR_cachersp if reqpath (client's clean path) exists in cache_root. */
static int
stat_cache_flags(const ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath)
{
    char        cache_path[PATH_MAX];
    struct stat cst;
    int         n;

    if (!conf->cache || conf->cache_root.len == 0 || reqpath == NULL) {
        return 0;
    }

    n = snprintf(cache_path, sizeof(cache_path), "%s%s",
                 (char *) conf->cache_root.data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(cache_path)) {
        return 0;
    }

    return (stat(cache_path, &cst) == 0 && S_ISREG(cst.st_mode))
           ? kXR_cachersp : 0;
}

ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               reqpath_buf[XROOTD_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;
    ngx_int_t          validate_rc;
    int                extra_flags = 0;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 0)) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", "-", "-",
                              kXR_ArgInvalid, "invalid path payload");
        }
        reqpath = reqpath_buf;

        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath, resolved, sizeof(resolved))) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotFound, "file not found");
        }

        if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_LOOKUP) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_NotAuthorized, "authdb denied");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_NotAuthorized, "VO not authorized");
        }

        if (xrootd_check_token_scope(ctx, reqpath, 0) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotAuthorized, "token scope denied");
        }

        if (stat(resolved, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotFound, "file not found");
        }

        extra_flags = stat_cache_flags(conf, reqpath);

    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (!xrootd_validate_file_handle(ctx, c, idx, "STAT",
                                         XROOTD_OP_STAT, &validate_rc)) {
            return validate_rc;
        }

        resolved[0] = '\0';
        ngx_cpystrn((u_char *) resolved,
                    (u_char *) (ctx->files[idx].path != NULL
                                ? ctx->files[idx].path : "-"),
                    sizeof(resolved));

        if (fstat(ctx->files[idx].fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_IOError, strerror(errno));
        }

        extra_flags = ctx->files[idx].from_cache ? kXR_cachersp : 0;
    }

    /* Convert the host stat struct into the exact ASCII body the client expects. */
    xrootd_make_stat_body(&st, is_vfs, extra_flags, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    /* Log the stat - use resolved path for handle-based stats */
    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : resolved,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}
