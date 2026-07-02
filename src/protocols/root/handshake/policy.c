#include "handshake.h"

/*
 * xrootd_check_token_scope — enforce WLCG token scopes on a path operation.
 *
 * Only active when ctx->token_auth == 1 (bearer-token session).  GSI and
 * anonymous sessions are not restricted by this function — the xrootd_allow_write
 * directive and VO ACL remain their access gate.
 *
 * logical_path: the client-facing XRootD path (e.g. "/cms/store/file.root"),
 *               NOT the resolved filesystem path.
 * need_write:   1 for mutations (write/create/delete/chmod/mv/mkdir/rmdir),
 *               0 for reads (stat/dirlist/locate/open-read/fattr-get).
 *
 * Returns NGX_OK if access is granted, NGX_ERROR if denied (the caller must
 * send the error response and log the access failure).
 */
ngx_int_t
xrootd_check_token_scope(xrootd_ctx_t *ctx, const char *logical_path,
    int need_write)
{
    if (!ctx->token_auth) {
        return NGX_OK;
    }

    if (ctx->identity != NULL) {
        return xrootd_identity_check_token_scope(ctx->identity, logical_path,
                                                 need_write);
    }

    if (need_write) {
        return xrootd_token_check_write(ctx->token_scopes,
                                        ctx->token_scope_count, logical_path)
               ? NGX_OK : NGX_ERROR;
    }

    return xrootd_token_check_read(ctx->token_scopes,
                                   ctx->token_scope_count, logical_path)
           ? NGX_OK : NGX_ERROR;
}

ngx_int_t
xrootd_dispatch_require_login(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    if (!ctx->logged_in) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required");
    }

    return XROOTD_DISPATCH_CONTINUE;
}

ngx_int_t
xrootd_dispatch_require_auth(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    if (!ctx->logged_in || !ctx->auth_done) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "authentication required");
    }

    return XROOTD_DISPATCH_CONTINUE;
}

ngx_int_t
xrootd_dispatch_require_write(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    rc = xrootd_dispatch_require_auth(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    if (ctx->is_bound) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "bound streams may only read primary handles");
    }

    if (!conf->common.allow_write) {
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    return XROOTD_DISPATCH_CONTINUE;
}
