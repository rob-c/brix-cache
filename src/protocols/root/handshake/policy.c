#include "handshake.h"

/*
 * brix_check_token_scope — enforce WLCG token scopes on a path operation.
 *
 * Only active when ctx->token.auth == 1 (bearer-token session).  GSI and
 * anonymous sessions are not restricted by this function — the brix_allow_write
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
brix_check_token_scope(brix_ctx_t *ctx, const char *logical_path,
    int need_write)
{
    if (!ctx->token.auth) {
        return NGX_OK;
    }

    if (ctx->identity != NULL) {
        return brix_identity_check_token_scope(ctx->identity, logical_path,
                                                 need_write);
    }

    if (need_write) {
        return brix_token_check_write(ctx->token.scopes,
                                        ctx->token.scope_count, logical_path)
               ? NGX_OK : NGX_ERROR;
    }

    return brix_token_check_read(ctx->token.scopes,
                                   ctx->token.scope_count, logical_path)
           ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_min_sec_enforce(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    if (conf->min_sec_level == BRIX_MIN_SEC_NONE) {
        return BRIX_DISPATCH_CONTINUE;
    }

    /*
     * compat and intense both require a TLS-encrypted transport.  brix_tls only
     * ADVERTISES kXR_ableTLS; a client is free to finish login/auth in cleartext
     * and reach here — that is precisely the walked-down session this floor
     * refuses.  We reject every data/metadata opcode (session opcodes were
     * dispatched before this gate) with kXR_TLSRequired; A-1 pairs the upstream
     * leg so neither side can be downgraded independently.
     */
    if (c->ssl == NULL || c->ssl->connection == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "brix: cleartext session refused by brix_min_sec_level=%ui (opcode=%d)",
            conf->min_sec_level, (int) ctx->recv.cur_reqid);
        return brix_send_error(ctx, c, kXR_TLSRequired,
            "server security policy requires a TLS-encrypted session");
    }

    /*
     * intense additionally requires a non-anonymous identity.  An auth=none
     * listener authenticates nobody (anonymous login sets auth_done=1 with no
     * credential), so even over TLS it is below the floor.
     */
    if (conf->min_sec_level >= BRIX_MIN_SEC_INTENSE
        && conf->auth == BRIX_AUTH_NONE)
    {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "brix: anonymous session refused by brix_min_sec_level=intense (opcode=%d)",
            (int) ctx->recv.cur_reqid);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
            "server security policy requires an authenticated identity");
    }

    return BRIX_DISPATCH_CONTINUE;
}

ngx_int_t
brix_dispatch_require_login(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (!ctx->login.logged_in) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required");
    }

    return BRIX_DISPATCH_CONTINUE;
}

ngx_int_t
brix_dispatch_require_auth(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (!ctx->login.logged_in || !ctx->login.auth_done) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "authentication required");
    }

    return BRIX_DISPATCH_CONTINUE;
}

ngx_int_t
brix_dispatch_require_write(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ngx_int_t rc;

    rc = brix_dispatch_require_auth(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    if (ctx->is_bound) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "bound streams may only read primary handles");
    }

    if (!conf->common.allow_write) {
        return brix_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    return BRIX_DISPATCH_CONTINUE;
}
