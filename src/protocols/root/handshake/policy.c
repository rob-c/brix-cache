#include "handshake.h"
#include "fs/vfs/vfs_secgate.h"   /* per-capability TLS gate (brix_tls_require) */

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

/* tls_require_opcode_caps — capability set an opcode exercises (vfs_secgate
 * mask bits).  login/auth → LOGIN; the read/write families → SESSION|DATA;
 * the handshake/session-control opcodes (protocol/bind/ping/endsess/set/
 * sigver) → 0 so the in-protocol TLS upgrade path is never blocked by the
 * very policy that demands it; everything else (stat/dirlist/open/mkdir/…)
 * → SESSION.  TPC is gated at its own choke point (read/open_tpc.c) where
 * the tpc.* opaque keys are actually parsed. */
static ngx_uint_t
tls_require_opcode_caps(ngx_uint_t reqid)
{
    switch (reqid) {
    case kXR_login:
    case kXR_auth:
        return BRIX_TLSREQ_LOGIN;
    case kXR_read:
    case kXR_readv:
    case kXR_pgread:
    case kXR_write:
    case kXR_writev:
    case kXR_pgwrite:
        return BRIX_TLSREQ_SESSION | BRIX_TLSREQ_DATA;
    case kXR_protocol:
    case kXR_bind:
    case kXR_ping:
    case kXR_endsess:
    case kXR_set:
    case kXR_sigver:
        return 0;
    default:
        return BRIX_TLSREQ_SESSION;
    }
}

ngx_int_t
brix_tls_require_enforce(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t  refused, is_tls;

    if (conf->common.tls_require == 0) {
        return BRIX_DISPATCH_CONTINUE;
    }

    is_tls = (c->ssl != NULL && c->ssl->connection != NULL);
    refused = brix_tls_gate_refused(conf->common.tls_require,
                                    tls_require_opcode_caps(
                                        ctx->recv.cur_reqid),
                                    is_tls);
    if (refused == 0) {
        return BRIX_DISPATCH_CONTINUE;
    }

    ngx_log_error(NGX_LOG_WARN, c->log, 0,
        "brix: cleartext request refused by brix_tls_require %s "
        "(opcode=%d)",
        brix_tls_cap_name(refused), (int) ctx->recv.cur_reqid);
    return brix_send_error(ctx, c, kXR_TLSRequired,
        "server security policy requires TLS for this capability");
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

    /* Phase 94: a bound secondary may carry a plain kXR_write data payload for a
     * primary-published writable handle (parallel upload) — but nothing else
     * (no open/close/mkdir/mv/rm/writev/pgwrite): those stay primary-only so a
     * secondary can never mutate the namespace or the handle table. */
    if (ctx->is_bound && ctx->recv.cur_reqid != kXR_write) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "bound streams may only read or write primary "
                                 "handles");
    }

    if (!conf->common.allow_write) {
        return brix_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    return BRIX_DISPATCH_CONTINUE;
}
