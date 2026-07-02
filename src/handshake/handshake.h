#ifndef XROOTD_HANDSHAKE_INTERNAL_H
#define XROOTD_HANDSHAKE_INTERNAL_H

#include "ngx_xrootd_module.h"

/*
 * Internal dispatcher helpers return this sentinel when routing should continue.
 * Any other value is the final return value for xrootd_dispatch(), usually from
 * xrootd_send_error() or NGX_ERROR.
 */
#define XROOTD_DISPATCH_CONTINUE NGX_DECLINED

/*
 * xrootd_verify_pending_sigver — if ctx->sigver_pending is set, verify the
 * HMAC-SHA256 envelope that the client sent before the current request.
 *
 * When GSI request signing is active the client wraps each request in a
 * kXR_sigver frame.  The dispatcher calls this after accumulating the current
 * request header/payload; failure returns kXR_NotAuthorized.
 *
 * Returns NGX_OK if no sigver is pending or verification passed; otherwise
 * returns the queued error response return value.
 */
ngx_int_t xrootd_verify_pending_sigver(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * xrootd_signing_enforce_level — enforce the configured security_level policy.
 * Rejects unsigned requests when the policy requires signing for the opcode.
 */
ngx_int_t xrootd_signing_enforce_level(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_dispatch_require_login — reject the request with kXR_NotAuthorized if
 * the session has not completed kXR_login yet.
 *
 * Returns XROOTD_DISPATCH_CONTINUE if logged in, error rc otherwise.
 */
ngx_int_t xrootd_dispatch_require_login(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * xrootd_dispatch_require_auth — reject if authentication has not completed.
 * Returns XROOTD_DISPATCH_CONTINUE if auth_done is set.
 */
ngx_int_t xrootd_dispatch_require_auth(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * xrootd_dispatch_require_write — reject if the server is configured read-only
 * (conf->common.allow_write == 0).  Returns XROOTD_DISPATCH_CONTINUE if writes are
 * permitted.
 */
ngx_int_t xrootd_dispatch_require_write(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_dispatch_session_opcode — handle session-level opcodes: kXR_login,
 * kXR_auth, kXR_protocol, kXR_ping, kXR_bind, kXR_sigver, kXR_endsess.
 */
ngx_int_t xrootd_dispatch_session_opcode(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_dispatch_read_opcode — handle file-read opcodes: kXR_open (read),
 * kXR_close, kXR_stat, kXR_statx, kXR_read, kXR_readv, kXR_pgread,
 * kXR_locate, kXR_dirlist, kXR_query, kXR_set.
 */
ngx_int_t xrootd_dispatch_read_opcode(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_dispatch_write_opcode — handle file-write and namespace-mutating
 * opcodes: kXR_open (write), kXR_write, kXR_pgwrite, kXR_writev, kXR_sync,
 * kXR_truncate, kXR_mkdir, kXR_rm, kXR_rmdir, kXR_mv, kXR_chmod,
 * kXR_fattr, kXR_chkpoint.
 *
 * Calls xrootd_dispatch_require_write before dispatching.
 */
ngx_int_t xrootd_dispatch_write_opcode(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_dispatch_signing_opcode — handle kXR_sigver (request-signing
 * envelope).  Saves the sigver state in ctx for the following request and
 * returns XROOTD_DISPATCH_CONTINUE so the dispatcher reads the next request.
 */
ngx_int_t xrootd_dispatch_signing_opcode(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

#endif /* XROOTD_HANDSHAKE_INTERNAL_H */
