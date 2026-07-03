#ifndef BRIX_HANDSHAKE_INTERNAL_H
#define BRIX_HANDSHAKE_INTERNAL_H

#include "core/ngx_brix_module.h"

/*
 * Internal dispatcher helpers return this sentinel when routing should continue.
 * Any other value is the final return value for brix_dispatch(), usually from
 * brix_send_error() or NGX_ERROR.
 */
#define BRIX_DISPATCH_CONTINUE NGX_DECLINED

/*
 * brix_verify_pending_sigver — if ctx->sigver_pending is set, verify the
 * HMAC-SHA256 envelope that the client sent before the current request.
 *
 * When GSI request signing is active the client wraps each request in a
 * kXR_sigver frame.  The dispatcher calls this after accumulating the current
 * request header/payload; failure returns kXR_NotAuthorized.
 *
 * Returns NGX_OK if no sigver is pending or verification passed; otherwise
 * returns the queued error response return value.
 */
ngx_int_t brix_verify_pending_sigver(brix_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * brix_signing_enforce_level — enforce the configured security_level policy.
 * Rejects unsigned requests when the policy requires signing for the opcode.
 */
ngx_int_t brix_signing_enforce_level(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_dispatch_require_login — reject the request with kXR_NotAuthorized if
 * the session has not completed kXR_login yet.
 *
 * Returns BRIX_DISPATCH_CONTINUE if logged in, error rc otherwise.
 */
ngx_int_t brix_dispatch_require_login(brix_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * brix_dispatch_require_auth — reject if authentication has not completed.
 * Returns BRIX_DISPATCH_CONTINUE if auth_done is set.
 */
ngx_int_t brix_dispatch_require_auth(brix_ctx_t *ctx,
    ngx_connection_t *c);

/*
 * brix_dispatch_require_write — reject if the server is configured read-only
 * (conf->common.allow_write == 0).  Returns BRIX_DISPATCH_CONTINUE if writes are
 * permitted.
 */
ngx_int_t brix_dispatch_require_write(brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_dispatch_session_opcode — handle session-level opcodes: kXR_login,
 * kXR_auth, kXR_protocol, kXR_ping, kXR_bind, kXR_sigver, kXR_endsess.
 */
ngx_int_t brix_dispatch_session_opcode(brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_dispatch_read_opcode — handle file-read opcodes: kXR_open (read),
 * kXR_close, kXR_stat, kXR_statx, kXR_read, kXR_readv, kXR_pgread,
 * kXR_locate, kXR_dirlist, kXR_query, kXR_set.
 */
ngx_int_t brix_dispatch_read_opcode(brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_dispatch_write_opcode — handle file-write and namespace-mutating
 * opcodes: kXR_open (write), kXR_write, kXR_pgwrite, kXR_writev, kXR_sync,
 * kXR_truncate, kXR_mkdir, kXR_rm, kXR_rmdir, kXR_mv, kXR_chmod,
 * kXR_fattr, kXR_chkpoint.
 *
 * Calls brix_dispatch_require_write before dispatching.
 */
ngx_int_t brix_dispatch_write_opcode(brix_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_dispatch_signing_opcode — handle kXR_sigver (request-signing
 * envelope).  Saves the sigver state in ctx for the following request and
 * returns BRIX_DISPATCH_CONTINUE so the dispatcher reads the next request.
 */
ngx_int_t brix_dispatch_signing_opcode(brix_ctx_t *ctx,
    ngx_connection_t *c);

#endif /* BRIX_HANDSHAKE_INTERNAL_H */
