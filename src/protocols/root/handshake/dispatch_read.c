#include "handshake.h"
#include "protocols/root/read/clone.h"
#include "protocols/root/write/ext_ops.h"   /* vendor readlink (read-side op) */

/* xrootd_reject_bound_nonread_file_op — on a bound (secondary) connection, reject a
 * non-read file op with kXR_NotAuthorized (a bound stream may only read primary
 * handles, preventing corruption/mutation); XROOTD_DISPATCH_CONTINUE if not bound. */
static ngx_int_t
xrootd_reject_bound_nonread_file_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb)
{
    if (!ctx->is_bound) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    xrootd_log_access(ctx, c, verb, "-", "bound",
                      0, kXR_NotAuthorized,
                      "bound streams may only read primary handles", 0);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                             "bound streams may only read primary handles");
}

/* Gate macros: check auth (and bound for non-read ops), then invoke handler.
 * ctx/c/conf/rc are from the enclosing xrootd_dispatch_read_opcode scope. */
#define DISPATCH_RD(fn, ...) \
    rc = xrootd_dispatch_require_auth(ctx, c); \
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; } \
    return fn(ctx, c, ##__VA_ARGS__)

#define DISPATCH_RD_BOUND(verb, fn, ...) \
    rc = xrootd_dispatch_require_auth(ctx, c); \
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; } \
    rc = xrootd_reject_bound_nonread_file_op(ctx, c, verb); \
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; } \
    return fn(ctx, c, ##__VA_ARGS__)

/* xrootd_dispatch_read_opcode — phase 2 routing (from handshake/dispatch.c) for the
 * non-mutating opcodes: a switch on ctx->cur_reqid over stat/statx, open/read/close,
 * dirlist/query/locate, readv/pgread, fattr, prepare, and clone. Each case passes
 * the DISPATCH_RD gate (xrootd_dispatch_require_auth) — and DISPATCH_RD_BOUND adds
 * the bound-stream check for handle-affecting ops — before its handler. Returns the
 * handler result, or XROOTD_DISPATCH_CONTINUE when not a read opcode. */
ngx_int_t
xrootd_dispatch_read_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    switch (ctx->cur_reqid) {

    case kXR_stat:    DISPATCH_RD_BOUND("STAT",    xrootd_handle_stat,    conf);
    case kXR_open:    DISPATCH_RD_BOUND("OPEN",    xrootd_handle_open,    conf);
    case kXR_read:    DISPATCH_RD(xrootd_handle_read);
    case kXR_close:   DISPATCH_RD_BOUND("CLOSE",   xrootd_handle_close);
    case kXR_dirlist: DISPATCH_RD_BOUND("DIRLIST", xrootd_handle_dirlist, conf);
    case kXR_readv:   DISPATCH_RD(xrootd_handle_readv);
    case kXR_query:   DISPATCH_RD_BOUND("QUERY",   xrootd_handle_query,   conf);
    case kXR_prepare: DISPATCH_RD_BOUND("PREPARE", xrootd_handle_prepare, conf);
    case kXR_pgread:  DISPATCH_RD(xrootd_handle_pgread);
    case kXR_locate:  DISPATCH_RD_BOUND("LOCATE",  xrootd_handle_locate,  conf);
    case kXR_statx:   DISPATCH_RD_BOUND("STATX",   xrootd_handle_statx,   conf);
    case kXR_fattr:   DISPATCH_RD_BOUND("FATTR",   xrootd_handle_fattr,   conf);
    case kXR_clone:   DISPATCH_RD_BOUND("CLONE",   xrootd_handle_clone);

    /* vendor readlink (read-side; capability "xrdfs.ext") */
    case kXR_readlink: DISPATCH_RD(xrootd_handle_readlink, conf);

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}

#undef DISPATCH_RD
#undef DISPATCH_RD_BOUND
