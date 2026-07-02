#include "handshake.h"
#include "protocols/root/write/chkpoint.h"
#include "protocols/root/write/ext_ops.h"   /* vendor setattr/symlink/link */
#include "net/manager/registry.h"   /* xrootd_srv_select_or_blacklisted */
#include "fs/path/path.h"          /* xrootd_extract_path */
#include "protocols/root/response/response.h"  /* xrootd_send_redirect / xrootd_send_error */

/* Gate macro: check write permission then invoke handler.
 * ctx/c/conf/rc are from the enclosing xrootd_dispatch_write_opcode scope. */
#define DISPATCH_WR(fn, ...) \
    rc = xrootd_dispatch_require_write(ctx, c, conf); \
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; } \
    return fn(ctx, c, ##__VA_ARGS__)

/* manager_redirect_mutation — Plane B manager orchestration.
 *
 * In manager_mode, a path-based namespace mutation (mkdir/rm/rmdir/mv/
 *       chmod/truncate) is redirected to the data node that should serve the
 *       path, mirroring the existing open-write redirect.  The client re-issues
 *       the op to that node, which executes it against real storage and enforces
 *       authz.  Data writes (write/pgwrite/writev/sync/chkpoint) are NOT
 *       redirected here — they ride an open handle already redirected at open.
 * WHY:  without this, a mutation sent to a manager executes against the manager's
 *       (empty) local export instead of the cluster — silently wrong.  This is
 *       the nginx-correct orchestration: per-worker node CMS connections make a
 *       cross-worker CMS fan-out impractical, whereas redirect needs no shared
 *       connection state.  (CMS forwarding remains the path for multi-replica
 *       fan-out via xrootd_cms_forward_to_node + the node executor.)
 * HOW:  the session layer guarantees the client is logged in before write
 *       dispatch, so this runs post-auth; it deliberately bypasses the local
 *       write-permission gate (the node enforces it), matching the open redirect.
 *
 * Returns XROOTD_DISPATCH_CONTINUE to fall through to local execution, or a
 * send-result (redirect / error) the caller returns directly.
 */
static ngx_int_t
manager_redirect_mutation(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char     path[XROOTD_MAX_PATH + 1];
    char     host[256];
    uint16_t port;

    if (!conf->manager_mode) {
        return XROOTD_DISPATCH_CONTINUE;
    }

    switch (ctx->cur_reqid) {
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        break;
    default:
        return XROOTD_DISPATCH_CONTINUE;
    }

    /* Handle-based ops (e.g. truncate by fhandle) carry no path payload and must
     * not be redirected — let them process locally / fail naturally. */
    if (ctx->cur_dlen == 0
        || xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                               path, sizeof(path), 1) <= 0
        || path[0] != '/')
    {
        return XROOTD_DISPATCH_CONTINUE;
    }

    if (xrootd_srv_select_or_blacklisted(path, 1, host, sizeof(host), &port)) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: manager redirect mutation \"%s\" -> %s",
                       path, host);
        return xrootd_send_redirect(ctx, c, host, port);
    }

    return xrootd_send_error(ctx, c, kXR_FSError,
                             "no data server available for path");
}

/* xrootd_dispatch_write_opcode — phase 2 routing (from handshake/dispatch.c) for
 * the mutating opcodes: a switch on ctx->cur_reqid over data writes (kXR_write,
 * kXR_pgwrite CRC32c-checked, kXR_writev), kXR_sync, structure changes
 * (truncate/mkdir/rm/rmdir), mv/chmod, and kXR_chkpoint. Each case passes the
 * DISPATCH_WR gate — xrootd_dispatch_require_write, stricter than require_auth
 * (needs auth AND conf->common.allow_write) — before its handler. In manager_mode,
 * path-based mutations redirect first (manager_redirect_mutation). Returns the
 * handler result, or XROOTD_DISPATCH_CONTINUE when not a write opcode. */
ngx_int_t
xrootd_dispatch_write_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    /* Plane B: in manager mode, redirect path-based mutations to a data node
     * before the local write gate (which the manager may not satisfy). */
    rc = manager_redirect_mutation(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    switch (ctx->cur_reqid) {

    case kXR_write:    DISPATCH_WR(xrootd_handle_write);
    case kXR_pgwrite:  DISPATCH_WR(xrootd_handle_pgwrite);
    case kXR_sync:     DISPATCH_WR(xrootd_handle_sync);
    case kXR_truncate: DISPATCH_WR(xrootd_handle_truncate, conf);
    case kXR_mkdir:    DISPATCH_WR(xrootd_handle_mkdir,    conf);
    case kXR_rm:       DISPATCH_WR(xrootd_handle_rm,       conf);
    case kXR_writev:   DISPATCH_WR(xrootd_handle_writev);
    case kXR_rmdir:    DISPATCH_WR(xrootd_handle_rmdir,    conf);
    case kXR_mv:       DISPATCH_WR(xrootd_handle_mv,       conf);
    case kXR_chmod:    DISPATCH_WR(xrootd_handle_chmod,    conf);
    case kXR_chkpoint: DISPATCH_WR(xrootd_handle_chkpoint, conf);

    /* vendor POSIX-completeness extensions (capability "xrdfs.ext") */
    case kXR_setattr:  DISPATCH_WR(xrootd_handle_setattr,  conf);
    case kXR_symlink:  DISPATCH_WR(xrootd_handle_symlink,  conf);
    case kXR_link:     DISPATCH_WR(xrootd_handle_link,     conf);

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}

#undef DISPATCH_WR
