#include "handshake.h"
#include "protocols/root/write/chkpoint.h"
#include "protocols/root/write/ext_ops.h"   /* vendor setattr/symlink/link */
#include "net/manager/registry.h"   /* brix_srv_select_or_blacklisted */
#include "fs/path/path.h"          /* brix_extract_path */
#include "protocols/root/response/response.h"  /* brix_send_redirect / brix_send_error */

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
 *       fan-out via brix_cms_forward_to_node + the node executor.)
 * HOW:  the session layer guarantees the client is logged in before write
 *       dispatch, so this runs post-auth; it deliberately bypasses the local
 *       write-permission gate (the node enforces it), matching the open redirect.
 *
 * Returns BRIX_DISPATCH_CONTINUE to fall through to local execution, or a
 * send-result (redirect / error) the caller returns directly.
 */
static ngx_int_t
manager_redirect_mutation(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char     path[BRIX_MAX_PATH + 1];
    char     host[256];
    uint16_t port;

    if (!conf->manager_mode) {
        return BRIX_DISPATCH_CONTINUE;
    }

    switch (ctx->recv.cur_reqid) {
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        break;
    default:
        return BRIX_DISPATCH_CONTINUE;
    }

    /* Handle-based ops (e.g. truncate by fhandle) carry no path payload and must
     * not be redirected — let them process locally / fail naturally. */
    if (ctx->recv.cur_dlen == 0
        || brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                               path, sizeof(path), 1) <= 0
        || path[0] != '/')
    {
        return BRIX_DISPATCH_CONTINUE;
    }

    if (brix_srv_select_or_blacklisted(path, 1, host, sizeof(host), &port)) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: manager redirect mutation \"%s\" -> %s",
                       path, host);
        return brix_send_redirect(ctx, c, host, port);
    }

    return brix_send_error(ctx, c, kXR_FSError,
                             "no data server available for path");
}

/* brix_wr_route_t — one row of the mutating-opcode dispatch table.
 *
 * WHAT: binds a write/mutation wire opcode to its handler.  Exactly one of
 *       fn2/fn3 is non-NULL per row: fn2 for data-write handlers that take
 *       (ctx, c); fn3 for the structure/metadata handlers that additionally
 *       take conf.  This split mirrors the two real handler signatures without
 *       altering any of them.
 * WHY:  a single table row per opcode is the readable source of truth for
 *       routing and collapses the former 14-case gate ladder into one scan,
 *       keeping the dispatcher under the complexity cap.  Row order is
 *       irrelevant to behaviour (opcodes are distinct); it follows the historic
 *       case order for reviewer familiarity.
 * HOW:  brix_dispatch_write_opcode linear-scans brix_wr_routes; on the first
 *       op match it runs the shared write gate, then the bound handler. */
typedef ngx_int_t (*brix_wr_fn2_pt)(brix_ctx_t *ctx, ngx_connection_t *c);
typedef ngx_int_t (*brix_wr_fn3_pt)(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

typedef struct {
    int             op;
    brix_wr_fn2_pt  fn2;   /* handlers taking (ctx, c) */
    brix_wr_fn3_pt  fn3;   /* handlers taking (ctx, c, conf) */
} brix_wr_route_t;

static const brix_wr_route_t  brix_wr_routes[] = {
    { kXR_write,    brix_handle_write,    NULL                 },
    { kXR_pgwrite,  brix_handle_pgwrite,  NULL                 },
    { kXR_sync,     brix_handle_sync,     NULL                 },
    { kXR_truncate, NULL,                 brix_handle_truncate },
    { kXR_mkdir,    NULL,                 brix_handle_mkdir    },
    { kXR_rm,       NULL,                 brix_handle_rm       },
    { kXR_writev,   brix_handle_writev,   NULL                 },
    { kXR_rmdir,    NULL,                 brix_handle_rmdir    },
    { kXR_mv,       NULL,                 brix_handle_mv       },
    { kXR_chmod,    NULL,                 brix_handle_chmod    },
    { kXR_chkpoint, NULL,                 brix_handle_chkpoint },

    /* vendor POSIX-completeness extensions (capability "xrdfs.ext") */
    { kXR_setattr,  NULL,                 brix_handle_setattr  },
    { kXR_symlink,  NULL,                 brix_handle_symlink  },
    { kXR_link,     NULL,                 brix_handle_link     },
};

/* brix_dispatch_write_opcode — phase 2 routing (from handshake/dispatch.c) for
 * the mutating opcodes: table lookup on ctx->recv.cur_reqid over data writes
 * (kXR_write, kXR_pgwrite CRC32c-checked, kXR_writev), kXR_sync, structure
 * changes (truncate/mkdir/rm/rmdir), mv/chmod, kXR_chkpoint, and the vendor
 * ext ops. Each matched opcode passes the write gate — brix_dispatch_require_write,
 * stricter than require_auth (needs auth AND conf->common.allow_write) — before
 * its handler. In manager_mode, path-based mutations redirect first
 * (manager_redirect_mutation). Returns the handler result, or
 * BRIX_DISPATCH_CONTINUE when not a write opcode. */
ngx_int_t
brix_dispatch_write_opcode(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const brix_wr_route_t  *route;
    ngx_uint_t              i;
    ngx_int_t               rc;

    /* Plane B: in manager mode, redirect path-based mutations to a data node
     * before the local write gate (which the manager may not satisfy). */
    rc = manager_redirect_mutation(ctx, c, conf);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    for (i = 0; i < sizeof(brix_wr_routes) / sizeof(brix_wr_routes[0]); i++) {
        route = &brix_wr_routes[i];
        if (route->op != (int) ctx->recv.cur_reqid) {
            continue;
        }

        /* Matched a write opcode: enforce the write gate before dispatching. */
        rc = brix_dispatch_require_write(ctx, c, conf);
        if (rc != BRIX_DISPATCH_CONTINUE) {
            return rc;
        }

        return route->fn2 ? route->fn2(ctx, c)
                          : route->fn3(ctx, c, conf);
    }

    return BRIX_DISPATCH_CONTINUE;
}
