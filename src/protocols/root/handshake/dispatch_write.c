#include "core/compat/log_event.h"
#include "handshake.h"
#include "protocols/root/write/chkpoint.h"
#include "protocols/root/write/ext_ops.h"   /* vendor setattr/symlink/link */
#include "protocols/root/write/write.h"     /* shared MV two-path decoder */
#include "net/manager/registry.h"   /* brix_srv_select_or_blacklisted */
#include "fs/path/path.h"          /* brix_extract_path */
#include "protocols/root/path/op_path.h"  /* lexical policy-path validation */
#include "protocols/root/response/response.h"  /* brix_send_redirect / brix_send_error */
#include "net/cms/fanout.h"        /* Phase-89 W8: rm/rmdir holder fan-out */

/* manager_mutation_t — decoded policy inputs for one manager-side mutation.
 *
 * WHAT: Carries the operation's logical path(s), lexical export path(s), and
 *       authorization metadata from decode through authorization and routing.
 * WHY: A manager does not probe its usually-empty local export, but it must
 *      make the same client-identity/path decision as a storage node before a
 *      proxy or CMS fan-out can execute with server authority.
 * HOW: manager_mutation_prepare() fills it from the authoritative wire
 *      decoders; manager_mutation_authorize() consumes it without mutation.
 */
typedef struct {
    const char       *verb;
    ngx_uint_t        op_id;
    int               auth_level;
    brix_acc_op_t     aop;
    char              path[BRIX_MAX_PATH + 1];
    char              resolved[PATH_MAX];
    char              dst[BRIX_MAX_PATH + 1];
    char              dst_resolved[PATH_MAX];
} manager_mutation_t;

/* manager_mutation_error — uniform manager-boundary decode/policy failure.
 *
 * WHAT: Emits the access record, operation metric, and one ROOT error reply.
 * WHY: A rejected manager request must be observable exactly like a local
 *      mutation and terminate before registry selection or CMS fan-out.
 * HOW: Records the stable client-facing path/message and returns the send
 *      result directly to the dispatcher.
 */
static ngx_int_t
manager_mutation_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const manager_mutation_t *m, int kxr, const char *msg)
{
    const char *path = (m->path[0] != '\0') ? m->path : "-";

    brix_log_access(ctx, c, m->verb, path, "-", 0, kxr, msg, 0);
    BRIX_OP_ERR(ctx, m->op_id);
    return brix_send_error(ctx, c, kxr, msg);
}

/* manager_mutation_lexical_path — validate one manager path without I/O.
 *
 * WHAT: Applies the shared depth, forbidden-component, reserved-name, and
 *       root-join checks with BRIX_PATH_NOEXIST.
 * WHY: Pure redirectors commonly have no local object to probe. Authorization
 *      still needs a canonical lexical backing path; existence remains the
 *      selected data node's responsibility.
 * HOW: Delegates to brix_path_resolve_beneath() in no-probe mode and maps
 *      malformed/reserved names to the local handlers' public error classes.
 */
static ngx_int_t
manager_mutation_lexical_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, manager_mutation_t *m, int destination)
{
    const char *path = destination ? m->dst : m->path;
    char       *resolved = destination ? m->dst_resolved : m->resolved;
    ngx_int_t   rc;

    if (path[0] != '/') {
        return manager_mutation_error(ctx, c, m, kXR_ArgInvalid,
                                      "path must be absolute");
    }

    rc = brix_path_resolve_beneath(conf, c->log, path, BRIX_PATH_NOEXIST,
                                   resolved, PATH_MAX);
    if (rc == NGX_OK) {
        return BRIX_DISPATCH_CONTINUE;
    }
    if (rc == NGX_DECLINED) {
        return manager_mutation_error(ctx, c, m, kXR_NotFound,
                                      "no such file or directory");
    }
    return manager_mutation_error(ctx, c, m, kXR_ArgInvalid,
                                  "invalid path");
}

/* manager_mutation_decode_single — extract a single-path mutation payload.
 *
 * WHAT: Copies the request path into the manager policy object.
 * WHY: Keeping the absent/malformed distinction here keeps prepare() flat and
 *      prevents unauthenticated payload parsing (the caller authenticates first).
 * HOW: Uses the shared path extractor and returns a fully formatted error.
 */
static ngx_int_t
manager_mutation_decode_single(brix_ctx_t *ctx, ngx_connection_t *c,
    manager_mutation_t *m)
{
    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return manager_mutation_error(ctx, c, m, kXR_ArgMissing,
                                      "no path given");
    }
    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                           m->path, sizeof(m->path), 1))
    {
        return manager_mutation_error(ctx, c, m, kXR_ArgInvalid,
                                      "invalid path payload");
    }
    return BRIX_DISPATCH_CONTINUE;
}

/* manager_mutation_prepare — decode one routable namespace mutation.
 *
 * WHAT: Selects the authorization class, decodes one path (or both MV paths),
 *       and produces lexical policy paths without touching storage.
 * WHY: The manager must authorize exactly the operands the data node executes;
 *      the old generic extraction treated an MV pair as one selection string.
 * HOW: Uses brix_extract_path for single-path opcodes and the shared MV decoder
 *      for kXR_mv, then validates each operand through the no-probe path seam.
 */
static ngx_int_t
manager_mutation_prepare(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, manager_mutation_t *m)
{
    brix_mv_paths_t mv;
    ngx_int_t       rc;

    ngx_memzero(m, sizeof(*m));
    m->aop = BRIX_AOP_ANY;

    switch (ctx->recv.cur_reqid) {
    case kXR_mkdir:
        m->verb = "MKDIR"; m->op_id = BRIX_OP_MKDIR;
        m->auth_level = BRIX_AUTH_MKDIR;
        break;
    case kXR_rm:
        m->verb = "RM"; m->op_id = BRIX_OP_RM;
        m->auth_level = BRIX_AUTH_DELETE;
        break;
    case kXR_rmdir:
        m->verb = "RMDIR"; m->op_id = BRIX_OP_RMDIR;
        m->auth_level = BRIX_AUTH_DELETE;
        break;
    case kXR_chmod:
        m->verb = "CHMOD"; m->op_id = BRIX_OP_CHMOD;
        m->auth_level = BRIX_AUTH_UPDATE;
        break;
    case kXR_truncate:
        m->verb = "TRUNCATE"; m->op_id = BRIX_OP_TRUNCATE;
        m->auth_level = BRIX_AUTH_UPDATE;
        break;
    case kXR_mv:
        m->verb = "MV"; m->op_id = BRIX_OP_MV;
        m->auth_level = BRIX_AUTH_DELETE;
        m->aop = BRIX_AOP_RENAME;
        ngx_memzero(&mv, sizeof(mv));
        if (brix_mv_parse_paths(ctx, c, &mv) != NGX_OK) {
            return ctx->write_rc;
        }
        ngx_cpystrn((u_char *) m->path, (u_char *) mv.src_buf,
                    sizeof(m->path));
        ngx_cpystrn((u_char *) m->dst, (u_char *) mv.dst_buf,
                    sizeof(m->dst));
        break;
    default:
        return BRIX_DISPATCH_CONTINUE;
    }

    if (ctx->recv.cur_reqid != kXR_mv) {
        rc = manager_mutation_decode_single(ctx, c, m);
        if (rc != BRIX_DISPATCH_CONTINUE) {
            return rc;
        }
    }

    rc = manager_mutation_lexical_path(ctx, c, conf, m, 0);
    if (rc != BRIX_DISPATCH_CONTINUE || ctx->recv.cur_reqid != kXR_mv) {
        return rc;
    }
    return manager_mutation_lexical_path(ctx, c, conf, m, 1);
}

/* manager_mutation_authorize — front-side path authorization for orchestration.
 *
 * WHAT: Runs native/XrdAcc, VO, and write-token checks for the source path and,
 *       for MV, independent destination Insert authorization.
 * WHY: Proxy and fan-out execute with server authority, so relying on the data
 *      node discards the initiating client's path policy.
 * HOW: Reuses brix_auth_gate_op; MV supplies its two operation-specific XrdAcc
 *      verbs, while other opcodes use the local handler's derived mapping.
 */
static ngx_int_t
manager_mutation_authorize(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const manager_mutation_t *m)
{
    if (brix_auth_gate_op(ctx, c, m->op_id, m->verb, m->path, m->resolved,
                          conf, m->auth_level, 1, m->aop) != NGX_OK)
    {
        return ctx->write_rc;
    }

    if (ctx->recv.cur_reqid != kXR_mv) {
        return BRIX_DISPATCH_CONTINUE;
    }
    if (brix_auth_gate_op(ctx, c, BRIX_OP_MV, "MV", m->dst,
                          m->dst_resolved, conf, BRIX_AUTH_UPDATE, 1,
                          BRIX_AOP_INSERT) != NGX_OK)
    {
        return ctx->write_rc;
    }
    return BRIX_DISPATCH_CONTINUE;
}

/* manager_mutation_applies — classify manager-routable namespace writes.
 *
 * WHAT: Identifies path-form mkdir/rm/rmdir/mv/chmod/truncate in manager mode.
 * WHY: Preflight and later orchestration must agree exactly on which requests
 *      may execute through manager authority.
 * HOW: Excludes handle-form truncate and every handle/data-write opcode.
 */
static int
manager_mutation_applies(const brix_ctx_t *ctx,
    const ngx_stream_brix_srv_conf_t *conf)
{
    if (!conf->manager_mode) {
        return 0;
    }

    /* Handle-based truncate carries no path and belongs to the ordinary local
     * write gate. Every other unlisted opcode also falls through unchanged. */
    if (ctx->recv.cur_reqid == kXR_truncate && ctx->recv.cur_dlen == 0) {
        return 0;
    }

    switch (ctx->recv.cur_reqid) {
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        return 1;
    default:
        return 0;
    }
}

/* brix_dispatch_manager_mutation_preflight — authorize before proxy routing.
 *
 * WHAT: Authenticates the session, rejects bound secondaries, decodes both MV
 *       operands, and applies client path policy for every manager mutation.
 * WHY: The top-level proxy shortcut precedes dispatch_write. A busy CMS pin or
 *      configured proxy could otherwise relay a mutation under broader service
 *      credentials without ever reaching the manager boundary below.
 * HOW: The central dispatcher calls this once after session posture and before
 *      any proxy/rate-limit/orchestration side effect. Successful requests are
 *      decoded again by manager_redirect_mutation only to obtain the route key.
 */
ngx_int_t
brix_dispatch_manager_mutation_preflight(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    manager_mutation_t m;
    ngx_int_t rc;

    if (!manager_mutation_applies(ctx, conf)) {
        return BRIX_DISPATCH_CONTINUE;
    }

    /* A hard read-only manager is rejected at config merge. Keep a runtime
     * tripwire so a future configuration path cannot route around that policy;
     * endpoint posture precedes identity and token evaluation. */
    if (conf->common.read_only == 1) {
        brix_io_monitor_record_err(&ctx->io_monitor, BRIX_ERR_FORBIDDEN);
        return brix_send_error(ctx, c, kXR_fsReadOnly,
                               "this is a read-only server");
    }

    rc = brix_dispatch_require_auth(ctx, c);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }
    if (ctx->is_bound) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
            "bound streams may only read or write primary handles");
    }

    rc = manager_mutation_prepare(ctx, c, conf, &m);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }
    return manager_mutation_authorize(ctx, c, conf, &m);
}

/* manager_redirect_mutation — Plane B manager orchestration.
 *
 * WHAT: Routes a preflighted manager mutation to CMS fan-out or one selected
 *       data node, bypassing only the manager's local-export allow_write flag.
 * WHY: Pure redirectors usually have no writable local export; executing there
 *      is wrong, while the selected node retains the typed mutation-policy gate.
 * HOW: Re-decodes the immutable route key after the dispatcher-level preflight,
 *      then starts fan-out or select/redirect/proxy with no intervening policy.
 */
static ngx_int_t
manager_redirect_mutation(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    manager_mutation_t m;
    char               host[256];
    uint16_t           port;
    ngx_int_t          rc;

    if (!manager_mutation_applies(ctx, conf)) {
        return BRIX_DISPATCH_CONTINUE;
    }

    /* The central dispatcher already completed the security preflight before
     * its proxy shortcut. Decode again only to obtain the immutable route key;
     * this function must perform no authorization after orchestration starts. */
    rc = manager_mutation_prepare(ctx, c, conf, &m);
    if (rc != BRIX_DISPATCH_CONTINUE) {
        return rc;
    }

    /* Phase-89 W8: with brix_cms_fanout on, a delete of a replicated path
     * fans out to EVERY holder node instead of redirecting to one (NGX_AGAIN
     * parks the client until the reply window settles).  NGX_DECLINED means
     * fan-out did not engage — fall through to the single-node redirect. */
    rc = brix_cms_fanout_mutation(ctx, c, conf, m.path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (brix_srv_select_or_blacklisted(m.path, 1, host, sizeof(host), &port)) {
        BRIX_LOG_DEBUG(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: manager redirect mutation \"%s\" -> %s",
                       m.path, host);
        return brix_cms_answer_selected(ctx, c, conf, host, port);
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
 * its handler. In manager_mode, path-based mutations pass the manager's
 * authentication/bound/path-policy preflight before redirect or fan-out;
 * local-export allow_write is intentionally not applied to a pure redirector.
 * Returns the handler result, or
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
