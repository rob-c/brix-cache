#include "handshake.h"
#include "../read/clone.h"

/* ---- Bound-stream restriction helper — read-only access for secondary connections ----
 *
 * WHAT: Rejects non-read file operations on bound (secondary) connections. Only read operations allowed.
 *       Returns XROOTD_DISPATCH_CONTINUE if connection is NOT bound; otherwise sends kXR_NotAuthorized error.
 *
 * WHY: Bound streams are established for parallel read transfers — secondary connections must only perform
 *      read operations on primary handles to prevent data corruption or unauthorized mutations. */

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

/* ---- Read phase dispatcher — non-mutating filesystem operations ----
 *
 * WHAT: Handles all non-mutating (read-only) and metadata opcodes after authentication is verified.
 *       Includes stat/statx (metadata), open/read/close (file access), dirlist/query/locate (directory ops),
 *       readv/pgread (multi-segment reads), fattr (extended attributes), prepare (staging), clone (server-side copy). */

/* ---- Authentication gate pattern (require_auth) ----
 *
 * WHAT: Every read opcode calls xrootd_dispatch_require_auth() first. Returns error if client is not authenticated.
 *       This ensures all filesystem operations require valid GSI/token/SSS authentication before proceeding. */

/* ---- Bound-stream check pattern (reject_bound_nonread_file_op) ----
 *
 * WHAT: For stat/open/close/dirlist/query/prepare/locate/statx/fattr — bound connections must be checked.
 *       These operations affect primary handle state, so secondary connections need explicit permission gating. */

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

/* ---- Function: xrootd_dispatch_read_opcode() ----
 *
 * WHAT: Dispatches all non-mutating (read-only) and metadata opcodes from the central dispatcher (src/handshake/dispatch.c). Handles
 *      fifteen read-side requests including: stat/statx (metadata queries), open/read/close (file access), dirlist/query/locate
 *      (directory operations), readv/pgread (multi-segment reads), fattr (extended attributes), prepare (staging), and clone
 *      (server-side file copy). Every opcode calls require_auth() first, then optionally reject_bound_nonread_file_op() for
 *      bound-stream connections. Returns XROOTD_DISPATCH_CONTINUE if opcode is not a read opcode — passes to write dispatcher.
 *
 * WHY: Ensures all filesystem operations are authenticated before proceeding. Read opcodes do not mutate data but affect session
 *      state (open handles, byte counters), so authentication gating prevents unauthorized access even on anonymous connections.
 *      Bound-stream secondary connections have additional restrictions — they may only read primary handles to prevent data corruption.
 *
 * HOW: Single switch statement matching ctx->cur_reqid against fifteen read opcodes → each case calls require_auth() first (return error if not authed),
 *      optionally calls reject_bound_nonread_file_op() for bound connections, then calls corresponding handler function → returns handler result
 *      or XROOTD_DISPATCH_CONTINUE for unhandled cases. kXR_open additionally requires write check before read-side handling. */

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

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}

#undef DISPATCH_RD
#undef DISPATCH_RD_BOUND
