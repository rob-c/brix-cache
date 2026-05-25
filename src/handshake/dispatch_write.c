#include "handshake.h"
#include "../write/chkpoint.h"

/* ---- Write phase dispatcher — mutating filesystem operations ----
 *
 * WHAT: Handles all mutating (write-modifying) filesystem opcodes after the write requirement gate is satisfied.
 *       Includes data writes (kXR_write, kXR_pgwrite), sync/flush (kXR_sync), file structure changes (truncate/mkdir/rm/rmdir),
 *       rename/move/chmod permissions, multi-segment writes (kXR_writev), and checkpoint transactions (kXR_chkpoint). */

/* ---- Write requirement gate pattern (require_write) — stricter than require_auth ----
 *
 * WHAT: Every write opcode calls xrootd_dispatch_require_write() instead of require_auth. This is a stricter gate that requires BOTH
 *       authentication AND explicit write permission configured for the path/operation. Configurable via conf->common.allow_write directive.
 *
 * WHY: Prevents unauthorized writes even on authenticated connections — write access must be explicitly granted per policy. */

/* ---- Data modification opcodes (write/pgwrite/writev) ----
 *
 * WHAT: kXR_write = single-segment file write at specified offset; kXR_pgwrite = paged write with CRC32c integrity checking
 *       (per-page checksum, 4007 status response); kXR_writev = vector/multi-buffer write. All modify file content at byte offsets. */

/* ---- File structure modification opcodes (truncate/mkdir/rm/rmdir) ----
 *
 * WHAT: kXR_truncate = reduce file to specified length; kXR_mkdir = create new directory; kXR_rm/kXR_rmdir = delete files/directories.
 *       These alter filesystem topology, not just content. */

/* ---- File rename/permission opcodes (mv/chmod) ----
 *
 * WHAT: kXR_mv = move/rename file to different path; kXR_chmod = change file permission bits. Both modify file metadata and location. */

/* ---- Checkpoint transaction opcodes (kXR_chkpoint) ----
 *
 * WHAT: Transactional write semantics — ckpBegin starts checkpoint, ckpCommit finalizes, ckpRollback cancels, ckpXeq executes query.
 *       Used for atomic operations across multiple writes to ensure consistency during bulk transfers or staging scenarios. */

/* ---- Function: xrootd_dispatch_write_opcode() ----
 *
 * WHAT: Dispatches all mutating (write-modifying) filesystem opcodes from the central dispatcher (src/handshake/dispatch.c). Handles twelve write-side requests including:
 *      data writes (kXR_write, kXR_pgwrite with CRC32c integrity), sync/flush (kXR_sync), file structure changes (truncate/mkdir/rm/rmdir),
 *      rename/move/chmod permissions, multi-segment writes (kXR_writev), and checkpoint transactions (kXR_chkpoint). Every opcode calls require_write() first —
 *      a stricter gate than require_auth that requires BOTH authentication AND explicit write permission. Returns XROOTD_DISPATCH_CONTINUE if opcode is not a write opcode.
 *
 * WHY: Ensures all filesystem mutations are authenticated and explicitly permitted before proceeding. Write access must be configured via conf->common.allow_write directive;
 *      even fully authenticated clients cannot mutate data without this gate passing. Checkpoint opcodes additionally require write permission because they enable atomic
 *      multi-write operations for staging scenarios.
 *
 * HOW: Single switch statement matching ctx->cur_reqid against twelve write opcodes → each case calls require_write() first (return error if not authed+write-permitted),
 *      then calls corresponding handler function → returns handler result or XROOTD_DISPATCH_CONTINUE for unhandled cases. kXR_open read-side path additionally handles write-open before passing to write dispatcher. */

/* Gate macro: check write permission then invoke handler.
 * ctx/c/conf/rc are from the enclosing xrootd_dispatch_write_opcode scope. */
#define DISPATCH_WR(fn, ...) \
    rc = xrootd_dispatch_require_write(ctx, c, conf); \
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; } \
    return fn(ctx, c, ##__VA_ARGS__)

ngx_int_t
xrootd_dispatch_write_opcode(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

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

    default:
        return XROOTD_DISPATCH_CONTINUE;
    }
}

#undef DISPATCH_WR
