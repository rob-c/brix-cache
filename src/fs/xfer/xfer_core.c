/*
 * xfer_core.c — the transfer engine's terminal chokepoint.
 *
 * WHAT: xrootd_xfer_finish() — the single call every transfer kind makes when it
 *       reaches a terminal state (commit or abort). It records the outcome
 *       through the unified ledger.
 *
 * WHY:  Before this, each kind (STAGE in vfs_staged.c, TAPE in frm/stage.c, WT in
 *       writethrough_flush.c) built an xrootd_xfer_audit_t inline and called the
 *       ledger — the same six-field boilerplate copied at seven sites. Funnelling
 *       every terminal transition through one function removes that duplication
 *       (one fewer place to get the audit wrong) and, crucially, gives the
 *       durable journal a single hook to update completion state in a later step
 *       without revisiting any caller. This is the BEGIN/MOVE/COMMIT/ABORT
 *       envelope's COMMIT/ABORT edge; the rest of the envelope lands with the
 *       journal generalization (spec §9 Phase 4).
 *
 * HOW:  Pure composition over the ledger — no new state, side effects at the edge.
 *       No goto.
 */

#include "xfer.h"

void
xrootd_xfer_finish(xrootd_xfer_kind_t kind, const char *direction,
    const char *path, const char *principal, size_t bytes,
    xrootd_xfer_result_t result, int sys_errno, ngx_log_t *log)
{
    xrootd_xfer_audit_t ev = {
        .kind      = kind,
        .direction = direction,
        .path      = path,
        .principal = principal,
        .bytes     = bytes,
        .result    = result,
        .sys_errno = sys_errno,
        .log       = log,
    };

    xrootd_xfer_ledger_record(&ev);
}
