#ifndef BRIX_CHKPOINT_H
#define BRIX_CHKPOINT_H

#include "core/ngx_brix_module.h"

/*
 * brix_handle_chkpoint — dispatch a kXR_chkpoint request to the appropriate
 * sub-operation handler.
 *
 * kXR_chkpoint implements transaction-like write semantics:
 *   kXR_ckpBegin    — snapshot the current file to <path>.ckp
 *   kXR_ckpCommit   — delete the snapshot (writes become permanent)
 *   kXR_ckpRollback — restore the file from the snapshot, then delete it
 *   kXR_ckpQuery    — report maxCkpSize and current checkpoint size
 *   kXR_ckpXeq      — execute a write sub-operation under checkpoint protection
 *
 * Active checkpoint state: f->ckp_path != NULL.
 * The checkpoint file is <open-path>.ckp; it is heap-allocated via ngx_alloc
 * and freed by brix_free_fhandle on close or disconnect.
 *
 * Preconditions: handle must be open and writable (validate_write_handle).
 * Thread safety: single-threaded; no concurrent checkpoint operations on the
 *   same handle are possible within one TCP session.
 */
ngx_int_t brix_handle_chkpoint(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_chkpoint_recover_root — startup rollback for abandoned .ckp files.
 *
 * Scans an export root for stale checkpoint snapshots left behind by worker
 * crashes or hard restarts.  Each <path>.ckp snapshot is copied back to <path>
 * and then removed, preserving the transaction rule that uncommitted writes do
 * not survive recovery.
 *
 * Serialised across workers by an exclusive flock on a lock file dropped at the
 * export root.  A root this worker cannot write (EACCES/EPERM/EROFS) cannot hold
 * a journal it never wrote, so recovery is SKIPPED with a warning and NGX_OK —
 * read-only and permission-restricted exports must still serve reads rather
 * than crash-loop worker init.  Returns NGX_ERROR only for a genuinely broken
 * export or a failed rollback; the caller fails worker init on NGX_ERROR.
 */
ngx_int_t brix_chkpoint_recover_root(ngx_log_t *log,
    const char *root_canon);

#endif /* BRIX_CHKPOINT_H */
