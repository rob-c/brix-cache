#ifndef XROOTD_CHKPOINT_H
#define XROOTD_CHKPOINT_H

#include "../ngx_xrootd_module.h"

/*
 * xrootd_handle_chkpoint — dispatch a kXR_chkpoint request to the appropriate
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
 * and freed by xrootd_free_fhandle on close or disconnect.
 *
 * Preconditions: handle must be open and writable (validate_write_handle).
 * Thread safety: single-threaded; no concurrent checkpoint operations on the
 *   same handle are possible within one TCP session.
 */
ngx_int_t xrootd_handle_chkpoint(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_chkpoint_recover_root — startup rollback for abandoned .ckp files.
 *
 * Scans an export root for stale checkpoint snapshots left behind by worker
 * crashes or hard restarts.  Each <path>.ckp snapshot is copied back to <path>
 * and then removed, preserving the transaction rule that uncommitted writes do
 * not survive recovery.
 */
ngx_int_t xrootd_chkpoint_recover_root(ngx_log_t *log,
    const char *root_canon);

#endif /* XROOTD_CHKPOINT_H */
