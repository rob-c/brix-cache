#ifndef BRIX_DASHBOARD_TRACKING_H
#define BRIX_DASHBOARD_TRACKING_H

/*
 * dashboard/dashboard_tracking.h — HTTP request → dashboard transfer-slot API.
 *
 * Declares the brix_dashboard_http_*() functions that WebDAV/S3/TPC handlers
 * call to bind an ngx_http_request_t to a live transfer slot for the duration of
 * a request: _start()/_start_identity() open and own a slot, _add()/_state()/
 * _error()/_tpc_remote() update it, and _finish() releases it.  Implemented by
 * http_tracking.c for normal builds and by noop.c when the dashboard is disabled.
 *
 * This header is HTTP-only (it pulls in ngx_http.h) and must not be included
 * from stream-module sources; the protocol-agnostic slot operations and SHM
 * types live in dashboard.h.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "dashboard.h"

/*
 * Begin tracking r as an "anonymous" transfer (thin wrapper over
 * _start_identity with identity="anonymous", vo=""). See that function for the
 * full contract; proto/direction are BRIX_XFER_PROTO_* / BRIX_XFER_DIR_* constants,
 * expected_bytes is the advertised transfer size in bytes (<0 if unknown).
 * Returns the slot index (>=0) or -1 if the dashboard is disabled/full.
 */
int brix_dashboard_http_start(ngx_http_request_t *r, const char *path,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes);

/*
 * Reserve a dashboard transfer slot, bind it to r as module ctx, and return its
 * index (>=0). All string args (path/identity/vo/op) are borrowed and copied
 * into the slot; identity NULL is treated as "anonymous", vo NULL as "". Returns
 * -1 if the dashboard SHM zone is absent/uninitialised or slot/cleanup alloc
 * fails. Idempotent: re-binding an already-tracked r returns the existing slot.
 * The slot is auto-freed when r->pool is destroyed even if _finish() is never
 * called, so callers may ignore the return value. Stamps the slot start time
 * with ngx_current_msec and snapshots the (NUL-bounded) client address.
 */
int brix_dashboard_http_start_identity(ngx_http_request_t *r,
    const char *path, const char *identity, const char *vo,
    uint8_t proto, uint8_t direction, const char *op,
    int64_t expected_bytes);

/*
 * Add bytes transferred (an incremental delta, not a cumulative total) to r's
 * slot and refresh its last-activity timestamp. No-op if r is untracked.
 */
void brix_dashboard_http_add(ngx_http_request_t *r,
    ngx_atomic_int_t bytes);

/*
 * Set r's slot display state to one of BRIX_XFER_STATE_* and stamp activity.
 * No-op if r is untracked.
 */
void brix_dashboard_http_state(ngx_http_request_t *r, uint8_t state);

/*
 * Record an error reason on r's slot (string is copied, not borrowed) and move
 * the slot to BRIX_XFER_STATE_ERROR. No-op if r is untracked. Does not free
 * the slot; the caller still calls _finish() afterward.
 */
void brix_dashboard_http_error(ngx_http_request_t *r, const char *reason);

/*
 * Record the redacted TPC remote endpoint on r's slot. remote_url is borrowed
 * and split into a "scheme://host[:port]" string plus basename-only path hint
 * with userinfo, query, and fragment stripped, so credentials never reach the
 * dashboard. remote_status is the remote HTTP status, curl_exit the libcurl
 * result code. No-op if r is untracked.
 */
void brix_dashboard_http_tpc_remote(ngx_http_request_t *r,
    const char *remote_url, int remote_status, int curl_exit);

/*
 * Stop tracking r: move its slot to BRIX_XFER_STATE_CLOSING then free it back
 * to the SHM pool, marking the binding released (slot index set to -1).
 * Idempotent and safe to call on an untracked r. Subsequent _add()/_state()/etc
 * calls become no-ops; the pool-cleanup handler will not double-free.
 */
void brix_dashboard_http_finish(ngx_http_request_t *r);

#endif /* BRIX_DASHBOARD_TRACKING_H */
