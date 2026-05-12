#ifndef XROOTD_CONN_DISCONNECT_H
#define XROOTD_CONN_DISCONNECT_H
#include "../ngx_xrootd_module.h"

/*
 * xrootd_on_disconnect — tear down all per-connection state when a client
 * disconnects (read EOF, write error, or timeout).
 *
 * Responsibilities:
 *   1. Sets ctx->destroyed = 1 so any in-flight AIO callbacks can detect the
 *      stale pointer and abort safely.
 *   2. Cancels any pending upstream redirector query.
 *   3. Frees heap-owned buffers (payload_buf, prepare_paths).
 *   4. Frees OpenSSL state (gsi_dh_key, sigver MAC handle/context).
 *   5. Decrements the active-connections metric and accumulates session I/O totals.
 *   6. Emits access-log entries for any files still open at disconnect time
 *      (with "interrupted" status and throughput).
 *   7. If the session was authenticated and not a bound secondary, removes the
 *      session from the shared registry (so kXR_bind cannot reuse this sessid).
 *   8. Emits the DISCONNECT access-log entry with session-level throughput.
 *
 * NOTE: This function does NOT close open file handles — the caller must call
 * xrootd_close_all_files(ctx) before or after this call.
 */
void xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c);

#endif /* XROOTD_CONN_DISCONNECT_H */
