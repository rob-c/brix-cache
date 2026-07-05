#include "upstream_internal.h"
/*
 * upstream lifecycle management
 *
 * WHAT: Cleans up and aborts an outbound XRootD redirector upstream connection. brix_upstream_cleanup() releases all resources held by the upstream struct (timer, TCP connection, client context pointer). brix_upstream_abort() cleans up the upstream then sends a kXR_ServerError response back to the client at the aborted stream ID and reschedules the client read event so nginx can continue processing the next request.
 *
 * WHY: Proxy mode creates lazy upstream connections on the first post-login opcode. When the upstream dies (timeout, TCP error, backend crash), cleanup() must release all resources without leaking timers or connections. abort() additionally notifies the client at the exact stream ID they were using so xrdcp can retry with a fresh connection rather than hanging forever.
 *
 * HOW: cleanup() checks each resource pointer/timer flag individually — ngx_del_timer(), ngx_close_connection(), nullify client context upstream pointer. abort() extracts client ctx/stream ID before cleanup, logs error reason, calls cleanup(), restores client state to req-header for retry, sends kXR_ServerError via brix_send_error(), reschedules read via brix_schedule_read_resume().
 */

void
brix_upstream_cleanup(brix_upstream_t *up)
{
    if (up == NULL) {
        return;
    }

    if (up->timer.timer_set) {
        ngx_del_timer(&up->timer);
    }

/*
 * HOW: Null-check up pointer first (caller may pass NULL on error path).
 *       Then check and delete timer if set — ngx_del_timer() removes the event loop timer.
 *       Close TCP connection if established, nullify up->conn to prevent double-close.
 *       Clear client context's upstream pointer back to NULL so ctx no longer references dead upstream.
 */
    if (up->conn != NULL) {
        ngx_close_connection(up->conn);
        up->conn = NULL;
    }

    if (up->client_ctx != NULL) {
        up->client_ctx->upstream = NULL;
        up->client_ctx = NULL;
    }
}

void
brix_upstream_abort(brix_upstream_t *up, const char *reason)
{
    brix_ctx_t     *ctx = up->client_ctx;
    ngx_connection_t *c = up->client_conn;
    u_char            sid[2];

    sid[0] = up->req_streamid[0];
    sid[1] = up->req_streamid[1];

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "brix: upstream abort: %s", reason);

    brix_upstream_cleanup(up);
/*
 * HOW: Extract client ctx and conn pointers before cleanup (upstream struct will be zeroed).
 *       Copy req_streamid into local sid[] so we know which stream ID the error belongs to.
 *       Log NGX_LOG_ERR with reason string on client connection's log.
 *       Call brix_upstream_cleanup() to release all upstream resources.
 *       Restore client ctx state: set cur_streamid = sid (same stream), state = XRD_ST_REQ_HEADER
 */

    ctx->recv.cur_streamid[0] = sid[0];
    ctx->recv.cur_streamid[1] = sid[1];
    ctx->state = XRD_ST_REQ_HEADER;

    brix_send_error(ctx, c, kXR_ServerError, reason);
    brix_schedule_read_resume(c);
}
