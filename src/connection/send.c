#include "../ngx_xrootd_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "write_helpers.h"

/*
 * Write event handler for pending response buffers and chains.
 *
 * nginx calls this when the kernel socket send buffer has room again (i.e.
 * after a previous c->send() / c->send_chain() returned NGX_AGAIN).
 *
 * Flow:
 *   1. Flush any pending wbuf / wchain bytes via xrootd_flush_pending().
 *   2. If the flush returns NGX_AGAIN (still blocked), return and wait.
 *   3. If the flush succeeds and state == XRD_ST_SENDING, transition back
 *      to XRD_ST_REQ_HEADER and re-enter the recv loop so the next request
 *      can be processed.
 *   4. If tls_pending, start the TLS handshake now that the kXR_haveTLS
 *      response has been fully flushed.
 */
void
ngx_stream_xrootd_send(ngx_event_t *wev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ngx_int_t                      rc;

    c = wev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: write timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rc = xrootd_flush_pending(ctx, c);
    if (rc == NGX_ERROR) {
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        return;
    }

    if (ctx->state != XRD_ST_SENDING) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "xrootd: send_done (state=%d, no recv) avail=%d ready=%d active=%d",
                      (int) ctx->state,
                      c->read->available, (int) c->read->ready,
                      (int) c->read->active);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "xrootd: send_done avail=%d ready=%d active=%d",
                  c->read->available, (int) c->read->ready,
                  (int) c->read->active);

    if (ctx->tls_pending) {
        xrootd_start_tls(ctx, c, conf);
        return;
    }

    ngx_stream_xrootd_recv(c->read);
}
