#include "upstream_internal.h"

void
xrootd_upstream_cleanup(xrootd_upstream_t *up)
{
    if (up == NULL) {
        return;
    }

    if (up->timer.timer_set) {
        ngx_del_timer(&up->timer);
    }

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
xrootd_upstream_abort(xrootd_upstream_t *up, const char *reason)
{
    xrootd_ctx_t     *ctx = up->client_ctx;
    ngx_connection_t *c = up->client_conn;
    u_char            sid[2];

    sid[0] = up->req_streamid[0];
    sid[1] = up->req_streamid[1];

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "xrootd: upstream abort: %s", reason);

    xrootd_upstream_cleanup(up);

    ctx->cur_streamid[0] = sid[0];
    ctx->cur_streamid[1] = sid[1];
    ctx->state = XRD_ST_REQ_HEADER;

    xrootd_send_error(ctx, c, kXR_ServerError, reason);
    xrootd_schedule_read_resume(c);
}

