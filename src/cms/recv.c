#include "cms_internal.h"
#include "../manager/pending.h"


/*
 * Parse the first host:port entry from a kYR_select or kYR_try payload
 * and wake the suspended XRootD client session that is waiting for it.
 *
 * Payload format (both kYR_select and the first entry of kYR_try):
 *   NUL-terminated hostname  (up to 255 chars)
 *   2-byte big-endian port
 *
 * Per-worker design (step 2): the CMS connection and the waiting XRootD
 * connection are in the same nginx worker process, so looking up the client
 * connection by file descriptor via ngx_cycle->connections is always safe.
 */
static ngx_int_t
cms_wake_pending_session(ngx_xrootd_cms_ctx_t *cms_ctx, uint32_t streamid,
    const char *host, uint16_t port)
{
    xrootd_pending_locate_t  *pending;
    ngx_connection_t         *client_conn;
    ngx_stream_session_t     *session;
    xrootd_ctx_t             *xrd_ctx;
    int                       conn_fd;

    pending = xrootd_pending_lookup(streamid, ngx_pid);
    if (pending == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_EVENT, cms_ctx->cycle->log, 0,
                      "xrootd: CMS wake: streamid=%uD not found in pending table",
                      streamid);
        return NGX_OK;  /* session timed out and was already removed */
    }

    conn_fd = pending->conn_fd;
    xrootd_pending_unlock();

    xrootd_pending_remove(streamid, ngx_pid);

    if ((ngx_uint_t) conn_fd >= ngx_cycle->connection_n) {
        return NGX_OK;
    }

    client_conn = &ngx_cycle->connections[conn_fd];
    if (client_conn->fd != conn_fd) {
        return NGX_OK;  /* fd was recycled after the client disconnected */
    }

    session = client_conn->data;
    if (session == NULL) {
        return NGX_OK;
    }

    xrd_ctx = ngx_stream_get_module_ctx(session, ngx_stream_xrootd_module);
    if (xrd_ctx == NULL || xrd_ctx->state != XRD_ST_WAITING_CMS) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, cms_ctx->cycle->log, 0,
                  "xrootd: CMS select: redirecting client fd=%d to %s:%u",
                  conn_fd, host, (unsigned) port);

    ngx_del_timer(client_conn->read);
    xrd_ctx->state = XRD_ST_REQ_HEADER;
    xrootd_send_redirect(xrd_ctx, client_conn, host, port);
    xrootd_schedule_read_resume(client_conn);
    return NGX_OK;
}


static ngx_int_t
ngx_xrootd_cms_process_frame(ngx_xrootd_cms_ctx_t *ctx)
{
    uint32_t  streamid;
    u_char    code;

    streamid = ngx_xrootd_cms_get32(ctx->inbuf);
    code = ctx->inbuf[4];

    ngx_log_error(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                  "xrootd: CMS process frame code=%ui streamid=%uD",
                  (ngx_uint_t) code, streamid);

    switch (code) {
    case CMS_RR_PING:
        return ngx_xrootd_cms_send_pong(ctx, streamid);

    case CMS_RR_SPACE:
        return ngx_xrootd_cms_send_avail(ctx, streamid);

    case CMS_RR_STATUS: {
        u_char mod = ctx->inbuf[5];
        if (mod & CMS_ST_SUSPEND) {
            ctx->conf->cms_suspended = 1;
            ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                          "xrootd: CMS suspend received — new logins paused");
        } else if (mod & CMS_ST_RESUME) {
            ctx->conf->cms_suspended = 0;
            ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                          "xrootd: CMS resume received — accepting logins");
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "xrootd: CMS status modifier=0x%02xi (no action)",
                           (ngx_uint_t) mod);
        }
        return NGX_OK;
    }

    case CMS_RR_SELECT: {
        /*
         * kYR_select payload: NUL-terminated hostname + 2-byte big-endian port.
         * The manager has resolved the kYR_locate and named a specific server.
         */
        const u_char  *payload = ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN;
        size_t         payload_len = ctx->in_need - NGX_XROOTD_CMS_HDR_LEN;
        char           host[256];
        size_t         host_len;
        uint16_t       port;

        if (payload_len < 3) {
            /* need at least one host byte, a NUL, and two port bytes */
            return NGX_OK;
        }

        ngx_cpystrn((u_char *) host, (u_char *) payload, sizeof(host));
        host_len = ngx_strlen(host);

        if (host_len + 3 > payload_len) {
            /* port bytes would fall outside the received payload */
            return NGX_OK;
        }

        port = ngx_xrootd_cms_get16(payload + host_len + 1);
        return cms_wake_pending_session(ctx, streamid, host, port);
    }

    case CMS_RR_TRY: {
        /*
         * kYR_try: the manager offers an ordered list of alternatives.
         * Each entry is a NUL-terminated hostname followed by a 2-byte
         * big-endian port.  Use only the first entry; the client will
         * retry remaining entries if it cannot reach this one.
         */
        const u_char  *payload = ctx->inbuf + NGX_XROOTD_CMS_HDR_LEN;
        size_t         payload_len = ctx->in_need - NGX_XROOTD_CMS_HDR_LEN;
        char           host[256];
        size_t         host_len;
        uint16_t       port;

        if (payload_len < 3) {
            return NGX_OK;
        }

        ngx_cpystrn((u_char *) host, (u_char *) payload, sizeof(host));
        host_len = ngx_strlen(host);

        if (host_len + 3 > payload_len) {
            return NGX_OK;
        }

        port = ngx_xrootd_cms_get16(payload + host_len + 1);
        return cms_wake_pending_session(ctx, streamid, host, port);
    }

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "xrootd: ignoring CMS rrCode=%ui", (ngx_uint_t) code);
        return NGX_OK;
    }
}


void
ngx_xrootd_cms_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_xrootd_cms_ctx_t  *ctx;
    ssize_t                n;
    uint16_t               dlen;

    c = ev->data;
    ctx = c->data;

    ngx_log_error(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                  "xrootd: CMS recv handler called timedout=%d in_pos=%uz in_need=%uz",
                  (int) ev->timedout, ctx->in_pos, ctx->in_need);

    if (ev->timedout) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        if (ctx->in_need == NGX_XROOTD_CMS_HDR_LEN) {
            dlen = ngx_xrootd_cms_get16(ctx->inbuf + 6);
            if ((size_t) dlen + NGX_XROOTD_CMS_HDR_LEN
                > NGX_XROOTD_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                              "xrootd: CMS frame too large: %ui",
                              (ngx_uint_t) dlen);
                ngx_xrootd_cms_disconnect(ctx);
                ngx_xrootd_cms_schedule_retry(ctx);
                return;
            }

            ctx->in_need = NGX_XROOTD_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        if (ngx_xrootd_cms_process_frame(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos = 0;
        ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
    }

    if (ctx->connection != NULL
        && ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
    }
}
