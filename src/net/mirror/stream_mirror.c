/*
 * stream_mirror.c — Phase 24 XRootD stream traffic mirror: the async shadow-
 * connection state machine (see stream_mirror.h / stream_mirror_internal.h).
 *
 * The mirror is a self-contained async XRootD client connection whose wire
 * framing reuses the proven upstream bootstrap, exactly like the Phase 22
 * health-check probe (src/manager/health_check.c): the bootstrap write buffer
 * is built by brix_upstream_build_bootstrap(), and responses are read as
 * uniform 8-byte ServerResponseHdr + dlen-byte body frames.  Unlike the health
 * probe, on bootstrap completion it sends the SAVED primary request frame
 * (header + payload, copied at launch with the streamid rewritten to 0x0002),
 * reads exactly one response, compares its status to the primary, and discards
 * the body.
 *
 * Lifetime: ctx + connection live in their own pool created from cycle->pool, so
 * the mirror outlives the client connection that triggered it.  All logging uses
 * ngx_cycle->log, never the (possibly freed) client connection log.
 *
 * Split (phase-79 file-size cap) into three focused files:
 *   stream_mirror.c        — this file: the shadow-connection state machine
 *                            (bootstrap/replay send, frame read, phase dispatch,
 *                            divergence compare, lifecycle start/finish).
 *   stream_mirror_launch.c — eligibility gates + per-target launch + the public
 *                            brix_stream_mirror_maybe() request-path hook.
 *   stream_mirror_config.c — configuration-time directive setters.
 * The context struct, phase enum, metric macro, replay-payload bound, and the
 * single cross-file entry point brix_mir_start() live in stream_mirror_internal.h.
 */
#include "stream_mirror.h"

#include <netdb.h>
#include <sys/socket.h>

#include "stream_mirror_internal.h"
#include "stream_mirror_io.h"
#include "observability/metrics/metrics_macros.h"

/* Built by src/upstream/bootstrap.c; pure wire framing, no client context. */
extern void brix_upstream_build_bootstrap(u_char *buf);

static void brix_mir_write_handler(ngx_event_t *wev);
static void brix_mir_read_handler(ngx_event_t *rev);
static void brix_mir_timeout_handler(ngx_event_t *ev);
static void brix_mir_finish(brix_stream_mirror_t *mir, int sent);


/* write side */
/* Drain the pending write buffer to the shadow socket; see
 * brix_mirror_io_flush(). */
static ngx_int_t
brix_mir_flush(brix_stream_mirror_t *mir)
{
    return brix_mirror_io_flush(mir->conn, mir->wbuf, mir->wbuf_len,
                                  &mir->wbuf_pos);
}

/* Bootstrap complete: send the saved primary request frame to the shadow. */
static void
brix_mir_send_request(brix_stream_mirror_t *mir)
{
    size_t  total = (size_t) 24 + mir->saved_dlen;
    u_char *buf   = ngx_palloc(mir->pool, total);

    if (buf == NULL) {
        brix_mir_finish(mir, 0);
        return;
    }

    ngx_memcpy(buf, mir->saved_hdr, 24);
    buf[0] = 0; buf[1] = 2;            /* streamid 0x0002 marks a mirror request */
    if (mir->saved_dlen > 0 && mir->saved_payload != NULL) {
        ngx_memcpy(buf + 24, mir->saved_payload, mir->saved_dlen);
    }

    mir->wbuf         = buf;
    mir->wbuf_len     = total;
    mir->wbuf_pos     = 0;
    mir->rhdr_pos     = 0;
    mir->resp_dlen    = 0;
    mir->resp_body    = NULL;
    mir->resp_body_pos = 0;
    mir->phase        = XRD_MIR_REQUEST;

    if (brix_mir_flush(mir) == NGX_ERROR) {
        brix_mir_finish(mir, 0);
    }
}

static void
brix_mir_write_handler(ngx_event_t *wev)
{
    ngx_connection_t       *c   = wev->data;
    brix_stream_mirror_t *mir = c->data;

    if (wev->timedout) {
        brix_mir_finish(mir, 0);
        return;
    }

    if (mir->connecting) {
        int       err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len) == -1
            || err != 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, mir->log, 0,
                           "xrootd mirror: %s:%d connect failed",
                           mir->host, (int) mir->port);
            brix_mir_finish(mir, 0);
            return;
        }
        mir->connecting = 0;
    }

    if (brix_mir_flush(mir) == NGX_ERROR) {
        brix_mir_finish(mir, 0);
    }
}


/* read side */
/* Read one shadow response frame (header + bounded body); see
 * brix_mirror_io_recv_frame(). */
static ngx_int_t
brix_mir_recv_frame(brix_stream_mirror_t *mir)
{
    return brix_mirror_io_recv_frame(mir->conn, mir->rhdr, &mir->rhdr_pos,
                                       &mir->resp_status, &mir->resp_dlen,
                                       &mir->resp_body, &mir->resp_body_pos);
}

/* The shadow answered our replayed request: compare status, count divergence. */
static void
brix_mir_on_response(brix_stream_mirror_t *mir)
{
    int shadow_ok = (mir->resp_status == kXR_ok
                     || mir->resp_status == kXR_oksofar
                     || mir->resp_status == kXR_redirect);

    /*
     * A shadow "operation not implemented" is a benign FEATURE-support
     * difference, not an nginx defect: e.g. mirroring a Qcksum to an official
     * xrootd that has no checksum configured returns kXR_Unsupported.  The
     * mirror must "just work" in front of any server, so this is never counted
     * as a divergence — nginx is free to support more than the server it
     * mirrors.  (kXR_error body is errnum[4] + message.)
     */
    int shadow_unsupported = 0;
    if (!shadow_ok && mir->resp_status == kXR_error
        && mir->resp_body != NULL && mir->resp_dlen >= 4)
    {
        uint32_t errnum;
        ngx_memcpy(&errnum, mir->resp_body, 4);
        if (ntohl(errnum) == (uint32_t) kXR_Unsupported) {
            shadow_unsupported = 1;
        }
    }

    BRIX_MIR_METRIC_INC(mirror_stream_total);

    if (!shadow_unsupported && shadow_ok != mir->primary_ok) {
        BRIX_MIR_METRIC_INC(mirror_stream_divergence_total);
        if (mir->log_diverge) {
            ngx_log_error(NGX_LOG_NOTICE, mir->log, 0,
                "xrootd mirror divergence: %s:%d op=%d "
                "primary_ok=%d shadow_kxr_status=%d",
                mir->host, (int) mir->port, (int) mir->saved_opcode,
                mir->primary_ok, (int) mir->resp_status);
        }
    }

    brix_mir_finish(mir, 1);
}

static void
brix_mir_dispatch(brix_stream_mirror_t *mir)
{
    switch (mir->phase) {

    case XRD_MIR_HANDSHAKE:
        if (mir->resp_status != kXR_ok) { brix_mir_finish(mir, 0); return; }
        mir->phase = XRD_MIR_PROTOCOL;
        break;

    case XRD_MIR_PROTOCOL:
        if (mir->resp_status != kXR_ok) { brix_mir_finish(mir, 0); return; }
        /* If the shadow demands TLS we can't continue the cleartext replay; the
         * server is alive though, so just stop without counting an error. */
        if (mir->resp_dlen >= 8) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, mir->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) {
                brix_mir_finish(mir, 1);
                return;
            }
        }
        mir->phase = XRD_MIR_LOGIN;
        break;

    case XRD_MIR_LOGIN:
        /* authmore => shadow wants credentials we cannot replay; stop quietly. */
        if (mir->resp_status == kXR_authmore) {
            brix_mir_finish(mir, 1);
            return;
        }
        if (mir->resp_status != kXR_ok) { brix_mir_finish(mir, 0); return; }
        brix_mir_send_request(mir);  /* sets phase = REQUEST */
        return;

    case XRD_MIR_REQUEST:
        brix_mir_on_response(mir);
        return;
    }

    /* Reset the accumulator and re-post the read so pipelined bootstrap frames
     * already in the socket buffer are processed in this cycle. */
    mir->rhdr_pos      = 0;
    mir->resp_dlen     = 0;
    mir->resp_body     = NULL;
    mir->resp_body_pos = 0;

    if (ngx_handle_read_event(mir->conn->read, 0) != NGX_OK) {
        brix_mir_finish(mir, 0);
        return;
    }
    ngx_post_event(mir->conn->read, &ngx_posted_events);
}

static void
brix_mir_read_handler(ngx_event_t *rev)
{
    ngx_connection_t       *c   = rev->data;
    brix_stream_mirror_t *mir = c->data;
    ngx_int_t               rc;

    if (rev->timedout) {
        brix_mir_finish(mir, 0);
        return;
    }

    rc = brix_mir_recv_frame(mir);
    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            brix_mir_finish(mir, 0);
        }
        return;
    }
    if (rc == NGX_ERROR) {
        brix_mir_finish(mir, 0);
        return;
    }
    brix_mir_dispatch(mir);
}


/* lifecycle */
static void
brix_mir_timeout_handler(ngx_event_t *ev)
{
    brix_stream_mirror_t *mir = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, mir->log, 0,
                   "xrootd mirror: %s:%d timed out", mir->host, (int) mir->port);
    brix_mir_finish(mir, 0);
}

static void
brix_mir_finish(brix_stream_mirror_t *mir, int sent)
{
    ngx_pool_t *pool = mir->pool;

    if (mir->tev.timer_set) {
        ngx_del_timer(&mir->tev);
    }
    if (mir->conn != NULL) {
        ngx_close_connection(mir->conn);
        mir->conn = NULL;
    }
    if (!sent) {
        BRIX_MIR_METRIC_INC(mirror_stream_errors_total);
    }
    ngx_destroy_pool(pool);            /* frees mir itself (last use above) */
}

void
brix_mir_start(brix_stream_mirror_t *mir, ngx_msec_t timeout_ms)
{
    ngx_connection_t *c;
    ngx_socket_t      fd;
    size_t            bslen;
    int               rc;

    fd = ngx_socket(mir->sockaddr.ss_family, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1 || ngx_nonblocking(fd) == -1) {
        if (fd != (ngx_socket_t) -1) { ngx_close_socket(fd); }
        brix_mir_finish(mir, 0);
        return;
    }

    c = ngx_get_connection(fd, mir->log);
    if (c == NULL) {
        ngx_close_socket(fd);
        brix_mir_finish(mir, 0);
        return;
    }
    c->pool          = mir->pool;
    c->data          = mir;
    c->recv          = ngx_recv;
    c->send          = ngx_send;
    c->read->handler  = brix_mir_read_handler;
    c->write->handler = brix_mir_write_handler;
    c->read->log = c->write->log = mir->log;
    mir->conn = c;

    /* Pipelined bootstrap: handshake + protocol + login. */
    bslen = XRD_HANDSHAKE_LEN + sizeof(ClientProtocolRequest)
          + sizeof(ClientLoginRequest);
    mir->wbuf = ngx_palloc(mir->pool, bslen);
    if (mir->wbuf == NULL) {
        brix_mir_finish(mir, 0);
        return;
    }
    brix_upstream_build_bootstrap(mir->wbuf);
    mir->wbuf_len = bslen;
    mir->wbuf_pos = 0;

    mir->tev.handler = brix_mir_timeout_handler;
    mir->tev.data    = mir;
    mir->tev.log     = mir->log;
    ngx_add_timer(&mir->tev, timeout_ms);

    rc = connect(fd, (struct sockaddr *) &mir->sockaddr, mir->socklen);

    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        brix_mir_finish(mir, 0);
        return;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        brix_mir_finish(mir, 0);
        return;
    }

    if (rc == 0) {
        mir->connecting = 0;
        if (brix_mir_flush(mir) == NGX_ERROR) {
            brix_mir_finish(mir, 0);
        }
    } else {
        mir->connecting = 1;           /* completes in the write handler */
    }
}
