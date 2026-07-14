/*
 * stream_wmirror_replay.c — XRootD stream data-write mirror: detached-replay
 * lifecycle and socket I/O (see stream_wmirror_internal.h).
 *
 * WHAT: The connection-lifetime half of the detached replay.  Opens the shadow
 *       socket, wires it into nginx's event loop, drains write buffers, reads
 *       response frames, bounds the whole exchange with a deadline timer, and
 *       tears everything down (freeing the transferred heap buffers) exactly
 *       once.  wmir_launch seeds a replay from a fully-buffered file.
 *
 * WHY:  Split out of stream_wmirror.c under the phase-79 500-line cap.  The
 *       socket setup, event handlers, flush, teardown and launch form one
 *       cohesive concern — the replay's lifetime — distinct from the shadow-side
 *       protocol decisions (stream_wmirror_state.c) and the client-side
 *       accumulation (stream_wmirror.c).
 *
 * HOW:  Each read event pulls one complete frame (wmir_recv_frame) and hands it
 *       to the state machine (wmir_dispatch, stream_wmirror_state.c); the state
 *       machine calls back into wmir_flush to queue frames and wmir_finish to
 *       tear down.  The shadow MUST be an isolated namespace — replaying writes
 *       onto the primary's backing store would corrupt it.
 */
#include "stream_wmirror.h"
#include "stream_wmirror_internal.h"
#include "mirror.h"
#include "stream_mirror_io.h"

#include <netdb.h>
#include <sys/socket.h>
#include <endian.h>

extern void brix_upstream_build_bootstrap(u_char *buf);

static void wmir_read_handler(ngx_event_t *rev);
static void wmir_write_handler(ngx_event_t *wev);
static void wmir_timeout_handler(ngx_event_t *ev);


/* send */
/* Drain the pending write buffer to the shadow socket; see
 * brix_mirror_io_flush(). Caller treats only NGX_ERROR as terminal —
 * NGX_AGAIN is a normal yield to the event loop (wmir_write_handler resumes). */
ngx_int_t
wmir_flush(brix_wmirror_replay_t *r)
{
    return brix_mirror_io_flush(r->conn, r->wbuf, r->wbuf_len, &r->wbuf_pos);
}

/* receive */
/* Read one shadow response frame (header + bounded body), incremental and
 * resumable; see brix_mirror_io_recv_frame(). */
static ngx_int_t
wmir_recv_frame(brix_wmirror_replay_t *r)
{
    return brix_mirror_io_recv_frame(r->conn, r->rhdr, &r->rhdr_pos,
                                       &r->resp_status, &r->resp_dlen,
                                       &r->resp_body, &r->resp_body_pos);
}

/* Read event entry point: pull one complete frame, then hand it to the state
 * machine.  NGX_AGAIN re-arms and yields; the deadline timer (wmir_timeout_
 * handler) is the only thing that bounds a stalled shadow. */
static void
wmir_read_handler(ngx_event_t *rev)
{
    ngx_connection_t        *c = rev->data;
    brix_wmirror_replay_t *r = c->data;
    ngx_int_t                rc;

    if (rev->timedout) { wmir_finish(r, 0); return; }

    rc = wmir_recv_frame(r);
    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) { wmir_finish(r, 0); }
        return;
    }
    if (rc == NGX_ERROR) { wmir_finish(r, 0); return; }
    wmir_dispatch(r);
}

/*
 * Write event entry point.  Two jobs: (1) finalize an in-flight non-blocking
 * connect() — the first writable event after EINPROGRESS means connect resolved,
 * so SO_ERROR is checked to distinguish success from a deferred failure; (2)
 * resume draining the current wbuf after an earlier NGX_AGAIN.  This is the only
 * place the `connecting` flag is cleared.
 */
static void
wmir_write_handler(ngx_event_t *wev)
{
    ngx_connection_t        *c = wev->data;
    brix_wmirror_replay_t *r = c->data;

    if (wev->timedout) { wmir_finish(r, 0); return; }

    if (r->connecting) {
        int       err = 0;
        socklen_t len = sizeof(err);
        /* SO_ERROR carries the async connect() result; nonzero (or getsockopt
         * failure) means the connection never came up. */
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len) == -1
            || err != 0)
        {
            wmir_finish(r, 0);
            return;
        }
        r->connecting = 0;
    }

    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/* Whole-exchange deadline fired: the shadow stalled at some phase — tear down
 * and count it as an error. */
static void
wmir_timeout_handler(ngx_event_t *ev)
{
    wmir_finish((brix_wmirror_replay_t *) ev->data, 0);
}

/*
 * Single teardown path for the replay (success and every failure route here).
 *
 * WHAT: cancel the deadline timer, close the shadow connection, record the
 * outcome metric, and free everything.  OWNERSHIP/ORDER (important): r->data and
 * r->open_frame are heap buffers (ngx_alloc) transferred in at launch and must
 * be ngx_free()d explicitly; r itself was pcalloc'd FROM r->pool, so destroying
 * the pool last frees r along with all its pool-allocated buffers.  `pool` is
 * cached first precisely because r becomes invalid after ngx_destroy_pool().
 */
void
wmir_finish(brix_wmirror_replay_t *r, int ok)
{
    ngx_pool_t *pool = r->pool;

    if (r->tev.timer_set) { ngx_del_timer(&r->tev); }
    if (r->conn != NULL) { ngx_close_connection(r->conn); r->conn = NULL; }

    if (ok) {
        BRIX_WMIR_METRIC_INC(mirror_stream_total);
    } else {
        BRIX_WMIR_METRIC_INC(mirror_stream_errors_total);
        if (r->log_diverge) {
            ngx_log_error(NGX_LOG_NOTICE, r->log, 0,
                "xrootd write-mirror: shadow write replay failed/diverged");
        }
    }
    if (r->data != NULL)       { ngx_free(r->data); }
    if (r->open_frame != NULL) { ngx_free(r->open_frame); }
    ngx_destroy_pool(pool);            /* frees r itself (last use above) */
}

/*
 * Open the shadow socket, register it with nginx's event loop, queue the
 * pipelined bootstrap, and kick off the (possibly async) connect.
 *
 * HOW: a non-blocking socket is wrapped in an ngx_connection_t whose read/write
 * handlers drive the state machine; the bootstrap (handshake + protocol + login)
 * is built into wbuf up front so it is sent the moment the socket is writable.
 * connect() either completes immediately (rc==0 -> flush now) or returns
 * EINPROGRESS (-> set `connecting`, finish in the write handler).  Any setup
 * failure routes through wmir_finish so the pool is always reclaimed.
 */
static void
wmir_start(brix_wmirror_replay_t *r, ngx_msec_t timeout_ms)
{
    ngx_connection_t *c;
    ngx_socket_t      fd;
    size_t            bslen;
    int               rc;

    fd = ngx_socket(r->sockaddr.ss_family, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1 || ngx_nonblocking(fd) == -1) {
        if (fd != (ngx_socket_t) -1) { ngx_close_socket(fd); }
        wmir_finish(r, 0);
        return;
    }
    c = ngx_get_connection(fd, r->log);
    if (c == NULL) { ngx_close_socket(fd); wmir_finish(r, 0); return; }
    c->pool          = r->pool;
    c->data          = r;
    c->recv          = ngx_recv;
    c->send          = ngx_send;
    c->read->handler  = wmir_read_handler;
    c->write->handler = wmir_write_handler;
    c->read->log = c->write->log = r->log;
    r->conn = c;

    /* Bootstrap is three frames concatenated into one write so they pipeline:
     * handshake, then ClientProtocolRequest, then ClientLoginRequest. */
    bslen = XRD_HANDSHAKE_LEN + sizeof(ClientProtocolRequest)
          + sizeof(ClientLoginRequest);
    r->wbuf = ngx_palloc(r->pool, bslen);
    if (r->wbuf == NULL) { wmir_finish(r, 0); return; }
    brix_upstream_build_bootstrap(r->wbuf);
    r->wbuf_len = bslen;
    r->wbuf_pos = 0;
    r->phase    = WMIR_HANDSHAKE;

    r->tev.handler = wmir_timeout_handler;
    r->tev.data    = r;
    r->tev.log     = r->log;
    ngx_add_timer(&r->tev,
                  timeout_ms ? timeout_ms : BRIX_MIRROR_DEFAULT_TIMEOUT_MS);

    rc = connect(fd, (struct sockaddr *) &r->sockaddr, r->socklen);
    /* Only a hard, non-EINPROGRESS error is fatal here; EINPROGRESS is the
     * normal async case and is resolved later via SO_ERROR. */
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        wmir_finish(r, 0);
        return;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        wmir_finish(r, 0);
        return;
    }
    if (rc == 0) {
        r->connecting = 0;             /* connected synchronously — send now */
        if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
    } else {
        r->connecting = 1;             /* completes in the write handler */
    }
}

/* Launch a detached replay for a fully-buffered file.  Ownership of the data
 * buffer transfers to the replay (freed in wmir_finish). */
void
wmir_launch(ngx_stream_brix_srv_conf_t *conf, brix_wmirror_file_t *f)
{
    brix_mirror_target_t  *t;
    ngx_pool_t              *pool;
    brix_wmirror_replay_t *r;
    u_char                  *frame;

    if (conf->mirror.targets == NULL || conf->mirror.targets->nelts == 0) {
        return;
    }
    t = (brix_mirror_target_t *) conf->mirror.targets->elts;   /* first target */
    if (t->socklen == 0) { return; }

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL) { return; }
    r = ngx_pcalloc(pool, sizeof(*r));
    if (r == NULL) { ngx_destroy_pool(pool); return; }
    r->pool        = pool;
    r->log         = ngx_cycle->log;     /* outlives the client connection */
    r->log_diverge = conf->mirror.log_diverge ? 1 : 0;
    r->port        = t->port;
    r->socklen     = t->socklen;
    ngx_memcpy(&r->sockaddr, &t->sockaddr, t->socklen);
    ngx_cpystrn((u_char *) r->host,
                t->host.data ? t->host.data : (u_char *) "?", sizeof(r->host));

    /* Rebuild the open frame as a single heap buffer: the captured 24-byte open
     * header followed by its path/cgi payload.  This is ngx_alloc (not pool) so
     * it survives independently and is ngx_free()d in wmir_finish. */
    r->open_frame_len = (size_t) 24 + f->open_dlen;
    frame = ngx_alloc(r->open_frame_len, ngx_cycle->log);
    if (frame == NULL) { ngx_destroy_pool(pool); return; }
    ngx_memcpy(frame, f->open_hdr, 24);
    if (f->open_dlen && f->open_payload != NULL) {
        ngx_memcpy(frame + 24, f->open_payload, f->open_dlen);
    }
    r->open_frame = frame;
    /* Move the accumulated file bytes to the replay rather than copy: f->data is
     * nulled so wmir_file_reset (called by the caller after this) won't free it;
     * the replay now owns and frees it. */
    r->data       = f->data;             /* transfer ownership */
    r->data_len   = f->data_len;
    f->data       = NULL;                /* the replay frees it now */

    wmir_start(r, conf->mirror.timeout_ms);
}
