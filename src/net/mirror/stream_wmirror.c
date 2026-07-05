/*
 * stream_wmirror.c — Phase 24 W3: XRootD stream DATA-write mirroring.
 *
 * See stream_wmirror.h.  Two halves:
 *
 *  1. Per-connection accumulation.  A write-open's bytes are gathered into a
 *     bounded per-file buffer hanging off the client connection context
 *     (brix_ctx_t.wmirror).  Only sequential kXR_write data is captured; a
 *     kXR_pgwrite (CRC-interleaved payload), a non-sequential offset, or a buffer
 *     that exceeds the per-file / per-connection cap aborts that file's mirror
 *     (counted) — never blocking the client.
 *
 *  2. Detached replay.  On kXR_close, a complete sequential file is handed to a
 *     self-contained async shadow client (its own cycle-pool context, the same
 *     fire-and-forget lifetime as the read mirror, src/mirror/stream_mirror.c)
 *     that bootstraps a fresh shadow session and performs open(create) -> write
 *     -> close.  The shadow-socket framing (flush / recv_frame) is shared with
 *     the read mirror via src/mirror/stream_mirror_io.c; the read+write handlers
 *     and start/finish lifecycle deliberately mirror stream_mirror.c.
 *
 * The shadow MUST be an isolated namespace — replaying writes onto the primary's
 * backing store would corrupt it (see brix_mirror_writes).
 */
#include "stream_wmirror.h"
#include "mirror.h"
#include "stream_mirror_io.h"
#include "observability/metrics/metrics_macros.h"

#include <netdb.h>
#include <sys/socket.h>
#include <endian.h>

extern void brix_upstream_build_bootstrap(u_char *buf);

/* Caps: data-write mirroring is best-effort validation, not a data path. */
#define BRIX_WMIRROR_FILE_CAP  (4u * 1024u * 1024u)   /* 4 MiB per file        */
#define BRIX_WMIRROR_CONN_CAP  (16u * 1024u * 1024u)  /* 16 MiB per connection */

#define BRIX_WMIR_METRIC_INC(field)                                        \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


typedef struct {
    unsigned   active:1;        /* a write-open is accumulating          */
    unsigned   aborted:1;       /* cap exceeded / non-seq / pgwrite      */
    u_char     open_hdr[24];    /* client's open request header (24 B)   */
    u_char    *open_payload;    /* malloc: open path (+cgi)              */
    uint32_t   open_dlen;
    u_char    *data;            /* malloc/realloc: accumulated bytes     */
    size_t     data_len;
    off_t      next_off;        /* expected next contiguous write offset */
} brix_wmirror_file_t;

typedef struct {
    size_t                 total_buffered;
    brix_wmirror_file_t  files[BRIX_MAX_FILES];
} brix_wmirror_conn_t;


/*
 * Replay state machine.  The first three are the shared bootstrap (identical to
 * the read mirror); the last three are this mirror's stateful create sequence.
 * Each phase names the frame we have SENT and are now awaiting a response for.
 * Linear progression only — any non-ok response aborts via wmir_finish(r, 0).
 */
typedef enum {
    WMIR_HANDSHAKE = 0,
    WMIR_PROTOCOL,
    WMIR_LOGIN,
    WMIR_OPEN,     /* sent open, awaiting open response (shadow fhandle) */
    WMIR_WRITE,    /* sent write, awaiting response                      */
    WMIR_CLOSE,    /* sent close, awaiting response                      */
} wmir_phase_t;

typedef struct {
    ngx_pool_t       *pool;
    ngx_connection_t *conn;
    ngx_log_t        *log;
    wmir_phase_t      phase;
    unsigned          connecting:1;
    unsigned          log_diverge:1;

    u_char    rhdr[XRD_RESPONSE_HDR_LEN];
    size_t    rhdr_pos;
    uint16_t  resp_status;
    uint32_t  resp_dlen;
    u_char   *resp_body;
    size_t    resp_body_pos;

    u_char   *wbuf;
    size_t    wbuf_len;
    size_t    wbuf_pos;

    ngx_event_t  tev;

    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    char                     host[256];
    uint16_t                 port;

    u_char   *open_frame;       /* malloc: open header(24) + path, to send */
    size_t    open_frame_len;
    u_char   *data;             /* malloc: file bytes                      */
    size_t    data_len;
    u_char    shadow_fhandle[4];
} brix_wmirror_replay_t;

static void wmir_read_handler(ngx_event_t *rev);
static void wmir_write_handler(ngx_event_t *wev);
static void wmir_timeout_handler(ngx_event_t *ev);
static void wmir_finish(brix_wmirror_replay_t *r, int ok);

/* send */
/* Drain the pending write buffer to the shadow socket; see
 * brix_mirror_io_flush(). Caller treats only NGX_ERROR as terminal —
 * NGX_AGAIN is a normal yield to the event loop (wmir_write_handler resumes). */
static ngx_int_t
wmir_flush(brix_wmirror_replay_t *r)
{
    return brix_mirror_io_flush(r->conn, r->wbuf, r->wbuf_len, &r->wbuf_pos);
}

/* Clear the response accumulator before awaiting the next frame: zero the
 * header read cursor and the parsed status/dlen/body so a stale value from the
 * previous phase cannot leak into the next response. */
static void
wmir_reset_frame(brix_wmirror_replay_t *r)
{
    r->rhdr_pos = 0;
    r->resp_status = 0;
    r->resp_dlen = 0;
    r->resp_body = NULL;
    r->resp_body_pos = 0;
}

/*
 * Replay the client's original open frame (header[24] + path/cgi payload) to the
 * shadow.  WHAT: re-sends the captured open verbatim so the shadow recreates the
 * same path under its own namespace.  HOW: copy into a fresh pool buffer (the
 * saved open_frame is reused per launch and must stay intact), overwrite the
 * streamid to 0x0002 (marks this as a mirror request, matching the read mirror),
 * then flush.  The original open's create/truncate flags are preserved as-is.
 */
static void
wmir_send_open(brix_wmirror_replay_t *r)
{
    u_char *p = ngx_palloc(r->pool, r->open_frame_len);

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memcpy(p, r->open_frame, r->open_frame_len);
    p[0] = 0; p[1] = 2;                              /* streamid 0x0002 */
    r->wbuf = p; r->wbuf_len = r->open_frame_len; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_OPEN;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/*
 * Send the whole accumulated file as a SINGLE kXR_write to the shadow.
 *
 * WHAT/WHY: the accumulator only ever captured sequential writes starting at
 * offset 0 (wmir_observe enforces contiguity), so the entire file collapses into
 * one write at offset 0 — we do NOT need to replay the client's original chunk
 * boundaries.  HOW: hand-build the 24-byte ClientWriteRequest header:
 *   [0..1]  streamid  = 0x0002 (mirror marker)
 *   [2..3]  requestid = kXR_write, big-endian
 *   [4..7]  fhandle   = the shadow's handle from the open response
 *   [8..15] offset    = 0 (whole file from start; off_be is already zero)
 *   [16..19] reserved (left zero by ngx_memzero)
 *   [20..23] dlen     = data_len, big-endian
 * followed by data_len payload bytes.  All multi-byte fields are network order.
 */
static void
wmir_send_write(brix_wmirror_replay_t *r)
{
    size_t   total = (size_t) 24 + r->data_len;
    u_char  *p = ngx_palloc(r->pool, total);
    uint32_t dlen_be;
    uint64_t off_be = 0;

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memzero(p, 24);
    p[0] = 0; p[1] = 2;
    p[2] = (u_char) (kXR_write >> 8); p[3] = (u_char) (kXR_write & 0xff);
    ngx_memcpy(p + 4, r->shadow_fhandle, 4);
    ngx_memcpy(p + 8, &off_be, 8);                   /* whole file at offset 0 */
    dlen_be = htonl((uint32_t) r->data_len);
    ngx_memcpy(p + 20, &dlen_be, 4);
    if (r->data_len) { ngx_memcpy(p + 24, r->data, r->data_len); }
    r->wbuf = p; r->wbuf_len = total; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_WRITE;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/*
 * Send kXR_close for the shadow handle — finalizes the replayed file.  Same
 * 24-byte header layout as the write: streamid 0x0002, requestid kXR_close at
 * [2..3], the shadow fhandle at [4..7]; all other fields stay zero.
 */
static void
wmir_send_close(brix_wmirror_replay_t *r)
{
    u_char *p = ngx_palloc(r->pool, 24);

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memzero(p, 24);
    p[0] = 0; p[1] = 2;
    p[2] = (u_char) (kXR_close >> 8); p[3] = (u_char) (kXR_close & 0xff);
    ngx_memcpy(p + 4, r->shadow_fhandle, 4);
    r->wbuf = p; r->wbuf_len = 24; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_CLOSE;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
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

/* A shadow op succeeded if it returned kXR_ok or kXR_oksofar (the latter is a
 * partial-but-fine status the server may use for streamed writes). */
static int
wmir_status_ok(uint16_t st)
{
    return st == kXR_ok || st == kXR_oksofar;
}

/* Advance one phase; bootstrap phases re-post the read so pipelined frames are
 * processed; request phases send the next frame (which arms the read itself). */
static void
wmir_dispatch(brix_wmirror_replay_t *r)
{
    switch (r->phase) {

    case WMIR_HANDSHAKE:
        if (r->resp_status != kXR_ok) { wmir_finish(r, 0); return; }
        r->phase = WMIR_PROTOCOL;
        break;

    case WMIR_PROTOCOL:
        if (r->resp_status != kXR_ok) { wmir_finish(r, 0); return; }
        /* A shadow that demands TLS cannot continue the cleartext replay.  The
         * gotoTLS flag lives in the protocol response body at byte offset 4
         * (a 4-byte big-endian flags word). */
        if (r->resp_dlen >= 8 && r->resp_body != NULL) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, r->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) { wmir_finish(r, 0); return; }
        }
        r->phase = WMIR_LOGIN;
        break;

    case WMIR_LOGIN:
        /* authmore => the shadow wants credentials we have no way to supply on
         * this anonymous replay; treat as a non-fatal stop (counted as error). */
        if (r->resp_status == kXR_authmore) { wmir_finish(r, 0); return; }
        if (r->resp_status != kXR_ok)       { wmir_finish(r, 0); return; }
        wmir_send_open(r);          /* resets accumulator + sends + arms read */
        return;

    case WMIR_OPEN:
        /* The shadow's open response body begins with its 4-byte file handle;
         * everything downstream (write/close) addresses this handle, so a short
         * or missing body means we cannot continue. */
        if (!wmir_status_ok(r->resp_status) || r->resp_dlen < 4
            || r->resp_body == NULL)
        {
            wmir_finish(r, 0); return;          /* shadow open failed/diverged */
        }
        ngx_memcpy(r->shadow_fhandle, r->resp_body, 4);
        wmir_send_write(r);
        return;

    case WMIR_WRITE:
        if (!wmir_status_ok(r->resp_status)) { wmir_finish(r, 0); return; }
        wmir_send_close(r);
        return;

    case WMIR_CLOSE:
        /* Terminal: success iff the close was accepted — this is the only path
         * that reports the replay as fully succeeded (ok=1). */
        wmir_finish(r, wmir_status_ok(r->resp_status) ? 1 : 0);
        return;
    }

    /* Only the bootstrap arms (HANDSHAKE/PROTOCOL) fall through to here — they
     * advanced r->phase via `break` instead of sending a frame.  The request
     * arms (LOGIN/OPEN/WRITE/CLOSE) all `return` after queuing their next frame,
     * whose wmir_flush() arms the read itself.  Here we instead re-post the read
     * manually: the pipelined bootstrap responses may already be sitting in the
     * socket buffer, so re-posting drains them within the same loop cycle rather
     * than waiting for a fresh readable event. */
    wmir_reset_frame(r);
    if (ngx_handle_read_event(r->conn->read, 0) != NGX_OK) {
        wmir_finish(r, 0);
        return;
    }
    ngx_post_event(r->conn->read, &ngx_posted_events);
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
static void
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
    ngx_add_timer(&r->tev, timeout_ms ? timeout_ms : 5000);

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
static void
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


/*
 * Free a per-file accumulator slot and return it to the empty state.  WHAT:
 * releases the two heap buffers (accumulated data + open payload) and zeroes the
 * struct.  WHY the guarded subtract: the connection-wide byte counter must be
 * decremented by exactly this file's contribution; the `<=` guard defends
 * against any accounting drift so total_buffered can never underflow.  Safe to
 * call on an already-empty slot (NULL buffers, data_len 0) and after launch has
 * stolen f->data (set to NULL).
 */
static void
wmir_file_reset(brix_wmirror_conn_t *wm, brix_wmirror_file_t *f)
{
    if (f->data != NULL)         { ngx_free(f->data); }
    if (f->open_payload != NULL) { ngx_free(f->open_payload); }
    if (wm != NULL && f->data_len <= wm->total_buffered) {
        wm->total_buffered -= f->data_len;
    }
    ngx_memzero(f, sizeof(*f));
}

/*
 * Is data-write mirroring active for this server?  Returns 1 only if ALL gates
 * pass: mirroring enabled with a target, the explicit mirror_writes opt-in is on
 * (writes are off by default — replaying them needs an isolated namespace), and
 * the OP_WRITE bit is in the allowlist and not in the exclude mask.  Every entry
 * point re-checks this so config can disable the feature mid-connection.
 */
static int
wmir_gate(ngx_stream_brix_srv_conf_t *conf)
{
    if (!conf->mirror.enabled || conf->mirror.targets == NULL) { return 0; }
    if (!conf->mirror.mirror_writes) { return 0; }
    if ((conf->mirror.opcode_mask & BRIX_MIRROR_OP_WRITE) == 0) { return 0; }
    if ((conf->mirror.opcode_exclude_mask & BRIX_MIRROR_OP_WRITE) != 0) {
        return 0;
    }
    return 1;
}


/*
 * Hook: a write-open succeeded on the primary — begin accumulating this file.
 *
 * WHAT: snapshot the client's open request (header + path/cgi payload) into the
 * per-connection slot keyed by the primary's file handle index, so kXR_close can
 * later replay it to the shadow.  Called only for write opens; read opens are
 * ignored.  HOW: lazily allocate the per-connection accumulator from the client
 * connection pool on first use; reset any prior open occupying this slot (handle
 * indices are reused across opens).  The payload is copied (own heap buffer)
 * because ctx->recv.payload is transient and reused by later requests; an oversize
 * open payload or OOM marks the slot aborted so it is never replayed.
 */
void
brix_stream_wmirror_on_open(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int client_idx, int is_write)
{
    brix_wmirror_conn_t *wm;
    brix_wmirror_file_t *f;

    if (!is_write || !wmir_gate(conf)) { return; }
    if (client_idx < 0 || client_idx >= BRIX_MAX_FILES) { return; }

    wm = ctx->wmirror;
    if (wm == NULL) {
        wm = ngx_pcalloc(c->pool, sizeof(*wm));
        if (wm == NULL) { return; }
        ctx->wmirror = wm;
    }

    f = &wm->files[client_idx];
    wmir_file_reset(wm, f);                  /* drop any prior open on this slot */

    ngx_memcpy(f->open_hdr, ctx->recv.hdr_buf, 24);
    if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL
        && ctx->recv.cur_dlen <= BRIX_WMIRROR_FILE_CAP)
    {
        f->open_payload = ngx_alloc(ctx->recv.cur_dlen, ngx_cycle->log);
        if (f->open_payload == NULL) { f->aborted = 1; }
        else {
            ngx_memcpy(f->open_payload, ctx->recv.payload, ctx->recv.cur_dlen);
            f->open_dlen = ctx->recv.cur_dlen;
        }
    }
    f->active   = 1;
    f->next_off = 0;
}

/*
 * Hook: observe each write/pgwrite/close on an accumulating file.
 *
 * WHAT: drives the per-file accumulator forward as the client streams writes,
 * and fires the detached replay on a clean close.  The slot is located by the
 * file-handle index carried in the request header (byte 4, the first byte of the
 * 4-byte fhandle the open hook keyed on).  This is best-effort: any condition we
 * can't faithfully replay just marks the slot aborted and is silently dropped —
 * the client is never blocked or affected.
 *
 * Abort triggers (file will NOT be mirrored): kXR_pgwrite (CRC-interleaved, not
 * plain bytes), a non-sequential offset, exceeding the per-file or per-connection
 * cap, an OOM on grow, or the primary itself failing the write.
 */
void
brix_stream_wmirror_observe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, ngx_int_t primary_rc)
{
    brix_wmirror_conn_t *wm;
    brix_wmirror_file_t *f;
    int                    idx;

    (void) c;
    wm = ctx->wmirror;
    if (wm == NULL || !wmir_gate(conf)) { return; }

    idx = (int) (unsigned char) ctx->recv.hdr_buf[4];   /* fhandle byte 0 */
    if (idx < 0 || idx >= BRIX_MAX_FILES) { return; }
    f = &wm->files[idx];
    if (!f->active) { return; }

    switch (ctx->recv.cur_reqid) {

    case kXR_pgwrite:
        f->aborted = 1;        /* CRC-interleaved payload — not a plain write */
        return;

    case kXR_write: {
        uint64_t off_be;
        off_t    off;
        size_t   len = ctx->recv.cur_dlen;
        u_char  *ndata;

        if (f->aborted) { return; }
        if (primary_rc == NGX_ERROR) { f->aborted = 1; return; }

        /* Write offset is an 8-byte big-endian field at header byte 8.  Only a
         * strictly contiguous stream (off == expected next offset) can collapse
         * into the single offset-0 replay write; a gap/seek aborts the file. */
        ngx_memcpy(&off_be, ctx->recv.hdr_buf + 8, 8);
        off = (off_t) be64toh(off_be);
        if (off != f->next_off) { f->aborted = 1; return; }   /* non-sequential */
        if (len == 0) { return; }
        /* Bounded buffering: enforce both the per-file and the connection-wide
         * caps before growing, so a large or many-file upload can't balloon
         * memory.  Hitting a cap is counted (dropped metric), not an error. */
        if (f->data_len + len > BRIX_WMIRROR_FILE_CAP
            || wm->total_buffered + len > BRIX_WMIRROR_CONN_CAP)
        {
            f->aborted = 1;
            BRIX_WMIR_METRIC_INC(mirror_stream_dropped_total);
            return;
        }
        /* Grow-by-copy append: allocate old+new, copy the existing prefix, free
         * the old buffer, then append the new bytes.  (Not ngx_realloc so the
         * old contents are explicitly preserved across the move.) */
        ndata = ngx_alloc(f->data_len + len, ngx_cycle->log);
        if (ndata == NULL) { f->aborted = 1; return; }
        if (f->data_len) {
            ngx_memcpy(ndata, f->data, f->data_len);
            ngx_free(f->data);
        }
        ngx_memcpy(ndata + f->data_len, ctx->recv.payload, len);
        f->data = ndata;
        f->data_len += len;
        f->next_off += (off_t) len;        /* advance expected contiguous offset */
        wm->total_buffered += len;
        return;
    }

    case kXR_close:
        f->active = 0;
        /* Replay only a clean, non-empty, non-aborted file whose primary close
         * also succeeded.  wmir_launch steals f->data, so the unconditional
         * wmir_file_reset that follows safely clears the (now-nulled) slot. */
        if (!f->aborted && f->data_len > 0 && primary_rc != NGX_ERROR) {
            wmir_launch(conf, f);            /* transfers f->data ownership */
        }
        wmir_file_reset(wm, f);
        return;

    default:
        return;
    }
}

/*
 * Hook: client connection is going away — free any still-open accumulators.
 *
 * WHY this matters: f->data / f->open_payload are heap buffers (ngx_alloc), NOT
 * pool memory, so they would leak if the connection dies mid-upload (no close
 * ever observed).  Resetting every slot frees them.  The accumulator struct (wm)
 * itself lives in the connection pool and is reclaimed automatically, so we only
 * drop the pointer.  Any replay already launched is fully detached and unaffected
 * (it owns its own copy of the data).
 */
void
brix_stream_wmirror_cleanup(brix_ctx_t *ctx)
{
    brix_wmirror_conn_t *wm = ctx->wmirror;
    int                    i;

    if (wm == NULL) { return; }
    for (i = 0; i < BRIX_MAX_FILES; i++) {
        wmir_file_reset(wm, &wm->files[i]);
    }
    ctx->wmirror = NULL;   /* wm itself is connection-pool memory */
}
