/*
 * stream_mirror.c — Phase 24 XRootD stream traffic mirror (see stream_mirror.h).
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
 */
#include "stream_mirror.h"
#include "stream_mirror_io.h"
#include "observability/metrics/metrics_macros.h"

#include <netdb.h>
#include <sys/socket.h>

/* Built by src/upstream/bootstrap.c; pure wire framing, no client context. */
extern void brix_upstream_build_bootstrap(u_char *buf);

/* Bound on the replayed payload — path + options for stat/locate/open/dirlist
 * fit easily; anything larger (e.g. a stray write body) is skipped. */
#define BRIX_MIRROR_MAX_PAYLOAD  4096

typedef enum {
    XRD_MIR_HANDSHAKE = 0,
    XRD_MIR_PROTOCOL,
    XRD_MIR_LOGIN,
    XRD_MIR_REQUEST,        /* sent the replayed request, awaiting its response */
} brix_mir_phase_t;

typedef struct {
    ngx_pool_t        *pool;          /* owns this ctx + conn->pool */
    ngx_connection_t  *conn;
    ngx_log_t         *log;
    brix_mir_phase_t phase;
    unsigned           connecting:1;

    /* Response accumulator (mirrors the health-check probe). */
    u_char    rhdr[XRD_RESPONSE_HDR_LEN];
    size_t    rhdr_pos;
    uint16_t  resp_status;
    uint32_t  resp_dlen;
    u_char   *resp_body;
    size_t    resp_body_pos;

    /* Write buffer. */
    u_char   *wbuf;
    size_t    wbuf_len;
    size_t    wbuf_pos;

    ngx_event_t  tev;                 /* single deadline timer for the exchange */

    char       host[256];
    uint16_t   port;
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;

    /* Saved primary request (copied at launch). */
    u_char     saved_hdr[24];         /* XRD_REQUEST_HDR_LEN */
    u_char    *saved_payload;
    uint32_t   saved_dlen;
    uint16_t   saved_opcode;

    int         primary_ok;           /* primary dispatch succeeded? */
    ngx_uint_t  log_diverge;
} brix_stream_mirror_t;

#define BRIX_MIR_METRIC_INC(field)                                         \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

static void brix_mir_write_handler(ngx_event_t *wev);
static void brix_mir_read_handler(ngx_event_t *rev);
static void brix_mir_timeout_handler(ngx_event_t *ev);
static void brix_mir_finish(brix_stream_mirror_t *mir, int sent);


/* opcode filter */
static ngx_uint_t
brix_mirror_opcode_bit(uint16_t reqid)
{
    switch (reqid) {
    case kXR_stat:    return BRIX_MIRROR_OP_STAT;
    case kXR_locate:  return BRIX_MIRROR_OP_LOCATE;
    case kXR_open:    return BRIX_MIRROR_OP_OPEN;
    case kXR_read:    return BRIX_MIRROR_OP_READ;
    case kXR_readv:   return BRIX_MIRROR_OP_READV;
    case kXR_dirlist: return BRIX_MIRROR_OP_DIRLIST;
    case kXR_statx:   return BRIX_MIRROR_OP_STATX;
    case kXR_query:   return BRIX_MIRROR_OP_QUERY;
    /* Write/mutation opcodes (Phase 24 write mirroring, gated by
     * brix_mirror_writes).  mkdir/rm/rmdir/mv/truncate/chmod are self-contained
     * path-based metadata ops replayable by this stateless mirror; data writes
     * (open-write/write/pgwrite/close) map to OP_WRITE but are handled by the
     * stateful write-mirror (W3), not here. */
    case kXR_mkdir:    return BRIX_MIRROR_OP_MKDIR;
    case kXR_rm:       return BRIX_MIRROR_OP_RM;
    case kXR_rmdir:    return BRIX_MIRROR_OP_RMDIR;
    case kXR_mv:       return BRIX_MIRROR_OP_MV;
    case kXR_truncate: return BRIX_MIRROR_OP_TRUNCATE;
    case kXR_chmod:    return BRIX_MIRROR_OP_CHMOD;
    default:          return 0;
    }
}

/* Write-implying open flags.  A read-path mirror must never replay these to a
 * shadow: they would create/truncate/append/mkdir on the official server. */
#define BRIX_MIRROR_OPEN_WRITE_FLAGS \
    (kXR_delete | kXR_new | kXR_open_updt | kXR_open_apnd | kXR_mkpath)

/*
 * Can this request be faithfully replayed to a fresh shadow session?
 *
 * The mirror is stateless — it opens a new connection, bootstraps, and sends ONE
 * saved request frame.  That only works for SELF-CONTAINED, side-effect-free
 * requests whose target lives entirely in the frame:
 *
 *   - locate / dirlist / query (incl. Qcksum) : path + args are in the payload.
 *   - stat / statx with dlen>0                : path-based (dlen==0 is by open
 *                                               handle and cannot be replayed).
 *   - open WITHOUT write flags                : a read-only open of a path.
 *
 * Handle-based ops (read, readv, stat/statx by handle) carry the CLIENT's file
 * handle, which is meaningless on the shadow's separate session, and write/
 * create opens would mutate the official server.  Neither is replayable by a
 * stateless mirror, so they are skipped — this is what lets the mirror "just
 * work" in front of an official xrootd instead of spuriously diverging.
 */
static int
brix_mirror_request_replayable(brix_ctx_t *ctx)
{
    switch (ctx->recv.cur_reqid) {
    case kXR_locate:
    case kXR_dirlist:
    case kXR_query:
        return 1;
    case kXR_stat:
    case kXR_statx:
        return ctx->recv.cur_dlen > 0;
    case kXR_open: {
        uint16_t options;     /* ClientOpenRequest.options — header byte 6 */
        ngx_memcpy(&options, ctx->recv.hdr_buf + 6, sizeof(options));
        options = ntohs(options);
        return (options & BRIX_MIRROR_OPEN_WRITE_FLAGS) == 0;
    }
    /* Metadata mutations (W1): self-contained and path-based — the path[s] live
     * in the payload, so a fresh shadow session replays them faithfully.
     * truncate may instead be by open-handle (dlen==0); that form is not
     * replayable, same as handle-based stat.  These reach here only when
     * brix_mirror_writes is on (gated in brix_stream_mirror_maybe). */
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        return ctx->recv.cur_dlen > 0;
    default:
        return 0;
    }
}


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

static void
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


/* launch hook (called from dispatch.c) */

/*
 * Is this write/mutation opcode cleared to proceed on the one-shot mirror?
 *
 * WHAT: for a WRITE-class @opbit, return 1 only when brix_mirror_writes is on
 *       AND the op is a self-contained metadata mutation (not OP_WRITE); for
 *       any non-write opcode return 1 unconditionally.
 * WHY:  write mirroring needs a second, independent gate beyond the opcode
 *       allowlist, and data writes (OP_WRITE) belong to the stateful write-
 *       mirror, never this stateless path — factoring it keeps the driver flat.
 * HOW:  short-circuits on the non-write case; otherwise checks the flag and
 *       excludes OP_WRITE.
 */
static int
brix_mirror_write_op_allowed(ngx_uint_t opbit,
    ngx_stream_brix_srv_conf_t *conf)
{
    if ((opbit & BRIX_MIRROR_OP_WRITE_ALL) == 0) {
        return 1;
    }
    if (!conf->mirror.mirror_writes || opbit == BRIX_MIRROR_OP_WRITE) {
        return 0;
    }
    return 1;
}

/*
 * Decide whether the current request is eligible to be mirrored at all.
 *
 * WHAT: run every fast-reject gate (feature off, opcode filtered, write-gate,
 *       non-replayable, oversized payload, sampling) and return 1 only when the
 *       request should proceed to per-target launch.
 * WHY:  collapses the whole guard ladder into one predicate so the launch
 *       driver expresses just "eligible? then fan out", not the policy.
 * HOW:  sequential early-returns; @opbit is returned to the caller so the launch
 *       path need not recompute it.  Emits the drop metric on sample loss.
 */
static int
brix_stream_mirror_eligible(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, ngx_uint_t *opbit_out)
{
    ngx_uint_t  opbit;

    if (!conf->mirror.enabled || conf->mirror.targets == NULL) {
        return 0;
    }

    opbit = brix_mirror_opcode_bit(ctx->recv.cur_reqid);
    /* Mirror all ops in opcode_mask (default ALL) that are not de-selected via
     * brix_mirror_exclude_opcodes. */
    if (opbit == 0
        || (conf->mirror.opcode_mask & opbit) == 0
        || (conf->mirror.opcode_exclude_mask & opbit) != 0)
    {
        return 0;
    }

    /* Second, independent guard for write/mutation opcodes: even if an operator
     * lists e.g. "mkdir" in brix_mirror_opcodes, it stays inert unless
     * brix_mirror_writes is explicitly on (and the shadow is an isolated
     * namespace).  OP_WRITE (data writes) is handled by the stateful write-mirror,
     * not this one-shot path, so it never proceeds here. */
    if (!brix_mirror_write_op_allowed(opbit, conf)) {
        return 0;
    }

    /* Only replay requests the shadow can answer standalone (path-based reads,
     * read-only opens, query/Qcksum).  Handle-based reads/readv/handle-stat and
     * write opens are skipped so the mirror never spuriously diverges against an
     * official xrootd — see brix_mirror_request_replayable(). */
    if (!brix_mirror_request_replayable(ctx)) {
        return 0;
    }

    /* Skip oversized payloads (write bodies); also a sanity guard. */
    if (ctx->recv.cur_dlen > BRIX_MIRROR_MAX_PAYLOAD) {
        return 0;
    }

    if (!brix_mirror_should_sample(conf->mirror.sample_pct)) {
        BRIX_MIR_METRIC_INC(mirror_stream_dropped_total);
        return 0;
    }

    *opbit_out = opbit;
    return 1;
}

/*
 * Allocate a mirror context, copy target + saved request into it, and start it.
 *
 * WHAT: for one resolved @target, create the mirror's private pool + ctx,
 *       snapshot the primary request frame (header, opcode, payload), and kick
 *       off brix_mir_start().  Unresolved targets and OOM are skipped silently.
 * WHY:  isolates the per-target allocation/snapshot from the fan-out loop, so
 *       the driver is a flat iteration and each launch owns its own cleanup.
 * HOW:  a fresh cycle-pool ctx (outlives the client conn); the request payload
 *       is copied now because ctx->recv.payload may be reused before the shadow
 *       exchange completes.
 */
static void
brix_stream_mirror_launch_target(brix_ctx_t *ctx,
    brix_mirror_target_t *target, ngx_stream_brix_srv_conf_t *conf,
    int primary_ok)
{
    ngx_pool_t            *pool;
    brix_stream_mirror_t  *mir;

    if (target->socklen == 0) {
        return;   /* unresolved target */
    }

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL) {
        return;
    }
    mir = ngx_pcalloc(pool, sizeof(*mir));
    if (mir == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    mir->pool        = pool;
    mir->log         = ngx_cycle->log;   /* outlives the client connection */
    mir->phase       = XRD_MIR_HANDSHAKE;
    mir->primary_ok  = primary_ok;
    mir->log_diverge = conf->mirror.log_diverge;
    mir->port        = target->port;
    mir->socklen     = target->socklen;
    ngx_memcpy(&mir->sockaddr, &target->sockaddr, target->socklen);
    ngx_cpystrn((u_char *) mir->host,
                target->host.data ? target->host.data
                                  : (u_char *) "?",
                sizeof(mir->host));

    /* Snapshot the request now — ctx->recv.payload may be reused by the next
     * request before the shadow exchange completes. */
    ngx_memcpy(mir->saved_hdr, ctx->recv.hdr_buf, 24);
    mir->saved_opcode = ctx->recv.cur_reqid;
    if (ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0) {
        mir->saved_payload = ngx_palloc(pool, ctx->recv.cur_dlen);
        if (mir->saved_payload != NULL) {
            ngx_memcpy(mir->saved_payload, ctx->recv.payload, ctx->recv.cur_dlen);
            mir->saved_dlen = ctx->recv.cur_dlen;
        }
    }

    brix_mir_start(mir, conf->mirror.timeout_ms);
}

void
brix_stream_mirror_maybe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, ngx_int_t primary_rc)
{
    brix_mirror_target_t *targets;
    ngx_uint_t              opbit = 0, i;
    int                     primary_ok;

    (void) c;

    if (!brix_stream_mirror_eligible(ctx, conf, &opbit)) {
        return;
    }
    (void) opbit;   /* eligibility owns opcode policy; driver just fans out */

    primary_ok = (primary_rc != NGX_ERROR);
    targets    = conf->mirror.targets->elts;

    for (i = 0; i < conf->mirror.targets->nelts; i++) {
        brix_stream_mirror_launch_target(ctx, &targets[i], conf, primary_ok);
    }
}


/* directive setters */
/*
 * brix_stream_mirror_url host:port — append one shadow target, resolved at
 * configuration time so request handlers never call getaddrinfo on the event
 * loop.  Up to BRIX_MIRROR_MAX_TARGETS may be configured.
 */
char *
brix_stream_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    brix_mirror_target_t       *t;
    ngx_url_t                     u;
    u_char                       *colon;
    ngx_str_t                     hostport = value[1];

    (void) cmd;

    if (xcf->mirror.targets == NULL) {
        xcf->mirror.targets = ngx_array_create(cf->pool,
            BRIX_MIRROR_MAX_TARGETS, sizeof(brix_mirror_target_t));
        if (xcf->mirror.targets == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    if (xcf->mirror.targets->nelts >= BRIX_MIRROR_MAX_TARGETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: at most %d targets supported",
            BRIX_MIRROR_MAX_TARGETS);
        return NGX_CONF_ERROR;
    }

    if (hostport.len == 0
        || ngx_strlchr(hostport.data, hostport.data + hostport.len, ':')
           == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: expected host:port, got \"%V\"",
            &hostport);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url          = hostport;
    u.default_port = 1094;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK || u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: cannot resolve \"%V\"%s%s", &hostport,
            u.err ? ": " : "", u.err ? u.err : "");
        return NGX_CONF_ERROR;
    }

    t = ngx_array_push(xcf->mirror.targets);
    if (t == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(t, sizeof(*t));
    t->url  = hostport;
    t->host = u.host;
    t->port = u.port;
    if (u.addrs[0].socklen > sizeof(t->sockaddr)) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(&t->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    t->socklen = u.addrs[0].socklen;

    /* keep the host:port colon split out of the host label for logging */
    colon = ngx_strlchr(hostport.data, hostport.data + hostport.len, ':');
    if (colon != NULL && t->host.len == 0) {
        t->host.data = hostport.data;
        t->host.len  = (size_t) (colon - hostport.data);
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: stream mirror target %V", &hostport);
    return NGX_CONF_OK;
}

/*
 * Opcode-name → bitmask table.
 *
 * WHAT: static lookup pairing each accepted brix_mirror_opcodes token with the
 *       BRIX_MIRROR_OP_* bit(s) it selects.  "all" expands to the full set.
 * WHY:  a data table replaces a 16-arm if/else ladder, keeping the parse loop
 *       branch-flat and making the accepted vocabulary a single edit point.
 * HOW:  terminated by a NULL name; brix_mirror_opcode_name_bit() scans it.
 */
typedef struct {
    const char  *name;
    ngx_uint_t   bit;
} brix_mirror_opcode_name_t;

static const brix_mirror_opcode_name_t  brix_mirror_opcode_names[] = {
    { "all",      BRIX_MIRROR_OP_ALL      },
    { "stat",     BRIX_MIRROR_OP_STAT     },
    { "locate",   BRIX_MIRROR_OP_LOCATE   },
    { "open",     BRIX_MIRROR_OP_OPEN     },
    { "read",     BRIX_MIRROR_OP_READ     },
    { "readv",    BRIX_MIRROR_OP_READV    },
    { "dirlist",  BRIX_MIRROR_OP_DIRLIST  },
    { "statx",    BRIX_MIRROR_OP_STATX    },
    { "query",    BRIX_MIRROR_OP_QUERY    },
    /* Write/mutation opcodes (require brix_mirror_writes on). */
    { "mkdir",    BRIX_MIRROR_OP_MKDIR    },
    { "rm",       BRIX_MIRROR_OP_RM       },
    { "rmdir",    BRIX_MIRROR_OP_RMDIR    },
    { "mv",       BRIX_MIRROR_OP_MV       },
    { "truncate", BRIX_MIRROR_OP_TRUNCATE },
    { "chmod",    BRIX_MIRROR_OP_CHMOD    },
    { "write",    BRIX_MIRROR_OP_WRITE    },
    { NULL,       0                       },
};

/*
 * Map one opcode-name token to its bitmask.
 *
 * WHAT: return the BRIX_MIRROR_OP_* bit(s) for @name, or 0 if unrecognised.
 * WHY:  isolates the table scan so the parse loop stays a flat data walk.
 * HOW:  linear scan of brix_mirror_opcode_names (small, config-time only).
 */
static ngx_uint_t
brix_mirror_opcode_name_bit(const u_char *name)
{
    const brix_mirror_opcode_name_t *e;

    for (e = brix_mirror_opcode_names; e->name != NULL; e++) {
        if (ngx_strcmp(name, e->name) == 0) {
            return e->bit;
        }
    }
    return 0;
}

/*
 * Parse opcode name args (cf->args[1..]) into a bitmask.  "all" expands to
 * BRIX_MIRROR_OP_ALL.  Shared by the allowlist and exclude setters.
 */
static char *
brix_mirror_parse_opcode_args(ngx_conf_t *cf, const char *directive,
    ngx_uint_t *mask_out)
{
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i, mask = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t  *v   = &value[i];
        ngx_uint_t  bit = brix_mirror_opcode_name_bit(v->data);

        if (bit == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s: unknown opcode \"%V\" (expected one of"
                " all stat locate open read readv dirlist statx query"
                " mkdir rm rmdir mv truncate chmod write)",
                directive, v);
            return NGX_CONF_ERROR;
        }
        mask |= bit;
    }
    *mask_out = mask;
    return NGX_CONF_OK;
}

/*
 * brix_mirror_opcodes stat locate open ...  — RESTRICT mirroring to exactly
 * the named opcodes (allowlist; overrides the default-all).  Most operators
 * want the default (mirror everything) or brix_mirror_exclude_opcodes instead.
 */
char *
brix_stream_mirror_set_opcodes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_mirror_parse_opcode_args(cf, "brix_mirror_opcodes",
                                           &xcf->mirror.opcode_mask);
}

/*
 * brix_mirror_exclude_opcodes read query ...  — DE-SELECT opcodes from the
 * mirrored set.  Mirroring defaults to ALL ops, so this is the normal way to
 * turn specific ops off without listing everything you want to keep.
 */
char *
brix_stream_mirror_set_exclude_opcodes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_mirror_parse_opcode_args(cf, "brix_mirror_exclude_opcodes",
                                           &xcf->mirror.opcode_exclude_mask);
}
