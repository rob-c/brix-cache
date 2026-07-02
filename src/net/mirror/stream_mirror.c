/*
 * stream_mirror.c — Phase 24 XRootD stream traffic mirror (see stream_mirror.h).
 *
 * The mirror is a self-contained async XRootD client connection whose wire
 * framing reuses the proven upstream bootstrap, exactly like the Phase 22
 * health-check probe (src/manager/health_check.c): the bootstrap write buffer
 * is built by xrootd_upstream_build_bootstrap(), and responses are read as
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
extern void xrootd_upstream_build_bootstrap(u_char *buf);

/* Bound on the replayed payload — path + options for stat/locate/open/dirlist
 * fit easily; anything larger (e.g. a stray write body) is skipped. */
#define XROOTD_MIRROR_MAX_PAYLOAD  4096

typedef enum {
    XRD_MIR_HANDSHAKE = 0,
    XRD_MIR_PROTOCOL,
    XRD_MIR_LOGIN,
    XRD_MIR_REQUEST,        /* sent the replayed request, awaiting its response */
} xrootd_mir_phase_t;

typedef struct {
    ngx_pool_t        *pool;          /* owns this ctx + conn->pool */
    ngx_connection_t  *conn;
    ngx_log_t         *log;
    xrootd_mir_phase_t phase;
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
} xrootd_stream_mirror_t;

#define XROOTD_MIR_METRIC_INC(field)                                         \
    do {                                                                     \
        ngx_xrootd_metrics_t *_m = xrootd_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

static void xrootd_mir_write_handler(ngx_event_t *wev);
static void xrootd_mir_read_handler(ngx_event_t *rev);
static void xrootd_mir_timeout_handler(ngx_event_t *ev);
static void xrootd_mir_finish(xrootd_stream_mirror_t *mir, int sent);


/* opcode filter */
static ngx_uint_t
xrootd_mirror_opcode_bit(uint16_t reqid)
{
    switch (reqid) {
    case kXR_stat:    return XROOTD_MIRROR_OP_STAT;
    case kXR_locate:  return XROOTD_MIRROR_OP_LOCATE;
    case kXR_open:    return XROOTD_MIRROR_OP_OPEN;
    case kXR_read:    return XROOTD_MIRROR_OP_READ;
    case kXR_readv:   return XROOTD_MIRROR_OP_READV;
    case kXR_dirlist: return XROOTD_MIRROR_OP_DIRLIST;
    case kXR_statx:   return XROOTD_MIRROR_OP_STATX;
    case kXR_query:   return XROOTD_MIRROR_OP_QUERY;
    /* Write/mutation opcodes (Phase 24 write mirroring, gated by
     * xrootd_mirror_writes).  mkdir/rm/rmdir/mv/truncate/chmod are self-contained
     * path-based metadata ops replayable by this stateless mirror; data writes
     * (open-write/write/pgwrite/close) map to OP_WRITE but are handled by the
     * stateful write-mirror (W3), not here. */
    case kXR_mkdir:    return XROOTD_MIRROR_OP_MKDIR;
    case kXR_rm:       return XROOTD_MIRROR_OP_RM;
    case kXR_rmdir:    return XROOTD_MIRROR_OP_RMDIR;
    case kXR_mv:       return XROOTD_MIRROR_OP_MV;
    case kXR_truncate: return XROOTD_MIRROR_OP_TRUNCATE;
    case kXR_chmod:    return XROOTD_MIRROR_OP_CHMOD;
    default:          return 0;
    }
}

/* Write-implying open flags.  A read-path mirror must never replay these to a
 * shadow: they would create/truncate/append/mkdir on the official server. */
#define XROOTD_MIRROR_OPEN_WRITE_FLAGS \
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
xrootd_mirror_request_replayable(xrootd_ctx_t *ctx)
{
    switch (ctx->cur_reqid) {
    case kXR_locate:
    case kXR_dirlist:
    case kXR_query:
        return 1;
    case kXR_stat:
    case kXR_statx:
        return ctx->cur_dlen > 0;
    case kXR_open: {
        uint16_t options;     /* ClientOpenRequest.options — header byte 6 */
        ngx_memcpy(&options, ctx->hdr_buf + 6, sizeof(options));
        options = ntohs(options);
        return (options & XROOTD_MIRROR_OPEN_WRITE_FLAGS) == 0;
    }
    /* Metadata mutations (W1): self-contained and path-based — the path[s] live
     * in the payload, so a fresh shadow session replays them faithfully.
     * truncate may instead be by open-handle (dlen==0); that form is not
     * replayable, same as handle-based stat.  These reach here only when
     * xrootd_mirror_writes is on (gated in xrootd_stream_mirror_maybe). */
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        return ctx->cur_dlen > 0;
    default:
        return 0;
    }
}


/* write side */
/* Drain the pending write buffer to the shadow socket; see
 * xrootd_mirror_io_flush(). */
static ngx_int_t
xrootd_mir_flush(xrootd_stream_mirror_t *mir)
{
    return xrootd_mirror_io_flush(mir->conn, mir->wbuf, mir->wbuf_len,
                                  &mir->wbuf_pos);
}

/* Bootstrap complete: send the saved primary request frame to the shadow. */
static void
xrootd_mir_send_request(xrootd_stream_mirror_t *mir)
{
    size_t  total = (size_t) 24 + mir->saved_dlen;
    u_char *buf   = ngx_palloc(mir->pool, total);

    if (buf == NULL) {
        xrootd_mir_finish(mir, 0);
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

    if (xrootd_mir_flush(mir) == NGX_ERROR) {
        xrootd_mir_finish(mir, 0);
    }
}

static void
xrootd_mir_write_handler(ngx_event_t *wev)
{
    ngx_connection_t       *c   = wev->data;
    xrootd_stream_mirror_t *mir = c->data;

    if (wev->timedout) {
        xrootd_mir_finish(mir, 0);
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
            xrootd_mir_finish(mir, 0);
            return;
        }
        mir->connecting = 0;
    }

    if (xrootd_mir_flush(mir) == NGX_ERROR) {
        xrootd_mir_finish(mir, 0);
    }
}


/* read side */
/* Read one shadow response frame (header + bounded body); see
 * xrootd_mirror_io_recv_frame(). */
static ngx_int_t
xrootd_mir_recv_frame(xrootd_stream_mirror_t *mir)
{
    return xrootd_mirror_io_recv_frame(mir->conn, mir->rhdr, &mir->rhdr_pos,
                                       &mir->resp_status, &mir->resp_dlen,
                                       &mir->resp_body, &mir->resp_body_pos);
}

/* The shadow answered our replayed request: compare status, count divergence. */
static void
xrootd_mir_on_response(xrootd_stream_mirror_t *mir)
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

    XROOTD_MIR_METRIC_INC(mirror_stream_total);

    if (!shadow_unsupported && shadow_ok != mir->primary_ok) {
        XROOTD_MIR_METRIC_INC(mirror_stream_divergence_total);
        if (mir->log_diverge) {
            ngx_log_error(NGX_LOG_NOTICE, mir->log, 0,
                "xrootd mirror divergence: %s:%d op=%d "
                "primary_ok=%d shadow_kxr_status=%d",
                mir->host, (int) mir->port, (int) mir->saved_opcode,
                mir->primary_ok, (int) mir->resp_status);
        }
    }

    xrootd_mir_finish(mir, 1);
}

static void
xrootd_mir_dispatch(xrootd_stream_mirror_t *mir)
{
    switch (mir->phase) {

    case XRD_MIR_HANDSHAKE:
        if (mir->resp_status != kXR_ok) { xrootd_mir_finish(mir, 0); return; }
        mir->phase = XRD_MIR_PROTOCOL;
        break;

    case XRD_MIR_PROTOCOL:
        if (mir->resp_status != kXR_ok) { xrootd_mir_finish(mir, 0); return; }
        /* If the shadow demands TLS we can't continue the cleartext replay; the
         * server is alive though, so just stop without counting an error. */
        if (mir->resp_dlen >= 8) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, mir->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) {
                xrootd_mir_finish(mir, 1);
                return;
            }
        }
        mir->phase = XRD_MIR_LOGIN;
        break;

    case XRD_MIR_LOGIN:
        /* authmore => shadow wants credentials we cannot replay; stop quietly. */
        if (mir->resp_status == kXR_authmore) {
            xrootd_mir_finish(mir, 1);
            return;
        }
        if (mir->resp_status != kXR_ok) { xrootd_mir_finish(mir, 0); return; }
        xrootd_mir_send_request(mir);  /* sets phase = REQUEST */
        return;

    case XRD_MIR_REQUEST:
        xrootd_mir_on_response(mir);
        return;
    }

    /* Reset the accumulator and re-post the read so pipelined bootstrap frames
     * already in the socket buffer are processed in this cycle. */
    mir->rhdr_pos      = 0;
    mir->resp_dlen     = 0;
    mir->resp_body     = NULL;
    mir->resp_body_pos = 0;

    if (ngx_handle_read_event(mir->conn->read, 0) != NGX_OK) {
        xrootd_mir_finish(mir, 0);
        return;
    }
    ngx_post_event(mir->conn->read, &ngx_posted_events);
}

static void
xrootd_mir_read_handler(ngx_event_t *rev)
{
    ngx_connection_t       *c   = rev->data;
    xrootd_stream_mirror_t *mir = c->data;
    ngx_int_t               rc;

    if (rev->timedout) {
        xrootd_mir_finish(mir, 0);
        return;
    }

    rc = xrootd_mir_recv_frame(mir);
    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            xrootd_mir_finish(mir, 0);
        }
        return;
    }
    if (rc == NGX_ERROR) {
        xrootd_mir_finish(mir, 0);
        return;
    }
    xrootd_mir_dispatch(mir);
}


/* lifecycle */
static void
xrootd_mir_timeout_handler(ngx_event_t *ev)
{
    xrootd_stream_mirror_t *mir = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, mir->log, 0,
                   "xrootd mirror: %s:%d timed out", mir->host, (int) mir->port);
    xrootd_mir_finish(mir, 0);
}

static void
xrootd_mir_finish(xrootd_stream_mirror_t *mir, int sent)
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
        XROOTD_MIR_METRIC_INC(mirror_stream_errors_total);
    }
    ngx_destroy_pool(pool);            /* frees mir itself (last use above) */
}

static void
xrootd_mir_start(xrootd_stream_mirror_t *mir, ngx_msec_t timeout_ms)
{
    ngx_connection_t *c;
    ngx_socket_t      fd;
    size_t            bslen;
    int               rc;

    fd = ngx_socket(mir->sockaddr.ss_family, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1 || ngx_nonblocking(fd) == -1) {
        if (fd != (ngx_socket_t) -1) { ngx_close_socket(fd); }
        xrootd_mir_finish(mir, 0);
        return;
    }

    c = ngx_get_connection(fd, mir->log);
    if (c == NULL) {
        ngx_close_socket(fd);
        xrootd_mir_finish(mir, 0);
        return;
    }
    c->pool          = mir->pool;
    c->data          = mir;
    c->recv          = ngx_recv;
    c->send          = ngx_send;
    c->read->handler  = xrootd_mir_read_handler;
    c->write->handler = xrootd_mir_write_handler;
    c->read->log = c->write->log = mir->log;
    mir->conn = c;

    /* Pipelined bootstrap: handshake + protocol + login. */
    bslen = XRD_HANDSHAKE_LEN + sizeof(ClientProtocolRequest)
          + sizeof(ClientLoginRequest);
    mir->wbuf = ngx_palloc(mir->pool, bslen);
    if (mir->wbuf == NULL) {
        xrootd_mir_finish(mir, 0);
        return;
    }
    xrootd_upstream_build_bootstrap(mir->wbuf);
    mir->wbuf_len = bslen;
    mir->wbuf_pos = 0;

    mir->tev.handler = xrootd_mir_timeout_handler;
    mir->tev.data    = mir;
    mir->tev.log     = mir->log;
    ngx_add_timer(&mir->tev, timeout_ms);

    rc = connect(fd, (struct sockaddr *) &mir->sockaddr, mir->socklen);

    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        xrootd_mir_finish(mir, 0);
        return;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        xrootd_mir_finish(mir, 0);
        return;
    }

    if (rc == 0) {
        mir->connecting = 0;
        if (xrootd_mir_flush(mir) == NGX_ERROR) {
            xrootd_mir_finish(mir, 0);
        }
    } else {
        mir->connecting = 1;           /* completes in the write handler */
    }
}


/* launch hook (called from dispatch.c) */
void
xrootd_stream_mirror_maybe(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_int_t primary_rc)
{
    xrootd_mirror_target_t *targets;
    ngx_uint_t              opbit, i;
    int                     primary_ok;

    if (!conf->mirror.enabled || conf->mirror.targets == NULL) {
        return;
    }

    opbit = xrootd_mirror_opcode_bit(ctx->cur_reqid);
    /* Mirror all ops in opcode_mask (default ALL) that are not de-selected via
     * xrootd_mirror_exclude_opcodes. */
    if (opbit == 0
        || (conf->mirror.opcode_mask & opbit) == 0
        || (conf->mirror.opcode_exclude_mask & opbit) != 0)
    {
        return;
    }

    /* Second, independent guard for write/mutation opcodes: even if an operator
     * lists e.g. "mkdir" in xrootd_mirror_opcodes, it stays inert unless
     * xrootd_mirror_writes is explicitly on (and the shadow is an isolated
     * namespace).  OP_WRITE (data writes) is handled by the stateful write-mirror,
     * not this one-shot path, so it never proceeds here. */
    if ((opbit & XROOTD_MIRROR_OP_WRITE_ALL) != 0) {
        if (!conf->mirror.mirror_writes || opbit == XROOTD_MIRROR_OP_WRITE) {
            return;
        }
    }

    /* Only replay requests the shadow can answer standalone (path-based reads,
     * read-only opens, query/Qcksum).  Handle-based reads/readv/handle-stat and
     * write opens are skipped so the mirror never spuriously diverges against an
     * official xrootd — see xrootd_mirror_request_replayable(). */
    if (!xrootd_mirror_request_replayable(ctx)) {
        return;
    }

    /* Skip oversized payloads (write bodies); also a sanity guard. */
    if (ctx->cur_dlen > XROOTD_MIRROR_MAX_PAYLOAD) {
        return;
    }

    if (!xrootd_mirror_should_sample(conf->mirror.sample_pct)) {
        XROOTD_MIR_METRIC_INC(mirror_stream_dropped_total);
        return;
    }

    primary_ok = (primary_rc != NGX_ERROR);
    targets    = conf->mirror.targets->elts;

    for (i = 0; i < conf->mirror.targets->nelts; i++) {
        ngx_pool_t             *pool;
        xrootd_stream_mirror_t *mir;

        if (targets[i].socklen == 0) {
            continue;   /* unresolved target */
        }

        pool = ngx_create_pool(2048, ngx_cycle->log);
        if (pool == NULL) {
            continue;
        }
        mir = ngx_pcalloc(pool, sizeof(*mir));
        if (mir == NULL) {
            ngx_destroy_pool(pool);
            continue;
        }
        mir->pool        = pool;
        mir->log         = ngx_cycle->log;   /* outlives the client connection */
        mir->phase       = XRD_MIR_HANDSHAKE;
        mir->primary_ok  = primary_ok;
        mir->log_diverge = conf->mirror.log_diverge;
        mir->port        = targets[i].port;
        mir->socklen     = targets[i].socklen;
        ngx_memcpy(&mir->sockaddr, &targets[i].sockaddr, targets[i].socklen);
        ngx_cpystrn((u_char *) mir->host,
                    targets[i].host.data ? targets[i].host.data
                                         : (u_char *) "?",
                    sizeof(mir->host));

        /* Snapshot the request now — ctx->payload may be reused by the next
         * request before the shadow exchange completes. */
        ngx_memcpy(mir->saved_hdr, ctx->hdr_buf, 24);
        mir->saved_opcode = ctx->cur_reqid;
        if (ctx->payload != NULL && ctx->cur_dlen > 0) {
            mir->saved_payload = ngx_palloc(pool, ctx->cur_dlen);
            if (mir->saved_payload != NULL) {
                ngx_memcpy(mir->saved_payload, ctx->payload, ctx->cur_dlen);
                mir->saved_dlen = ctx->cur_dlen;
            }
        }

        xrootd_mir_start(mir, conf->mirror.timeout_ms);
    }
}


/* directive setters */
/*
 * xrootd_stream_mirror_url host:port — append one shadow target, resolved at
 * configuration time so request handlers never call getaddrinfo on the event
 * loop.  Up to XROOTD_MIRROR_MAX_TARGETS may be configured.
 */
char *
xrootd_stream_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    xrootd_mirror_target_t       *t;
    ngx_url_t                     u;
    u_char                       *colon;
    ngx_str_t                     hostport = value[1];

    (void) cmd;

    if (xcf->mirror.targets == NULL) {
        xcf->mirror.targets = ngx_array_create(cf->pool,
            XROOTD_MIRROR_MAX_TARGETS, sizeof(xrootd_mirror_target_t));
        if (xcf->mirror.targets == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    if (xcf->mirror.targets->nelts >= XROOTD_MIRROR_MAX_TARGETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_stream_mirror_url: at most %d targets supported",
            XROOTD_MIRROR_MAX_TARGETS);
        return NGX_CONF_ERROR;
    }

    if (hostport.len == 0
        || ngx_strlchr(hostport.data, hostport.data + hostport.len, ':')
           == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_stream_mirror_url: expected host:port, got \"%V\"",
            &hostport);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url          = hostport;
    u.default_port = 1094;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK || u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_stream_mirror_url: cannot resolve \"%V\"%s%s", &hostport,
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
        "xrootd: stream mirror target %V", &hostport);
    return NGX_CONF_OK;
}

/*
 * Parse opcode name args (cf->args[1..]) into a bitmask.  "all" expands to
 * XROOTD_MIRROR_OP_ALL.  Shared by the allowlist and exclude setters.
 */
static char *
xrootd_mirror_parse_opcode_args(ngx_conf_t *cf, const char *directive,
    ngx_uint_t *mask_out)
{
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i, mask = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *v = &value[i];
        if      (ngx_strcmp(v->data, "all")     == 0) mask |= XROOTD_MIRROR_OP_ALL;
        else if (ngx_strcmp(v->data, "stat")    == 0) mask |= XROOTD_MIRROR_OP_STAT;
        else if (ngx_strcmp(v->data, "locate")  == 0) mask |= XROOTD_MIRROR_OP_LOCATE;
        else if (ngx_strcmp(v->data, "open")    == 0) mask |= XROOTD_MIRROR_OP_OPEN;
        else if (ngx_strcmp(v->data, "read")    == 0) mask |= XROOTD_MIRROR_OP_READ;
        else if (ngx_strcmp(v->data, "readv")   == 0) mask |= XROOTD_MIRROR_OP_READV;
        else if (ngx_strcmp(v->data, "dirlist") == 0) mask |= XROOTD_MIRROR_OP_DIRLIST;
        else if (ngx_strcmp(v->data, "statx")   == 0) mask |= XROOTD_MIRROR_OP_STATX;
        else if (ngx_strcmp(v->data, "query")   == 0) mask |= XROOTD_MIRROR_OP_QUERY;
        /* Write/mutation opcodes (require xrootd_mirror_writes on). */
        else if (ngx_strcmp(v->data, "mkdir")    == 0) mask |= XROOTD_MIRROR_OP_MKDIR;
        else if (ngx_strcmp(v->data, "rm")       == 0) mask |= XROOTD_MIRROR_OP_RM;
        else if (ngx_strcmp(v->data, "rmdir")    == 0) mask |= XROOTD_MIRROR_OP_RMDIR;
        else if (ngx_strcmp(v->data, "mv")       == 0) mask |= XROOTD_MIRROR_OP_MV;
        else if (ngx_strcmp(v->data, "truncate") == 0) mask |= XROOTD_MIRROR_OP_TRUNCATE;
        else if (ngx_strcmp(v->data, "chmod")    == 0) mask |= XROOTD_MIRROR_OP_CHMOD;
        else if (ngx_strcmp(v->data, "write")    == 0) mask |= XROOTD_MIRROR_OP_WRITE;
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s: unknown opcode \"%V\" (expected one of"
                " all stat locate open read readv dirlist statx query"
                " mkdir rm rmdir mv truncate chmod write)",
                directive, v);
            return NGX_CONF_ERROR;
        }
    }
    *mask_out = mask;
    return NGX_CONF_OK;
}

/*
 * xrootd_mirror_opcodes stat locate open ...  — RESTRICT mirroring to exactly
 * the named opcodes (allowlist; overrides the default-all).  Most operators
 * want the default (mirror everything) or xrootd_mirror_exclude_opcodes instead.
 */
char *
xrootd_stream_mirror_set_opcodes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    (void) cmd;
    return xrootd_mirror_parse_opcode_args(cf, "xrootd_mirror_opcodes",
                                           &xcf->mirror.opcode_mask);
}

/*
 * xrootd_mirror_exclude_opcodes read query ...  — DE-SELECT opcodes from the
 * mirrored set.  Mirroring defaults to ALL ops, so this is the normal way to
 * turn specific ops off without listing everything you want to keep.
 */
char *
xrootd_stream_mirror_set_exclude_opcodes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    (void) cmd;
    return xrootd_mirror_parse_opcode_args(cf, "xrootd_mirror_exclude_opcodes",
                                           &xcf->mirror.opcode_exclude_mask);
}
