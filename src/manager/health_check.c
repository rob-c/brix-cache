/*
 * health_check.c — Phase 22 active stream health checks (see health_check.h).
 *
 * The probe is a self-contained async XRootD client connection.  Its wire
 * framing mirrors the proven upstream bootstrap (src/upstream/bootstrap.c):
 * the bootstrap write buffer is built by the shared
 * xrootd_upstream_build_bootstrap(), and responses are read as uniform 8-byte
 * ServerResponseHdr + dlen-byte body frames, exactly as the upstream read loop
 * does.  Unlike the upstream path it carries no client context — on bootstrap
 * completion it sends kXR_ping (or kXR_stat "/") and reports the verdict to the
 * registry rather than forwarding a saved client request.
 *
 * A single deadline timer (hc_timeout_ms) bounds the whole probe; a hung server
 * that accepts the TCP connection but never answers is failed on timeout.
 */
#include "manager/health_check.h"
#include "manager/registry.h"
#include "metrics/metrics_macros.h"
#include "compat/log_diag.h"

#include <netdb.h>
#include <sys/socket.h>

/* Built by src/upstream/bootstrap.c; pure wire framing, no client context. */
extern void xrootd_upstream_build_bootstrap(u_char *buf);

/*
 * Probe state machine, advanced one step per complete response frame received.
 * Each phase consumes the server's reply to the request the previous phase (or
 * the pipelined bootstrap) sent: HANDSHAKE -> PROTOCOL -> LOGIN -> PROBE.  See
 * xrootd_hc_dispatch() for the per-phase transitions and early-exit verdicts.
 */
typedef enum {
    XRD_HC_HANDSHAKE = 0,
    XRD_HC_PROTOCOL,
    XRD_HC_LOGIN,
    XRD_HC_PROBE,
} xrootd_hc_phase_t;

/*
 * Per-probe state.  Allocated from its own pool (hc->pool, also used as
 * conn->pool) so the entire probe — ctx, connection, scratch buffers — is freed
 * in one ngx_destroy_pool() in xrootd_hc_finish().  One of these exists per
 * in-flight probe; there is no shared mutable state between probes.
 */
typedef struct {
    ngx_pool_t        *pool;          /* owns this ctx + conn->pool */
    ngx_connection_t  *conn;
    ngx_log_t         *log;
    xrootd_hc_phase_t  phase;
    unsigned           connecting:1;  /* until TCP connect confirmed */

    /* Response accumulator (mirrors xrootd_upstream_t). */
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

    ngx_event_t  tev;                 /* single probe deadline timer */

    char       host[256];
    uint16_t   port;

    uint32_t    threshold;
    ngx_msec_t  blacklist_ms;
    ngx_uint_t  probe_type;
} xrootd_hc_ctx_t;

/*
 * Per-worker, per-server-block manager state.  Long-lived (allocated from
 * cycle->pool); drives the recurring scan timer that claims one due registry
 * slot every scan_interval_ms and launches a probe for it.
 */
typedef struct {
    ngx_event_t                   timer;
    ngx_cycle_t                  *cycle;
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_msec_t                    scan_interval_ms;
} xrootd_hc_mgr_t;

/* Atomically bump a shared-memory health-check counter; no-op if the metrics
 * zone is not mapped (e.g. metrics disabled). */
#define XROOTD_HC_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_xrootd_metrics_t *_m = xrootd_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

static void xrootd_hc_write_handler(ngx_event_t *wev);
static void xrootd_hc_read_handler(ngx_event_t *rev);
static void xrootd_hc_timeout_handler(ngx_event_t *ev);
static void xrootd_hc_finish(xrootd_hc_ctx_t *hc, int passed);


/* write side */
/*
 * Drain hc->wbuf to the socket without blocking.  Returns NGX_OK once the whole
 * buffer is sent (and read events re-armed so the reply can arrive), NGX_AGAIN
 * if the socket is full (write event re-armed; xrootd_hc_write_handler resumes
 * here), or NGX_ERROR on a fatal send error.
 */
static ngx_int_t
xrootd_hc_flush(xrootd_hc_ctx_t *hc)
{
    ngx_connection_t *c = hc->conn;
    ssize_t           n;

    /* Partial-write loop: send() may consume only part of the buffer, so track
     * wbuf_pos and resume from there on the next writable event. */
    while (hc->wbuf_pos < hc->wbuf_len) {
        n = c->send(c, hc->wbuf + hc->wbuf_pos, hc->wbuf_len - hc->wbuf_pos);
        if (n > 0) {
            hc->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * Build and send the final liveness probe (kXR_ping or kXR_stat "/") after a
 * successful login, transitioning to XRD_HC_PROBE.  The reply's status is the
 * pass/fail verdict, decided back in xrootd_hc_dispatch().
 */
static void
xrootd_hc_send_probe(xrootd_hc_ctx_t *hc)
{
    if (hc->probe_type == XROOTD_HC_TYPE_STAT) {
        /* kXR_stat request followed by a 1-byte path body "/".  Over-allocate
         * by 1 so the path char sits immediately after the fixed header. */
        size_t total = sizeof(ClientStatRequest) + 1;   /* path "/" */
        ClientStatRequest *r = ngx_palloc(hc->pool, total);
        if (r == NULL) { xrootd_hc_finish(hc, 0); return; }
        ngx_memzero(r, sizeof(*r));
        /* streamid is a 2-byte client tag echoed in the reply; {0,2} marks this
         * as a health request (see ping branch below). */
        r->streamid[0] = 0;
        r->streamid[1] = 2;
        r->requestid   = htons(kXR_stat);          /* opcode, network order */
        r->dlen        = htonl((kXR_int32) 1);      /* body length = 1 ("/") */
        ((u_char *) r)[sizeof(*r)] = '/';           /* append path after header */
        hc->wbuf     = (u_char *) r;
        hc->wbuf_len = total;
    } else {
        ClientPingRequest *r = ngx_palloc(hc->pool, sizeof(*r));
        if (r == NULL) { xrootd_hc_finish(hc, 0); return; }
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0;
        r->streamid[1] = 2;            /* streamid 2 marks a health request */
        r->requestid   = htons(kXR_ping);
        r->dlen        = 0;            /* ping carries no body */
        hc->wbuf     = (u_char *) r;
        hc->wbuf_len = sizeof(*r);
    }
    /* Reset both write and read accumulators for this fresh request/response. */
    hc->wbuf_pos      = 0;
    hc->rhdr_pos      = 0;
    hc->resp_dlen     = 0;
    hc->resp_body     = NULL;
    hc->resp_body_pos = 0;
    hc->phase         = XRD_HC_PROBE;

    if (xrootd_hc_flush(hc) == NGX_ERROR) {
        xrootd_hc_finish(hc, 0);
    }
}

/*
 * Writable-event handler.  First writable event after a non-blocking connect()
 * confirms (or rejects) the TCP connection via SO_ERROR; subsequent calls just
 * resume a partially-flushed write buffer.
 */
static void
xrootd_hc_write_handler(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    xrootd_hc_ctx_t  *hc = c->data;
    ngx_int_t         rc;

    if (wev->timedout) {
        xrootd_hc_finish(hc, 0);
        return;
    }

    /* Non-blocking connect completes asynchronously: the first writable event
     * means connect() finished — SO_ERROR carries success (0) or the failure
     * code, since connect() itself returned EINPROGRESS earlier. */
    if (hc->connecting) {
        int       err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len) == -1
            || err != 0)
        {
            XROOTD_DIAG_WARN(hc->log, err, /* may be 0 */
                "xrootd: health check failed to connect to %s:%d",
                "the cluster member is down or unreachable from the manager",
                "check that member's xrootd/data service and the network path "
                "to it; it is marked DOWN and clients are routed elsewhere "
                "until it passes again",
                hc->host, (int) hc->port);
            xrootd_hc_finish(hc, 0);
            return;
        }
        hc->connecting = 0;
    }

    rc = xrootd_hc_flush(hc);
    if (rc == NGX_ERROR) {
        xrootd_hc_finish(hc, 0);
    }
}


/* read side */
/* Accumulate one full ServerResponseHdr + body frame; return NGX_OK when a
 * complete frame is ready, NGX_AGAIN to wait for more, NGX_ERROR on close. */
static ngx_int_t
xrootd_hc_recv_frame(xrootd_hc_ctx_t *hc)
{
    ngx_connection_t *c = hc->conn;
    ssize_t           n;

    /* Stage 1: fill the fixed 8-byte header, possibly across several reads
     * (rhdr_pos tracks how much has arrived).  Only once it is complete do we
     * decode status/dlen and learn the body length. */
    if (hc->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
        size_t need = XRD_RESPONSE_HDR_LEN - hc->rhdr_pos;
        n = c->recv(c, hc->rhdr + hc->rhdr_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }  /* 0 = peer closed */
        hc->rhdr_pos += (size_t) n;
        if (hc->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            return NGX_AGAIN;
        }
        /* Header complete: decode the wire fields (big-endian on the wire). */
        {
            ServerResponseHdr *h = (ServerResponseHdr *) (void *) hc->rhdr;
            hc->resp_status = ntohs(h->status);
            hc->resp_dlen   = ntohl(h->dlen);
        }
        if (hc->resp_dlen > 0) {
            /* Bound attacker/garbage-controlled body length: a probe reply is
             * tiny, so cap the allocation rather than trust the wire dlen. */
            if (hc->resp_dlen > 4096) {     /* bound probe response bodies */
                return NGX_ERROR;
            }
            hc->resp_body = ngx_palloc(c->pool, hc->resp_dlen);
            if (hc->resp_body == NULL) { return NGX_ERROR; }
            hc->resp_body_pos = 0;
        }
    }

    /* Stage 2: fill the dlen-byte body (again possibly across several reads).
     * Skipped entirely when dlen == 0. */
    if (hc->resp_body_pos < hc->resp_dlen) {
        size_t need = hc->resp_dlen - hc->resp_body_pos;
        n = c->recv(c, hc->resp_body + hc->resp_body_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }
        hc->resp_body_pos += (size_t) n;
        if (hc->resp_body_pos < hc->resp_dlen) {
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}

/*
 * Consume one complete response frame and advance the probe state machine.
 * Several phases short-circuit to a verdict (alive/dead) without reaching the
 * final PROBE phase — see the per-case comments.  On a non-terminal transition
 * it resets the accumulator and re-posts the read event so any already-buffered
 * pipelined reply is processed in the same event cycle.
 */

static void
xrootd_hc_dispatch(xrootd_hc_ctx_t *hc)
{
    switch (hc->phase) {

    case XRD_HC_HANDSHAKE:
        if (hc->resp_status != kXR_ok) { xrootd_hc_finish(hc, 0); return; }
        hc->phase = XRD_HC_PROTOCOL;
        break;

    case XRD_HC_PROTOCOL:
        if (hc->resp_status != kXR_ok) { xrootd_hc_finish(hc, 0); return; }
        /* If the server demands TLS we don't probe deeper (no TLS in the
         * probe path); it answered at the protocol level, so treat it as
         * alive rather than blacklisting it.
         *
         * ServerResponseBody_Protocol layout: bytes 0-3 = pval (protocol
         * version), bytes 4-7 = flags.  Read the flags word at offset 4 and
         * test the kXR_gotoTLS bit.  Guard on dlen >= 8 so short/old replies
         * that omit the flags simply fall through to the LOGIN phase. */
        if (hc->resp_dlen >= 8) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, hc->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) {
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->log, 0,
                    "xrootd: health check: %s:%d wants TLS; "
                    "treating protocol-OK as alive", hc->host, (int) hc->port);
                xrootd_hc_finish(hc, 1);
                return;
            }
        }
        hc->phase = XRD_HC_LOGIN;
        break;

    case XRD_HC_LOGIN:
        /* authmore => server is alive but wants credentials; we don't carry
         * any, so accept protocol liveness rather than fail. */
        if (hc->resp_status == kXR_authmore) {
            xrootd_hc_finish(hc, 1);
            return;
        }
        if (hc->resp_status != kXR_ok) { xrootd_hc_finish(hc, 0); return; }
        xrootd_hc_send_probe(hc);      /* sets phase = PROBE, sends ping/stat */
        return;

    case XRD_HC_PROBE:
        xrootd_hc_finish(hc, hc->resp_status == kXR_ok ? 1 : 0);
        return;
    }

    /* Reset accumulator for the next frame and post a synthetic read so any
     * pipelined bytes already in the socket buffer are processed this cycle. */
    hc->rhdr_pos      = 0;
    hc->resp_dlen     = 0;
    hc->resp_body     = NULL;
    hc->resp_body_pos = 0;

    if (ngx_handle_read_event(hc->conn->read, 0) != NGX_OK) {
        xrootd_hc_finish(hc, 0);
        return;
    }
    ngx_post_event(hc->conn->read, &ngx_posted_events);
}

/*
 * Readable-event handler.  Pulls exactly one complete frame per invocation and
 * hands it to xrootd_hc_dispatch(), which re-arms (or posts) the read event for
 * the next frame; this keeps each event-loop iteration bounded.
 */
static void
xrootd_hc_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c  = rev->data;
    xrootd_hc_ctx_t  *hc = c->data;
    ngx_int_t         rc;

    if (rev->timedout) {
        xrootd_hc_finish(hc, 0);
        return;
    }

    /* Loop is structural only: every branch returns.  It exists so a future
     * "read another frame inline" change has an obvious place to continue. */
    for ( ;; ) {
        rc = xrootd_hc_recv_frame(hc);
        if (rc == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                xrootd_hc_finish(hc, 0);
            }
            return;
        }
        if (rc == NGX_ERROR) {
            xrootd_hc_finish(hc, 0);
            return;
        }
        xrootd_hc_dispatch(hc);
        return;                        /* dispatch re-arms / posts as needed */
    }
}


/* lifecycle */
/* Whole-probe deadline fired (hc_timeout_ms): a server that accepted the TCP
 * connection but never finished answering is failed. */
static void
xrootd_hc_timeout_handler(ngx_event_t *ev)
{
    xrootd_hc_ctx_t *hc = ev->data;

    XROOTD_DIAG_WARN(hc->log, 0,
        "xrootd: health check to %s:%d timed out",
        "the member accepted the TCP connection but never finished the "
        "health probe — it is overloaded, hung, or half-broken",
        "investigate that member's load and logs; it is marked DOWN until it "
        "answers a probe within the timeout",
        hc->host, (int) hc->port);
    xrootd_hc_finish(hc, 0);
}

/*
 * Single termination point for a probe (called from every error/success path).
 * Reports the verdict to the shared registry, bumps metrics, and tears down all
 * probe state.  MUST be the last thing any caller does with hc: it destroys the
 * pool that backs hc itself, so hc is dangling on return.
 */
static void
xrootd_hc_finish(xrootd_hc_ctx_t *hc, int passed)
{
    /* Stash the pool before any registry call: hc lives inside it and is freed
     * by the ngx_destroy_pool() at the end. */
    ngx_pool_t *pool = hc->pool;

    /* Cancel the deadline timer and close the socket before reporting, so a
     * verdict callback can never observe a half-torn-down probe. */
    if (hc->tev.timer_set) {
        ngx_del_timer(&hc->tev);
    }
    if (hc->conn != NULL) {
        ngx_close_connection(hc->conn);
        hc->conn = NULL;
    }

    if (passed) {
        xrootd_srv_hc_pass(hc->host, hc->port);
        XROOTD_HC_METRIC_INC(hc_pass_total);
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->log, 0,
                       "xrootd: health check: %s:%d passed",
                       hc->host, (int) hc->port);
    } else {
        if (xrootd_srv_hc_fail(hc->host, hc->port,
                               hc->threshold, hc->blacklist_ms))
        {
            XROOTD_HC_METRIC_INC(hc_blacklist_total);
            ngx_log_error(NGX_LOG_WARN, hc->log, 0,
                          "xrootd: health check: %s:%d blacklisted after"
                          " %ui consecutive failures",
                          hc->host, (int) hc->port, (ngx_uint_t) hc->threshold);
        }
        XROOTD_HC_METRIC_INC(hc_fail_total);
    }

    ngx_destroy_pool(pool);            /* frees hc itself (last use above) */
}

/*
 * Pre-connection failure cleanup for xrootd_hc_start(): the socket/connection
 * could not be set up before hc took ownership, so the resolver result (if any)
 * is freed here, the probe is reported as a real failure (configured
 * threshold/blacklist), and the probe pool is destroyed.
 */
static void
xrootd_hc_pre_connect_fail(struct addrinfo *res, const char *host,
    uint16_t port, ngx_stream_xrootd_srv_conf_t *conf, ngx_pool_t *pool)
{
    if (res != NULL) {
        freeaddrinfo(res);
    }
    xrootd_srv_hc_fail(host, port, conf->hc_threshold, conf->hc_blacklist_ms);
    ngx_destroy_pool(pool);
}

/*
 * Launch one probe against host:port (the slot was already claimed by
 * xrootd_srv_hc_claim()).  Sets up a non-blocking connection, queues the
 * pipelined bootstrap, arms the deadline timer, and starts connect().  Control
 * then returns to the event loop; the probe completes asynchronously in the
 * read/write handlers, always ending at xrootd_hc_finish().
 *
 * Ownership note: every early-exit path here MUST release the claim — either
 * via xrootd_hc_finish() (once hc exists and reports a verdict) or via a direct
 * xrootd_srv_hc_fail() (before hc is usable).  Otherwise the slot stays
 * hc_in_progress=1 forever and is never probed again.
 */
static void
xrootd_hc_start(ngx_cycle_t *cycle, ngx_stream_xrootd_srv_conf_t *conf,
    const char *host, uint16_t port)
{
    ngx_pool_t        *pool;
    xrootd_hc_ctx_t   *hc;
    ngx_connection_t  *c;
    struct addrinfo    hints, *res = NULL;
    char               portstr[8];
    ngx_socket_t       fd;
    size_t             bslen;
    int                rc;

    /* Allocation failures before the probe is viable count as neither pass nor
     * fail toward blacklisting (threshold/blacklist_ms = 0); they only clear
     * hc_in_progress so the slot is re-probed next interval. */
    pool = ngx_create_pool(1024, cycle->log);
    if (pool == NULL) {
        xrootd_srv_hc_fail(host, port, 0, 0);   /* release the claim */
        return;
    }
    hc = ngx_pcalloc(pool, sizeof(*hc));
    if (hc == NULL) {
        ngx_destroy_pool(pool);
        xrootd_srv_hc_fail(host, port, 0, 0);
        return;
    }
    hc->pool         = pool;
    hc->log          = cycle->log;
    hc->phase        = XRD_HC_HANDSHAKE;
    hc->probe_type   = conf->hc_type;
    hc->threshold    = (uint32_t) conf->hc_threshold;
    hc->blacklist_ms = conf->hc_blacklist_ms;
    hc->port         = port;
    ngx_cpystrn((u_char *) hc->host, (u_char *) host, sizeof(hc->host));

    /* Resolve target. */
    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) ngx_snprintf((u_char *) portstr, sizeof(portstr), "%d%Z",
                        (int) port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "xrootd: health check: cannot resolve %s:%d",
                      host, (int) port);
        xrootd_srv_hc_fail(host, port, conf->hc_threshold,
                           conf->hc_blacklist_ms);
        ngx_destroy_pool(pool);
        return;
    }

    /* Until hc->conn is wired up, the socket is owned manually and must be
     * closed by hand on error (the pool does not know about a bare fd).  These
     * pre-connection failures jump to `fail`, which counts as a real probe
     * failure (uses the configured threshold/blacklist). */
    fd = ngx_socket(res->ai_family, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1 || ngx_nonblocking(fd) == -1) {
        if (fd != (ngx_socket_t) -1) { ngx_close_socket(fd); }
        xrootd_hc_pre_connect_fail(res, host, port, conf, pool);
        return;
    }

    c = ngx_get_connection(fd, cycle->log);
    if (c == NULL) {
        ngx_close_socket(fd);
        xrootd_hc_pre_connect_fail(res, host, port, conf, pool);
        return;
    }
    /* From here the connection (and therefore the fd) is owned by hc->conn and
     * released through xrootd_hc_finish() -> ngx_close_connection(). */
    c->pool          = pool;
    c->data          = hc;
    c->recv          = ngx_recv;
    c->send          = ngx_send;
    c->read->handler  = xrootd_hc_read_handler;
    c->write->handler = xrootd_hc_write_handler;
    c->read->log = c->write->log = cycle->log;
    hc->conn = c;

    /* Pipelined bootstrap: handshake + protocol + login. */
    bslen = XRD_HANDSHAKE_LEN + sizeof(ClientProtocolRequest)
          + sizeof(ClientLoginRequest);
    hc->wbuf = ngx_palloc(pool, bslen);
    if (hc->wbuf == NULL) {
        freeaddrinfo(res);
        xrootd_hc_finish(hc, 0);
        return;
    }
    xrootd_upstream_build_bootstrap(hc->wbuf);
    hc->wbuf_len = bslen;
    hc->wbuf_pos = 0;

    /* Single deadline for the whole probe. */
    hc->tev.handler = xrootd_hc_timeout_handler;
    hc->tev.data    = hc;
    hc->tev.log     = cycle->log;
    ngx_add_timer(&hc->tev, conf->hc_timeout_ms);

    XROOTD_HC_METRIC_INC(hc_probes_total);

    /* Non-blocking connect: rc == 0 means it completed immediately (typical for
     * localhost/loopback); EINPROGRESS means it is in flight; any other error
     * is a hard failure.  Free the resolver result either way before branching. */
    rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    res = NULL;

    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        xrootd_hc_finish(hc, 0);
        return;
    }
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        xrootd_hc_finish(hc, 0);
        return;
    }

    if (rc == 0) {
        /* Connected synchronously: send the bootstrap now; the reply arrives
         * via the read handler. */
        hc->connecting = 0;
        if (xrootd_hc_flush(hc) == NGX_ERROR) {
            xrootd_hc_finish(hc, 0);
        }
    } else {
        /* In progress: the first writable event runs xrootd_hc_write_handler,
         * which confirms SO_ERROR and then flushes the bootstrap. */
        hc->connecting = 1;            /* finish in the write handler */
    }
    return;
}

/*
 * Recurring scan tick.  Re-arms itself first (so a probe-launch failure can't
 * stop future scans), then tries to claim at most one due server from the
 * shared registry and probe it.  Claiming exactly one per tick is what spreads
 * load and guarantees a single worker probes each server per interval.
 */
static void
xrootd_hc_timer_handler(ngx_event_t *ev)
{
    xrootd_hc_mgr_t              *mgr  = ev->data;
    ngx_stream_xrootd_srv_conf_t *conf = mgr->conf;
    char        host[256];
    uint16_t    port;
    ngx_msec_t  next_due = conf->hc_interval_ms;
    ngx_msec_t  delay;

    /* Claim is atomic under the registry spinlock and self-rate-limits via
     * hc_next_check, so concurrent workers never double-probe one server. */
    if (xrootd_srv_hc_claim(host, sizeof(host), &port,
                            conf->hc_interval_ms, &next_due))
    {
        xrootd_hc_start(mgr->cycle, conf, host, port);
        /* More servers may be due now — spread the remaining probes at the
         * per-slot cadence rather than firing them all this tick. */
        delay = mgr->scan_interval_ms;
    } else {
        /* Nothing due: sleep until the soonest server becomes due instead of
         * waking at the sub-second floor to find nothing (the old idle drain).
         * Floored by the spread cadence (burst guard) and capped by the probe
         * interval (so a freshly-registered server is probed within one). */
        delay = next_due;
        if (delay < mgr->scan_interval_ms) {
            delay = mgr->scan_interval_ms;
        }
        if (delay > conf->hc_interval_ms) {
            delay = conf->hc_interval_ms;
        }
    }

    /* Re-arm (bounded to [scan_interval, hc_interval]) — a probe-launch
     * failure or empty registry can never stop future scans.  Suppressed once
     * the worker is exiting so the scan loop releases the draining worker. */
    if (!ngx_exiting) {
        ngx_add_timer(ev, delay);
    }
}

void
xrootd_hc_manager_start(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_hc_mgr_t *mgr;
    ngx_msec_t       scan;

    if (!conf->hc_enabled || conf->hc_interval_ms == 0) {
        return;
    }

    mgr = ngx_pcalloc(cycle->pool, sizeof(*mgr));
    if (mgr == NULL) {
        return;
    }
    mgr->cycle = cycle;
    mgr->conf  = conf;

    /* Spread probes across the interval: one claim attempt every
     * interval/slots ms, floored at 100 ms. */
    scan = conf->hc_interval_ms / XROOTD_SRV_REGISTRY_SLOTS;
    mgr->scan_interval_ms = scan < 100 ? 100 : scan;

    mgr->timer.handler = xrootd_hc_timer_handler;
    mgr->timer.data    = mgr;
    mgr->timer.log     = cycle->log;

    ngx_add_timer(&mgr->timer, 2000);  /* let CMS connections settle first */

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: health check manager started "
                  "(interval=%Ms timeout=%Ms scan=%Ms)",
                  conf->hc_interval_ms, conf->hc_timeout_ms,
                  mgr->scan_interval_ms);
}
