/*
 * health_check.c — Phase 22 active stream health checks (see health_check.h).
 *
 * The probe is a self-contained async XRootD client connection.  Its wire
 * framing mirrors the proven upstream bootstrap (src/upstream/bootstrap.c):
 * the bootstrap write buffer is built by the shared
 * brix_upstream_build_bootstrap(), and responses are read as uniform 8-byte
 * ServerResponseHdr + dlen-byte body frames, exactly as the upstream read loop
 * does.  Unlike the upstream path it carries no client context — on bootstrap
 * completion it sends kXR_ping (or kXR_stat "/") and reports the verdict to the
 * registry rather than forwarding a saved client request.
 *
 * A single deadline timer (hc_timeout_ms) bounds the whole probe; a hung server
 * that accepts the TCP connection but never answers is failed on timeout.
 */
#include "health_check.h"
#include "registry.h"
#include "observability/metrics/metrics_macros.h"
#include "core/compat/log_diag.h"
#include "health_check_internal.h"

#include <netdb.h>
#include <sys/socket.h>

/* Built by src/upstream/bootstrap.c; pure wire framing, no client context. */
extern void brix_upstream_build_bootstrap_flags(u_char *buf,
    uint8_t protocol_flags);

/*
 * Per-worker, per-server-block manager state.  Long-lived (allocated from
 * cycle->pool); drives the recurring scan timer that claims one due registry
 * slot every scan_interval_ms and launches a probe for it.
 */
typedef struct {
    ngx_event_t                   timer;
    ngx_cycle_t                  *cycle;
    ngx_stream_brix_srv_conf_t *conf;
    ngx_msec_t                    scan_interval_ms;
} brix_hc_mgr_t;


/* lifecycle */
/* Whole-probe deadline fired (hc_timeout_ms): a server that accepted the TCP
 * connection but never finished answering is failed. */
static void
brix_hc_timeout_handler(ngx_event_t *ev)
{
    brix_hc_ctx_t *hc = ev->data;

    BRIX_DIAG_WARN(hc->log, 0,
        "brix: health check to %s:%d timed out",
        "the member accepted the TCP connection but never finished the "
        "health probe — it is overloaded, hung, or half-broken",
        "investigate that member's load and logs; it is marked DOWN until it "
        "answers a probe within the timeout",
        hc->host, (int) hc->port);
    brix_hc_finish(hc, 0);
}

/*
 * Single termination point for a probe (called from every error/success path).
 * Reports the verdict to the shared registry, bumps metrics, and tears down all
 * probe state.  MUST be the last thing any caller does with hc: it destroys the
 * pool that backs hc itself, so hc is dangling on return.
 */
void
brix_hc_finish(brix_hc_ctx_t *hc, int passed)
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
        brix_srv_hc_pass(hc->host, hc->port);
        BRIX_HC_METRIC_INC(hc_pass_total);
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->log, 0,
                       "brix: health check: %s:%d passed",
                       hc->host, (int) hc->port);
    } else {
        if (brix_srv_hc_fail(hc->host, hc->port,
                               hc->threshold, hc->blacklist_ms))
        {
            BRIX_HC_METRIC_INC(hc_blacklist_total);
            ngx_log_error(NGX_LOG_WARN, hc->log, 0,
                          "brix: health check: %s:%d blacklisted after"
                          " %ui consecutive failures",
                          hc->host, (int) hc->port, (ngx_uint_t) hc->threshold);
        }
        BRIX_HC_METRIC_INC(hc_fail_total);
    }

    ngx_destroy_pool(pool);            /* frees hc itself (last use above) */
}

/*
 * Pre-connection failure cleanup for brix_hc_start(): the socket/connection
 * could not be set up before hc took ownership, so the resolver result (if any)
 * is freed here, the probe is reported as a real failure (configured
 * threshold/blacklist), and the probe pool is destroyed.
 */
static void
brix_hc_pre_connect_fail(struct addrinfo *res, const char *host,
    uint16_t port, ngx_stream_brix_srv_conf_t *conf, ngx_pool_t *pool)
{
    if (res != NULL) {
        freeaddrinfo(res);
    }
    brix_srv_hc_fail(host, port, conf->hc.threshold, conf->hc.blacklist_ms);
    ngx_destroy_pool(pool);
}

/*
 * Allocate the probe pool + ctx and seed the identity/config fields for
 * brix_hc_start().  Returns the ctx, or NULL after releasing the claim.
 * Allocation failures before the probe is viable count as neither pass nor
 * fail toward blacklisting (threshold/blacklist_ms = 0); they only clear
 * hc_in_progress so the slot is re-probed next interval.
 */
static brix_hc_ctx_t *
brix_hc_ctx_create(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf,
    const char *host, uint16_t port)
{
    ngx_pool_t      *pool;
    brix_hc_ctx_t *hc;

    pool = ngx_create_pool(1024, cycle->log);
    if (pool == NULL) {
        brix_srv_hc_fail(host, port, 0, 0);   /* release the claim */
        return NULL;
    }
    hc = ngx_pcalloc(pool, sizeof(*hc));
    if (hc == NULL) {
        ngx_destroy_pool(pool);
        brix_srv_hc_fail(host, port, 0, 0);
        return NULL;
    }
    hc->pool         = pool;
    hc->log          = cycle->log;
    hc->conf         = conf;
    hc->phase        = XRD_HC_HANDSHAKE;
    hc->probe_type   = conf->hc.type;
    hc->threshold    = (uint32_t) conf->hc.threshold;
    hc->blacklist_ms = conf->hc.blacklist_ms;
    hc->port         = port;
    ngx_cpystrn((u_char *) hc->host, (u_char *) host, sizeof(hc->host));
    return hc;
}

/*
 * Resolve host:port for brix_hc_start().  Returns the addrinfo list (owned by
 * the caller), or NULL after reporting a real probe failure (configured
 * threshold/blacklist) and destroying the probe pool.
 */
static struct addrinfo *
brix_hc_resolve(brix_hc_ctx_t *hc, const char *host, uint16_t port)
{
    struct addrinfo  hints, *res = NULL;
    char             portstr[8];

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) ngx_snprintf((u_char *) portstr, sizeof(portstr), "%d%Z",
                        (int) port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        ngx_log_error(NGX_LOG_WARN, hc->log, 0,
                      "brix: health check: cannot resolve %s:%d",
                      host, (int) port);
        brix_srv_hc_fail(host, port, hc->conf->hc.threshold,
                           hc->conf->hc.blacklist_ms);
        ngx_destroy_pool(hc->pool);
        return NULL;
    }
    return res;
}

/*
 * Create the non-blocking probe socket and wire it into an nginx connection
 * for brix_hc_start().  Returns NGX_OK with hc->conn owning the fd, or
 * NGX_ERROR after full pre-connection cleanup (socket closed by hand,
 * brix_hc_pre_connect_fail() frees res, records the failure, destroys the
 * pool).
 */
static ngx_int_t
brix_hc_open_conn(ngx_cycle_t *cycle, brix_hc_ctx_t *hc,
    struct addrinfo *res, const char *host, uint16_t port)
{
    ngx_connection_t  *c;
    ngx_socket_t       fd;

    /* Until hc->conn is wired up, the socket is owned manually and must be
     * closed by hand on error (the pool does not know about a bare fd).  These
     * pre-connection failures count as a real probe failure (they use the
     * configured threshold/blacklist). */
    fd = ngx_socket(res->ai_family, SOCK_STREAM, 0);
    if (fd == (ngx_socket_t) -1 || ngx_nonblocking(fd) == -1) {
        if (fd != (ngx_socket_t) -1) { ngx_close_socket(fd); }
        brix_hc_pre_connect_fail(res, host, port, hc->conf, hc->pool);
        return NGX_ERROR;
    }

    c = ngx_get_connection(fd, cycle->log);
    if (c == NULL) {
        ngx_close_socket(fd);
        brix_hc_pre_connect_fail(res, host, port, hc->conf, hc->pool);
        return NGX_ERROR;
    }
    /* From here the connection (and therefore the fd) is owned by hc->conn and
     * released through brix_hc_finish() -> ngx_close_connection(). */
    c->pool          = hc->pool;
    c->data          = hc;
    c->recv          = ngx_recv;
    c->send          = ngx_send;
    c->read->handler  = brix_hc_read_handler;
    c->write->handler = brix_hc_write_handler;
    c->read->log = c->write->log = cycle->log;
    hc->conn = c;
    return NGX_OK;
}

/*
 * Build the pipelined bootstrap write buffer for brix_hc_start().  Returns
 * NGX_OK with hc->wbuf/wbuf_len/wbuf_pos queued for sending, or NGX_ERROR on
 * allocation failure (no cleanup here; the caller reports the verdict).
 */
static ngx_int_t
brix_hc_queue_bootstrap(brix_hc_ctx_t *hc)
{
    size_t  bslen;

    /* Step F: with an outbound TLS ctx the probe can complete a kXR_gotoTLS
     * upgrade, so advertise kXR_ableTLS — a brix server only answers gotoTLS
     * to TLS-capable clients (it lets others finish in cleartext, which would
     * silently skip the deep-probe path).  A TLS-capable probe must NOT
     * pipeline the plaintext login behind the protocol request: on gotoTLS
     * the server hands every pending cleartext byte to the TLS layer, and a
     * pre-sent login corrupts the handshake ("packet length too long").  So
     * it sends handshake + protocol only and defers login until the protocol
     * verdict.  Without a ctx the flag byte stays 0 and the full pipelined
     * bootstrap is byte-identical to pre-Step-F probes. */
#if (NGX_SSL)
    hc->tls_capable = (hc->conf->upstream_tls
                       && hc->conf->upstream_tls_ctx != NULL);
#endif
    /* Always allocate (and build) all three frames; wbuf_len truncates the
     * SEND to handshake + protocol for a TLS-capable probe. */
    bslen = XRD_HANDSHAKE_LEN + sizeof(ClientProtocolRequest)
          + sizeof(ClientLoginRequest);
    hc->wbuf = ngx_palloc(hc->pool, bslen);
    if (hc->wbuf == NULL) {
        return NGX_ERROR;
    }
    brix_upstream_build_bootstrap_flags(hc->wbuf,
                                        hc->tls_capable ? kXR_ableTLS : 0);
    hc->wbuf_len = hc->tls_capable
                   ? bslen - sizeof(ClientLoginRequest) : bslen;
    hc->wbuf_pos = 0;
    return NGX_OK;
}

/*
 * Kick off the connect() for brix_hc_start() and hand the probe to the event
 * loop.  Frees the resolver result; every failure path ends in
 * brix_hc_finish(), so the claim is always released.
 */
static void
brix_hc_begin_connect(brix_hc_ctx_t *hc, struct addrinfo *res)
{
    int  rc;

    /* Non-blocking connect: rc == 0 means it completed immediately (typical for
     * localhost/loopback); EINPROGRESS means it is in flight; any other error
     * is a hard failure.  Free the resolver result either way before branching. */
    rc = connect(hc->conn->fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        brix_hc_finish(hc, 0);
        return;
    }
    if (ngx_handle_write_event(hc->conn->write, 0) != NGX_OK) {
        brix_hc_finish(hc, 0);
        return;
    }

    if (rc == 0) {
        /* Connected synchronously: send the bootstrap now; the reply arrives
         * via the read handler. */
        hc->connecting = 0;
        if (brix_hc_flush(hc) == NGX_ERROR) {
            brix_hc_finish(hc, 0);
        }
    } else {
        /* In progress: the first writable event runs brix_hc_write_handler,
         * which confirms SO_ERROR and then flushes the bootstrap. */
        hc->connecting = 1;            /* finish in the write handler */
    }
}

/*
 * Launch one probe against host:port (the slot was already claimed by
 * brix_srv_hc_claim()).  Sets up a non-blocking connection, queues the
 * pipelined bootstrap, arms the deadline timer, and starts connect().  Control
 * then returns to the event loop; the probe completes asynchronously in the
 * read/write handlers, always ending at brix_hc_finish().
 *
 * Ownership note: every early-exit path here MUST release the claim — either
 * via brix_hc_finish() (once hc exists and reports a verdict) or via a direct
 * brix_srv_hc_fail() (before hc is usable).  The helpers above uphold this on
 * their own failure paths.  Otherwise the slot stays hc_in_progress=1 forever
 * and is never probed again.
 */
static void
brix_hc_start(ngx_cycle_t *cycle, ngx_stream_brix_srv_conf_t *conf,
    const char *host, uint16_t port)
{
    brix_hc_ctx_t   *hc;
    struct addrinfo   *res;

    hc = brix_hc_ctx_create(cycle, conf, host, port);
    if (hc == NULL) {
        return;
    }

    /* Resolve target. */
    res = brix_hc_resolve(hc, host, port);
    if (res == NULL) {
        return;
    }

    if (brix_hc_open_conn(cycle, hc, res, host, port) != NGX_OK) {
        return;
    }

    if (brix_hc_queue_bootstrap(hc) != NGX_OK) {
        freeaddrinfo(res);
        brix_hc_finish(hc, 0);
        return;
    }

    /* Single deadline for the whole probe. */
    hc->tev.handler = brix_hc_timeout_handler;
    hc->tev.data    = hc;
    hc->tev.log     = cycle->log;
    ngx_add_timer(&hc->tev, conf->hc.timeout_ms);

    BRIX_HC_METRIC_INC(hc_probes_total);

    brix_hc_begin_connect(hc, res);
}

/*
 * Recurring scan tick.  Re-arms itself first (so a probe-launch failure can't
 * stop future scans), then tries to claim at most one due server from the
 * shared registry and probe it.  Claiming exactly one per tick is what spreads
 * load and guarantees a single worker probes each server per interval.
 */
static void
brix_hc_timer_handler(ngx_event_t *ev)
{
    brix_hc_mgr_t              *mgr  = ev->data;
    ngx_stream_brix_srv_conf_t *conf = mgr->conf;
    char        host[256];
    uint16_t    port;
    ngx_msec_t  next_due = conf->hc.interval_ms;
    ngx_msec_t  delay;

    /* Claim is atomic under the registry spinlock and self-rate-limits via
     * hc_next_check, so concurrent workers never double-probe one server. */
    if (brix_srv_hc_claim(host, sizeof(host), &port,
                            conf->hc.interval_ms, &next_due))
    {
        brix_hc_start(mgr->cycle, conf, host, port);
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
        if (delay > conf->hc.interval_ms) {
            delay = conf->hc.interval_ms;
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
brix_hc_manager_start(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_hc_mgr_t *mgr;
    ngx_msec_t       scan;

    if (!conf->hc.enabled || conf->hc.interval_ms == 0) {
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
    scan = conf->hc.interval_ms / BRIX_SRV_REGISTRY_SLOTS;
    mgr->scan_interval_ms = scan < 100 ? 100 : scan;

    mgr->timer.handler = brix_hc_timer_handler;
    mgr->timer.data    = mgr;
    mgr->timer.log     = cycle->log;

    ngx_add_timer(&mgr->timer, 2000);  /* let CMS connections settle first */

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: health check manager started "
                  "(interval=%Ms timeout=%Ms scan=%Ms)",
                  conf->hc.interval_ms, conf->hc.timeout_ms,
                  mgr->scan_interval_ms);
}
