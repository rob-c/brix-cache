/*
 * health_check_internal.h — declarations shared across the Phase 22 active
 * stream health-check files after the file-size split.
 *
 * WHAT: Cross-declares the per-probe context struct, its phase enum, the one
 *       metric-increment macro, and the four functions that straddle the
 *       health_check.c / health_check_probe.c boundary.
 * WHY:  health_check.c (934 lines) split into two focused files under the
 *       600-line cap: health_check.c (connection lifecycle + manager entry —
 *       ctx_create/resolve/open_conn/queue_bootstrap/begin_connect/start/timer/
 *       manager_start plus the shared brix_hc_finish termination point) and
 *       health_check_probe.c (the async probe I/O state machine —
 *       flush/send_probe/write+read handlers/recv_frame/TLS handshake/dispatch).
 *       The lifecycle side wires the probe's read/write handlers onto the
 *       connection and flushes the pipelined bootstrap; the probe side reports
 *       every verdict through brix_hc_finish — exactly the struct, the phase
 *       enum, the metric macro, and those four functions cross the boundary.
 * HOW:  both files include this header; none of these symbols is part of the
 *       health-check public surface (health_check.h).  brix_hc_flush,
 *       brix_hc_read_handler and brix_hc_write_handler are defined non-static in
 *       health_check_probe.c; brix_hc_finish is defined non-static in
 *       health_check.c.
 *
 * Requires: health_check.h (→ core/ngx_brix_module.h, which transitively
 *           provides XRD_RESPONSE_HDR_LEN and the wire types) and
 *           observability/metrics/metrics_macros.h (brix_metrics_shared /
 *           ngx_brix_metrics_t used by BRIX_HC_METRIC_INC) included before this
 *           header, plus <sys/socket.h> for socklen_t.
 */
#ifndef BRIX_MANAGER_HEALTH_CHECK_INTERNAL_H
#define BRIX_MANAGER_HEALTH_CHECK_INTERNAL_H

/*
 * Probe state machine, advanced one step per complete response frame received.
 * Each phase consumes the server's reply to the request the previous phase (or
 * the pipelined bootstrap) sent: HANDSHAKE -> PROTOCOL -> LOGIN -> PROBE.  See
 * brix_hc_dispatch() for the per-phase transitions and early-exit verdicts.
 */
typedef enum {
    XRD_HC_HANDSHAKE = 0,
    XRD_HC_PROTOCOL,
    XRD_HC_LOGIN,
    XRD_HC_PROBE,
} brix_hc_phase_t;

/*
 * Per-probe state.  Allocated from its own pool (hc->pool, also used as
 * conn->pool) so the entire probe — ctx, connection, scratch buffers — is freed
 * in one ngx_destroy_pool() in brix_hc_finish().  One of these exists per
 * in-flight probe; there is no shared mutable state between probes.
 */
typedef struct {
    ngx_pool_t        *pool;          /* owns this ctx + conn->pool */
    ngx_connection_t  *conn;
    ngx_log_t         *log;
    brix_hc_phase_t  phase;
    unsigned           connecting:1;  /* until TCP connect confirmed */
    unsigned           tls:1;         /* probe upgraded to TLS (Step F) */
    unsigned           tls_capable:1; /* advertised kXR_ableTLS -> login NOT
                                         pipelined; sent after the protocol
                                         verdict (plaintext or over TLS) */

    /* Owning server conf — read-only; supplies the outbound TLS ctx for
     * kXR_gotoTLS deep probes (Step F).  Lives in cycle memory, so it safely
     * outlives the probe pool. */
    ngx_stream_brix_srv_conf_t *conf;

    /* Response accumulator (mirrors brix_upstream_t). */
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
} brix_hc_ctx_t;

/* Atomically bump a shared-memory health-check counter; no-op if the metrics
 * zone is not mapped (e.g. metrics disabled). */
#define BRIX_HC_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

/* Defined in health_check_probe.c (the async probe I/O state machine). */
ngx_int_t brix_hc_flush(brix_hc_ctx_t *hc);
void brix_hc_write_handler(ngx_event_t *wev);
void brix_hc_read_handler(ngx_event_t *rev);

/* Defined in health_check.c (the single probe termination point). */
void brix_hc_finish(brix_hc_ctx_t *hc, int passed);

#endif /* BRIX_MANAGER_HEALTH_CHECK_INTERNAL_H */
