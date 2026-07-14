/*
 * stream_mirror_internal.h — declarations shared across the XRootD stream
 * traffic-mirror files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the shadow-connection context struct, its phase enum, the
 *       one metric-increment macro, the replay payload bound, and the single
 *       engine entry point (brix_mir_start) that straddle the
 *       stream_mirror.c / stream_mirror_launch.c boundary.
 * WHY:  stream_mirror.c (844 lines) split into three focused files under the
 *       500-line cap: stream_mirror.c (the async shadow-connection state machine
 *       — bootstrap/replay/read/dispatch/lifecycle), stream_mirror_launch.c
 *       (opcode filter + eligibility gates + per-target launch + the public
 *       brix_stream_mirror_maybe hook), and stream_mirror_config.c (directive
 *       setters).  The launch driver allocates a brix_stream_mirror_t, snapshots
 *       the request into it, and calls brix_mir_start() — exactly the struct, the
 *       phase enum, the metric macro, the payload bound, and brix_mir_start()
 *       cross that boundary and are declared here; nothing else crosses.  The
 *       config setters are self-contained and do not include this header.
 * HOW:  stream_mirror.c and stream_mirror_launch.c both include this header;
 *       none of these symbols is part of the mirror's public surface
 *       (stream_mirror.h).  brix_mir_start is the ONLY symbol here with external
 *       linkage — it is defined non-static in stream_mirror.c.
 *
 * Requires: stream_mirror.h (→ core/ngx_brix_module.h, which transitively
 *           provides XRD_RESPONSE_HDR_LEN and the brix metrics accessor used by
 *           BRIX_MIR_METRIC_INC) included before this header, plus <sys/socket.h>
 *           for struct sockaddr_storage / socklen_t.
 */
#ifndef BRIX_MIRROR_STREAM_MIRROR_INTERNAL_H
#define BRIX_MIRROR_STREAM_MIRROR_INTERNAL_H

/* Bound on the replayed payload — path + options for stat/locate/open/dirlist
 * fit easily; anything larger (e.g. a stray write body) is skipped.  Enforced by
 * the eligibility gate in stream_mirror_launch.c. */
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

/* Increment a shared root-metrics counter (low cardinality, no per-target labels
 * per metrics INVARIANT 8).  Used by the engine in stream_mirror.c and the
 * sampling gate in stream_mirror_launch.c. */
#define BRIX_MIR_METRIC_INC(field)                                           \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)

/*
 * Open the shadow socket, arm the exchange timer, and begin the pipelined
 * bootstrap (handshake -> protocol -> login).  Defined in stream_mirror.c and
 * called from the per-target launch path in stream_mirror_launch.c, so it is
 * non-static.  Takes ownership of @mir's private pool for the whole exchange and
 * destroys it via brix_mir_finish() on every terminal path.
 */
void brix_mir_start(brix_stream_mirror_t *mir, ngx_msec_t timeout_ms);

#endif /* BRIX_MIRROR_STREAM_MIRROR_INTERNAL_H */
