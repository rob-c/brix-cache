/*
 * stream_family.c — per-server-slot Prometheus family emitters (split from
 * stream.c for file-size hygiene; zero behaviour change).
 *
 * WHAT: The descriptor-table infrastructure (srv_family_desc_t + the shared
 *       slot-scan emitter) and every per-server stream-layer metric family it
 *       drives: connections, transfer-heap budget, payload/wire/frame bytes,
 *       fault-timeout reaps, io_uring backend, path-depth violations, SSI, and
 *       the config-generation reload gauge.
 * WHY:  Each per-server family repeats the identical slot-scan/label/emit loop;
 *       keeping the descriptor tables plus the one emitter here keeps the
 *       exposition format frozen in one place and the top-level scrape driver
 *       (stream.c) a flat call sequence.
 * HOW:  brix_export_prometheus_metrics() in stream.c calls these helpers in a
 *       frozen order; each reads its counters lock-free via
 *       ngx_atomic_fetch_add(..., 0) for an eventually-consistent snapshot.
 */

#include "metrics_internal.h"
#include "stream_internal.h"

/*
 * srv_family_desc_t — one per-server-slot Prometheus family.
 *
 * WHAT: Describes a family emitted once per in-use server slot with
 *       {port,auth} labels: its verbatim HELP/TYPE preamble, its sample-line
 *       metric name, and where its counter lives in the per-server struct.
 * WHY: Every stream-layer per-server family repeats the identical
 *      slot-scan/label/emit loop; descriptor tables plus one emitter keep the
 *      exporter a flat call sequence with the output format frozen in one
 *      place.
 * HOW: `header` is printed verbatim (it may include a DEPRECATED notice
 *      before the HELP line); `field_off` is the offsetof() of the family's
 *      ngx_atomic_t counter inside ngx_brix_srv_metrics_t.
 */
typedef struct {
    const char *header;    /* verbatim "# HELP…\n# TYPE…\n" preamble       */
    const char *name;      /* metric name on each sample line              */
    size_t      field_off; /* offsetof(ngx_brix_srv_metrics_t, <counter>)  */
} srv_family_desc_t;

/* Standard counter/gauge HELP+TYPE preambles (compile-time concatenation —
 * byte-identical to the historical hand-written banners). */
#define SRV_COUNTER_HDR(name, help)                                          \
    "# HELP " name " " help "\n# TYPE " name " counter\n"
#define SRV_GAUGE_HDR(name, help)                                            \
    "# HELP " name " " help "\n# TYPE " name " gauge\n"

/* Descriptor-table entry: preamble, sample-line name, counter field. */
#define SRV_FAMILY(hdr, metric, field)                                      \
    { hdr, metric, offsetof(ngx_brix_srv_metrics_t, field) }

/*
 * metrics_emit_srv_family() — emit one per-server family.
 *
 * WHAT: Prints the family's HELP/TYPE preamble, then one sample line per
 *       in-use server slot, labelled {port,auth}.
 * WHY: Single home for the slot-scan/label/emit loop shared by every
 *      per-server counter and gauge in this exporter.
 * HOW: Locates the descriptor's ngx_atomic_t via `field_off` and reads it
 *      with an atomic fetch — an eventually-consistent snapshot, no lock.
 */
static void
metrics_emit_srv_family(metrics_writer_t *mw, ngx_brix_metrics_t *shm,
    const srv_family_desc_t *d)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_atomic_t             *field;
    ngx_uint_t                i;
    char                      port_str[16];

    mw_printf(mw, "%s", d->header);

    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        field = (ngx_atomic_t *) ((char *) srv + d->field_off);
        mw_printf(mw,
            "%s{port=\"%s\",auth=\"%s\"} %lu\n",
            d->name, port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(field, 0));
    }
}

/*
 * metrics_emit_srv_families() — emit a descriptor table in order.
 *
 * WHAT: Runs metrics_emit_srv_family() over each entry of a family table.
 * WHY: Lets each metric-family helper below be a table plus one call.
 * HOW: Straight iteration; table order == exposition order (frozen).
 */
static void
metrics_emit_srv_families(metrics_writer_t *mw, ngx_brix_metrics_t *shm,
    const srv_family_desc_t *tab, ngx_uint_t n)
{
    ngx_uint_t k;

    for (k = 0; k < n; k++) {
        metrics_emit_srv_family(mw, shm, &tab[k]);
    }
}

/*
 * metrics_emit_config_generation() — config-reload signal gauge.
 *
 * WHAT: Emits `brix_config_generation`, stepping by one on every
 *       `nginx -s reload` (published by the master in init_module).
 * WHY: Graph it to correlate behaviour changes with config reloads, or
 *      alert when it moves unexpectedly.
 * HOW: Single unlabelled gauge line from the zone-global counter.
 */
void
metrics_emit_config_generation(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_printf(mw,
        "# HELP brix_config_generation "
            "Config loads since master start (steps on each reload).\n"
        "# TYPE brix_config_generation gauge\n"
        "brix_config_generation %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->config_generation, 0));
}

/*
 * metrics_emit_connections() — connection lifecycle families.
 *
 * WHAT: Total accepted connections (counter) and currently open
 *       connections (gauge), per server slot.
 * WHY: The basic capacity/health signals for every stream listener.
 * HOW: Two-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_connections(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_connections_total",
                "Total TCP connections accepted since process start."),
            "brix_connections_total", connections_total),
        SRV_FAMILY(SRV_GAUGE_HDR("brix_connections_active",
                "Currently open XRootD connections."),
            "brix_connections_active", connections_active),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_xfer_heap() — transfer-heap memory budget families.
 *
 * WHAT: Phase 31 W4 — current and peak transfer-scratch bytes (gauges) plus
 *       reads deferred with kXR_wait by the memory budget (counter).
 * WHY: Observability for the brix_memory_budget backpressure mechanism.
 * HOW: Three-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_xfer_heap(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_GAUGE_HDR("brix_xfer_heap_bytes",
                "Bytes currently held in per-connection transfer scratch buffers."),
            "brix_xfer_heap_bytes", xfer_heap_in_use),
        SRV_FAMILY(SRV_GAUGE_HDR("brix_xfer_heap_high_water_bytes",
                "Peak transfer-heap bytes observed since start."),
            "brix_xfer_heap_high_water_bytes", xfer_heap_high_water),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_budget_waits_total",
                "Reads deferred with kXR_wait because they would exceed "
                "brix_memory_budget."),
            "brix_budget_waits_total", budget_waits_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_bytes() — payload byte-count families.
 *
 * WHAT: Client payload rx/tx totals — legacy aggregate pair (DEPRECATED in
 *       favour of the protocol-neutral brix_io_bytes_* series), the native
 *       root:// per-protocol pair, and the per-IP-version split.
 * WHY: Throughput accounting; the IPv4/IPv6 split avoids the
 *      high-cardinality label explosion of per-client series.
 * HOW: Eight-entry descriptor table; deprecated families carry their
 *      DEPRECATED notice verbatim in the header preamble.
 */
void
metrics_emit_bytes(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(
            "# DEPRECATED: use brix_io_bytes_written{proto=\"stream\"} "
                "for protocol-neutral write throughput.\n"
            SRV_COUNTER_HDR("brix_bytes_rx_total",
                "Bytes received from clients (write payloads)."),
            "brix_bytes_rx_total", bytes_rx_total),
        SRV_FAMILY(
            "# DEPRECATED: use brix_io_bytes_read{proto=\"stream\"} "
                "for protocol-neutral read throughput.\n"
            SRV_COUNTER_HDR("brix_bytes_tx_total",
                "Bytes sent to clients (read data)."),
            "brix_bytes_tx_total", bytes_tx_total),

        /* Per-protocol byte counters — native XRootD stream-layer data only. */
        SRV_FAMILY(
            "# DEPRECATED: use brix_io_bytes_written{proto=\"stream\"} "
                "for protocol-neutral write throughput.\n"
            SRV_COUNTER_HDR("brix_bytes_root_rx_total",
                "Bytes received from clients via the native XRootD root:// protocol."),
            "brix_bytes_root_rx_total", proto_root_bytes_rx_total),
        SRV_FAMILY(
            "# DEPRECATED: use brix_io_bytes_read{proto=\"stream\"} "
                "for protocol-neutral read throughput.\n"
            SRV_COUNTER_HDR("brix_bytes_root_tx_total",
                "Bytes sent to clients via the native XRootD root:// protocol."),
            "brix_bytes_root_tx_total", proto_root_bytes_tx_total),

        /* Per-IP-version bandwidth counters — avoids high-cardinality label
         * explosion. */
        SRV_FAMILY(SRV_COUNTER_HDR("brix_bytes_rx_ipv4_total",
                "Bytes received from IPv4 clients (stream layer)."),
            "brix_bytes_rx_ipv4_total", bytes_rx_ipv4_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_bytes_tx_ipv4_total",
                "Bytes sent to IPv4 clients (stream layer)."),
            "brix_bytes_tx_ipv4_total", bytes_tx_ipv4_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_bytes_rx_ipv6_total",
                "Bytes received from IPv6 clients (stream layer)."),
            "brix_bytes_rx_ipv6_total", bytes_rx_ipv6_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_bytes_tx_ipv6_total",
                "Bytes sent to IPv6 clients (stream layer)."),
            "brix_bytes_tx_ipv6_total", bytes_tx_ipv6_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_wire_frames() — raw wire and frame accounting families.
 *
 * WHAT: Raw socket byte totals plus request-frame parse and response-frame
 *       send accounting (payload bytes, oversized rejects, write
 *       stalls/errors).
 * WHY: Distinguishes wire-level throughput from payload throughput and
 *      surfaces framing/back-pressure problems.
 * HOW: Eight-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_wire_frames(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_wire_bytes_rx_total",
                "Raw socket bytes received from native XRootD clients."),
            "brix_wire_bytes_rx_total", wire_bytes_rx_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_wire_bytes_tx_total",
                "Raw socket bytes sent to native XRootD clients."),
            "brix_wire_bytes_tx_total", wire_bytes_tx_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_request_frames_total",
                "Native XRootD request headers parsed by the stream module."),
            "brix_stream_request_frames_total", request_frames_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_request_payload_bytes_total",
                "Declared native XRootD request payload bytes parsed by the stream module."),
            "brix_stream_request_payload_bytes_total",
            request_payload_bytes_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_oversized_payloads_total",
                "Native XRootD requests rejected because their payload was too large."),
            "brix_stream_oversized_payloads_total", oversized_payloads_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_response_frames_total",
                "Native XRootD response send attempts."),
            "brix_stream_response_frames_total", response_frames_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_response_write_stalls_total",
                "Native XRootD response sends that had to wait for socket writability."),
            "brix_stream_response_write_stalls_total",
            response_write_stalls_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_response_write_errors_total",
                "Native XRootD response send or send_chain failures."),
            "brix_stream_response_write_errors_total",
            response_write_errors_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_fault_timeouts() — network-fault resilience families.
 *
 * WHAT: Phase 39 — connections dropped by the handshake/read/send watchdog
 *       timers plus accepts refused at the connection cap.
 * WHY: All 0 unless the resilience directives are set; non-zero values show
 *      which timeout is reaping clients.
 * HOW: Four-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_fault_timeouts(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_handshake_timeouts_total",
                "Connections dropped because the pre-auth handshake stalled past brix_handshake_timeout."),
            "brix_stream_handshake_timeouts_total", handshake_timeouts_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_read_pdu_timeouts_total",
                "Connections dropped because an incomplete request PDU stalled past brix_read_timeout."),
            "brix_stream_read_pdu_timeouts_total", read_pdu_timeouts_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_send_drain_timeouts_total",
                "Connections dropped because the response drain stalled past brix_send_timeout."),
            "brix_stream_send_drain_timeouts_total", send_drain_timeouts_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_connections_rejected_total",
                "Connections refused at accept because the listener was at brix_max_connections."),
            "brix_stream_connections_rejected_total",
            connections_rejected_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_io_uring() — optional io_uring disk-I/O backend families.
 *
 * WHAT: Phase 44 — ops submitted via io_uring, thread-pool fallbacks, and
 *       the per-listener "backend has been used" gauge (1 = a worker
 *       fronting this listener used the ring; a kill-switch flip is
 *       observable via the ops/fallback ratio).
 * WHY: All 0 unless the io_uring backend is enabled; the fallback counter
 *      shows ring saturation or runtime disablement.
 * HOW: Three-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_io_uring(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_io_uring_ops_total",
                "Mapped disk ops (read/write/single-group readv/writev) submitted via the io_uring backend."),
            "brix_stream_io_uring_ops_total", io_uring_ops_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_stream_io_uring_fallback_total",
                "Mapped disk ops that fell back to the thread pool because io_uring was full or runtime-disabled."),
            "brix_stream_io_uring_fallback_total", io_uring_fallback_total),
        SRV_FAMILY(SRV_GAUGE_HDR("brix_stream_io_uring_active",
                "1 if a worker fronting this listener has used the io_uring backend."),
            "brix_stream_io_uring_active", io_uring_active),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_path_depth() — path-depth violation family.
 *
 * WHAT: Requests rejected because path component count exceeded
 *       BRIX_MAX_WALK_DEPTH.
 * WHY: Prevents CPU exhaustion from malicious symlink traversal chains or
 *      deep nesting; the counter shows whether the guard is firing.
 * HOW: Single-entry descriptor through the shared slot-scan emitter.
 */
void
metrics_emit_path_depth(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_path_depth_violations_total",
                "Requests rejected because path depth exceeded "
                "BRIX_MAX_WALK_DEPTH. Prevents CPU exhaustion from "
                "malicious symlink traversal chains or deep nesting."),
            "brix_path_depth_violations_total", path_depth_violations_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}

/*
 * metrics_emit_ssi() — §7 XrdSsi service families.
 *
 * WHAT: XrdSsi request/error totals plus out-of-band alert push accounting.
 * WHY: Observability for the SSI request-response service plane.
 * HOW: Four-entry descriptor table through the shared slot-scan emitter.
 */
void
metrics_emit_ssi(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const srv_family_desc_t tab[] = {
        SRV_FAMILY(SRV_COUNTER_HDR("brix_ssi_requests_total",
                "XrdSsi requests dispatched."),
            "brix_ssi_requests_total", ssi_requests_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_ssi_errors_total",
                "XrdSsi error responses."),
            "brix_ssi_errors_total", ssi_errors_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_ssi_alerts_pushed_total",
                "XrdSsi out-of-band alerts pushed to clients."),
            "brix_ssi_alerts_pushed_total", ssi_alerts_pushed_total),
        SRV_FAMILY(SRV_COUNTER_HDR("brix_ssi_attn_push_failures_total",
                "XrdSsi kXR_attn pushes that failed to queue."),
            "brix_ssi_attn_push_failures_total", ssi_attn_push_failures_total),
    };

    metrics_emit_srv_families(mw, shm, tab,
        sizeof(tab) / sizeof(tab[0]));
}
