#include "metrics_internal.h"
#include "core/compat/fs_usage.h"

/*
 * WHAT: Prometheus HTTP exporter for read-through cache metrics — filesystem occupancy, eviction counters,
 *      and configured thresholds per server listener.
 * WHY: The brix_cache_root provides XCache-style direct-mode fills from anonymous root:// origins. Cache
 *      behavior (eviction on high occupancy, bytes reclaimed, eviction errors) needs observable Prometheus
 *      gauges and counters so operators can tune cache_eviction_threshold_ratio and monitor fill efficiency.
 * HOW: brix_cache_statvfs() calls statvfs(2) on the configured root directory to compute total/used/available
 *      bytes and occupancy_ppm (parts per million). brix_export_stream_cache_metrics() calls one static
 *      per-family emit helper in sequence; each helper writes the family's HELP/TYPE block then fans a
 *      labelled row (or rows) across the SHM server slots. The exporter itself is a flat call sequence.
 */

/*
 * WHAT: Snapshot the filesystem occupancy of one cache root directory.
 * WHY:  Cache gauges (occupancy ratio, bytes by state) must reflect live disk
 *       usage at scrape time, so we re-stat per scrape rather than caching.
 * HOW:  Delegates to the shared brix_fs_usage_stat() (statvfs(2) wrapper) and
 *       unpacks its struct into the caller's out-params. occupancy_ppm is
 *       parts-per-million (used/total * 1e6) computed once by the helper so the
 *       caller need not redo the division. Returns NGX_ERROR if the root cannot
 *       be statted (e.g. unmounted/missing) — callers skip that server's row.
 */
static ngx_int_t
brix_cache_statvfs(const char *root, uint64_t *total, uint64_t *used,
    uint64_t *available, ngx_uint_t *occupancy_ppm)
{
    brix_fs_usage_t fsu;

    if (brix_fs_usage_stat(root, &fsu) != NGX_OK) {
        return NGX_ERROR;
    }

    *total = fsu.total_bytes;
    *available = fsu.available_bytes;
    *used = fsu.occupancy_bytes;
    *occupancy_ppm = fsu.occupancy_ppm;

    return NGX_OK;
}

/*
 * WHAT: Render one server slot's numeric port into a NUL-terminated C string.
 * WHY:  Every labelled row uses the "%s" port label, but ngx_snprintf does not
 *       NUL-terminate; the "%Z" verb appends the trailing '\0' so the buffer is a
 *       valid C string for "%s". Centralised so all families render identically.
 * HOW:  Writes into the caller's fixed buffer (port_str[16], matching u16 port
 *       widths). Pure formatter with no side effects beyond filling the buffer.
 */
static void
stream_cache_port_str(char *buf, size_t buf_size, ngx_uint_t port)
{
    ngx_snprintf((u_char *) buf, buf_size, "%ui%Z", port);
}

/* The three filesystem-shape gauge families share one header + per-server loop
 * (cache_enabled gate, optional statvfs, port label); the enum selects which
 * family's rows the single worker below emits. */
typedef enum {
    STREAM_CACHE_FAM_OCCUPANCY,     /* live used/total ratio (statvfs) */
    STREAM_CACHE_FAM_THRESHOLD,     /* configured high-water mark (no statvfs) */
    STREAM_CACHE_FAM_BYTES,         /* total/used/available triple (statvfs) */
} stream_cache_fs_family_t;

/*
 * WHAT: Emit one filesystem-shape gauge family (header + per-server rows).
 * WHY:  Prometheus groups all rows of a family under one HELP/TYPE block, and
 *       the three families differ only in header, statvfs need, and row shape —
 *       one parametrised worker keeps a single copy of the fan-out loop.
 * HOW:  Emits the family's HELP/TYPE header, then per cache-enabled active
 *       server: the THRESHOLD family renders the SHM-stored ppm config value
 *       directly, while the statvfs-backed families skip roots that cannot be
 *       statted (missing/unmounted) and render ppm/1e6 (the 0..1 gauge ratio
 *       convention) or the state-labelled bytes triple.
 */
static void
stream_cache_emit_fs_family(metrics_writer_t *mw, ngx_brix_metrics_t *shm,
    stream_cache_fs_family_t fam)
{
    static const char *const fam_header[] = {
        "# HELP brix_cache_occupancy_ratio "
            "Filesystem occupancy ratio for brix_cache_export.\n"
        "# TYPE brix_cache_occupancy_ratio gauge\n",
        "# HELP brix_cache_eviction_threshold_ratio "
            "Configured cache eviction high-water occupancy ratio.\n"
        "# TYPE brix_cache_eviction_threshold_ratio gauge\n",
        "# HELP brix_cache_bytes "
            "Cache filesystem bytes by state.\n"
        "# TYPE brix_cache_bytes gauge\n",
    };
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t              i;
    char                    port_str[16];

    mw_printf(mw, "%s", fam_header[fam]);
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        uint64_t   total = 0, used = 0, available = 0;
        ngx_uint_t occupancy_ppm = 0;

        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        if (fam != STREAM_CACHE_FAM_THRESHOLD
            && brix_cache_statvfs(srv->cache_root, &total, &used,
                                    &available, &occupancy_ppm) != NGX_OK)
        {
            continue;
        }
        stream_cache_port_str(port_str, sizeof(port_str), srv->port);

        switch (fam) {
        case STREAM_CACHE_FAM_OCCUPANCY:
            /* ppm (parts-per-million) -> ratio for Prometheus's 0..1 gauge
             * convention. */
            mw_printf(mw,
                "brix_cache_occupancy_ratio{port=\"%s\",auth=\"%s\"} %0.6f\n",
                port_str, srv->auth, (double) occupancy_ppm / 1000000.0);
            break;
        case STREAM_CACHE_FAM_THRESHOLD:
            mw_printf(mw,
                "brix_cache_eviction_threshold_ratio"
                    "{port=\"%s\",auth=\"%s\"} %0.6f\n",
                port_str, srv->auth,
                (double) srv->cache_eviction_threshold / 1000000.0);
            break;
        default:
            mw_printf(mw,
                "brix_cache_bytes{port=\"%s\",auth=\"%s\",state=\"total\"}"
                    " %llu\n",
                port_str, srv->auth, (unsigned long long) total);
            mw_printf(mw,
                "brix_cache_bytes{port=\"%s\",auth=\"%s\",state=\"used\"}"
                    " %llu\n",
                port_str, srv->auth, (unsigned long long) used);
            mw_printf(mw,
                "brix_cache_bytes{port=\"%s\",auth=\"%s\",state=\"available\"}"
                    " %llu\n",
                port_str, srv->auth, (unsigned long long) available);
            break;
        }
    }
}

static void
stream_cache_emit_occupancy_ratio(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_fs_family(mw, shm, STREAM_CACHE_FAM_OCCUPANCY);
}

static void
stream_cache_emit_eviction_threshold(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_fs_family(mw, shm, STREAM_CACHE_FAM_THRESHOLD);
}

static void
stream_cache_emit_cache_bytes(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_fs_family(mw, shm, STREAM_CACHE_FAM_BYTES);
}

/*
 * WHAT: Emit one single-row per-server counter family, gate selectable.
 * WHY:  The eviction counters (cache_enabled gate) and the write-through
 *       single-row families (in_use gate only) share an identical shape —
 *       header + one atomically-read counter row per matching server — so a
 *       single parametrised worker backs both wrapper families.
 * HOW:  Emits the caller-supplied HELP/TYPE header block, then one row per
 *       active server (also requiring cache_enabled when require_cache is set)
 *       reading *counter via ngx_atomic_fetch_add(&x,0) (adding zero is the
 *       lock-free atomic-load idiom, not a mutation). counter is a pointer to
 *       the srv-relative offset resolved by the caller per slot.
 */
static void
stream_cache_emit_counter_family(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm, int require_cache, const char *header,
    const char *metric_name, size_t counter_off)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t              i;
    char                    port_str[16];

    mw_printf(mw, "%s", header);
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        ngx_atomic_t *counter;

        srv = &shm->servers[i];
        if (!srv->in_use || (require_cache && !srv->cache_enabled)) {
            continue;
        }
        stream_cache_port_str(port_str, sizeof(port_str), srv->port);
        counter = (ngx_atomic_t *) ((char *) srv + counter_off);
        mw_printf(mw, "%s{port=\"%s\",auth=\"%s\"} %lu\n",
            metric_name, port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(counter, 0));
    }
}

static void
stream_cache_emit_eviction_counter(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm, const char *header, const char *metric_name,
    size_t counter_off)
{
    stream_cache_emit_counter_family(mw, shm, 1, header, metric_name,
                                     counter_off);
}

/*
 * WHAT: Emit the three cache-eviction counter families (files/bytes/errors).
 * WHY:  All three are monotonic SHM counters gated on cache_enabled; grouping
 *       their emission keeps the exporter's call sequence readable.
 * HOW:  Three calls to stream_cache_emit_eviction_counter(), one per counter,
 *       passing each family's HELP/TYPE header, metric name, and SHM field offset.
 */
static void
stream_cache_emit_eviction_counters(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_eviction_counter(mw, shm,
        "# HELP brix_cache_evictions_total "
            "Files evicted from brix_cache_export.\n"
        "# TYPE brix_cache_evictions_total counter\n",
        "brix_cache_evictions_total",
        offsetof(ngx_brix_srv_metrics_t, cache_evictions_total));

    stream_cache_emit_eviction_counter(mw, shm,
        "# HELP brix_cache_evicted_bytes_total "
            "Bytes reclaimed by cache eviction.\n"
        "# TYPE brix_cache_evicted_bytes_total counter\n",
        "brix_cache_evicted_bytes_total",
        offsetof(ngx_brix_srv_metrics_t, cache_evicted_bytes_total));

    stream_cache_emit_eviction_counter(mw, shm,
        "# HELP brix_cache_eviction_errors_total "
            "Cache eviction maintenance errors.\n"
        "# TYPE brix_cache_eviction_errors_total counter\n",
        "brix_cache_eviction_errors_total",
        offsetof(ngx_brix_srv_metrics_t, cache_eviction_errors_total));
}

/*
 * WHAT: Emit the stale-dirty reaper counter family (per-reason rows).
 * WHY:  The reaper scans the unified cache-state root shared by read-through and
 *       write-through caches, so this is gated on in_use ONLY (not cache_enabled),
 *       and split by the `reason` label to distinguish data-loss severity.
 * HOW:  Header then, per active server, one row per reap reason ("abandoned" =
 *       un-flushed dirty discarded; "incomplete" = re-dirtied after a prior flush;
 *       "completed" = a finished write-back staging copy reclaimed; "cold" = a
 *       clean read-fill purged by age), each read via the lock-free
 *       ngx_atomic_fetch_add(&x, 0) load idiom.
 */
static void
stream_cache_emit_dirty_reaped(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    static const char *const reap_reason[BRIX_CACHE_REAP_REASON_COUNT] = {
        [BRIX_CACHE_REAP_ABANDONED]  = "abandoned",
        [BRIX_CACHE_REAP_INCOMPLETE] = "incomplete",
        [BRIX_CACHE_REAP_COMPLETED]  = "completed",
        [BRIX_CACHE_REAP_COLD]       = "cold",
    };
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t              i;
    ngx_uint_t              r;
    char                    port_str[16];

    mw_printf(mw,
        "# HELP brix_cache_dirty_reaped_total "
            "Cache files reaped by the stale-dirty reaper, by reason "
            "(abandoned/incomplete = write-back discarded; "
            "completed = finished staging reclaimed).\n"
        "# TYPE brix_cache_dirty_reaped_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        stream_cache_port_str(port_str, sizeof(port_str), srv->port);
        for (r = 0; r < BRIX_CACHE_REAP_REASON_COUNT; r++) {
            mw_printf(mw,
                "brix_cache_dirty_reaped_total"
                "{port=\"%s\",auth=\"%s\",reason=\"%s\"} %lu\n",
                port_str, srv->auth, reap_reason[r],
                (unsigned long) ngx_atomic_fetch_add(
                    &srv->cache_dirty_reaped[r], 0));
        }
    }
}

/*
 * WHAT: Emit one single-row write-through gauge/counter family (in_use gate).
 * WHY:  The three single-row write-through families (dirty_handles, flush_pending,
 *       flush_bytes_total) share an identical shape — header + one atomic row per
 *       active server — so one parametrised helper avoids near-duplicate loops.
 * HOW:  Emits the caller-supplied HELP/TYPE header, then one row per active server
 *       (in_use ONLY: write-through mirroring is independent of the read-through
 *       cache feature) reading the field at counter_off via the atomic-load idiom.
 */
static void
stream_cache_emit_wt_single(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm, const char *header, const char *metric_name,
    size_t counter_off)
{
    stream_cache_emit_counter_family(mw, shm, 0, header, metric_name,
                                     counter_off);
}

/*
 * WHAT: Emit the write-through flush-completions counter family (success/error rows).
 * WHY:  Flush completions carry a result="success|error" label, so this family has
 *       two rows per server and needs its own helper distinct from the single-row
 *       write-through families.
 * HOW:  Header then, per active server (in_use ONLY), a success row and an error
 *       row, each read via the lock-free ngx_atomic_fetch_add(&x, 0) load idiom.
 */
static void
stream_cache_emit_wt_flushes(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t              i;
    char                    port_str[16];

    mw_printf(mw,
        "# HELP brix_wt_flushes_total "
            "Write-through flush completions by result.\n"
        "# TYPE brix_wt_flushes_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        stream_cache_port_str(port_str, sizeof(port_str), srv->port);
        mw_printf(mw,
            "brix_wt_flushes_total{port=\"%s\",auth=\"%s\",result=\"success\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_success_total, 0));
        mw_printf(mw,
            "brix_wt_flushes_total{port=\"%s\",auth=\"%s\",result=\"error\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->wt_flush_error_total, 0));
    }
}

/*
 * WHAT: Emit the write-through gauge + counter families (dirty handles, flush
 *       pending, flush completions, flush bytes).
 * WHY:  These are gated on in_use ONLY (write-through mirroring to origin is
 *       independent of the read-through cache feature); grouping their emission
 *       keeps the exporter's call sequence readable.
 * HOW:  Two single-row gauges and one single-row counter via
 *       stream_cache_emit_wt_single(), plus the two-row flush-completions family
 *       via stream_cache_emit_wt_flushes(), in wire order.
 */
static void
stream_cache_emit_write_through(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_wt_single(mw, shm,
        "# HELP brix_wt_dirty_handles "
            "Open write-through handles with unflushed dirty data.\n"
        "# TYPE brix_wt_dirty_handles gauge\n",
        "brix_wt_dirty_handles",
        offsetof(ngx_brix_srv_metrics_t, wt_dirty_handles));

    stream_cache_emit_wt_single(mw, shm,
        "# HELP brix_wt_flush_pending "
            "Write-through flush tasks currently pending completion.\n"
        "# TYPE brix_wt_flush_pending gauge\n",
        "brix_wt_flush_pending",
        offsetof(ngx_brix_srv_metrics_t, wt_flush_pending));

    stream_cache_emit_wt_flushes(mw, shm);

    stream_cache_emit_wt_single(mw, shm,
        "# HELP brix_wt_flush_bytes_total "
            "Bytes mirrored to origin by successful write-through flushes.\n"
        "# TYPE brix_wt_flush_bytes_total counter\n",
        "brix_wt_flush_bytes_total",
        offsetof(ngx_brix_srv_metrics_t, wt_flush_bytes_total));
}

/*
 * WHAT: Emit the full read-through-cache + write-through metric families to the
 *       Prometheus writer, one labelled row per active server listener.
 * WHY:  Each server block can have its own cache root, threshold, and counters,
 *       so every gauge/counter is fanned out across the SHM server slots and
 *       labelled by {port,auth} to stay low-cardinality (no paths as labels).
 * HOW:  Prometheus format requires all rows of a family to be grouped under a
 *       single HELP/TYPE block, hence the deliberate "one family per helper"
 *       shape: this orchestrator is a flat call sequence, one helper per family,
 *       in wire order. Cache families gate on in_use && cache_enabled; the reaper
 *       and write-through families gate on in_use only. The two statvfs-backed
 *       families re-stat per server (cheap, keeps the gauge fresh).
 */
void
brix_export_stream_cache_metrics(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    stream_cache_emit_occupancy_ratio(mw, shm);
    stream_cache_emit_eviction_threshold(mw, shm);
    stream_cache_emit_cache_bytes(mw, shm);
    stream_cache_emit_eviction_counters(mw, shm);
    stream_cache_emit_dirty_reaped(mw, shm);
    stream_cache_emit_write_through(mw, shm);
}
