#include "metrics_internal.h"
#include "metrics_macros.h"                /* brix_metrics_shared() */
#include "core/compat/fs_usage.h"          /* live statvfs capacity gauges */
#include "core/shm/kv.h"
#include "fs/vfs/vfs_backend_registry.h"   /* C-7: composed-stack introspection */

/*
 * Shared low-cardinality label tables for both WebDAV and S3 Prometheus export.
 * Defined once here; extern-declared in metrics_internal.h.
 */
const char *brix_http_status_names[BRIX_HTTP_NSTATUS] = {
    "1xx", "2xx", "3xx", "4xx", "5xx", "other",
};

const char *brix_http_range_result_names[3] = {
    "full", "partial", "unsatisfied",
};

/*
 * WHAT: metrics_writer_t buffer-chain writer — alloc, append, printf, and finish for Prometheus exposition output.
 * WHY: The /metrics endpoint must emit HELP/TYPE/value lines in the Prometheus text format (0.0.4). A
 *      linked chain of ngx_buf_t buffers provides a growing write surface that can expand when vsnprintf
 *      output exceeds the current buffer capacity — nginx-chain-compatible for direct filter delivery.
 * HOW: mw_init allocates the first buffer and sets position markers. mw_printf uses vsnprintf with available-space
 *      check; on overflow, mw_append_buffer creates a new chain link and resets positions. mw_select_tail_buffer()
 *      establishes write boundaries (mw->pos / mw->last) within the selected tail buffer. mw_finish marks the last
 *      buffer's last_buf flag so nginx knows this is the complete response chain.
 */

static ngx_int_t
mw_alloc_chain_buffer(ngx_pool_t *pool, ngx_chain_t **chain_out)
{
    ngx_buf_t   *buffer;
    ngx_chain_t *chain;

    buffer = ngx_create_temp_buf(pool, METRICS_BUF_SIZE);
    if (buffer == NULL) {
        return NGX_ERROR;
    }

    chain = ngx_alloc_chain_link(pool);
    if (chain == NULL) {
        return NGX_ERROR;
    }

    chain->buf = buffer;
    chain->next = NULL;

    *chain_out = chain;
    return NGX_OK;
}

/* WHAT: Selects the metrics_writer_t's tail ngx_buf_t for appending by initializing mw->pos to buffer's current position (buffer->pos) and setting mw->last = buffer->last + METRICS_BUF_SIZE. This establishes the write boundaries within the tail buffer before subsequent mw_append_buffer calls fill content.
 * WHY: The metrics writer uses a linked chain of buffers where each new buffer is appended via mw_append_buffer(). Before appending to any buffer, mw_select_tail_buffer() must establish position markers so mw->pos (write start) and mw->last (write end) are correctly set relative to the selected tail buffer. METRICS_BUF_SIZE defines how much beyond buffer->last we consider writable — this accounts for pre-allocated extra space in nginx_buf_t allocation.
 * HOW: Single three-step assignment → read mw->tail->buf pointer, copy buffer->pos into mw->pos (write start), set mw->last = buffer->last + METRICS_BUF_SIZE (write end boundary). No validation or error handling — assumes tail buffer is valid and pre-allocated with sufficient capacity. */

static void
mw_select_tail_buffer(metrics_writer_t *mw)
{
    ngx_buf_t *buffer;

    buffer = mw->tail->buf;
    mw->pos = buffer->pos;
    mw->last = buffer->last + METRICS_BUF_SIZE;
}

static ngx_int_t
mw_append_buffer(metrics_writer_t *mw)
{
    ngx_chain_t *chain;

    mw->tail->buf->last = mw->pos;

    if (mw_alloc_chain_buffer(mw->pool, &chain) != NGX_OK) {
        return NGX_ERROR;
    }

    mw->tail->next = chain;
    mw->tail = chain;
    mw_select_tail_buffer(mw);

    return NGX_OK;
}

ngx_int_t
mw_init(metrics_writer_t *mw, ngx_pool_t *pool)
{
    ngx_chain_t *chain;

    if (mw_alloc_chain_buffer(pool, &chain) != NGX_OK) {
        return NGX_ERROR;
    }

    mw->pool  = pool;
    mw->head  = chain;
    mw->tail  = chain;
    mw->total = 0;

    mw_select_tail_buffer(mw);

    return NGX_OK;
}

ngx_int_t
mw_printf(metrics_writer_t *mw, const char *fmt, ...)
{
    va_list     args;
    int         formatted_len;
    size_t      available;

    available = (size_t) (mw->last - mw->pos);

    va_start(args, fmt);
    formatted_len = vsnprintf((char *) mw->pos, available, fmt, args);
    va_end(args);

    if (formatted_len < 0) {
        return NGX_ERROR;
    }

    if ((size_t) formatted_len >= available) {
        if (mw_append_buffer(mw) != NGX_OK) {
            return NGX_ERROR;
        }

        available = METRICS_BUF_SIZE;
        va_start(args, fmt);
        formatted_len = vsnprintf((char *) mw->pos, available, fmt, args);
        va_end(args);

        if (formatted_len < 0 || (size_t) formatted_len >= available) {
            return NGX_ERROR;
        }
    }

    mw->pos += formatted_len;
    mw->total += formatted_len;

    return NGX_OK;
}

void
mw_emit_labeled(metrics_writer_t *mw, const char *name, const char *help,
    const char *label_key, const char * const *names, ngx_uint_t n,
    ngx_atomic_t *counters)
{
    ngx_uint_t  i;

    mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n", name, help, name);
    for (i = 0; i < n; i++) {
        mw_printf(mw, "%s{%s=\"%s\"} %lu\n", name, label_key, names[i],
                  (unsigned long) ngx_atomic_fetch_add(&counters[i], 0));
    }
}

void
mw_emit_scalar(metrics_writer_t *mw, const char *name, const char *help,
    ngx_atomic_t *counter)
{
    mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n%s %lu\n",
              name, help, name,
              name, (unsigned long) ngx_atomic_fetch_add(counter, 0));
}

/*
 * brix_kv_metrics_emit — export per-zone counters for every configured KV
 * zone (token cache, auth cache, rate-limit buckets).  Low cardinality: one
 * label (`zone`) drawn from the operator-chosen zone name.  Note mw_printf is
 * vsnprintf-based, so ngx_str_t is rendered with %.*s, not %V.
 */
void
brix_kv_metrics_emit(metrics_writer_t *mw)
{
    ngx_uint_t         n = brix_kv_zone_count();
    ngx_uint_t         i;
    brix_kv_stats_t  s;
    brix_kv_t       *kv;

    if (n == 0) {
        return;
    }

    mw_printf(mw, "# HELP brix_kv_hits_total KV cache hits per zone.\n"
                  "# TYPE brix_kv_hits_total counter\n");
    for (i = 0; i < n; i++) {
        kv = brix_kv_zone_get(i);
        brix_kv_stats(kv, &s);
        mw_printf(mw, "brix_kv_hits_total{zone=\"%.*s\"} %lu\n",
                  (int) kv->name.len, kv->name.data, (unsigned long) s.hits);
    }

    mw_printf(mw, "# HELP brix_kv_misses_total KV cache misses per zone.\n"
                  "# TYPE brix_kv_misses_total counter\n");
    for (i = 0; i < n; i++) {
        kv = brix_kv_zone_get(i);
        brix_kv_stats(kv, &s);
        mw_printf(mw, "brix_kv_misses_total{zone=\"%.*s\"} %lu\n",
                  (int) kv->name.len, kv->name.data, (unsigned long) s.misses);
    }

    mw_printf(mw, "# HELP brix_kv_evictions_total KV cache TTL evictions per zone.\n"
                  "# TYPE brix_kv_evictions_total counter\n");
    for (i = 0; i < n; i++) {
        kv = brix_kv_zone_get(i);
        brix_kv_stats(kv, &s);
        mw_printf(mw, "brix_kv_evictions_total{zone=\"%.*s\"} %lu\n",
                  (int) kv->name.len, kv->name.data,
                  (unsigned long) s.evictions);
    }

    mw_printf(mw, "# HELP brix_kv_entries Live entries per KV zone.\n"
                  "# TYPE brix_kv_entries gauge\n");
    for (i = 0; i < n; i++) {
        kv = brix_kv_zone_get(i);
        brix_kv_stats(kv, &s);
        mw_printf(mw, "brix_kv_entries{zone=\"%.*s\"} %lu\n",
                  (int) kv->name.len, kv->name.data, (unsigned long) s.count);
    }

    mw_printf(mw, "# HELP brix_kv_capacity Bucket capacity per KV zone.\n"
                  "# TYPE brix_kv_capacity gauge\n");
    for (i = 0; i < n; i++) {
        kv = brix_kv_zone_get(i);
        brix_kv_stats(kv, &s);
        mw_printf(mw, "brix_kv_capacity{zone=\"%.*s\"} %lu\n",
                  (int) kv->name.len, kv->name.data,
                  (unsigned long) s.capacity);
    }
}

/*
 * brix_storage_backend_info_emit — C-7: one info gauge per registered export
 * describing its composed storage stack: the source backend, its origin (host:port
 * [+tls]), the auth method threaded through the §14 credential, and whether the
 * write-back stage decorator (C-2/C-6) is composed. Value is always 1 (the labels
 * carry the information, Prometheus `_info` convention). Exports are config-fixed
 * and few, so the export-root label stays low-cardinality.
 */
static void
brix_storage_backend_info_emit(metrics_writer_t *mw, ngx_uint_t n)
{
    ngx_uint_t i;

    mw_printf(mw,
        "# HELP brix_storage_backend_info Composed storage stack per export "
            "(source backend, origin, auth, stage); value always 1.\n"
        "# TYPE brix_storage_backend_info gauge\n");

    for (i = 0; i < n; i++) {
        brix_vfs_backend_info_t info;
        char                      origin[320];
        const char               *auth;

        if (brix_vfs_backend_export_info(i, &info) != NGX_OK) {
            continue;
        }
        auth = info.has_proxy ? "gsi" : (info.has_token ? "token" : "none");
        if (info.host != NULL && info.host[0] != '\0') {
            snprintf(origin, sizeof(origin), "%.255s:%d%s", info.host, info.port,
                     info.tls ? "+tls" : "");
        } else {
            origin[0] = '\0';
        }
        mw_printf(mw,
            "brix_storage_backend_info{export=\"%s\",backend=\"%s\","
            "origin=\"%s\",auth=\"%s\",staging=\"%d\"} 1\n",
            info.root_canon, info.backend, origin, auth, info.staging);
    }
}

/* brix_storage_backend_is_local — 1 iff the census backend name is a LOCAL
 * driver whose export root is a real local filesystem (statvfs-able). Remote/
 * origin backends (xroot/http/s3/ceph...) have no local volume behind
 * root_canon — a statvfs there would report the wrong filesystem. */
static int
brix_storage_backend_is_local(const char *backend)
{
    return strcmp(backend, "posix") == 0 || strcmp(backend, "pblock") == 0;
}

/*
 * brix_storage_capacity_emit — per-export capacity gauges (live statvfs) for
 * LOCAL backends: bytes total/used/available plus the occupancy ratio, labeled
 * {export, backend} to match the info gauge's convention.
 */
static void
brix_storage_capacity_emit(metrics_writer_t *mw, ngx_uint_t n)
{
    ngx_uint_t i;

    mw_printf(mw,
        "# HELP brix_storage_bytes_total Backend export filesystem size in bytes (local backends).\n"
        "# TYPE brix_storage_bytes_total gauge\n"
        "# HELP brix_storage_bytes_used Backend export filesystem bytes used.\n"
        "# TYPE brix_storage_bytes_used gauge\n"
        "# HELP brix_storage_bytes_available Backend export filesystem bytes available.\n"
        "# TYPE brix_storage_bytes_available gauge\n"
        "# HELP brix_storage_occupancy_ratio Backend export filesystem occupancy (0-1).\n"
        "# TYPE brix_storage_occupancy_ratio gauge\n");

    for (i = 0; i < n; i++) {
        brix_vfs_backend_info_t info;
        brix_fs_usage_t         fsu;

        if (brix_vfs_backend_export_info(i, &info) != NGX_OK
            || !brix_storage_backend_is_local(info.backend)
            || brix_fs_usage_stat(info.root_canon, &fsu) != NGX_OK)
        {
            continue;
        }
        mw_printf(mw,
            "brix_storage_bytes_total{export=\"%s\",backend=\"%s\"} %llu\n"
            "brix_storage_bytes_used{export=\"%s\",backend=\"%s\"} %llu\n"
            "brix_storage_bytes_available{export=\"%s\",backend=\"%s\"} %llu\n"
            "brix_storage_occupancy_ratio{export=\"%s\",backend=\"%s\"} %.6f\n",
            info.root_canon, info.backend,
            (unsigned long long) fsu.total_bytes,
            info.root_canon, info.backend,
            (unsigned long long) fsu.occupancy_bytes,
            info.root_canon, info.backend,
            (unsigned long long) fsu.available_bytes,
            info.root_canon, info.backend,
            (double) fsu.occupancy_ppm / 1000000.0);
    }
}

/*
 * brix_storage_io_bytes_emit — the per-backend storage byte totals (the
 * three-seam attribution counters, spec 2026-07-03). Zero rows are emitted
 * too: a scraper needs the series to exist before traffic flows.
 */
static void
brix_storage_io_bytes_emit(metrics_writer_t *mw)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();
    int                   id;

    if (shm == NULL) {
        return;
    }

    mw_printf(mw,
        "# HELP brix_storage_io_bytes_read Bytes read by each storage backend driver.\n"
        "# TYPE brix_storage_io_bytes_read counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw, "brix_storage_io_bytes_read{backend=\"%s\"} %lu\n",
            brix_fs_id_name(id),
            (unsigned long) ngx_atomic_fetch_add(
                &shm->unified.io_bytes_read_backend[id], 0));
    }

    mw_printf(mw,
        "# HELP brix_storage_io_bytes_written Bytes written by each storage backend driver.\n"
        "# TYPE brix_storage_io_bytes_written counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw, "brix_storage_io_bytes_written{backend=\"%s\"} %lu\n",
            brix_fs_id_name(id),
            (unsigned long) ngx_atomic_fetch_add(
                &shm->unified.io_bytes_written_backend[id], 0));
    }
}

/*
 * brix_storage_backend_metrics_emit — the storage-plane metric block: the
 * per-export composed-stack info gauge (C-7) and capacity gauges (registry-
 * keyed, skipped when no export registered), then the per-backend io byte
 * totals (global SHM counters, emitted regardless of registry state).
 */
void
brix_storage_backend_metrics_emit(metrics_writer_t *mw)
{
    ngx_uint_t n = brix_vfs_backend_export_count();

    if (n > 0) {
        brix_storage_backend_info_emit(mw, n);
        brix_storage_capacity_emit(mw, n);
    }

    brix_storage_io_bytes_emit(mw);
}

void
mw_finish(metrics_writer_t *mw)
{
    mw->tail->buf->last    = mw->pos;
    mw->tail->buf->last_buf = 1;
}
