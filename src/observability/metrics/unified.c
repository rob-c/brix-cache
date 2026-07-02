#include "metrics_internal.h"
#include "core/types/identity.h"

#include <errno.h>
#include <string.h>

/*
 * unified.c — cross-protocol metric recording, classification, and export.
 *
 * WHAT: Implements the unified metrics API declared in unified.h. Two halves:
 *       (1) record-side helpers (xrootd_metric_op_done / _cache_result / _auth /
 *       _tpc) that protocol handlers call to bump SHM counters using the shared
 *       proto/op/err vocabulary, plus the name/classification helpers
 *       (proto/op/err/auth names, errno→err, http-status→err, auth-slot mapper);
 *       and (2) the Prometheus exporter xrootd_export_unified_metrics() that
 *       renders the xrootd_io_*, xrootd_cache_*, xrootd_auth_total, and
 *       xrootd_tpc_* series.
 * WHY:  One implementation behind one vocabulary keeps the three protocols'
 *       dashboards directly comparable and keeps labels low-cardinality
 *       (INVARIANT #8). It also bridges the legacy per-server stream counters
 *       (servers[].op_ok/op_err/bytes_*) into the new unified series so the
 *       /metrics output stays continuous across the metrics rework — older
 *       stream activity still shows up under the unified names.
 * HOW:  Static name tables map each enum to its label string. Record helpers
 *       resolve the SHM block via xrootd_metrics_shared(), validate the
 *       proto/op/err triple, then bump counters with the lock-free
 *       XROOTD_ATOMIC_* macros. The latency histogram is stored NON-cumulative
 *       (each sample increments only the single bucket it falls in, bounding the
 *       hot path to 3 atomics); the exporter cumulates buckets at scrape time so
 *       Prometheus `le` semantics and +Inf == count still hold. The legacy
 *       bridge functions sum matching servers[] slots and add them into the
 *       stream-protocol values during export only.
 */

/* Generated from the central protocol declaration (core/types/proto_list.h). */
static const char *xrootd_unified_proto_names[XROOTD_PROTO_COUNT] = {
#define X(ID, metric_label, dash_name, http_plane) metric_label,
    XROOTD_PROTO_LIST(X)
#undef X
};

static const char *xrootd_unified_op_names[XROOTD_METRIC_OP_COUNT] = {
    "read",
    "write",
    "stat",
    "delete",
    "mkdir",
    "rename",
    "dirlist",
    "tpc",
    "xattr",
    "copy",
};

static const char *xrootd_unified_err_names[XROOTD_ERR_COUNT] = {
    "ok",
    "not_found",
    "forbidden",
    "io_error",
    "other",
};

static const char *xrootd_unified_auth_names[XROOTD_METRIC_AUTH_COUNT] = {
    "none",
    "gsi",
    "token",
    "sss",
    "s3key",
    "unix",
    "krb5",
    "host",
    "pwd",
};

static const char *xrootd_unified_tpc_direction_names[
    XROOTD_METRIC_TPC_DIRECTION_COUNT] =
{
    "pull",
    "push",
};

static const ngx_msec_t xrootd_latency_bounds[XROOTD_IO_LATENCY_BUCKETS - 1] = {
    1000,
    5000,
    10000,
    50000,
    100000,
    500000,
    1000000,
    5000000,
};

const char *
xrootd_metric_proto_name(xrootd_proto_t proto)
{
    return proto < XROOTD_PROTO_COUNT ? xrootd_unified_proto_names[proto]
                                      : "unknown";
}

const char *
xrootd_metric_op_name(xrootd_metric_op_t op)
{
    return op < XROOTD_METRIC_OP_COUNT ? xrootd_unified_op_names[op]
                                       : "unknown";
}

const char *
xrootd_metric_err_name(xrootd_err_class_t err)
{
    return err < XROOTD_ERR_COUNT ? xrootd_unified_err_names[err] : "other";
}

/*
 * xrootd_metric_auth_slot — map an identity auth_method bitmask to one
 * XROOTD_METRIC_AUTH_* slot. Tested in priority order (GSI, TOKEN, SSS, S3KEY,
 * UNIX, KRB5); returns XROOTD_METRIC_AUTH_NONE when no known bit is set.
 */
ngx_uint_t
xrootd_metric_auth_slot(ngx_uint_t auth_method)
{
    if (auth_method & XROOTD_AUTHN_GSI) {
        return XROOTD_METRIC_AUTH_GSI;
    }
    if (auth_method & XROOTD_AUTHN_TOKEN) {
        return XROOTD_METRIC_AUTH_TOKEN;
    }
    if (auth_method & XROOTD_AUTHN_SSS) {
        return XROOTD_METRIC_AUTH_SSS;
    }
    if (auth_method & XROOTD_AUTHN_S3KEY) {
        return XROOTD_METRIC_AUTH_S3KEY;
    }
    if (auth_method & XROOTD_AUTHN_UNIX) {
        return XROOTD_METRIC_AUTH_UNIX;
    }
    if (auth_method & XROOTD_AUTHN_KRB5) {
        return XROOTD_METRIC_AUTH_KRB5;
    }
    if (auth_method & XROOTD_AUTHN_HOST) {
        return XROOTD_METRIC_AUTH_HOST;
    }
    if (auth_method & XROOTD_AUTHN_PWD) {
        return XROOTD_METRIC_AUTH_PWD;
    }

    return XROOTD_METRIC_AUTH_NONE;
}

const char *
xrootd_metric_auth_method_name(ngx_uint_t auth_method)
{
    return xrootd_unified_auth_names[xrootd_metric_auth_slot(auth_method)];
}

/*
 * xrootd_metric_err_from_errno — classify a POSIX errno into an
 * xrootd_err_class_t bucket (0→NONE, ENOENT/ENOTDIR→NOT_FOUND,
 * EACCES/EPERM→FORBIDDEN, EIO/ENOMEM/ENOSPC→IO, else OTHER).
 */
xrootd_err_class_t
xrootd_metric_err_from_errno(int sys_errno)
{
    switch (sys_errno) {
    case 0:
        return XROOTD_ERR_NONE;
    case ENOENT:
    case ENOTDIR:
        return XROOTD_ERR_NOT_FOUND;
    case EACCES:
    case EPERM:
        return XROOTD_ERR_FORBIDDEN;
    case EIO:
    case ENOMEM:
    case ENOSPC:
        return XROOTD_ERR_IO;
    default:
        return XROOTD_ERR_OTHER;
    }
}

/*
 * xrootd_metric_err_from_http_status — classify an HTTP status code into an
 * xrootd_err_class_t bucket (2xx/3xx→NONE, 404→NOT_FOUND, 401/403→FORBIDDEN,
 * 5xx→IO, else OTHER), so WebDAV/S3 outcomes share the unified error vocabulary.
 */
xrootd_err_class_t
xrootd_metric_err_from_http_status(ngx_uint_t status)
{
    if (status >= 200 && status < 400) {
        return XROOTD_ERR_NONE;
    }
    if (status == NGX_HTTP_NOT_FOUND) {
        return XROOTD_ERR_NOT_FOUND;
    }
    if (status == NGX_HTTP_FORBIDDEN || status == NGX_HTTP_UNAUTHORIZED) {
        return XROOTD_ERR_FORBIDDEN;
    }
    if (status >= 500 && status < 600) {
        return XROOTD_ERR_IO;
    }

    return XROOTD_ERR_OTHER;
}

/*
 * xrootd_metric_op_done — record one completed I/O operation: bump the
 * io_ops_total[proto][op][err] counter, add bytes to the read/write totals for
 * read/write ops, and update the latency histogram (single bucket + count + sum).
 * Validates the proto/op/err triple and no-ops if the SHM zone is unavailable.
 */
void
xrootd_metric_op_done(xrootd_proto_t proto, xrootd_metric_op_t op,
    size_t bytes, ngx_msec_t latency_usec, xrootd_err_class_t err)
{
    ngx_xrootd_metrics_t *shm;
    ngx_uint_t            i;

    if (proto >= XROOTD_PROTO_COUNT || op >= XROOTD_METRIC_OP_COUNT
        || err >= XROOTD_ERR_COUNT)
    {
        return;
    }

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    XROOTD_ATOMIC_INC(&shm->unified.io_ops_total[proto][op][err]);

    if (op == XROOTD_METRIC_OP_READ) {
        XROOTD_ATOMIC_ADD(&shm->unified.io_bytes_read[proto], bytes);
    } else if (op == XROOTD_METRIC_OP_WRITE) {
        XROOTD_ATOMIC_ADD(&shm->unified.io_bytes_written[proto], bytes);
    }

    /*
     * Non-cumulative histogram: increment ONLY the single bucket this sample
     * falls into, not every bucket whose bound it satisfies.  This bounds the
     * hot path to a fixed 3 atomics (one bucket + count + sum) instead of up to
     * XROOTD_IO_LATENCY_BUCKETS atomics per I/O.  The exporter cumulates the
     * per-bucket counts at scrape time (Prometheus `le` buckets stay cumulative
     * and +Inf still equals count), so /metrics output is byte-identical.
     */
    for (i = 0; i < XROOTD_IO_LATENCY_BUCKETS - 1; i++) {
        if (latency_usec <= xrootd_latency_bounds[i]) {
            break;
        }
    }
    /* i is the matching finite bucket, or BUCKETS-1 (the +Inf bucket). */
    XROOTD_ATOMIC_INC(&shm->unified.io_latency_bucket[proto][op][i]);
    XROOTD_ATOMIC_INC(&shm->unified.io_latency_count[proto][op]);
    XROOTD_ATOMIC_ADD(&shm->unified.io_latency_sum_usec[proto][op],
                      latency_usec);
}

/*
 * xrootd_metric_cache_result — record a cache lookup outcome for proto:
 * increment cache_hits or cache_misses per hit, and add bytes_evicted to the
 * per-protocol eviction total.
 */
void
xrootd_metric_cache_result(xrootd_proto_t proto, unsigned int hit,
    size_t bytes_evicted)
{
    ngx_xrootd_metrics_t *shm;

    if (proto >= XROOTD_PROTO_COUNT) {
        return;
    }

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (hit) {
        XROOTD_ATOMIC_INC(&shm->unified.cache_hits[proto]);
    } else {
        XROOTD_ATOMIC_INC(&shm->unified.cache_misses[proto]);
    }
    XROOTD_ATOMIC_ADD(&shm->unified.cache_bytes_evicted[proto], bytes_evicted);
}

/*
 * xrootd_metric_cache_usage_ratio — publish the current cache_root occupancy
 * (ppm, 0-1e6) as a process-wide gauge. Called from the watermark reaper timer
 * each tick. A plain aligned-word store is atomic on the platforms nginx targets;
 * no read-modify-write is needed for a gauge.
 */
void
xrootd_metric_cache_usage_ratio(ngx_uint_t occupancy_ppm)
{
    ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();

    if (shm != NULL) {
        shm->unified.cache_usage_ratio_ppm = (ngx_atomic_t) occupancy_ppm;
    }
}

/*
 * xrootd_metric_cache_watermark_purge — account one watermark-reaper purge that
 * reclaimed space: bumps the purge-run counter and adds the evicted file/byte
 * totals. The connection-less reaper cannot feed the per-proto/per-server
 * eviction series, so this dedicated family is its sole reporting path.
 */
void
xrootd_metric_cache_watermark_purge(ngx_uint_t files, uint64_t bytes)
{
    ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();

    if (shm == NULL || files == 0) {
        return;
    }
    XROOTD_ATOMIC_INC(&shm->unified.cache_watermark_purges);
    XROOTD_ATOMIC_ADD(&shm->unified.cache_watermark_evicted_files, files);
    XROOTD_ATOMIC_ADD(&shm->unified.cache_watermark_evicted_bytes, bytes);
}

/*
 * xrootd_metric_wt_stage_usage_ratio — publish write-back staging occupancy (ppm)
 * as a process-wide gauge. Called from the admission gate each time it samples.
 */
void
xrootd_metric_wt_stage_usage_ratio(ngx_uint_t occupancy_ppm)
{
    ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();

    if (shm != NULL) {
        shm->unified.wt_stage_usage_ratio_ppm = (ngx_atomic_t) occupancy_ppm;
    }
}

/*
 * xrootd_metric_wt_stage_throttled — count a write shed by staging backpressure:
 * reject != 0 → hard-cap rejection, else a soft-band delay.
 */
void
xrootd_metric_wt_stage_throttled(int reject)
{
    ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();

    if (shm == NULL) {
        return;
    }
    if (reject) {
        XROOTD_ATOMIC_INC(&shm->unified.wt_stage_throttled_reject);
    } else {
        XROOTD_ATOMIC_INC(&shm->unified.wt_stage_throttled_wait);
    }
}

/*
 * xrootd_metric_auth — record an authentication attempt: map auth_method to its
 * slot, then bump auth_total[proto][method][ok|fail] according to success.
 */
void
xrootd_metric_auth(xrootd_proto_t proto, ngx_uint_t auth_method,
    unsigned int success)
{
    ngx_xrootd_metrics_t *shm;
    ngx_uint_t            method;
    ngx_uint_t            status;

    if (proto >= XROOTD_PROTO_COUNT) {
        return;
    }

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    method = xrootd_metric_auth_slot(auth_method);
    status = success ? XROOTD_METRIC_AUTH_OK : XROOTD_METRIC_AUTH_FAIL;
    XROOTD_ATOMIC_INC(&shm->unified.auth_total[proto][method][status]);
}

/*
 * xrootd_metric_tpc — record a third-party-copy transfer outcome: bump
 * tpc_transfers[proto][pull|push][err], and on success add bytes to
 * tpc_bytes[proto][direction]. is_push selects push vs pull direction.
 */
void
xrootd_metric_tpc(xrootd_proto_t proto, unsigned int is_push,
    size_t bytes, xrootd_err_class_t err)
{
    ngx_xrootd_metrics_t *shm;
    ngx_uint_t            direction;

    if (proto >= XROOTD_PROTO_COUNT || err >= XROOTD_ERR_COUNT) {
        return;
    }

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    direction = is_push ? XROOTD_METRIC_TPC_PUSH : XROOTD_METRIC_TPC_PULL;
    XROOTD_ATOMIC_INC(&shm->unified.tpc_transfers[proto][direction][err]);
    if (err == XROOTD_ERR_NONE) {
        XROOTD_ATOMIC_ADD(&shm->unified.tpc_bytes[proto][direction], bytes);
    }
}

/* Lock-free read of an atomic counter (fetch-add of 0) as an unsigned long long. */
static unsigned long long
xrootd_metric_value(ngx_atomic_t *counter)
{
    return (unsigned long long) ngx_atomic_fetch_add(counter, 0);
}

/*
 * Legacy-bridge helpers (xrootd_unified_legacy_*): the stream protocol predates
 * the unified counters and still records into the per-server servers[] slots
 * (op_ok/op_err/bytes_rx/bytes_tx and the auth string). These functions sum the
 * matching in-use servers[] slots so the exporter can fold legacy stream activity
 * into the unified stream-protocol values, keeping /metrics output continuous.
 * They are export-time read-only aggregations — never used on the record path.
 */
static unsigned long long
xrootd_unified_legacy_stream_bytes(ngx_xrootd_metrics_t *shm,
    unsigned int is_write)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    total = 0;
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) {
            continue;
        }
        total += is_write
            ? xrootd_metric_value(&srv->bytes_rx_total)
            : xrootd_metric_value(&srv->bytes_tx_total);
    }

    return total;
}

static unsigned long long
xrootd_unified_legacy_stream_op_slot(ngx_xrootd_metrics_t *shm,
    ngx_uint_t slot, unsigned int ok)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    if (slot >= XROOTD_NOPS) {
        return 0;
    }

    total = 0;
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) {
            continue;
        }
        total += ok ? xrootd_metric_value(&srv->op_ok[slot])
                    : xrootd_metric_value(&srv->op_err[slot]);
    }

    return total;
}

static unsigned long long
xrootd_unified_legacy_stream_op(ngx_xrootd_metrics_t *shm,
    xrootd_metric_op_t op, unsigned int ok)
{
    switch (op) {
    case XROOTD_METRIC_OP_READ:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_READ, ok)
             + xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_READV, ok)
             + xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_PGREAD, ok);
    case XROOTD_METRIC_OP_WRITE:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_WRITE, ok)
             + xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_WRITEV, ok);
    case XROOTD_METRIC_OP_STAT:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_STAT, ok)
             + xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_STATX, ok);
    case XROOTD_METRIC_OP_DELETE:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_RM, ok)
             + xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_RMDIR, ok);
    case XROOTD_METRIC_OP_MKDIR:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_MKDIR, ok);
    case XROOTD_METRIC_OP_RENAME:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_MV, ok);
    case XROOTD_METRIC_OP_DIRLIST:
        return xrootd_unified_legacy_stream_op_slot(shm, XROOTD_OP_DIRLIST, ok);
    default:
        return 0;
    }
}

static ngx_uint_t
xrootd_unified_srv_auth_slot(const char *auth)
{
    if (auth == NULL) {
        return XROOTD_METRIC_AUTH_NONE;
    }
    if (strncmp(auth, "gsi", 3) == 0) {
        return XROOTD_METRIC_AUTH_GSI;
    }
    if (strncmp(auth, "sss", 3) == 0) {
        return XROOTD_METRIC_AUTH_SSS;
    }
    if (strncmp(auth, "token", 5) == 0) {
        return XROOTD_METRIC_AUTH_TOKEN;
    }
    if (strncmp(auth, "unix", 4) == 0) {
        return XROOTD_METRIC_AUTH_UNIX;
    }
    if (strncmp(auth, "krb5", 4) == 0) {
        return XROOTD_METRIC_AUTH_KRB5;
    }

    return XROOTD_METRIC_AUTH_NONE;
}

static unsigned long long
xrootd_unified_legacy_stream_auth(ngx_xrootd_metrics_t *shm,
    ngx_uint_t method, ngx_uint_t status)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    total = 0;
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || xrootd_unified_srv_auth_slot(srv->auth) != method) {
            continue;
        }
        total += status == XROOTD_METRIC_AUTH_OK
            ? xrootd_metric_value(&srv->op_ok[XROOTD_OP_AUTH])
            : xrootd_metric_value(&srv->op_err[XROOTD_OP_AUTH]);
    }

    return total;
}

static unsigned long long
xrootd_unified_legacy_auth(ngx_xrootd_metrics_t *shm, xrootd_proto_t proto,
    ngx_uint_t method, ngx_uint_t status)
{
    if (proto == XROOTD_PROTO_ROOT) {
        return xrootd_unified_legacy_stream_auth(shm, method, status);
    }

    (void) method;
    (void) status;
    return 0;
}

/*
 * xrootd_export_unified_metrics — render all unified counter families to the
 * Prometheus text writer: io bytes read/written, io_ops_total, the io latency
 * histogram (cumulated from non-cumulative storage), cache hits/misses/evicted,
 * auth_total, and tpc transfers/bytes — each as HELP/TYPE plus per-label lines.
 * Legacy per-server stream counters are folded into the stream-protocol values.
 */
void
xrootd_export_unified_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t       proto, op, err, bucket, method, status, direction;
    unsigned long long value;

    mw_printf(mw,
        "# HELP xrootd_io_bytes_read Total bytes read from storage, by protocol.\n"
        "# TYPE xrootd_io_bytes_read counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        value = xrootd_metric_value(&shm->unified.io_bytes_read[proto]);
        if (proto == XROOTD_PROTO_ROOT) {
            value += xrootd_unified_legacy_stream_bytes(shm, 0);
        } else if (proto == XROOTD_PROTO_WEBDAV) {
            value += xrootd_metric_value(&shm->webdav.bytes_tx_total);
        } else if (proto == XROOTD_PROTO_S3) {
            value += xrootd_metric_value(&shm->s3.bytes_tx_total);
        }
        mw_printf(mw, "xrootd_io_bytes_read{proto=\"%s\"} %llu\n",
                  xrootd_metric_proto_name((xrootd_proto_t) proto), value);
    }

    mw_printf(mw,
        "# HELP xrootd_io_bytes_written Total bytes written to storage, by protocol.\n"
        "# TYPE xrootd_io_bytes_written counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        value = xrootd_metric_value(&shm->unified.io_bytes_written[proto]);
        if (proto == XROOTD_PROTO_ROOT) {
            value += xrootd_unified_legacy_stream_bytes(shm, 1);
        } else if (proto == XROOTD_PROTO_WEBDAV) {
            value += xrootd_metric_value(&shm->webdav.bytes_rx_total);
        } else if (proto == XROOTD_PROTO_S3) {
            value += xrootd_metric_value(&shm->s3.bytes_rx_total);
        }
        mw_printf(mw, "xrootd_io_bytes_written{proto=\"%s\"} %llu\n",
                  xrootd_metric_proto_name((xrootd_proto_t) proto), value);
    }

    mw_printf(mw,
        "# HELP xrootd_io_ops_total I/O operations completed, by protocol, operation, and status.\n"
        "# TYPE xrootd_io_ops_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        for (op = 0; op < XROOTD_METRIC_OP_COUNT; op++) {
            for (err = 0; err < XROOTD_ERR_COUNT; err++) {
                value = xrootd_metric_value(
                    &shm->unified.io_ops_total[proto][op][err]);
                if (proto == XROOTD_PROTO_ROOT) {
                    if (err == XROOTD_ERR_NONE) {
                        value += xrootd_unified_legacy_stream_op(
                            shm, (xrootd_metric_op_t) op, 1);
                    } else if (err == XROOTD_ERR_OTHER) {
                        value += xrootd_unified_legacy_stream_op(
                            shm, (xrootd_metric_op_t) op, 0);
                    }
                }
                mw_printf(mw,
                    "xrootd_io_ops_total"
                    "{proto=\"%s\",op=\"%s\",status=\"%s\"} %llu\n",
                    xrootd_metric_proto_name((xrootd_proto_t) proto),
                    xrootd_metric_op_name((xrootd_metric_op_t) op),
                    xrootd_metric_err_name((xrootd_err_class_t) err),
                    value);
            }
        }
    }

    mw_printf(mw,
        "# HELP xrootd_io_latency_usec I/O operation latency in microseconds.\n"
        "# TYPE xrootd_io_latency_usec histogram\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        for (op = 0; op < XROOTD_METRIC_OP_COUNT; op++) {
            /*
             * The write side stores NON-cumulative per-bucket counts (each I/O
             * increments only the bucket it lands in).  Prometheus histogram
             * `le` buckets are cumulative, so accumulate as we emit: every
             * bucket's reported value is the running sum of all lower buckets,
             * and the +Inf bucket equals the total count.
             */
            value = 0;
            for (bucket = 0; bucket < XROOTD_IO_LATENCY_BUCKETS - 1; bucket++) {
                value += xrootd_metric_value(&shm->unified.io_latency_bucket
                    [proto][op][bucket]);
                mw_printf(mw,
                    "xrootd_io_latency_usec_bucket"
                    "{proto=\"%s\",op=\"%s\",le=\"%llu\"} %llu\n",
                    xrootd_metric_proto_name((xrootd_proto_t) proto),
                    xrootd_metric_op_name((xrootd_metric_op_t) op),
                    (unsigned long long) xrootd_latency_bounds[bucket],
                    value);
            }
            value += xrootd_metric_value(&shm->unified.io_latency_bucket
                [proto][op][XROOTD_IO_LATENCY_BUCKETS - 1]);
            mw_printf(mw,
                "xrootd_io_latency_usec_bucket"
                "{proto=\"%s\",op=\"%s\",le=\"+Inf\"} %llu\n",
                xrootd_metric_proto_name((xrootd_proto_t) proto),
                xrootd_metric_op_name((xrootd_metric_op_t) op),
                value);
            mw_printf(mw,
                "xrootd_io_latency_usec_sum{proto=\"%s\",op=\"%s\"} %llu\n",
                xrootd_metric_proto_name((xrootd_proto_t) proto),
                xrootd_metric_op_name((xrootd_metric_op_t) op),
                xrootd_metric_value(&shm->unified.io_latency_sum_usec[proto][op]));
            mw_printf(mw,
                "xrootd_io_latency_usec_count{proto=\"%s\",op=\"%s\"} %llu\n",
                xrootd_metric_proto_name((xrootd_proto_t) proto),
                xrootd_metric_op_name((xrootd_metric_op_t) op),
                xrootd_metric_value(&shm->unified.io_latency_count[proto][op]));
        }
    }

    mw_printf(mw,
        "# HELP xrootd_cache_hits_total Cache hits by protocol.\n"
        "# TYPE xrootd_cache_hits_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        mw_printf(mw, "xrootd_cache_hits_total{proto=\"%s\"} %llu\n",
                  xrootd_metric_proto_name((xrootd_proto_t) proto),
                  xrootd_metric_value(&shm->unified.cache_hits[proto]));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_misses_total Cache misses by protocol.\n"
        "# TYPE xrootd_cache_misses_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        mw_printf(mw, "xrootd_cache_misses_total{proto=\"%s\"} %llu\n",
                  xrootd_metric_proto_name((xrootd_proto_t) proto),
                  xrootd_metric_value(&shm->unified.cache_misses[proto]));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_bytes_evicted_total Cache bytes evicted, by protocol.\n"
        "# TYPE xrootd_cache_bytes_evicted_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        value = xrootd_metric_value(&shm->unified.cache_bytes_evicted[proto]);
        mw_printf(mw,
                  "xrootd_cache_bytes_evicted_total{proto=\"%s\"} %llu\n",
                  xrootd_metric_proto_name((xrootd_proto_t) proto), value);
    }

    /* Watermark-driven LRU reaper (background timer). usage_ratio is a gauge in
     * 0-1 (stored as ppm); the rest are counters dedicated to the proactive
     * reaper so they never collide with the per-proto/per-server eviction series. */
    mw_printf(mw,
        "# HELP xrootd_cache_usage_ratio Cache filesystem occupancy (0-1).\n"
        "# TYPE xrootd_cache_usage_ratio gauge\n"
        "xrootd_cache_usage_ratio %.6f\n",
        (double) xrootd_metric_value(&shm->unified.cache_usage_ratio_ppm)
            / 1000000.0);

    mw_printf(mw,
        "# HELP xrootd_cache_watermark_purges_total Watermark reaper purge runs that reclaimed space.\n"
        "# TYPE xrootd_cache_watermark_purges_total counter\n"
        "xrootd_cache_watermark_purges_total %llu\n",
        xrootd_metric_value(&shm->unified.cache_watermark_purges));

    mw_printf(mw,
        "# HELP xrootd_cache_watermark_evicted_files_total Files reaped by the watermark reaper.\n"
        "# TYPE xrootd_cache_watermark_evicted_files_total counter\n"
        "xrootd_cache_watermark_evicted_files_total %llu\n",
        xrootd_metric_value(&shm->unified.cache_watermark_evicted_files));

    mw_printf(mw,
        "# HELP xrootd_cache_watermark_evicted_bytes_total Bytes reaped by the watermark reaper.\n"
        "# TYPE xrootd_cache_watermark_evicted_bytes_total counter\n"
        "xrootd_cache_watermark_evicted_bytes_total %llu\n",
        xrootd_metric_value(&shm->unified.cache_watermark_evicted_bytes));

    /* Write-back-staging backpressure. usage_ratio is a gauge (0-1, stored ppm);
     * throttled_total is split by the action taken on the shed write. */
    mw_printf(mw,
        "# HELP xrootd_wt_stage_usage_ratio Write-back staging filesystem occupancy (0-1).\n"
        "# TYPE xrootd_wt_stage_usage_ratio gauge\n"
        "xrootd_wt_stage_usage_ratio %.6f\n",
        (double) xrootd_metric_value(&shm->unified.wt_stage_usage_ratio_ppm)
            / 1000000.0);

    mw_printf(mw,
        "# HELP xrootd_wt_stage_throttled_total Writes shed by staging backpressure, by action.\n"
        "# TYPE xrootd_wt_stage_throttled_total counter\n"
        "xrootd_wt_stage_throttled_total{action=\"wait\"} %llu\n"
        "xrootd_wt_stage_throttled_total{action=\"reject\"} %llu\n",
        xrootd_metric_value(&shm->unified.wt_stage_throttled_wait),
        xrootd_metric_value(&shm->unified.wt_stage_throttled_reject));

    mw_printf(mw,
        "# HELP xrootd_auth_total Authentication attempts by protocol, method, and status.\n"
        "# TYPE xrootd_auth_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        for (method = 0; method < XROOTD_METRIC_AUTH_COUNT; method++) {
            for (status = 0; status < XROOTD_METRIC_AUTH_STATUS_COUNT; status++) {
                value = xrootd_metric_value(
                    &shm->unified.auth_total[proto][method][status]);
                value += xrootd_unified_legacy_auth(
                    shm, (xrootd_proto_t) proto, method, status);
                mw_printf(mw,
                    "xrootd_auth_total"
                    "{proto=\"%s\",method=\"%s\",status=\"%s\"} %llu\n",
                    xrootd_metric_proto_name((xrootd_proto_t) proto),
                    xrootd_unified_auth_names[method],
                    status == XROOTD_METRIC_AUTH_OK ? "ok" : "fail",
                    value);
            }
        }
    }

    mw_printf(mw,
        "# HELP xrootd_tpc_transfers_total Third-party-copy transfer outcomes.\n"
        "# TYPE xrootd_tpc_transfers_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        for (direction = 0; direction < XROOTD_METRIC_TPC_DIRECTION_COUNT;
             direction++)
        {
            for (err = 0; err < XROOTD_ERR_COUNT; err++) {
                mw_printf(mw,
                    "xrootd_tpc_transfers_total"
                    "{proto=\"%s\",direction=\"%s\",status=\"%s\"} %llu\n",
                    xrootd_metric_proto_name((xrootd_proto_t) proto),
                    xrootd_unified_tpc_direction_names[direction],
                    xrootd_metric_err_name((xrootd_err_class_t) err),
                    xrootd_metric_value(&shm->unified.tpc_transfers
                        [proto][direction][err]));
            }
        }
    }

    mw_printf(mw,
        "# HELP xrootd_tpc_bytes_total Successful third-party-copy bytes.\n"
        "# TYPE xrootd_tpc_bytes_total counter\n");
    for (proto = 0; proto < XROOTD_PROTO_COUNT; proto++) {
        for (direction = 0; direction < XROOTD_METRIC_TPC_DIRECTION_COUNT;
             direction++)
        {
            mw_printf(mw,
                "xrootd_tpc_bytes_total{proto=\"%s\",direction=\"%s\"} %llu\n",
                xrootd_metric_proto_name((xrootd_proto_t) proto),
                xrootd_unified_tpc_direction_names[direction],
                xrootd_metric_value(&shm->unified.tpc_bytes[proto][direction]));
        }
    }
}
