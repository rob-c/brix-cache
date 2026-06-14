/*
 * unified.h — cross-protocol metric vocabulary and record-side API.
 *
 * WHAT: Declares the enums that give stream, WebDAV, and S3 a single shared
 *       label vocabulary — xrootd_proto_t (stream/webdav/s3), xrootd_metric_op_t
 *       (read/write/stat/delete/mkdir/rename/dirlist/tpc), and xrootd_err_class_t
 *       (ok/not_found/forbidden/io_error/other) — plus the AUTH_*, TPC_*, and
 *       latency-bucket slot constants. It also declares the record-side helpers
 *       (xrootd_metric_op_done / _cache_result / _auth / _tpc) every protocol
 *       handler calls, and the name/classification helpers (proto/op/err/auth
 *       name lookups, errno→err and http-status→err mappers, auth-slot mapper).
 * WHY:  Per-protocol metric modules historically each defined their own labels,
 *       producing inconsistent dashboards. Funnelling all three protocols through
 *       one enum set keeps Prometheus labels low-cardinality (INVARIANT #8) and
 *       lets a single exporter (xrootd_export_unified_metrics in unified.c) emit
 *       directly comparable xrootd_io_* / xrootd_auth_total / xrootd_tpc_* series.
 * HOW:  Enum members are dense 0-based so they index fixed-size SHM counter arrays
 *       directly; the trailing *_COUNT member sizes those arrays. The implementation
 *       lives in unified.c; consumers include this header to record an event with a
 *       proto/op/err triple rather than touching SHM fields by hand.
 */
#ifndef XROOTD_METRICS_UNIFIED_H
#define XROOTD_METRICS_UNIFIED_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef enum {
    XROOTD_PROTO_STREAM = 0,
    XROOTD_PROTO_WEBDAV = 1,
    XROOTD_PROTO_S3     = 2,
    XROOTD_PROTO_COUNT  = 3
} xrootd_proto_t;

typedef enum {
    XROOTD_METRIC_OP_READ    = 0,
    XROOTD_METRIC_OP_WRITE   = 1,
    XROOTD_METRIC_OP_STAT    = 2,
    XROOTD_METRIC_OP_DELETE  = 3,
    XROOTD_METRIC_OP_MKDIR   = 4,
    XROOTD_METRIC_OP_RENAME  = 5,
    XROOTD_METRIC_OP_DIRLIST = 6,
    XROOTD_METRIC_OP_TPC     = 7,
    XROOTD_METRIC_OP_COUNT   = 8
} xrootd_metric_op_t;

typedef enum {
    XROOTD_ERR_NONE      = 0,
    XROOTD_ERR_NOT_FOUND = 1,
    XROOTD_ERR_FORBIDDEN = 2,
    XROOTD_ERR_IO        = 3,
    XROOTD_ERR_OTHER     = 4,
    XROOTD_ERR_COUNT     = 5
} xrootd_err_class_t;

#define XROOTD_METRIC_AUTH_NONE    0
#define XROOTD_METRIC_AUTH_GSI     1
#define XROOTD_METRIC_AUTH_TOKEN   2
#define XROOTD_METRIC_AUTH_SSS     3
#define XROOTD_METRIC_AUTH_S3KEY   4
#define XROOTD_METRIC_AUTH_UNIX    5
#define XROOTD_METRIC_AUTH_KRB5    6
#define XROOTD_METRIC_AUTH_COUNT   7

#define XROOTD_METRIC_AUTH_FAIL    0
#define XROOTD_METRIC_AUTH_OK      1
#define XROOTD_METRIC_AUTH_STATUS_COUNT 2

#define XROOTD_METRIC_TPC_PULL     0
#define XROOTD_METRIC_TPC_PUSH     1
#define XROOTD_METRIC_TPC_DIRECTION_COUNT 2

/* Eight finite buckets plus +Inf, all in microseconds. */
#define XROOTD_IO_LATENCY_BUCKETS  9

/*
 * Map a proto/op/err enum to its Prometheus label string. The returned pointer
 * is a borrowed static literal (never freed by the caller); out-of-range input
 * yields the literal "unknown" (proto/op) or "other" (err) rather than NULL.
 */
const char *xrootd_metric_proto_name(xrootd_proto_t proto);
const char *xrootd_metric_op_name(xrootd_metric_op_t op);
const char *xrootd_metric_err_name(xrootd_err_class_t err);
/*
 * Label string for an identity auth_method BITMASK (not a slot): resolves the
 * mask via xrootd_metric_auth_slot() then names it. Borrowed static literal;
 * an empty/unknown mask yields "none". Never returns NULL.
 */
const char *xrootd_metric_auth_method_name(ngx_uint_t auth_method);

/*
 * Classify a POSIX errno into an xrootd_err_class_t bucket: 0 -> NONE,
 * ENOENT/ENOTDIR -> NOT_FOUND, EACCES/EPERM -> FORBIDDEN,
 * EIO/ENOMEM/ENOSPC -> IO, everything else -> OTHER.
 */
xrootd_err_class_t xrootd_metric_err_from_errno(int sys_errno);
/*
 * Classify an HTTP status into an xrootd_err_class_t bucket: 2xx AND 3xx -> NONE,
 * 404 -> NOT_FOUND, 401/403 -> FORBIDDEN, 5xx -> IO, everything else -> OTHER.
 */
xrootd_err_class_t xrootd_metric_err_from_http_status(ngx_uint_t status);
/*
 * Reduce an identity auth_method bitmask to a single XROOTD_METRIC_AUTH_* slot,
 * tested in priority order GSI > TOKEN > SSS > S3KEY > UNIX > KRB5; returns
 * XROOTD_METRIC_AUTH_NONE when no known bit is set. Pure, no side effects.
 */
ngx_uint_t xrootd_metric_auth_slot(ngx_uint_t auth_method);

/*
 * Record one completed I/O op into the shared counters: bumps
 * io_ops_total[proto][op][err], adds bytes to io_bytes_read/written (only for
 * READ/WRITE ops; ignored otherwise), and files latency_usec (microseconds)
 * into the single matching histogram bucket plus count and sum. Lock-free via
 * atomics. Silently no-ops on an out-of-range proto/op/err triple or when the
 * metrics SHM zone is not yet attached.
 */
void xrootd_metric_op_done(xrootd_proto_t proto, xrootd_metric_op_t op,
    size_t bytes, ngx_msec_t latency_usec, xrootd_err_class_t err);
/*
 * Record a cache lookup outcome: bumps cache_hits or cache_misses[proto] by hit
 * (treated as boolean) and adds bytes_evicted to cache_bytes_evicted[proto].
 * Lock-free; no-ops on out-of-range proto or detached SHM.
 */
void xrootd_metric_cache_result(xrootd_proto_t proto, unsigned int hit,
    size_t bytes_evicted);
/*
 * Record one auth attempt: maps auth_method (a bitmask) to its slot via
 * xrootd_metric_auth_slot(), then bumps auth_total[proto][slot][ok|fail] keyed
 * by success (boolean). Lock-free; no-ops on out-of-range proto or detached SHM.
 */
void xrootd_metric_auth(xrootd_proto_t proto, ngx_uint_t auth_method,
    unsigned int success);
/*
 * Record a third-party-copy outcome: bumps tpc_transfers[proto][dir][err] where
 * dir is push when is_push is nonzero else pull, and ONLY on err==XROOTD_ERR_NONE
 * adds bytes to tpc_bytes[proto][dir]. Lock-free; no-ops on out-of-range
 * proto/err or detached SHM.
 */
void xrootd_metric_tpc(xrootd_proto_t proto, unsigned int is_push,
    size_t bytes, xrootd_err_class_t err);

#endif /* XROOTD_METRICS_UNIFIED_H */
