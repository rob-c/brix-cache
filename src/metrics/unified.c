#include "metrics_internal.h"
#include "../types/identity.h"

#include <errno.h>
#include <string.h>

static const char *xrootd_unified_proto_names[XROOTD_PROTO_COUNT] = {
    "stream",
    "webdav",
    "s3",
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

    return XROOTD_METRIC_AUTH_NONE;
}

const char *
xrootd_metric_auth_method_name(ngx_uint_t auth_method)
{
    return xrootd_unified_auth_names[xrootd_metric_auth_slot(auth_method)];
}

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

    for (i = 0; i < XROOTD_IO_LATENCY_BUCKETS - 1; i++) {
        if (latency_usec <= xrootd_latency_bounds[i]) {
            XROOTD_ATOMIC_INC(&shm->unified.io_latency_bucket[proto][op][i]);
        }
    }
    XROOTD_ATOMIC_INC(&shm->unified.io_latency_bucket[proto][op]
                                                  [XROOTD_IO_LATENCY_BUCKETS - 1]);
    XROOTD_ATOMIC_INC(&shm->unified.io_latency_count[proto][op]);
    XROOTD_ATOMIC_ADD(&shm->unified.io_latency_sum_usec[proto][op],
                      latency_usec);
}

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

static unsigned long long
xrootd_metric_value(ngx_atomic_t *counter)
{
    return (unsigned long long) ngx_atomic_fetch_add(counter, 0);
}

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
    if (proto == XROOTD_PROTO_STREAM) {
        return xrootd_unified_legacy_stream_auth(shm, method, status);
    }

    (void) method;
    (void) status;
    return 0;
}

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
        if (proto == XROOTD_PROTO_STREAM) {
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
        if (proto == XROOTD_PROTO_STREAM) {
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
                if (proto == XROOTD_PROTO_STREAM) {
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
            for (bucket = 0; bucket < XROOTD_IO_LATENCY_BUCKETS - 1; bucket++) {
                mw_printf(mw,
                    "xrootd_io_latency_usec_bucket"
                    "{proto=\"%s\",op=\"%s\",le=\"%llu\"} %llu\n",
                    xrootd_metric_proto_name((xrootd_proto_t) proto),
                    xrootd_metric_op_name((xrootd_metric_op_t) op),
                    (unsigned long long) xrootd_latency_bounds[bucket],
                    xrootd_metric_value(&shm->unified.io_latency_bucket
                        [proto][op][bucket]));
            }
            mw_printf(mw,
                "xrootd_io_latency_usec_bucket"
                "{proto=\"%s\",op=\"%s\",le=\"+Inf\"} %llu\n",
                xrootd_metric_proto_name((xrootd_proto_t) proto),
                xrootd_metric_op_name((xrootd_metric_op_t) op),
                xrootd_metric_value(&shm->unified.io_latency_bucket
                    [proto][op][XROOTD_IO_LATENCY_BUCKETS - 1]));
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
