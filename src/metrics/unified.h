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

const char *xrootd_metric_proto_name(xrootd_proto_t proto);
const char *xrootd_metric_op_name(xrootd_metric_op_t op);
const char *xrootd_metric_err_name(xrootd_err_class_t err);
const char *xrootd_metric_auth_method_name(ngx_uint_t auth_method);

xrootd_err_class_t xrootd_metric_err_from_errno(int sys_errno);
xrootd_err_class_t xrootd_metric_err_from_http_status(ngx_uint_t status);
ngx_uint_t xrootd_metric_auth_slot(ngx_uint_t auth_method);

void xrootd_metric_op_done(xrootd_proto_t proto, xrootd_metric_op_t op,
    size_t bytes, ngx_msec_t latency_usec, xrootd_err_class_t err);
void xrootd_metric_cache_result(xrootd_proto_t proto, unsigned int hit,
    size_t bytes_evicted);
void xrootd_metric_auth(xrootd_proto_t proto, ngx_uint_t auth_method,
    unsigned int success);
void xrootd_metric_tpc(xrootd_proto_t proto, unsigned int is_push,
    size_t bytes, xrootd_err_class_t err);

#endif /* XROOTD_METRICS_UNIFIED_H */
