#ifndef XROOTD_METRICS_ACCESS_LOG_H
#define XROOTD_METRICS_ACCESS_LOG_H

#include "fs/vfs.h"
#include "unified.h"

void xrootd_access_log_emit(const xrootd_vfs_ctx_t *ctx, const char *path,
    xrootd_metric_op_t op, const xrootd_vfs_io_result_t *result,
    size_t bytes, xrootd_err_class_t err, ngx_msec_t latency_usec);

#endif /* XROOTD_METRICS_ACCESS_LOG_H */
