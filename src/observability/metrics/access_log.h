#ifndef BRIX_METRICS_ACCESS_LOG_H
#define BRIX_METRICS_ACCESS_LOG_H

#include "fs/vfs/vfs.h"
#include "unified.h"

void brix_access_log_emit(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, brix_err_class_t err, ngx_msec_t latency_usec);

#endif /* BRIX_METRICS_ACCESS_LOG_H */
