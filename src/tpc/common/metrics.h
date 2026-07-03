#ifndef BRIX_TPC_COMMON_METRICS_H
#define BRIX_TPC_COMMON_METRICS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "transfer.h"

#define BRIX_TPC_METRIC_STARTED 1
#define BRIX_TPC_METRIC_SUCCESS 2
#define BRIX_TPC_METRIC_ERROR   3

void brix_tpc_metric_transfer(ngx_uint_t protocol, ngx_uint_t direction,
    ngx_uint_t event, size_t bytes, ngx_log_t *log);

#endif /* BRIX_TPC_COMMON_METRICS_H */
