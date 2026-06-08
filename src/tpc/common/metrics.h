#ifndef XROOTD_TPC_COMMON_METRICS_H
#define XROOTD_TPC_COMMON_METRICS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "transfer.h"

#define XROOTD_TPC_METRIC_STARTED 1
#define XROOTD_TPC_METRIC_SUCCESS 2
#define XROOTD_TPC_METRIC_ERROR   3

void xrootd_tpc_metric_transfer(ngx_uint_t protocol, ngx_uint_t direction,
    ngx_uint_t event, size_t bytes, ngx_log_t *log);

#endif /* XROOTD_TPC_COMMON_METRICS_H */
