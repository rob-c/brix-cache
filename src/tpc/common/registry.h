#ifndef XROOTD_TPC_COMMON_REGISTRY_H
#define XROOTD_TPC_COMMON_REGISTRY_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "transfer.h"

typedef struct {
    uint64_t       id;
    ngx_uint_t     protocol;
    ngx_uint_t     direction;
    off_t          bytes_total;
    off_t          bytes_done;
    time_t         started_at;
    time_t         updated_at;
    ngx_uint_t     state;
    char           src_url[XROOTD_TPC_SRC_URL_MAX];
    char           dst_path[XROOTD_TPC_DST_PATH_MAX];
} xrootd_tpc_transfer_snapshot_t;

ngx_int_t xrootd_tpc_registry_configure(ngx_conf_t *cf);

uint64_t xrootd_tpc_registry_add(const xrootd_tpc_transfer_t *transfer,
    ngx_log_t *log);

ngx_int_t xrootd_tpc_registry_update(uint64_t id, off_t bytes_done,
    ngx_uint_t state, ngx_log_t *log);

ngx_int_t xrootd_tpc_registry_remove(uint64_t id, ngx_log_t *log);

const xrootd_tpc_transfer_t *xrootd_tpc_registry_find(uint64_t id);

ngx_uint_t xrootd_tpc_registry_snapshot(xrootd_tpc_transfer_snapshot_t *out,
    ngx_uint_t max_transfers);

ngx_int_t xrootd_tpc_progress_emit(uint64_t id, off_t bytes_done,
    off_t bytes_total, ngx_uint_t state, ngx_log_t *log);

#endif /* XROOTD_TPC_COMMON_REGISTRY_H */
