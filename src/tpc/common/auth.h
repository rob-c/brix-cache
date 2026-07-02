#ifndef XROOTD_TPC_COMMON_AUTH_H
#define XROOTD_TPC_COMMON_AUTH_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/identity.h"

ngx_int_t xrootd_tpc_check_authz(const xrootd_identity_t *identity,
    const ngx_str_t *src_path, const ngx_str_t *dst_path, ngx_log_t *log);

#endif /* XROOTD_TPC_COMMON_AUTH_H */
