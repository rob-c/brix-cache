#ifndef XROOTD_TPC_COMMON_CREDENTIAL_H
#define XROOTD_TPC_COMMON_CREDENTIAL_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "../../types/identity.h"

typedef enum {
    XROOTD_TPC_CREDENTIAL_NONE  = 0,
    XROOTD_TPC_CREDENTIAL_PROXY = 1,
    XROOTD_TPC_CREDENTIAL_TOKEN = 2,
} xrootd_tpc_credential_type_t;

typedef struct {
    xrootd_tpc_credential_type_t  type;
    ngx_str_t                     proxy_pem;
    ngx_str_t                     bearer;
    xrootd_identity_t            *identity;
    time_t                        expires_at;
} xrootd_tpc_credential_t;

ngx_int_t xrootd_tpc_credential_parse(const ngx_str_t *raw_credential,
    xrootd_tpc_credential_type_t hint, xrootd_tpc_credential_t *cred,
    ngx_pool_t *pool, ngx_log_t *log);

ngx_int_t xrootd_tpc_credential_validate(
    const xrootd_tpc_credential_t *cred, ngx_log_t *log);

const char *xrootd_tpc_credential_type_name(
    xrootd_tpc_credential_type_t type);

#endif /* XROOTD_TPC_COMMON_CREDENTIAL_H */
