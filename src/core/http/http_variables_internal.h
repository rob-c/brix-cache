/* Internal handlers shared by the HTTP variable registration units. */
#ifndef BRIX_CORE_HTTP_VARIABLES_INTERNAL_H
#define BRIX_CORE_HTTP_VARIABLES_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/config/http_common.h"
#include "core/types/identity.h"

typedef enum {
    BRIX_HV_DN = 0,
    BRIX_HV_VO,
    BRIX_HV_FQAN,
    BRIX_HV_SUB,
    BRIX_HV_ISSUER
} brix_http_idvar_e;

typedef enum {
    BRIX_HV_BYTES_RECEIVED = 0,
    BRIX_HV_OPS
} brix_http_monitor_u64_e;

ngx_int_t brix_var_set_static(ngx_http_variable_value_t *v, const char *s,
    ngx_uint_t no_cacheable);
brix_identity_t *brix_request_identity(ngx_http_request_t *r);
ngx_http_brix_shared_conf_t *brix_request_shared_conf(ngx_http_request_t *r);

#define BRIX_HTTP_VAR_HANDLER(name) \
    ngx_int_t name(ngx_http_request_t *r, ngx_http_variable_value_t *v, \
        uintptr_t data)
BRIX_HTTP_VAR_HANDLER(brix_var_identity_str);
BRIX_HTTP_VAR_HANDLER(brix_var_auth_method);
BRIX_HTTP_VAR_HANDLER(brix_var_tier);
BRIX_HTTP_VAR_HANDLER(brix_var_origin);
BRIX_HTTP_VAR_HANDLER(brix_var_bytes_served);
BRIX_HTTP_VAR_HANDLER(brix_var_backend_time);
BRIX_HTTP_VAR_HANDLER(brix_var_checksum);
BRIX_HTTP_VAR_HANDLER(brix_var_op);
BRIX_HTTP_VAR_HANDLER(brix_var_path);
BRIX_HTTP_VAR_HANDLER(brix_var_status);
BRIX_HTTP_VAR_HANDLER(brix_var_user);
BRIX_HTTP_VAR_HANDLER(brix_var_monitor_u64);
BRIX_HTTP_VAR_HANDLER(brix_var_duration);
#undef BRIX_HTTP_VAR_HANDLER

#endif /* BRIX_CORE_HTTP_VARIABLES_INTERNAL_H */
