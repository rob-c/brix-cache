#include "voms_internal.h"

#include <dlfcn.h>

/*
 * Runtime libvomsapi loader. The module has no link-time VOMS dependency.
 */

xrootd_voms_api_t xrootd_voms_api;
ngx_flag_t        xrootd_voms_loaded;


ngx_flag_t
xrootd_voms_available(void)
{
    return xrootd_voms_loaded;
}


ngx_int_t
xrootd_voms_init(ngx_log_t *log)
{
    if (xrootd_voms_loaded) {
        return NGX_OK;
    }

    xrootd_voms_api.handle = dlopen("libvomsapi.so.1", RTLD_NOW | RTLD_LOCAL);
    if (xrootd_voms_api.handle == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: libvomsapi.so.1 not found (%s) — "
                      "VOMS VO ACL enforcement disabled",
                      dlerror());
        return NGX_DECLINED;
    }

    (void) dlerror();

#define LOAD_SYM(field, name)                                          \
    do {                                                              \
        *(void **) (&xrootd_voms_api.field) =                         \
            dlsym(xrootd_voms_api.handle, #name);                     \
        if (xrootd_voms_api.field == NULL) {                          \
            ngx_log_error(NGX_LOG_ERR, log, 0,                        \
                          "xrootd: dlsym(%s) failed: %s",             \
                          #name, dlerror());                          \
            dlclose(xrootd_voms_api.handle);                          \
            ngx_memzero(&xrootd_voms_api, sizeof(xrootd_voms_api));    \
            return NGX_ERROR;                                         \
        }                                                             \
    } while (0)

    LOAD_SYM(init, VOMS_Init);
    LOAD_SYM(retrieve, VOMS_Retrieve);
    LOAD_SYM(destroy, VOMS_Destroy);
    LOAD_SYM(error_message, VOMS_ErrorMessage);

#undef LOAD_SYM

    xrootd_voms_loaded = 1;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd: libvomsapi.so.1 loaded — "
                  "VOMS VO ACL enforcement available");
    return NGX_OK;
}
