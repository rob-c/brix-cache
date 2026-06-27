#include "voms_internal.h"

#include <dlfcn.h>

/* File: voms loader — runtime libvomsapi dynamic loading (no link-time dependency)
 * WHAT: Declares global variables for VOMS API interface and availability flag. xrootd_voms_api_t structure contains dlopen handle plus four function pointers (init, retrieve, destroy, error_message). xrootd_voms_loaded is a ngx_flag_t indicating whether libvomsapi.so.1 was successfully loaded at runtime — zero means unavailable, one means fully initialized with all symbols resolved. This file provides the bridge between nginx-xrootd and VOMS VO ACL enforcement without requiring compile-time linking to libvomsapi. */

/*
 * Runtime libvomsapi loader. The module has no link-time VOMS dependency.
 */

xrootd_voms_api_t xrootd_voms_api;
ngx_flag_t        xrootd_voms_loaded;

/*
 *
 * WHAT: Simple accessor returning ngx_flag_t indicating whether libvomsapi.so.1 has been successfully loaded via dlopen/dlsym during nginx startup. Returns 1 (NGX_OK equivalent) when all four required symbols (VOMS_Init, VOMS_Retrieve, VOMS_Destroy, VOMS_ErrorMessage) were resolved and xrootd_voms_api structure is fully populated; returns 0 when library not found or symbol loading failed. Used by VO ACL enforcement code in path/acl.c and voms/collect.c to conditionally enable VOMS checks only when the runtime library is available. Thread safety: reads immutable flag set once during startup — no concurrent access concerns after initialization. */

ngx_flag_t
xrootd_voms_available(void)
{
    return xrootd_voms_loaded;
}

/*
 *
 * WHAT: Dynamically loads VOMS API library (libvomsapi.so.1) via dlopen(RTLD_NOW | RTLD_LOCAL) performing four-step initialization: first checks if already loaded (returns NGX_OK immediately to avoid duplicate loading). Opens library with RTLD_NOW for immediate symbol resolution and RTLD_LOCAL to prevent namespace pollution across modules. On successful open, clears any prior dlerror() state then loads four required symbols using LOAD_SYM macro helper: VOMS_Init (session initialization), VOMS_Retrieve (VO list extraction from proxy certificate), VOMS_Destroy (session cleanup), VOMS_ErrorMessage (human-readable error strings). Each symbol load checks for NULL result — on failure closes handle, zeroes API structure via ngx_memzero(), logs NGX_LOG_ERR and returns NGX_ERROR. On successful load of all four symbols sets xrootd_voms_loaded=1, logs NGX_LOG_NOTICE confirming availability, returns NGX_OK. Returns NGX_DECLINED when library not found (graceful degradation — VOMS enforcement disabled but server continues operating).
 *
 * WHY: Runtime dynamic loading eliminates compile-time dependency on libvomsapi.so.1 allowing nginx-xrootd to operate without VOMS on systems that don't have it installed. RTLD_LOCAL prevents symbol namespace pollution across nginx modules — critical when multiple modules use dlopen for different libraries. The graceful degradation path (NGX_DECLINED + notice-level log) enables operators to deploy servers with partial capabilities without requiring all optional dependencies simultaneously. LOAD_SYM macro ensures consistent error handling pattern across all four symbol loads: same logging level, same cleanup sequence, same return code on failure. Thread safety: initialization runs once during nginx startup process; no concurrent access after xrootd_voms_loaded is set. */

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
