#include "voms_internal.h"

#include <dlfcn.h>

/* File: voms loader - runtime libvomsapi dynamic loading (no link-time dependency)
 *
 * WHAT: VOMS API runtime loader - encapsulated module state with accessor.
 *
 *   - brix_voms_state_t: module state struct (API handle + availability flag)
 *   - brix_voms_api_t: dlopen handle + 4 function pointers
 *     - init, retrieve, destroy, error_message
 *   - brix_voms_loaded: ngx_flag_t runtime load status
 *     - 0 = unavailable, 1 = fully initialized with all symbols resolved
 *   - Bridge between nginx-xrootd and VOMS VO ACL enforcement
 *   - No compile-time linking to libvomsapi required
 *
 * WHY: Encapsulation prevents accidental modification, enables future extension
 *      (e.g., multiple VOMS instances, lazy loading, testing hooks).
 *
 * HOW: Static state struct with const accessor function - immutable after init.
 */

/*
 * Runtime libvomsapi loader. The module has no link-time VOMS dependency.
 * State is set-once during startup, immutable thereafter.
 */

typedef struct {
    brix_voms_api_t  api;      /* dlopen handle + function pointers */
    ngx_flag_t       loaded;   /* 1 = initialized, 0 = unavailable */
} brix_voms_state_t;

static brix_voms_state_t  brix_voms_state = {
    .api    = { 0 },
    .loaded = 0
};

/*
 * WHAT: Accessor returning ngx_flag_t for libvomsapi.so.1 load status.
 *
 *   - Returns 1 (NGX_OK): all 4 symbols resolved, brix_voms_api populated
 *     - VOMS_Init, VOMS_Retrieve, VOMS_Destroy, VOMS_ErrorMessage
 *   - Returns 0: library not found or symbol loading failed
 *   - Used by: path/acl.c, voms/collect.c (conditional VOMS checks)
 *   - Thread safety: immutable flag set once during startup
 */

ngx_flag_t
brix_voms_available(void)
{
    return brix_voms_state.loaded;
}

/*
 * WHAT: Internal accessor for VOMS API function pointer table.
 * WHY: Encapsulation — callers use accessor rather than direct global access.
 * HOW: Returns pointer to static state.api — safe because immutable after init.
 */
brix_voms_api_t *
brix_voms_get_api_internal(void)
{
    return &brix_voms_state.api;
}

/*
 * WHAT: Dynamically loads VOMS API library (libvomsapi.so.1) via dlopen.
 *
 *   - Flags: RTLD_NOW (immediate resolution) | RTLD_LOCAL (no namespace pollution)
 *   - Step 1: Check if already loaded → returns NGX_OK (no duplicate loading)
 *   - Step 2: dlopen() library; on failure → NGX_DECLINED (graceful degradation)
 *   - Step 3: Clear dlerror() state
 *   - Step 4: Load 4 symbols via LOAD_SYM macro:
 *     - VOMS_Init (session initialization)
 *     - VOMS_Retrieve (VO list extraction from proxy cert)
 *     - VOMS_Destroy (session cleanup)
 *     - VOMS_ErrorMessage (human-readable error strings)
 *   - Symbol failure: close handle, ngx_memzero(), NGX_LOG_ERR, NGX_ERROR
 *   - Success: brix_voms_loaded=1, NGX_LOG_NOTICE, NGX_OK
 *   - Library not found: NGX_DECLINED (VOMS disabled, server continues)
 *
 * WHY: Runtime loading eliminates compile-time dependency on libvomsapi.so.1.
 *
 *   - RTLD_LOCAL prevents symbol namespace pollution across modules
 *   - Graceful degradation: NGX_DECLINED + notice-level log
 *   - LOAD_SYM macro: consistent error handling (logging, cleanup, return)
 *   - Thread safety: runs once during startup, immutable after
 */

ngx_int_t
brix_voms_init(ngx_log_t *log)
{
    if (brix_voms_state.loaded) {
        return NGX_OK;
    }

    brix_voms_state.api.handle = dlopen("libvomsapi.so.1", RTLD_NOW | RTLD_LOCAL);
    if (brix_voms_state.api.handle == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "brix: libvomsapi.so.1 not found (%s) — "
                      "VOMS VO ACL enforcement disabled",
                      dlerror());
        return NGX_DECLINED;
    }

    (void) dlerror();

#define LOAD_SYM(field, name)                                          \
    do {                                                              \
        *(void **) (&brix_voms_state.api.field) =                   \
            dlsym(brix_voms_state.api.handle, #name);               \
        if (brix_voms_state.api.field == NULL) {                    \
            ngx_log_error(NGX_LOG_ERR, log, 0,                        \
                          "brix: dlsym(%s) failed: %s",             \
                          #name, dlerror());                          \
            dlclose(brix_voms_state.api.handle);                    \
            ngx_memzero(&brix_voms_state, sizeof(brix_voms_state)); \
            return NGX_ERROR;                                         \
        }                                                             \
    } while (0)

    LOAD_SYM(init, VOMS_Init);
    LOAD_SYM(retrieve, VOMS_Retrieve);
    LOAD_SYM(destroy, VOMS_Destroy);
    LOAD_SYM(error_message, VOMS_ErrorMessage);

#undef LOAD_SYM

    brix_voms_state.loaded = 1;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: libvomsapi.so.1 loaded — "
                  "VOMS VO ACL enforcement available");
    return NGX_OK;
}
