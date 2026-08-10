#ifndef BRIX_LOCATE_INTERNAL_H
#define BRIX_LOCATE_INTERNAL_H

/*
 * locate_internal.h — private split contract between locate.c and
 * locate_manager.c (2026-08-09 file-size split).  Not a public API: include
 * only from src/protocols/root/read/locate*.c.
 *
 * locate.c owns the orchestrator, request-path resolution, static-map and
 * data-server legs, and the local-location formatter; locate_manager.c owns
 * the manager-mode dynamic-discovery chain (SUPCount floor, collapse cache,
 * multi-source, W3 dynamic location + stage-aware selection, registry select,
 * CMS parent locate).  The shared per-request state and the one cross-file
 * entry point live here.
 *
 * Requires: core/ngx_brix_module.h (brix_ctx_t, conf types) before inclusion.
 */

#include "core/ngx_brix_module.h"

/*
 * locate_ctx_t — per-request state threaded through the locate steps.
 * Bundles the connection/config context, the confined request-path buffer and
 * the request flags so each step takes them as one parameter (no globals).
 */
typedef struct {
    brix_ctx_t                  *ctx;
    ngx_connection_t            *c;
    ngx_stream_brix_srv_conf_t  *conf;
    char                        *reqpath;    /* confined path buffer (NUL-term) */
    size_t                       reqpath_sz;
    int                          is_wildcard;
    int                          tolerate_missing; /* '*'-prefixed create-locate */
    int                          refresh;    /* §2.7: kXR_refresh — bypass and
                                                flush the location caches */
    int                          nowait;     /* §1.8: kXR_nowait — answer
                                                kXR_wait instead of parking */
} locate_ctx_t;

/*
 * locate_try_manager — resolve a path via the manager-mode discovery chain
 * (locate_manager.c).  Returns 1 when a leg produced a terminal result
 * (redirect / kXR_wait / kXR_NotFound stored through *out_rc, or NGX_AGAIN
 * from a CMS/state suspend); returns 0 to fall through to the static map.
 */
int locate_try_manager(locate_ctx_t *lc, ngx_int_t *out_rc);

#endif /* BRIX_LOCATE_INTERNAL_H */
