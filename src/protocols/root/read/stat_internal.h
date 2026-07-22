#ifndef BRIX_STAT_INTERNAL_H
#define BRIX_STAT_INTERNAL_H

/*
 * stat_internal.h — cross-file glue for the kXR_stat serve paths.
 *
 * WHAT: the handful of stat helpers the dispatcher (stat.c) reaches into a
 * sibling translation unit to call.  Everything declared here is DEFINED in one
 * of those units and REFERENCED from another; helpers used within a single file
 * stay static there and never appear in this header.
 * WHY: stat.c was split for file-size — this header keeps the split link-clean
 * without changing any behavior.
 */

#include "core/ngx_brix_module.h"

/*
 * stat_manager_route — redirector-side answers for a path-mode stat.
 * Defined in stat_manager.c.  Returns 0 when the request was answered (*rc
 * holds the value to return, possibly NGX_AGAIN) and 1 when the caller should
 * continue with a local stat.
 */
int stat_manager_route(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *reqpath, ngx_int_t *rc);

#endif // BRIX_STAT_INTERNAL_H
