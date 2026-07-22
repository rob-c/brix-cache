#ifndef BRIX_PREPARE_INTERNAL_H
#define BRIX_PREPARE_INTERNAL_H

/*
 * prepare_internal.h — helpers shared across the kXR_prepare / kXR_QPrep
 * translation units (prepare.c, prepare_qprep.c).  These were file-static in
 * prepare.c until the QPrep handler was split into prepare_qprep.c to keep each
 * file focused (and under the size cap); only the genuinely shared entry points
 * are promoted here — everything else stays static in its owning .c.
 */

#include "core/ngx_brix_module.h"

/*
 * Log a PREPARE/QPREP access event and send the wire error in one step.
 * Returns brix_send_error()'s result verbatim (NGX_OK on a queued response).
 * `path` may be NULL (rendered as "-").
 */
ngx_int_t brix_prepare_send_fail(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg);

/*
 * Validate + authorize ONE newline-separated prepare path (length/extract/
 * forbidden-component pre-checks, confined stat, three authorization tiers).
 * Lives in prepare_check.c; the prepare.c scan pipeline is the sole caller.
 * `out_resolved` is a PATH_MAX buffer filled with the absolute path on auth-pass
 * paths ('\0' if unresolvable); pass NULL when staging collection is not needed.
 * Returns NGX_OK on pass, NGX_DONE when a response was already sent, or an error.
 */
ngx_int_t brix_prepare_check_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const u_char *line, size_t line_len,
    ngx_flag_t noerrs, ngx_uint_t *missing, char *out_resolved);

#endif /* BRIX_PREPARE_INTERNAL_H */
