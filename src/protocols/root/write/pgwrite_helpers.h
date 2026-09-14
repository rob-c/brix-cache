#pragma once

/*
 * pgwrite_helpers.h — Helper function declarations for kXR_pgwrite.
 * 
 * Private request state and synchronous-completion contract shared by
 * pgwrite.c and pgwrite_helpers.c. Requires no prior includes.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/pgio.h"

/* Per-request state: parse fills the request fields, decode fills the flat
 * buffer and bad-page list, and synchronous completion consumes both. */
typedef struct {
	xrdw_pgwrite_req_t             req;
	ngx_stream_brix_srv_conf_t    *rconf;
	int                            idx;
	int64_t                        offset;
	size_t                         dlen;
	u_char                        *payload;
	int                            is_retry;
	u_char                        *flat;
	size_t                         flat_sz;
	xrdp_pg_bad_t                  bad_pages[kXR_pgMaxEpr];
	size_t                         bad_count;
} pgw_state_t;

void pgw_fmt_detail(char *buf, size_t bufsz, int64_t offset, size_t len);

/* Error handling helpers */
int pgwrite_handle_write_error(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, const char *ioerr, ngx_int_t *rc);
int pgwrite_handle_short_write(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, size_t written, ngx_int_t *rc);

/* Metrics and tracking helpers */
void pgwrite_update_metrics(brix_ctx_t *ctx, int idx, size_t total_written);
void pgwrite_mark_dirty_if_needed(brix_ctx_t *ctx, ngx_int_t idx,
    int64_t offset, size_t len, int wt_enabled);
void pgwrite_log_success(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, size_t total_written);

/* Cleanup and journal helpers */
void pgwrite_cleanup_retry_fob(brix_ctx_t *ctx, ngx_int_t idx,
    int is_retry, size_t bad_count, int64_t offset, size_t flat_sz);
void pgwrite_record_journal(brix_ctx_t *ctx, ngx_int_t idx,
    int64_t offset, size_t nw, int wrts_enabled);

/* Reply helper */
ngx_int_t pgwrite_send_reply(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st);
