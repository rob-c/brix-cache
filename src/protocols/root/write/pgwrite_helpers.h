#ifndef _PGWRITE_HELPERS_H_INCLUDED_
#define _PGWRITE_HELPERS_H_INCLUDED_

/*
 * pgwrite_helpers.h — Helper function declarations for kXR_pgwrite.
 * 
 * These helpers decompose pgwrite_execute_sync() into focused,
 * single-responsibility functions for better testability and readability.
 */

#include "write.h"

/* Error handling helpers */
static int pgwrite_handle_write_error(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, const char *ioerr, ngx_int_t *rc);
static int pgwrite_handle_short_write(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, size_t written, ngx_int_t *rc);

/* Metrics and tracking helpers */
static void pgwrite_update_metrics(brix_ctx_t *ctx, size_t total_written);
static void pgwrite_mark_dirty_if_needed(brix_ctx_t *ctx, ngx_int_t idx,
    int64_t offset, size_t len, int wt_enabled);
static void pgwrite_log_success(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, size_t total_written);

/* Cleanup and journal helpers */
static void pgwrite_cleanup_retry_fob(brix_ctx_t *ctx, ngx_int_t idx,
    int is_retry, size_t bad_count, int64_t offset, size_t flat_sz);
static void pgwrite_record_journal(brix_ctx_t *ctx, ngx_int_t idx,
    int64_t offset, size_t nw, int wrts_enabled);

/* Reply helper */
static ngx_int_t pgwrite_send_reply(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st);

#endif /* _PGWRITE_HELPERS_H_INCLUDED_ */
