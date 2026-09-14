/*
 * pgwrite_helpers.c — Helper functions for kXR_pgwrite synchronous execution.
 * 
 * These helpers decompose the 113-line pgwrite_execute_sync() function into
 * focused, single-responsibility functions for better testability and readability.
 */

#include "pgwrite_helpers.h"
#include "pgw_fob.h"
#include "wrts_journal.h"
#include "fs/cache/writethrough_metrics.h"

/* pgw_fmt_detail()
 * WHAT: Format the "<offset>+<len>" access-log/error detail string used by every
 *       pgwrite reply path.
 * WHY:  The parse, decode and completion paths must use identical detail bytes.
 * HOW:  1. Format into the caller-owned buffer with a bounded snprintf. */
void
pgw_fmt_detail(char *buf, size_t bufsz, int64_t offset, size_t len)
{
	snprintf(buf, bufsz, "%lld+%zu", (long long) offset, len);
}

/*
 * pgwrite_handle_write_error — handle I/O error from pwrite()
 * WHAT: Logs error access event, increments error metric, sends kXR_IOError response.
 * WHY: Centralizes error handling for consistent logging and metrics.
 * HOW: Formats detail string, logs via brix_log_access(), calls BRIX_OP_ERR(),
 *      sends error response via brix_send_error().
 *
 * Returns 1 (response sent).
 */
int
pgwrite_handle_write_error(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    const char *ioerr, ngx_int_t *rc)
{
	char write_detail[64];

	pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset, st->flat_sz);
	brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
	                  write_detail, 0, kXR_IOError, ioerr, 0);
	BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
	*rc = brix_send_error(ctx, c, kXR_IOError, ioerr);
	return 1;
}

/*
 * pgwrite_handle_short_write — handle short write (disk full)
 * WHAT: Logs short write error, sends kXR_IOError response.
 * WHY: Separate helper for short write case (different from I/O error).
 * HOW: Formats detail with bytes written, logs, sends error response.
 *
 * Returns 1 (response sent).
 */
int
pgwrite_handle_short_write(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    size_t written, ngx_int_t *rc)
{
	char write_detail[64];

	pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset, written);
	brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
	                  write_detail, 0, kXR_IOError,
	                  "short write (disk full?)", 0);
	BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
	*rc = brix_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
	return 1;
}

/*
 * pgwrite_update_metrics — update write metrics and charge bandwidth
 * WHAT: Updates per-file and total bytes_written, charges rate limiter.
 * WHY: Centralizes metrics updates for consistency and testability.
 * HOW: Adds to ctx->files[idx].bytes_written and ctx->totals.bytes_written,
 *      calls brix_rl_charge_ctx() for Phase 25 bandwidth accounting.
 */
void
pgwrite_update_metrics(brix_ctx_t *ctx, int idx, size_t total_written)
{
	ctx->files[idx].bytes_written += total_written;
	ctx->totals.bytes_written   += total_written;
	brix_rl_charge_ctx(ctx, total_written);
}

/*
 * pgwrite_mark_dirty_if_needed — mark file dirty for write-through cache
 * WHAT: Marks file dirty when write-through is enabled.
 * WHY: Isolates write-through dirty tracking logic.
 * HOW: Calls brix_wt_mark_dirty() with the written range.
 */
void
pgwrite_mark_dirty_if_needed(brix_ctx_t *ctx, ngx_int_t idx, int64_t offset,
    size_t len, int wt_enabled)
{
	if (wt_enabled) {
		brix_wt_mark_dirty(ctx, idx, offset + (int64_t) len - 1, len);
	}
}

/*
 * pgwrite_log_success — log successful write access
 * WHAT: Logs successful write access event if access_log is configured.
 * WHY: Centralizes access logging for consistency.
 * HOW: Formats detail string, logs via brix_log_access() with success flag.
 */
void
pgwrite_log_success(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    size_t total_written)
{
	char write_detail[64];

	if (st->rconf->access_log_fd != NGX_INVALID_FILE) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
		               total_written);
		brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
		                  write_detail, 1, 0, NULL, total_written);
	}
}

/*
 * pgwrite_cleanup_retry_fob — clean up Fob entry for successful retry
 * WHAT: Removes Fob entry if this was a successful retry with no bad pages.
 * WHY: Isolates retry cleanup logic from main write path.
 * HOW: Calls brix_pgw_fob_del() when is_retry && bad_count == 0.
 */
void
pgwrite_cleanup_retry_fob(brix_ctx_t *ctx, ngx_int_t idx, int is_retry,
    size_t bad_count, int64_t offset, size_t flat_sz)
{
	if (is_retry && bad_count == 0) {
		brix_pgw_fob_del(&ctx->files[idx], offset, (uint32_t) flat_sz);
	}
}

/*
 * pgwrite_record_journal — record write in recovery journal
 * WHAT: Records committed write in the write recovery journal.
 * WHY: Isolates journal recording for testability.
 * HOW: Calls brix_wrts_record() when journal is enabled.
 */
void
pgwrite_record_journal(brix_ctx_t *ctx, ngx_int_t idx, int64_t offset,
    size_t nw, int wrts_enabled)
{
	if (wrts_enabled) {
		brix_wrts_record(&ctx->files[idx], offset, (uint32_t) nw);
	}
}

/*
 * pgwrite_send_reply — send CSE or status reply
 * WHAT: Sends kXR_status reply — CSE retransmit list if bad pages, else status.
 * WHY: Centralizes reply logic for clarity.
 * HOW: Calls brix_send_pgwrite_cse() or brix_send_pgwrite_status().
 *
 * Returns the result of the send function.
 */
ngx_int_t
pgwrite_send_reply(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st)
{
	if (st->bad_count > 0) {
		return brix_send_pgwrite_cse(ctx, c, st->offset, st->bad_pages,
		                              st->bad_count);
	}
	return brix_send_pgwrite_status(ctx, c, st->offset);
}
