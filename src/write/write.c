/*
 * write.c — kXR_write opcode handler.
 *
 * This file implements the standard XRootD write operation: client sends data,
 * server writes it to a local file at the specified offset. The flow is:
 *   1. Validate that the requested file handle is open and writable
 *   2. If thread pool available → post async pwrite task (non-blocking)
 *   3. Otherwise → synchronously write from recv buffer to disk
 *   4. Track bytes written for access-log throughput calculation
 *   5. Return kXR_ok response to client
 */

/* ---- Write-through dirty state tracking section ----
 *
 * This is the core of the Policy File Cache (PFC) write-back feature.
 * When wt_enabled = 1, every write increments two counters:
 *   - wt_bytes_written: cumulative total for session metrics reporting
 *   - wt_dirty_offset: highest offset that hasn't been flushed to origin yet
 *
 * These values are retained for a future close-time write-back implementation.
 * At close time, if wt_dirty_offset > -1 (dirty data exists), the flush handler
 * propagates those bytes back to an origin XRootD server before closing the handle.
 */

/* ---- AIO (Async I/O) section ----
 *
 * When nginx has a thread pool configured, writes are posted to background threads
 * so the main event loop doesn't block on disk I/O. The payload buffer is detached
 * from ctx->payload_buf and freed in the completion callback. This allows the main
 * thread to continue reading the next request header while write happens elsewhere. */

/* ---- Synchronous fallback section ----
 *
 * When no thread pool is configured OR queue is full, writes happen synchronously
 * on the main event loop thread using pwrite() directly from the recv buffer.
 * This ensures writes always succeed even under degraded conditions. */

/* ---- Function: xrootd_handle_write() ----
 *
 * WHAT: Protocol-level kXR_write handler — validates write handle (must be open and writable), handles zero-length writes as valid no-ops, dispatches to AIO thread pool when configured (pwrite in worker thread with detached payload buffer), falls back to synchronous inline pwrite on main event loop. Tracks bytes written for access-log throughput calculation and PFC write-through dirty state tracking (wt_bytes_written + wt_dirty_offset for future close-time origin flush). Access-log detail format: "<offset>+<requested-bytes>".
 *
 * WHY: AIO dispatch detaches the payload buffer from ctx->payload_buf so the main thread can safely begin reading the next request header while write happens in a worker thread. PFC write-through dirty state tracking accumulates wt_bytes_written and wt_dirty_offset for future close-time origin propagation — mirroring XrdPfcFile::m_bytesWritten, m_dirtyOffset semantics. Short-write detection catches disk-full conditions before silently truncating client data. */

#include "ngx_xrootd_module.h"
#include "cache/writethrough_metrics.h"
#include "wrts_journal.h"

/*
 * xrootd_handle_write — handle kXR_write: write the request payload to an
 * open file at the specified offset.
 *
 * Wire format (from ClientWriteRequest):
 *   fhandle[4]: open file handle (first byte is the slot index)
 *   offset:     big-endian int64 file position
 *   dlen:       payload byte count (ctx->cur_dlen, already received)
 *
 * When a thread pool is configured, the pwrite is posted asynchronously and
 * the payload buffer is detached from ctx->payload_buf so the main thread can
 * safely begin reading the next request header.  The done callback frees the
 * detached buffer and sends the kXR_ok response.
 *
 * Falls back to synchronous pwrite if no thread pool is configured or the
 * thread pool queue is full.
 *
 * Access-log detail: "<offset>+<requested-bytes>"
 */
ngx_int_t
xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
	ClientWriteRequest           *req  = (ClientWriteRequest *) ctx->hdr_buf;
	int     idx    = (int)(unsigned char) req->fhandle[0];
	int64_t offset = (int64_t) be64toh((uint64_t) req->offset);
	size_t  wlen   = ctx->cur_dlen;
	ngx_int_t rc;
	ssize_t nwritten;
	char    write_detail[64];

	if (!xrootd_validate_write_handle(ctx, c, idx, "WRITE",
									  XROOTD_OP_WRITE, &rc)) {
		return rc;
	}

	if (wlen == 0) {
		/* Zero-length writes are valid no-ops that still count as successful requests. */
		XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
		return xrootd_send_ok(ctx, c, NULL, 0);
	}

	/*
	 * Phase-42 W5: inline write decompression (opt-in, off by default).  Routed
	 * to its own isolated synchronous handler so EVERYTHING below — the AIO write
	 * fast path and the write-recovery journal — stays byte-identical for the
	 * default (write_codec == 0) case.  pgwrite/writev have their own handlers and
	 * never reach here, so their plaintext + per-page CRC32c invariant is kept.
	 */
	if (ctx->files[idx].write_codec != 0) {
		return xrootd_write_compressed(ctx, c, idx, offset, wlen);
	}

	/* ---- kXR_recoverWrts replay detection ----
	 *
	 * If the journal already covers this (offset, wlen) range, this is a
	 * replayed write from a recovering XrdCl client.  The bytes are already
	 * on disk — skip pwrite() and return kXR_ok so the client can advance.
	 */
	if (ctx->files[idx].wrts_enabled &&
	    xrootd_wrts_is_replay(&ctx->files[idx], offset, (uint32_t) wlen))
	{
		ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
		    "xrootd: write recovery replay skip offset=%L len=%uz",
		    offset, wlen);
		XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
		return xrootd_send_ok(ctx, c, NULL, 0);
	}

	{
	ngx_flag_t posted;

	rc = xrootd_try_post_write_aio(ctx, c, idx, (off_t) offset,
								   ctx->payload ? ctx->payload : (u_char *) "",
								   wlen, offset, 0, ctx->payload, NULL, 0,
								   "xrootd: thread_task_post failed, falling back to sync write",
								   &posted);
	if (rc != NGX_OK) {
		return rc;
	}
	if (posted) {
		ctx->payload = NULL;
		ctx->payload_buf = NULL;
		ctx->payload_buf_size = 0;
		/*
		 * Write pipelining: account this pwrite as in-flight.  The recv loop
		 * (which sees state == XRD_ST_AIO on return) keeps receiving the next
		 * write while this one runs, bounded by out_count + wr_inflight <
		 * ctx->pipeline_depth.  xrootd_write_aio_done decrements wr_inflight and
		 * queues the ack asynchronously (no recv suspend).
		 */
		ctx->wr_inflight++;
		return NGX_OK;
	}
	} /* end NGX_THREADS block */


	/* Synchronous fallback writes the request payload directly from the recv buffer. */
	nwritten = pwrite(ctx->files[idx].fd,
					  ctx->payload ? ctx->payload : (u_char *) "",
					  wlen, (off_t) offset);

	/* Access log detail format for writes is "<offset>+<requested-bytes>". */
	snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
			 (long long) offset, wlen);

	if (nwritten < 0) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, strerror(errno));
	}

	if ((size_t) nwritten < wlen) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, "short write (disk full?)");
	}

	ctx->files[idx].bytes_written  += (size_t) nwritten;
	ctx->session_bytes_written     += (size_t) nwritten;
	xrootd_rl_charge_ctx(ctx, (size_t) nwritten);  /* Phase 25 bandwidth */

	if (ctx->files[idx].dashboard_slot >= 0 &&
	    ngx_xrootd_dashboard_shm_zone != NULL)
	{
		xrootd_transfer_slot_update(ngx_xrootd_dashboard_shm_zone->data,
		                            ctx->files[idx].dashboard_slot,
		                            (ngx_atomic_int_t) nwritten,
		                            (int64_t) ngx_current_msec);
		xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
		                              ctx->files[idx].dashboard_slot,
		                              "write");
	}

	/* ---- write-through dirty state tracking (mirrors XrdPfcFile::m_bytesWritten, m_dirtyOffset) ----
	 *
	 * When wt_enabled = 1 this handle has a cached DECISION to propagate writes
	 * back to the origin at close time. We track:
	 *   - wt_bytes_written: cumulative bytes since last sync point (for metrics)
	 *   - wt_dirty_offset:  offset of most recent write that hasn't been flushed yet
	 *
	 * These fields are retained for a future close-time write-back implementation.
	 */
	if (ctx->files[idx].wt_enabled) {
		xrootd_wt_mark_dirty(ctx, idx,
		                      offset + (int64_t) nwritten - 1,
		                      (size_t) nwritten);
	}

	/* Record the committed write in the recovery journal. */
	if (ctx->files[idx].wrts_enabled) {
		xrootd_wrts_record(&ctx->files[idx], offset, (uint32_t) nwritten);
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_WRITE, "WRITE",
					 ctx->files[idx].path, write_detail, (size_t) nwritten);
}

/* ---- HOW: Extracts idx from req->fhandle[0], offset from be64toh(req->offset), wlen from ctx->cur_dlen. Validates write handle via xrootd_validate_write_handle() — returns early on failure. Zero-length writes return kXR_ok immediately as valid no-ops. NGX_THREADS block: calls xrootd_try_post_write_aio() with detached payload; if posted=1 sets ctx->payload=NULL and returns NGX_OK (completion callback sends response); if posted=0 falls through to sync write. Synchronous fallback: pwrite(fd, payload, wlen, offset) inline. Logs access detail "<offset>+<wlen>". On negative nwritten returns kXR_IOError; on short write (<wlen) returns kXR_IOError with "disk full?" message. Updates bytes_written counters (file+session). If wt_enabled updates wt_bytes_written and wt_dirty_offset for PFC write-through tracking. Returns XROOTD_RETURN_OK. */
