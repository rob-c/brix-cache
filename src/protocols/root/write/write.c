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

/* Write-through dirty state tracking section
 * This is the core of the Policy File Cache (PFC) write-back feature.
 * When wt_enabled = 1, every write increments two counters:
 *   - wt_bytes_written: cumulative total for session metrics reporting
 *   - wt_dirty_offset: highest offset that hasn't been flushed to origin yet
 *
 * These values are retained for a future close-time write-back implementation.
 * At close time, if wt_dirty_offset > -1 (dirty data exists), the flush handler
 * propagates those bytes back to an origin XRootD server before closing the handle.
 */

/* AIO (Async I/O) section
 * When nginx has a thread pool configured, writes are posted to background threads
 * so the main event loop doesn't block on disk I/O. The payload buffer is detached
 * from ctx->recv.payload_buf and freed in the completion callback. This allows the main
 * thread to continue reading the next request header while write happens elsewhere. */

/* Synchronous fallback section
 * When no thread pool is configured OR queue is full, writes happen synchronously
 * on the main event loop thread using pwrite() directly from the recv buffer.
 * This ensures writes always succeed even under degraded conditions. */

/*
 *
 * WHAT: Protocol-level kXR_write handler — validates write handle (must be open and writable), handles zero-length writes as valid no-ops, dispatches to AIO thread pool when configured (pwrite in worker thread with detached payload buffer), falls back to synchronous inline pwrite on main event loop. Tracks bytes written for access-log throughput calculation and PFC write-through dirty state tracking (wt_bytes_written + wt_dirty_offset for future close-time origin flush). Access-log detail format: "<offset>+<requested-bytes>".
 *
 * WHY: AIO dispatch detaches the payload buffer from ctx->recv.payload_buf so the main thread can safely begin reading the next request header while write happens in a worker thread. PFC write-through dirty state tracking accumulates wt_bytes_written and wt_dirty_offset for future close-time origin propagation — mirroring XrdPfcFile::m_bytesWritten, m_dirtyOffset semantics. Short-write detection catches disk-full conditions before silently truncating client data. */

#include "core/ngx_brix_module.h"
#include "protocols/ssi/ssi.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"

/*
 * brix_write_desc_t — the decoded kXR_write request parameters, bundled so the
 * write-stage helpers stay within the ≤5-parameter budget without adding globals.
 * idx/offset/wlen mirror the wire fields; hdrbody points at the request body for
 * the SSI raw-offset reinterpretation.
 */
typedef struct {
	int           idx;      /* file-handle slot index (fhandle[0]) */
	int64_t       offset;   /* big-endian int64 write offset */
	size_t        wlen;     /* payload byte count (ctx->recv.cur_dlen) */
	const u_char *hdrbody;  /* request header body (for SSI raw offset bytes) */
} brix_write_desc_t;

/*
 * brix_write_route_special — dispatch a validated write handle to its
 * non-standard early-return path (SSI accumulate, zero-length no-op, whole-object
 * staged commit, inline write-decompression, or recovery-journal replay skip)
 * before the default AIO/sync fast path runs.
 *
 * WHAT: Checks, in wire order, every condition that must short-circuit
 *   brix_handle_write. On a match it performs the matching action and writes the
 *   handler return code to *out_rc, returning 1 (handled). Returns 0 when the
 *   handle takes the normal file-write path (out_rc untouched).
 * WHY:  Factoring these mutually-exclusive early returns out of brix_handle_write
 *   keeps the hot AIO/sync body — and its CCN — small while preserving the exact
 *   ordering and behavior of every special case.
 * HOW:  Ordered guards on ctx->files[idx] state (ssi / wlen==0 / staged /
 *   write_codec / wrts replay); each mirrors the original inline block verbatim.
 */
static ngx_flag_t
brix_write_route_special(brix_ctx_t *ctx, ngx_connection_t *c,
						  const brix_write_desc_t *w, ngx_int_t *out_rc)
{
	int idx = w->idx;

	/* §7 XrdSsi: an SSI handle accumulates the request body (no fd write). The
	 * write offset carries an XrdSsiRRInfo (raw big-endian bytes). Clean
	 * early-return — the normal write path below is unchanged for file handles. */
	if (ctx->files[idx].ssi != NULL) {
		BRIX_OP_OK(ctx, BRIX_OP_WRITE);
		/* SSI reinterprets the offset field as a raw big-endian XrdSsiRRInfo;
		 * pass the wire bytes (offset field = body byte 4), not the decoded int. */
		*out_rc = brix_ssi_write(ctx, c, idx, w->hdrbody + 4);
		return 1;
	}

	if (w->wlen == 0) {
		/* Zero-length writes are valid no-ops that still count as successful requests. */
		BRIX_OP_OK(ctx, BRIX_OP_WRITE);
		*out_rc = brix_send_ok(ctx, c, NULL, 0);
		return 1;
	}

	/* Whole-object staged-commit adapter (phase-70): this handle writes to a
	 * backend with no random write, so the block is APPENDED to a VFS staged
	 * handle at the running offset and the object is PUT whole on sync/close.
	 * Isolated early-return keeps the AIO/journal/wt fast path below unchanged. */
	if (ctx->files[idx].staged != NULL) {
		*out_rc = brix_write_staged(ctx, c, idx, w->offset, w->wlen);
		return 1;
	}

	/*
	 * Phase-42 W5: inline write decompression (opt-in, off by default).  Routed
	 * to its own isolated synchronous handler so EVERYTHING below — the AIO write
	 * fast path and the write-recovery journal — stays byte-identical for the
	 * default (write_codec == 0) case.  pgwrite/writev have their own handlers and
	 * never reach here, so their plaintext + per-page CRC32c invariant is kept.
	 */
	if (ctx->files[idx].write_codec != 0) {
		*out_rc = brix_write_compressed(ctx, c, idx, w->offset, w->wlen);
		return 1;
	}

	/* kXR_recoverWrts replay detection
	 * If the journal already covers this (offset, wlen) range, this is a
	 * replayed write from a recovering XrdCl client.  The bytes are already
	 * on disk — skip pwrite() and return kXR_ok so the client can advance.
	 */
	if (ctx->files[idx].wrts_enabled &&
	    brix_wrts_is_replay(&ctx->files[idx], w->offset, (uint32_t) w->wlen))
	{
		ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
		    "brix: write recovery replay skip offset=%L len=%uz",
		    w->offset, w->wlen);
		BRIX_OP_OK(ctx, BRIX_OP_WRITE);
		*out_rc = brix_send_ok(ctx, c, NULL, 0);
		return 1;
	}

	return 0;
}

/*
 * brix_write_finalize_sync — commit the accounting and journaling side effects
 * of a completed synchronous pwrite and return the client response.
 *
 * WHAT: Given the byte count returned by the inline pwrite, emits the kXR error
 *   response on failure (negative / short write) or, on success, updates the
 *   file+session byte counters, bandwidth charge, dashboard slot, write-through
 *   dirty state and recovery journal, then returns the kXR_ok response.
 * WHY:  Splitting the post-write bookkeeping out of brix_handle_write keeps the
 *   handler's cyclomatic complexity and length within budget while leaving every
 *   counter update, error path and return code byte-identical.
 * HOW:  Mirrors the original inline tail verbatim; BRIX_RETURN_ERR / BRIX_RETURN_OK
 *   expand to a return, so this helper's return value is the handler's return.
 */
static ngx_int_t
brix_write_finalize_sync(brix_ctx_t *ctx, ngx_connection_t *c,
						 const brix_write_desc_t *w, ssize_t nwritten,
						 const char *write_detail)
{
	int     idx    = w->idx;
	int64_t offset = w->offset;

	if (nwritten < 0) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, strerror(errno));
	}

	if ((size_t) nwritten < w->wlen) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, "short write (disk full?)");
	}

	ctx->files[idx].bytes_written  += (size_t) nwritten;
	ctx->totals.bytes_written     += (size_t) nwritten;
	brix_rl_charge_ctx(ctx, (size_t) nwritten);  /* Phase 25 bandwidth */

	if (ctx->files[idx].dashboard_slot >= 0 &&
	    ngx_brix_dashboard_shm_zone != NULL)
	{
		brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
		                            ctx->files[idx].dashboard_slot,
		                            (ngx_atomic_int_t) nwritten,
		                            (int64_t) ngx_current_msec);
		brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
		                              ctx->files[idx].dashboard_slot,
		                              "write");
	}

	/* write-through dirty state tracking (mirrors XrdPfcFile::m_bytesWritten, m_dirtyOffset)
	 * When wt_enabled = 1 this handle has a cached DECISION to propagate writes
	 * back to the origin at close time. We track:
	 *   - wt_bytes_written: cumulative bytes since last sync point (for metrics)
	 *   - wt_dirty_offset:  offset of most recent write that hasn't been flushed yet
	 *
	 * These fields are retained for a future close-time write-back implementation.
	 */
	if (ctx->files[idx].wt_enabled) {
		brix_wt_mark_dirty(ctx, idx,
		                      offset + (int64_t) nwritten - 1,
		                      (size_t) nwritten);
	}

	/* Record the committed write in the recovery journal. */
	if (ctx->files[idx].wrts_enabled) {
		brix_wrts_record(&ctx->files[idx], offset, (uint32_t) nwritten);
	}

	BRIX_RETURN_OK(ctx, c, BRIX_OP_WRITE, "WRITE",
					 ctx->files[idx].path, write_detail, (size_t) nwritten);
}

/*
 * brix_handle_write — handle kXR_write: write the request payload to an
 * open file at the specified offset.
 *
 * Wire format (from ClientWriteRequest):
 *   fhandle[4]: open file handle (first byte is the slot index)
 *   offset:     big-endian int64 file position
 *   dlen:       payload byte count (ctx->recv.cur_dlen, already received)
 *
 * When a thread pool is configured, the pwrite is posted asynchronously and
 * the payload buffer is detached from ctx->recv.payload_buf so the main thread can
 * safely begin reading the next request header.  The done callback frees the
 * detached buffer and sends the kXR_ok response.
 *
 * Falls back to synchronous pwrite if no thread pool is configured or the
 * thread pool queue is full.
 *
 * Access-log detail: "<offset>+<requested-bytes>"
 */
ngx_int_t
brix_handle_write(brix_ctx_t *ctx, ngx_connection_t *c)
{
	const u_char *hdrbody = ((ClientRequestHdr *) ctx->recv.hdr_buf)->body;
	xrdw_write_req_t req;
	int     idx;
	int64_t offset;
	size_t  wlen   = ctx->recv.cur_dlen;

	xrdw_write_req_unpack(hdrbody, &req);
	idx    = (int)(unsigned char) req.fhandle[0];
	offset = req.offset;
	ngx_int_t rc      = NGX_OK;
	ssize_t nwritten  = 0;
	char    write_detail[64];
	brix_write_desc_t w = { idx, offset, wlen, hdrbody };

	if (!brix_validate_write_handle(ctx, c, idx, "WRITE",
									  BRIX_OP_WRITE, &rc)) {
		return rc;
	}

	if (brix_write_route_special(ctx, c, &w, &rc)) {
		return rc;
	}

	{
	ngx_flag_t posted = 0;

	rc = brix_try_post_write_aio(ctx, c, idx, (off_t) offset,
								   ctx->recv.payload ? ctx->recv.payload : (u_char *) "",
								   wlen, offset, 0, ctx->recv.payload, NULL, 0,
								   "brix: thread_task_post failed, falling back to sync write",
								   &posted);
	if (rc != NGX_OK) {
		return rc;
	}
	if (posted) {
		ctx->recv.payload = NULL;
		ctx->recv.payload_buf = NULL;
		ctx->recv.payload_buf_size = 0;
		/*
		 * Write pipelining: account this pwrite as in-flight.  The recv loop
		 * (which sees state == XRD_ST_AIO on return) keeps receiving the next
		 * write while this one runs, bounded by out_count + wr_inflight <
		 * ctx->out.pipeline_depth.  brix_write_aio_done decrements wr_inflight and
		 * queues the ack asynchronously (no recv suspend).
		 */
		ctx->out.wr_inflight++;
		return NGX_OK;
	}
	} /* end NGX_THREADS block */


	/* Synchronous fallback writes the request payload directly from the recv buffer. */
	{
		brix_vfs_job_t job;

		brix_vfs_job_write_init(&job, ctx->files[idx].fd, (off_t) offset,
								  ctx->recv.payload ? ctx->recv.payload : (u_char *) "",
								  wlen);
		job.csi = ctx->files[idx].csi;   /* phase-59 W2: update page tags */
		brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
		brix_vfs_io_execute(&job);
		nwritten = job.nio;
		if (job.io_errno != 0) {
			errno = job.io_errno;
		}
	}

	/* Access log detail format for writes is "<offset>+<requested-bytes>". */
	snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
			 (long long) offset, wlen);

	return brix_write_finalize_sync(ctx, c, &w, nwritten, write_detail);
}

/* HOW: Extracts idx from req->fhandle[0], offset from be64toh(req->offset), wlen from ctx->recv.cur_dlen. Validates write handle via brix_validate_write_handle() — returns early on failure. Zero-length writes return kXR_ok immediately as valid no-ops. NGX_THREADS block: calls brix_try_post_write_aio() with detached payload; if posted=1 sets ctx->recv.payload=NULL and returns NGX_OK (completion callback sends response); if posted=0 falls through to sync write. Synchronous fallback: pwrite(fd, payload, wlen, offset) inline. Logs access detail "<offset>+<wlen>". On negative nwritten returns kXR_IOError; on short write (<wlen) returns kXR_IOError with "disk full?" message. Updates bytes_written counters (file+session). If wt_enabled updates wt_bytes_written and wt_dirty_offset for PFC write-through tracking. Returns BRIX_RETURN_OK. */
