#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"
#include "writev_internal.h"   /* writev_run_t + writev_try_aio (writev_aio.c) */

/* brix_writev_body_extra — trailing segment-data length for kXR_writev
 * WHAT: Validates a dlen-framed write_list descriptor block under the stock
 * wire contract (dlen frames ONLY the descriptors: non-zero, 16-aligned,
 * <= BRIX_WRITEV_MAXSEGS entries, descriptors + declared data within
 * BRIX_MAX_WRITE_PAYLOAD) and reports sum(wlen) — the number of segment-data
 * bytes the client streams after the request frame.
 * WHY: Shared by the recv framing (to extend the read obligation so the
 * streamed data lands in payload_buf before dispatch) and kept next to the
 * handler that consumes the same layout.  Also delegated to by
 * brix_ckpxeq_body_extra (chkpoint_xeq.c): a kXR_ckpXeq-embedded writev
 * tunnels this exact contract — its embedded header's dlen frames the
 * descriptors only, and the segment data streams behind.  Returns NGX_OK
 * with *extra set, or NGX_DECLINED when the block violates the contract (the
 * caller decides the error; the framing never rejects so the auth gates
 * still run first). */
ngx_int_t
brix_writev_body_extra(const u_char *desc, uint32_t dlen, uint32_t *extra)
{
	const write_list *wl = (const write_list *) desc;
	uint32_t          n_segs, i;
	uint64_t          total = 0;

	*extra = 0;

	if (desc == NULL || dlen == 0 || dlen % BRIX_WRITEV_SEGSIZE != 0) {
		return NGX_DECLINED;
	}

	n_segs = dlen / BRIX_WRITEV_SEGSIZE;
	if (n_segs > BRIX_WRITEV_MAXSEGS) {
		return NGX_DECLINED;
	}

	for (i = 0; i < n_segs; i++) {
		total += (uint32_t) ntohl((uint32_t) wl[i].wlen);
	}

	if ((uint64_t) dlen + total > BRIX_MAX_WRITE_PAYLOAD) {
		return NGX_DECLINED;
	}

	*extra = (uint32_t) total;
	return NGX_OK;
}

/* writev_validate_framing — enforce the stock do_WriteV framing contract.
 * WHAT: Validates the descriptor block that recv left in ctx->recv.payload —
 * dlen present and a whole number of 16-byte descriptors, segment count within
 * the vector cap, descriptors + declared data within the aggregate transfer
 * cap, and the recv-appended trailing byte count matching sum(wlen).  On
 * success it publishes the segment count (*n_segs_out) and total data length
 * (*total_wlen_out) to the caller.
 * WHY: This is the FROZEN stock-framing gate — the same contract the recv path
 * and the ckpXeq-embedded writev depend on.  Concentrating it here keeps the
 * handler flat and the wire-error parity (kXR error code + message + link drop)
 * byte-identical to the reference server.
 * HOW: Each violation emits its stock error via brix_send_error and returns
 * NGX_ERROR (caller drops the link — a doubtful descriptor block makes the
 * trailing byte count unknowable, so the connection cannot resynchronise).  An
 * all-zero-length vector is the stock immediate-success case: it sends OK and
 * returns NGX_DONE.  A clean, non-empty vector returns NGX_OK. */
static ngx_int_t
writev_validate_framing(brix_ctx_t *ctx, ngx_connection_t *c,
                        const write_list *wl, size_t *n_segs_out,
                        uint64_t *total_wlen_out)
{
	size_t   n_segs, i;
	uint64_t total_wlen = 0;

	*n_segs_out = 0;
	*total_wlen_out = 0;

	/* Stock parity: a dlen that is zero or not a whole number of write_list
	 * descriptors is "Write vector is invalid" (kXR_ArgInvalid) + link drop. */
	if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0
	    || ctx->recv.cur_dlen % BRIX_WRITEV_SEGSIZE != 0)
	{
		BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
		(void) brix_send_error(ctx, c, kXR_ArgInvalid,
								 "Write vector is invalid");
		return NGX_ERROR;
	}

	n_segs = ctx->recv.cur_dlen / BRIX_WRITEV_SEGSIZE;

	/* Stock parity: vector count cap (stock maxWvecsz == 1024 == ours). */
	if (n_segs > BRIX_WRITEV_MAXSEGS) {
		BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
		(void) brix_send_error(ctx, c, kXR_ArgTooLong,
								 "Write vector is too long");
		return NGX_ERROR;
	}

	for (i = 0; i < n_segs; i++) {
		total_wlen += (uint32_t) ntohl((uint32_t) wl[i].wlen);
	}

	/* Our aggregate transfer cap (stock instead caps each element at its
	 * maxTransz); enforced by the framing BEFORE it reads the data, so a
	 * violation means the trailing bytes were never accepted — drop. */
	if ((uint64_t) ctx->recv.cur_dlen + total_wlen > BRIX_MAX_WRITE_PAYLOAD) {
		BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
		(void) brix_send_error(ctx, c, kXR_NoMemory,
								 "writev transfer is too large");
		return NGX_ERROR;
	}

	/* Defensive: the recv framing extends the body by exactly sum(wlen); a
	 * mismatch means the extension never ran for this frame (unreachable in
	 * normal operation) and the data bytes are not in the buffer. */
	if (total_wlen != (uint64_t) ctx->recv.cur_body_extra) {
		BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
		(void) brix_send_error(ctx, c, kXR_ArgInvalid,
								 "Write vector is invalid");
		return NGX_ERROR;
	}

	/* Stock parity: an all-zero-length vector succeeds immediately, before
	 * any handle validation (do_WriteV returns Send() when maxSZ == 0). */
	if (total_wlen == 0) {
		BRIX_OP_OK(ctx, BRIX_OP_WRITEV);
		(void) brix_send_ok(ctx, c, NULL, 0);
		return NGX_DONE;
	}

	*n_segs_out = n_segs;
	*total_wlen_out = total_wlen;
	return NGX_OK;
}

/* writev_validate_handles — all-or-nothing handle admission for the vector.
 * WHAT: Verifies every segment's target handle is open and writable before any
 * byte is written.
 * WHY: INVARIANT — a bad handle in a later segment must never leave earlier
 * segments already written; admitting the whole vector up front makes the write
 * all-or-nothing.  Only fhandle[0] is significant (handles are 0..255).
 * HOW: Returns NGX_OK when every handle passes.  On the first failure it emits
 * the stock error (kXR_FileNotOpen for a stale/closed slot, kXR_NotAuthorized
 * for a read-only handle) and returns its brix_send_error result for the caller
 * to propagate unchanged. */
static ngx_int_t
writev_validate_handles(brix_ctx_t *ctx, ngx_connection_t *c,
                        const write_list *wl, size_t n_segs)
{
	size_t i;

	for (i = 0; i < n_segs; i++) {
		int idx = (int)(unsigned char) wl[i].fhandle[0];

		/* fd < 0 means the slot is closed/never-opened (stale handle). */
		if (idx < 0 || idx >= BRIX_MAX_FILES || ctx->files[idx].fd < 0) {
			BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
			return brix_send_error(ctx, c, kXR_FileNotOpen,
									 "invalid file handle in writev");
		}
		if (!ctx->files[idx].writable) {
			BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
			return brix_send_error(ctx, c, kXR_NotAuthorized,
									 "file not open for writing");
		}
	}

	return NGX_OK;
}

/* writev_write_segment — write one segment through the VFS on this thread.
 * WHAT: Handles a single (fd, offset, data, wlen) segment on the event-loop
 * thread: replay neutralisation, the VFS write, dirty-extent marking, and the
 * write-recovery journal update; accumulates the client-visible byte total and
 * advances *data_ptr past this segment's data block.
 * WHY: The synchronous fallback body per segment is a self-contained unit; the
 * loop that drives it stays flat and the replay/short-write parity lives in one
 * reviewable place.
 * HOW: Decodes the wire fields, returns NGX_OK for an empty or replayed segment
 * (already accounted, pointer advanced).  On I/O error it emits the stock error
 * via BRIX_RETURN_ERR (which returns brix_send_error's result) and propagates
 * it as NGX_ERROR so the caller stops the loop and drops the link; on success
 * it returns NGX_OK. */
static ngx_int_t
writev_write_segment(brix_ctx_t *ctx, ngx_connection_t *c,
                     const write_list *seg, const u_char **data_ptr,
                     size_t *bytes_written_total)
{
	int      idx    = (int)(unsigned char) seg->fhandle[0];
	int64_t  offset = (int64_t) be64toh((uint64_t) seg->offset);  /* BE64 */
	uint32_t wlen   = (uint32_t) ntohl((uint32_t) seg->wlen);     /* BE32 */
	ssize_t  nw;

	/* Empty segment carries no data block; nothing to advance over. */
	if (wlen == 0) {
		return NGX_OK;
	}

	/* Same replay handling as the AIO path: a range already written on a prior
	 * (dropped) connection is acknowledged as success but not re-issued to
	 * disk. data_ptr must still skip this segment's bytes to stay aligned, and
	 * we count the bytes toward the client-visible total so the reply matches
	 * what the client thinks it sent. */
	/* phase79-fp: security.ArrayBound — idx (0..255 from fhandle[0]) was already
	 * bounds-checked against BRIX_MAX_FILES by writev_validate_handles before the
	 * sync path runs; the analyzer cannot correlate the separate validation loop. */
	if (ctx->files[idx].wrts_enabled &&
	    brix_wrts_is_replay(&ctx->files[idx], offset, wlen))
	{
		ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
		    "brix: writev recovery replay skip offset=%lld len=%u",
		    (long long) offset, wlen);
		*bytes_written_total += (size_t) wlen;
		*data_ptr += wlen;
		return NGX_OK;
	}

	{
		brix_vfs_job_t job;

		brix_vfs_job_write_init(&job, ctx->files[idx].fd,
								  (off_t) offset, *data_ptr, (size_t) wlen);
		brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
		brix_vfs_io_execute(&job);
		nw = job.nio;
		if (job.io_errno != 0) {
			errno = job.io_errno;
		}
	}

	if (nw < 0) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITEV, "WRITEV",
						  ctx->files[idx].path, "-",
						  kXR_IOError, strerror(errno));
	}
	if ((uint32_t) nw < wlen) {
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITEV, "WRITEV",
						  ctx->files[idx].path, "-",
						  kXR_IOError, "short write (disk full?)");
	}

	ctx->files[idx].bytes_written  += (size_t) nw;
	ctx->totals.bytes_written     += (size_t) nw;
	*bytes_written_total           += (size_t) nw;
	/* write-through cache: flag the just-written extent dirty so it gets
	 * flushed to the backing store (end offset is inclusive: off+nw-1). */
	if (ctx->files[idx].wt_enabled) {
		brix_wt_mark_dirty(ctx, idx, offset + (int64_t) nw - 1,
		                      (size_t) nw);
	}
	/* write-recovery journal: remember this range so a later replay after
	 * reconnect is recognised by brix_wrts_is_replay() above. */
	if (ctx->files[idx].wrts_enabled) {
		brix_wrts_record(&ctx->files[idx], offset, (uint32_t) nw);
	}
	/* Advance by wlen (== nw here, short writes already errored out). */
	*data_ptr                      += wlen;
	return NGX_OK;
}

/* writev_execute_sync — synchronous fallback: write every segment in order.
 * WHAT: Iterates the vector, writing each segment on the event-loop thread and
 * accumulating the client-visible byte total.
 * WHY: Used when no thread pool is configured or the AIO post failed; keeps the
 * orchestrator flat by owning the segment loop.
 * HOW: Delegates each segment to writev_write_segment, propagating its NGX_ERROR
 * (already-sent I/O error, link drop) on the first failure; returns NGX_OK once
 * the whole vector is written. */
static ngx_int_t
writev_execute_sync(const writev_run_t *run, size_t *bytes_written_total)
{
	const u_char *data_ptr = run->data_ptr;
	size_t        i;

	for (i = 0; i < run->n_segs; i++) {
		ngx_int_t rc = writev_write_segment(run->ctx, run->c, &run->wl[i],
		                                    &data_ptr, bytes_written_total);
		if (rc != NGX_OK) {
			return rc;
		}
	}

	return NGX_OK;
}

/* writev_sync_handles — honour kXR_wv_doSync by flushing each written handle.
 * WHAT: fsyncs every handle that received data in this vector.
 * WHY: Completes the doSync contract after the synchronous writes land.
 * HOW: Re-decodes wlen from the wire to skip zero-length segments; a handle may
 * appear in several segments but fsync is idempotent so duplicates are harmless. */
static void
writev_sync_handles(brix_ctx_t *ctx, const write_list *wl, size_t n_segs)
{
	size_t i;

	for (i = 0; i < n_segs; i++) {
		int idx = (int)(unsigned char) wl[i].fhandle[0];
		if (ntohl((uint32_t) wl[i].wlen) > 0) {
			brix_vfs_job_t job;

			brix_vfs_job_sync_init(&job, ctx->files[idx].fd);
			brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
			brix_vfs_io_execute(&job);
		}
	}
}

/* writev_reply — access-log the completed vector and send the aggregate OK.
 * WHAT: Emits the access-log line (when access logging is enabled) and sends the
 * success reply for the synchronous path.
 * WHY: Keeps the log-format detail ("<n>_segs") and the metric/reply pairing in
 * one edge helper.
 * HOW: Looks up the server conf off c->data, formats the segment-count detail,
 * marks the op OK, and returns brix_send_ok's result unchanged. */
static ngx_int_t
writev_reply(brix_ctx_t *ctx, ngx_connection_t *c, size_t n_segs,
             size_t bytes_written_total)
{
	ngx_stream_brix_srv_conf_t *rconf;
	char                        detail[64];

	rconf = ngx_stream_get_module_srv_conf(
	    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
	if (rconf->access_log_fd != NGX_INVALID_FILE) {
		snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
		brix_log_access(ctx, c, "WRITEV", "-", detail, 1, 0, NULL,
		                  bytes_written_total);
	}

	BRIX_OP_OK(ctx, BRIX_OP_WRITEV);
	return brix_send_ok(ctx, c, NULL, 0);
}

/* Handle kXR_writev — scatter the request's data segments to their per-handle
 * (fd, offset) targets through the VFS write path, then reply with the aggregate
 * status.
 *
 * Wire contract (stock XrdXrootdProtocol::do_WriteV): the header dlen frames
 * ONLY the N*16-byte write_list descriptor block; the concatenated segment data
 * (sum(wlen) bytes) streams after the frame.  The recv framing has already
 * appended that trailing data to ctx->recv.payload (ctx->recv.cur_body_extra bytes), so
 * descriptors and data are contiguous here.  Framing violations are rejected
 * exactly like the reference server — send the error, then drop the link
 * (return NGX_ERROR): once the descriptor block is in doubt the trailing byte
 * count is unknowable and the connection cannot be resynchronised.
 *
 * The checkpoint-embedded form (kXR_ckpXeq carrying a writev — ckp_xeq_writev
 * in chkpoint_xeq.c) tunnels this SAME layout one level down: the embedded
 * sub-header's dlen frames the descriptors and the data streams behind, so
 * the two paths must be kept contract-identical.
 *
 * Orchestrator: validate framing → admit every handle → try the AIO offload
 * (returns early when posted) → synchronous per-segment write → optional
 * doSync flush → access-log + reply. */
ngx_int_t
brix_handle_writev(brix_ctx_t *ctx, ngx_connection_t *c)
{
	xrdw_writev_req_t    req;
	write_list          *wl;
	size_t               n_segs = 0;
	uint64_t             total_wlen = 0;
	const u_char        *data_ptr;
	size_t               bytes_written_total = 0;
	int                  do_sync;
	ngx_int_t            rc;
	ngx_flag_t           posted = 0;
	writev_run_t         run = { 0 };

	xrdw_writev_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	do_sync = (req.options & kXR_wv_doSync) ? 1 : 0;

	wl = (write_list *) ctx->recv.payload;

	rc = writev_validate_framing(ctx, c, wl, &n_segs, &total_wlen);
	if (rc == NGX_DONE) {
		return NGX_OK;   /* all-zero-length vector: OK already sent. */
	}
	if (rc != NGX_OK) {
		return rc;       /* framing violation: error sent, drop the link. */
	}

	rc = writev_validate_handles(ctx, c, wl, n_segs);
	if (rc != NGX_OK) {
		return rc;
	}

	/* All N descriptors occupy the first n_segs*16 bytes; the per-segment data
	 * blocks follow contiguously in segment order from here. */
	data_ptr = ctx->recv.payload + n_segs * BRIX_WRITEV_SEGSIZE;

	run.ctx      = ctx;
	run.c        = c;
	run.wl       = wl;
	run.n_segs   = n_segs;
	run.data_ptr = data_ptr;

	rc = writev_try_aio(&run, do_sync, &posted);
	if (rc != NGX_OK) {
		return rc;       /* allocation failure: drop the link. */
	}
	if (posted) {
		return NGX_OK;   /* done callback owns the buffer + reply. */
	}

	/* Synchronous fallback: write each segment on the event-loop thread. */
	rc = writev_execute_sync(&run, &bytes_written_total);
	if (rc != NGX_OK) {
		return rc;
	}

	if (do_sync) {
		writev_sync_handles(ctx, wl, n_segs);
	}

	return writev_reply(ctx, c, n_segs, bytes_written_total);
}
