#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"

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
 * the two paths must be kept contract-identical. */
ngx_int_t
brix_handle_writev(brix_ctx_t *ctx, ngx_connection_t *c)
{
	xrdw_writev_req_t    req;
	write_list          *wl;
	size_t               n_segs, i;
	uint64_t             total_wlen;
	const u_char        *data_ptr;
	size_t               bytes_written_total = 0;
	int                  do_sync;

	xrdw_writev_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	do_sync = (req.options & kXR_wv_doSync) ? 1 : 0;

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

	wl     = (write_list *) ctx->recv.payload;
	n_segs = ctx->recv.cur_dlen / BRIX_WRITEV_SEGSIZE;

	/* Stock parity: vector count cap (stock maxWvecsz == 1024 == ours). */
	if (n_segs > BRIX_WRITEV_MAXSEGS) {
		BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
		(void) brix_send_error(ctx, c, kXR_ArgTooLong,
								 "Write vector is too long");
		return NGX_ERROR;
	}

	total_wlen = 0;
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
		return brix_send_ok(ctx, c, NULL, 0);
	}

	/* INVARIANT: validate every targeted handle up front so a bad handle in a
	 * later segment can never leave earlier segments already written (all-or-
	 * nothing admission). Only fhandle[0] is significant — handles are 0..255. */
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

	/* All N descriptors occupy the first n_segs*16 bytes; the per-segment data
	 * blocks follow contiguously in segment order from here. */
	data_ptr = ctx->recv.payload + n_segs * BRIX_WRITEV_SEGSIZE;

	{
		ngx_stream_brix_srv_conf_t *conf;

		conf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

		if (conf->common.thread_pool != NULL) {
			ngx_thread_task_t        *task;
			brix_writev_aio_t      *t;
			brix_writev_seg_desc_t *seg_descs;
			ngx_flag_t                posted;
			const u_char             *dp = data_ptr;

			/* Flatten the wire descriptors into a self-contained array the
			 * worker thread can consume without touching ctx (which the main
			 * thread may mutate once we return). Decode all big-endian fields
			 * now, while we are still on the event-loop thread. */
			seg_descs = ngx_palloc(c->pool,
			                       n_segs * sizeof(brix_writev_seg_desc_t));
			if (seg_descs == NULL) {
				return NGX_ERROR;
			}

			for (i = 0; i < n_segs; i++) {
				uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);
				int      hidx = (int)(unsigned char) wl[i].fhandle[0];
				int64_t  off  = (int64_t) be64toh((uint64_t) wl[i].offset);

				seg_descs[i].fd         = ctx->files[hidx].fd;
				seg_descs[i].obj        = ctx->files[hidx].sd_obj; /* Layer 3 */
				seg_descs[i].handle_idx = hidx;
				seg_descs[i].offset     = (off_t) off;
				seg_descs[i].data       = dp;   /* points into payload_buf */
				seg_descs[i].wlen       = wlen;

				/* write-recovery (kXR_recoverWrts): if this byte range was
				 * already durably written before the connection dropped, it is
				 * a client replay. Neutralise it to a no-op by zeroing wlen;
				 * the worker thread treats wlen == 0 as "skip" so the bytes are
				 * neither rewritten nor double-counted. */
				if (ctx->files[hidx].wrts_enabled &&
				    brix_wrts_is_replay(&ctx->files[hidx], off, wlen))
				{
					ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
					    "brix: writev AIO recovery replay skip"
					    " offset=%lld len=%u", (long long) off, wlen);
					seg_descs[i].wlen = 0;
				}

				/* Advance over the (original, un-zeroed) data block so dp stays
				 * aligned with the wire layout regardless of replay skipping. */
				dp += wlen;
			}

			task = ngx_thread_task_alloc(c->pool, sizeof(brix_writev_aio_t));
			if (task == NULL) {
				return NGX_ERROR;
			}

			t = task->ctx;
			t->c           = c;
			t->ctx         = ctx;
			t->n_segs      = n_segs;
			t->segs        = seg_descs;
			t->payload_buf = ctx->recv.payload_buf;  /* transfer ownership */
			t->do_sync     = do_sync;
			t->bytes_total = 0;
			t->io_error    = 0;
			t->streamid[0] = ctx->recv.cur_streamid[0];
			t->streamid[1] = ctx->recv.cur_streamid[1];

			brix_task_bind(task, brix_writev_write_aio_thread, brix_writev_write_aio_done);

			(void) brix_aio_post_task(ctx, c, conf->common.thread_pool, task,
			    "brix: thread_task_post failed, falling back to sync writev",
			    &posted);
			/* posted == 1: ownership of payload_buf now lives on the task and
			 * the done callback will free it and send the reply. Detach it from
			 * ctx so the main thread can start the next request without racing
			 * the worker or double-freeing the buffer. posted == 0: posting
			 * failed; payload_buf is still ours and we fall through to the
			 * synchronous path below using the original data_ptr. */
			if (posted) {
				ctx->recv.payload         = NULL;
				ctx->recv.payload_buf     = NULL;
				ctx->recv.payload_buf_size = 0;
				return NGX_OK;
			}
		}
	}

	/* Synchronous fallback: write each segment on the event-loop thread. */
	for (i = 0; i < n_segs; i++) {
		int      idx    = (int)(unsigned char) wl[i].fhandle[0];
		int64_t  offset = (int64_t) be64toh((uint64_t) wl[i].offset);  /* BE64 */
		uint32_t wlen   = (uint32_t) ntohl((uint32_t) wl[i].wlen);     /* BE32 */
		ssize_t  nw;

		/* Empty segment carries no data block; nothing to advance over. */
		if (wlen == 0) {
			continue;
		}

		/* kXR_recoverWrts replay detection		 * Same replay handling as the AIO path: a range already written on a
		 * prior (dropped) connection is acknowledged as success but not
		 * re-issued to disk. data_ptr must still skip this segment's bytes to
		 * stay aligned, and we count the bytes toward the client-visible total
		 * so the reply matches what the client thinks it sent. */
		if (ctx->files[idx].wrts_enabled &&
		    brix_wrts_is_replay(&ctx->files[idx], offset, wlen))
		{
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "brix: writev recovery replay skip offset=%lld len=%u",
			    (long long) offset, wlen);
			bytes_written_total += (size_t) wlen;
			data_ptr += wlen;
			continue;
		}

		{
			brix_vfs_job_t job;

			brix_vfs_job_write_init(&job, ctx->files[idx].fd,
									  (off_t) offset, data_ptr, (size_t) wlen);
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
		bytes_written_total            += (size_t) nw;
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
		data_ptr                       += wlen;
	}

	/* kXR_wv_doSync: flush each handle that actually received data. Re-decode
	 * wlen from the wire to skip zero-length segments; a handle may appear in
	 * several segments but fsync is idempotent so duplicates are harmless. */
	if (do_sync) {
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

	{
		ngx_stream_brix_srv_conf_t *rconf;
		char                          detail[64];

		rconf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
		if (rconf->access_log_fd != NGX_INVALID_FILE) {
			snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
			brix_log_access(ctx, c, "WRITEV", "-", detail, 1, 0, NULL,
			                  bytes_written_total);
		}
	}
	BRIX_OP_OK(ctx, BRIX_OP_WRITEV);
	return brix_send_ok(ctx, c, NULL, 0);
}
