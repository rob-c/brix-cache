// xrootd_handle_writev implementation.
#include "ngx_xrootd_module.h"


ngx_int_t
xrootd_handle_writev(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
	ClientWriteVRequest *req = (ClientWriteVRequest *) ctx->hdr_buf;
	write_list          *wl;
	size_t               n_segs, i;
	size_t               total_wlen;
	size_t               max_segs;
	const u_char        *data_ptr;
	size_t               bytes_written_total = 0;
	int                  do_sync;

	do_sync = (req->options & kXR_wv_doSync) ? 1 : 0;

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
		return xrootd_send_error(ctx, c, kXR_ArgMissing,
								 "empty writev payload");
	}

	if (ctx->cur_dlen < XROOTD_WRITEV_SEGSIZE) {
		XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "writev payload too short for one segment");
	}

	wl       = (write_list *) ctx->payload;
	max_segs = ctx->cur_dlen / XROOTD_WRITEV_SEGSIZE;
	if (max_segs > XROOTD_WRITEV_MAXSEGS) {
		max_segs = XROOTD_WRITEV_MAXSEGS;
	}

	/* Scan descriptors until n*16 + sum(wlen) == dlen, which identifies n. */
	n_segs     = 0;
	total_wlen = 0;

	for (i = 0; i < max_segs; i++) {
		uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);
		n_segs++;
		total_wlen += wlen;

		if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen == ctx->cur_dlen) {
			break;
		}

		if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen > ctx->cur_dlen) {
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
			return xrootd_send_error(ctx, c, kXR_ArgInvalid,
									 "malformed writev: payload size mismatch");
		}
	}

	if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen != ctx->cur_dlen) {
		XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "malformed writev: payload size mismatch");
	}

	/* Validate all handles before writing anything. */
	for (i = 0; i < n_segs; i++) {
		int idx = (int)(unsigned char) wl[i].fhandle[0];

		if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
			return xrootd_send_error(ctx, c, kXR_FileNotOpen,
									 "invalid file handle in writev");
		}
		if (!ctx->files[idx].writable) {
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
			return xrootd_send_error(ctx, c, kXR_NotAuthorized,
									 "file not open for writing");
		}
	}

	/* Data starts immediately after all N segment descriptors. */
	data_ptr = ctx->payload + n_segs * XROOTD_WRITEV_SEGSIZE;

#if (NGX_THREADS)
	{
		ngx_stream_xrootd_srv_conf_t *conf;

		conf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

		if (conf->thread_pool != NULL) {
			ngx_thread_task_t        *task;
			xrootd_writev_aio_t      *t;
			xrootd_writev_seg_desc_t *seg_descs;
			ngx_flag_t                posted;
			const u_char             *dp = data_ptr;

			seg_descs = ngx_palloc(c->pool,
			                       n_segs * sizeof(xrootd_writev_seg_desc_t));
			if (seg_descs == NULL) {
				return NGX_ERROR;
			}

			for (i = 0; i < n_segs; i++) {
				uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);
				seg_descs[i].fd = ctx->files[
				    (int)(unsigned char) wl[i].fhandle[0]].fd;
				seg_descs[i].handle_idx =
				    (int)(unsigned char) wl[i].fhandle[0];
				seg_descs[i].offset =
				    (off_t)(int64_t) be64toh((uint64_t) wl[i].offset);
				seg_descs[i].data = dp;
				seg_descs[i].wlen = wlen;
				dp += wlen;
			}

			task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_writev_aio_t));
			if (task == NULL) {
				return NGX_ERROR;
			}

			t = task->ctx;
			t->c           = c;
			t->ctx         = ctx;
			t->n_segs      = n_segs;
			t->segs        = seg_descs;
			t->payload_buf = ctx->payload_buf;  /* transfer ownership */
			t->do_sync     = do_sync;
			t->bytes_total = 0;
			t->io_error    = 0;
			t->streamid[0] = ctx->cur_streamid[0];
			t->streamid[1] = ctx->cur_streamid[1];

			task->handler       = xrootd_writev_write_aio_thread;
			task->event.handler = xrootd_writev_write_aio_done;
			task->event.data    = task;

			(void) xrootd_aio_post_task(ctx, c, conf->thread_pool, task,
			    "xrootd: thread_task_post failed, falling back to sync writev",
			    &posted);
			if (posted) {
				ctx->payload         = NULL;
				ctx->payload_buf     = NULL;
				ctx->payload_buf_size = 0;
				return NGX_OK;
			}
		}
	}
#endif /* NGX_THREADS */

	/* Synchronous fallback: write each segment on the event-loop thread. */
	for (i = 0; i < n_segs; i++) {
		int      idx    = (int)(unsigned char) wl[i].fhandle[0];
		int64_t  offset = (int64_t) be64toh((uint64_t) wl[i].offset);
		uint32_t wlen   = (uint32_t) ntohl((uint32_t) wl[i].wlen);
		ssize_t  nw;

		if (wlen == 0) {
			continue;
		}

		nw = pwrite(ctx->files[idx].fd, data_ptr, (size_t) wlen, (off_t) offset);

		if (nw < 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITEV, "WRITEV",
							  ctx->files[idx].path, "-",
							  kXR_IOError, strerror(errno));
		}
		if ((uint32_t) nw < wlen) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITEV, "WRITEV",
							  ctx->files[idx].path, "-",
							  kXR_IOError, "short write (disk full?)");
		}

		ctx->files[idx].bytes_written  += (size_t) nw;
		ctx->session_bytes_written     += (size_t) nw;
		bytes_written_total            += (size_t) nw;
		data_ptr                       += wlen;
	}

	/* Optional fsync on every touched handle. */
	if (do_sync) {
		for (i = 0; i < n_segs; i++) {
			int idx = (int)(unsigned char) wl[i].fhandle[0];
			if (ntohl((uint32_t) wl[i].wlen) > 0) {
				(void) fsync(ctx->files[idx].fd);
			}
		}
	}

	{
		ngx_stream_xrootd_srv_conf_t *rconf;
		char                          detail[64];

		rconf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
		if (rconf->access_log_fd != NGX_INVALID_FILE) {
			snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
			xrootd_log_access(ctx, c, "WRITEV", "-", detail, 1, 0, NULL,
			                  bytes_written_total);
		}
	}
	XROOTD_OP_OK(ctx, XROOTD_OP_WRITEV);
	return xrootd_send_ok(ctx, c, NULL, 0);
}
