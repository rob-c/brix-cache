/*
 * writev_aio.c — kXR_writev thread-pool offload path (split from writev.c,
 * phase-79).
 *
 * WHAT: Holds writev_try_aio — the single function that, when a thread pool is
 *       configured, flattens the validated write_list descriptors into a
 *       self-contained decoded array, builds the writev AIO task, and posts it
 *       to a worker thread. The synchronous fallback, framing, handle admission,
 *       reply, and orchestrator stay in writev.c; the shared invariant context
 *       (writev_run_t) and this function's declaration live in writev_internal.h.
 * WHY:  writev.c was 551 lines and owned two distinct concerns — the
 *       event-loop-thread synchronous write and the thread-pool offload. The
 *       offload path is a cohesive, self-contained unit (big-endian decode +
 *       replay neutralisation + task build + buffer-ownership transfer), so
 *       lifting it into its own file holds each half under the 500-line cap and
 *       focused on one responsibility. Zero behaviour change: the code is moved
 *       verbatim and now reached through the shared header declaration.
 * HOW:  brix_handle_writev (writev.c) populates a writev_run_t and calls
 *       writev_try_aio here; on a successful post the done callback owns
 *       payload_buf and the reply, so the caller returns immediately.
 */

#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"
#include "writev_internal.h"   /* cross-file: writev_run_t + writev_try_aio decl */

/* writev_try_aio — offload the whole vector to a worker thread if configured.
 * WHAT: When a thread pool is configured, flattens the wire descriptors into a
 * self-contained decoded array, builds the writev AIO task, and posts it.
 * WHY: Keeps the per-segment big-endian decode + replay neutralisation on the
 * event-loop thread (before the worker can race ctx) and hands buffer ownership
 * to the task so the main thread can advance to the next request.
 * HOW: data_ptr is the start of the contiguous per-segment data blocks.  On a
 * successful post it detaches payload_buf from ctx (the done callback frees it
 * and replies) and reports posted via *posted (NGX_OK).  It returns NGX_ERROR
 * on allocation failure (caller drops the link).  When no pool is configured or
 * the post fails it leaves *posted 0 and returns NGX_OK so the caller falls
 * through to the synchronous path with payload_buf still owned by ctx. */
ngx_int_t
writev_try_aio(const writev_run_t *run, int do_sync, ngx_flag_t *posted)
{
	brix_ctx_t                 *ctx = run->ctx;
	ngx_connection_t           *c = run->c;
	const write_list           *wl = run->wl;
	size_t                      n_segs = run->n_segs;
	ngx_stream_brix_srv_conf_t *conf;
	ngx_thread_task_t          *task;
	brix_writev_aio_t          *t;
	brix_writev_seg_desc_t     *seg_descs;
	const u_char               *dp = run->data_ptr;
	size_t                      i;

	*posted = 0;

	conf = ngx_stream_get_module_srv_conf(
	    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

	if (conf->common.thread_pool == NULL) {
		return NGX_OK;
	}

	/* Flatten the wire descriptors into a self-contained array the worker
	 * thread can consume without touching ctx (which the main thread may mutate
	 * once we return). Decode all big-endian fields now, while we are still on
	 * the event-loop thread. */
	seg_descs = ngx_palloc(c->pool,
	                       n_segs * sizeof(brix_writev_seg_desc_t));
	if (seg_descs == NULL) {
		return NGX_ERROR;
	}

	for (i = 0; i < n_segs; i++) {
		uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);
		/* phase77-fp: hidx (0..255) was already bounds-checked against
		 * BRIX_MAX_FILES for every segment by writev_validate_handles above,
		 * which the caller made all-or-nothing; the analyzer cannot correlate
		 * the two same-index loops. */
		int      hidx = (int)(unsigned char) wl[i].fhandle[0];
		int64_t  off  = (int64_t) be64toh((uint64_t) wl[i].offset);

		seg_descs[i].fd         = ctx->files[hidx].fd;  /* NOLINT(clang-analyzer-security.ArrayBound) */
		seg_descs[i].obj        = ctx->files[hidx].sd_obj; /* Layer 3 */
		seg_descs[i].handle_idx = hidx;
		seg_descs[i].offset     = (off_t) off;
		seg_descs[i].data       = dp;   /* points into payload_buf */
		seg_descs[i].wlen       = wlen;

		/* write-recovery (kXR_recoverWrts): if this byte range was already
		 * durably written before the connection dropped, it is a client replay.
		 * Neutralise it to a no-op by zeroing wlen; the worker thread treats
		 * wlen == 0 as "skip" so the bytes are neither rewritten nor
		 * double-counted. */
		if (ctx->files[hidx].wrts_enabled &&
		    brix_wrts_is_replay(&ctx->files[hidx], off, wlen))
		{
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "brix: writev AIO recovery replay skip"
			    " offset=%lld len=%u", (long long) off, wlen);
			seg_descs[i].wlen = 0;
		}

		/* Advance over the (original, un-zeroed) data block so dp stays aligned
		 * with the wire layout regardless of replay skipping. */
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
	    posted);
	/* *posted == 1: ownership of payload_buf now lives on the task and the done
	 * callback will free it and send the reply. Detach it from ctx so the main
	 * thread can start the next request without racing the worker or
	 * double-freeing the buffer. *posted == 0: posting failed; payload_buf is
	 * still ours and the caller falls through to the synchronous path using the
	 * original data_ptr. */
	if (*posted) {
		ctx->recv.payload         = NULL;
		ctx->recv.payload_buf     = NULL;
		ctx->recv.payload_buf_size = 0;
	}

	return NGX_OK;
}
