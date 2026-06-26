/*
 * sync.c — kXR_sync opcode.  See each function's docblock below.
 */

#include "ngx_xrootd_module.h"
#include "cache/cache_internal.h"
#include "wrts_journal.h"

/*
 * xrootd_handle_sync — sync an open file by handle through the VFS core.
 *
 * Wire format (ClientSyncRequest): fhandle[4] identifies the open slot.
 * No payload is expected.  On success, all pending writes on the file
 * descriptor are flushed to stable storage before kXR_ok is sent.
 */
ngx_int_t
xrootd_handle_sync(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
	ClientSyncRequest *req = (ClientSyncRequest *) ctx->hdr_buf;
	int idx = (int)(unsigned char) req->fhandle[0];
	ngx_int_t rc;

	if (!xrootd_validate_file_handle(ctx, c, idx, "SYNC",
									 XROOTD_OP_SYNC, &rc)) {
		return rc;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
				   "xrootd: kXR_sync handle=%d", idx);

	if (ctx->files[idx].tpc_destination && !ctx->files[idx].tpc_done) {
		if (!ctx->files[idx].tpc_armed) {
			ctx->files[idx].tpc_armed = 1;
			XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SYNC, "SYNC",
							 ctx->files[idx].path, "tpc-arm", 0);
		}

		return xrootd_tpc_start_pull(ctx, c, ngx_stream_get_module_srv_conf(
									 ctx->session, ngx_stream_xrootd_module),
									 idx);
	}

	{
		xrootd_vfs_job_t job;

		xrootd_vfs_job_sync_init(&job, ctx->files[idx].fd);
		xrootd_vfs_io_execute(&job);
		if (job.io_errno != 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_SYNC, "SYNC",
							  ctx->files[idx].path, "-",
							  kXR_IOError, strerror(job.io_errno));
		}
	}

	/* kXR_sync committed writes to stable storage — flush the journal. */
	if (ctx->files[idx].wrts_enabled) {
		xrootd_wrts_flush(&ctx->files[idx]);
	}

	if (ctx->files[idx].dashboard_slot >= 0 &&
	    ngx_xrootd_dashboard_shm_zone != NULL)
	{
		xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
		                              ctx->files[idx].dashboard_slot,
		                              "sync");
	}

	if (ctx->files[idx].wt_enabled && ctx->files[idx].wt_dirty_offset >= 0) {
		ngx_stream_xrootd_srv_conf_t *conf;

		conf = ngx_stream_get_module_srv_conf(ctx->session,
		                                      ngx_stream_xrootd_module);
		rc = xrootd_wt_flush_sync_handle(ctx, c, conf, idx,
		                                  ctx->files[idx].path,
		                                  kXR_IOError);
		if (rc != NGX_OK) {
			/* Flush failed: the helper only reports status, so send the
			 * single kXR_error wire response here. */
			XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
			return xrootd_send_error(ctx, c, kXR_IOError,
			                          "write-through flush to origin failed");
		}
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SYNC, "SYNC",
					 ctx->files[idx].path, "-", 0);
}
