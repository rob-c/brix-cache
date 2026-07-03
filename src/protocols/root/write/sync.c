/*
 * sync.c — kXR_sync opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "fs/cache/cache_internal.h"
#include "wrts_journal.h"

/*
 * brix_handle_sync — sync an open file by handle through the VFS core.
 *
 * Wire format (ClientSyncRequest): fhandle[4] identifies the open slot.
 * No payload is expected.  On success, all pending writes on the file
 * descriptor are flushed to stable storage before kXR_ok is sent.
 */
ngx_int_t
brix_handle_sync(brix_ctx_t *ctx, ngx_connection_t *c)
{
	xrdw_sync_req_t req;
	int idx;
	ngx_int_t rc;

	xrdw_sync_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
	idx = (int)(unsigned char) req.fhandle[0];

	if (!brix_validate_file_handle(ctx, c, idx, "SYNC",
									 BRIX_OP_SYNC, &rc)) {
		return rc;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
				   "xrootd: kXR_sync handle=%d", idx);

	if (ctx->files[idx].tpc_destination && !ctx->files[idx].tpc_done) {
		if (!ctx->files[idx].tpc_armed) {
			ctx->files[idx].tpc_armed = 1;
			BRIX_RETURN_OK(ctx, c, BRIX_OP_SYNC, "SYNC",
							 ctx->files[idx].path, "tpc-arm", 0);
		}

		return brix_tpc_start_pull(ctx, c, ngx_stream_get_module_srv_conf(
									 ctx->session, ngx_stream_brix_module),
									 idx);
	}

	{
		brix_vfs_job_t job;

		brix_vfs_job_sync_init(&job, ctx->files[idx].fd);
		brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
		brix_vfs_io_execute(&job);
		if (job.io_errno != 0) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_SYNC, "SYNC",
							  ctx->files[idx].path, "-",
							  kXR_IOError, strerror(job.io_errno));
		}
	}

	/* kXR_sync committed writes to stable storage — flush the journal. */
	if (ctx->files[idx].wrts_enabled) {
		brix_wrts_flush(&ctx->files[idx]);
	}

	if (ctx->files[idx].dashboard_slot >= 0 &&
	    ngx_brix_dashboard_shm_zone != NULL)
	{
		brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
		                              ctx->files[idx].dashboard_slot,
		                              "sync");
	}

	/* Write-through flush is part of the storage path now (Option A): a wt sd_stage
	 * handle flushes to the origin through the VFS fsync job above (sd_stage_wb_fsync,
	 * which surfaces a failure as kXR_error) and on close (sd_stage_wb_close). The
	 * legacy run_flush loop has been retired. */

	BRIX_RETURN_OK(ctx, c, BRIX_OP_SYNC, "SYNC",
					 ctx->files[idx].path, "-", 0);
}
