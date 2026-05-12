/*
 * sync.c — kXR_sync opcode handler.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_sync — fsync(2) an open file by handle.
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

	if (fsync(ctx->files[idx].fd) != 0) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_SYNC, "SYNC",
						  ctx->files[idx].path, "-",
						  kXR_IOError, strerror(errno));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SYNC, "SYNC",
					 ctx->files[idx].path, "-", 0);
}
