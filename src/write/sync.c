/* ------------------------------------------------------------------ */
/* File Synchronization — kXR_sync handler                                  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_sync opcode — forcing fsync(2) on an open file handle to flush all pending writes to stable storage. The wire format uses fhandle[4] (first byte is slot index) with no payload expected. On success, all buffered writes on the file descriptor are guaranteed written to disk before kXR_ok response is sent. Additionally supports TPC destination arm/flush functionality: first sync call arms TPC pull (ctx->tpc_armed=1), subsequent sync calls trigger actual TPC data transfer from source server via xrootd_tpc_start_pull().
 *
 * WHY: File synchronization ensures write durability — critical for staging uploads, checkpoint transactions, and TPC transfers where data integrity guarantees are required. Without fsync(2), pending writes could be lost if the system crashes or power fails before completion. In TPC mode, sync serves dual purpose: first call arms transfer (flags ctx->tpc_armed=1), subsequent call triggers actual pull from source server — enabling atomic TPC commit semantics where client explicitly requests data synchronization after staging completes.
 *
 * HOW: Two-phase sync → validate file handle (xrootd_validate_file_handle) — check TPC destination state (if tpc_destination && !tpc_done): first call arms TPC (ctx->tpc_armed=1, return kXR_ok "tpc-arm"), subsequent call triggers pull via xrootd_tpc_start_pull()) — perform fsync(2) on file descriptor — return kXR_ok with access-log detail "-" and byte count 0. */

/* ------------------------------------------------------------------ */
/* Section: TPC Arm/Flush Semantics                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: In TPC (Third-Party Copy) destination mode, sync serves dual purpose beyond standard fsync. First sync call on a pending TPC file arms the transfer by setting ctx->tpc_armed=1 and returning kXR_ok with detail "tpc-arm" — no actual data transfer occurs yet. Subsequent sync call triggers the actual pull from source server via xrootd_tpc_start_pull(), streaming bytes from tpc.src=root://host//path to local destination while maintaining TPC key registry state.
 *
 * WHY: Provides atomic TPC commit semantics where client explicitly controls when staging data is synchronized to final location. First sync arms the transfer (flags readiness), subsequent sync triggers actual pull — enabling clients to stage files locally and then explicitly request synchronization only after verifying staging completeness or performing additional operations on staged content before committing to final destination. */

/* ---- Function: xrootd_handle_sync() ----
 *
 * WHAT: Handles the kXR_sync opcode — forces fsync(2) on an open file handle flushing all pending writes to stable storage. Additionally supports TPC destination arm/flush semantics: first sync call arms transfer (ctx->tpc_armed=1, returns kXR_ok "tpc-arm"), subsequent sync call triggers actual pull from source server via xrootd_tpc_start_pull(). Validates file handle via xrootd_validate_file_handle, performs fsync(2) syscall on file descriptor, returns kXR_ok with access-log detail "-" and byte count 0. TPC arm/flush enables atomic commit semantics where client explicitly controls when staging data is synchronized to final destination location.
 *
 * WHY: Ensures write durability — critical for staging uploads, checkpoint transactions, and TPC transfers where data integrity guarantees are required. Without fsync(2), pending writes could be lost if system crashes or power fails before completion. In TPC mode provides atomic commit semantics: first sync arms transfer (flags readiness), subsequent sync triggers actual pull from source server — enabling clients to stage files locally then explicitly request synchronization only after verifying staging completeness.
 *
 * HOW: Two-phase sync → validate file handle (xrootd_validate_file_handle) — check TPC destination state (if tpc_destination && !tpc_done): first call arms TPC (ctx->tpc_armed=1, return kXR_ok "tpc-arm"), subsequent call triggers pull via xrootd_tpc_start_pull()) — perform fsync(2) on file descriptor — return kXR_ok with access-log detail "-" and byte count 0. */

/*
 * sync.c — kXR_sync opcode handler.
 */
#include "ngx_xrootd_module.h"
#include "cache/cache_internal.h"
#include "wrts_journal.h"

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
			return rc;
		}
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_SYNC, "SYNC",
					 ctx->files[idx].path, "-", 0);
}
