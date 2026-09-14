/*
 * sync.c — kXR_sync opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/error_mapping.h"   /* brix_kxr_from_errno */
#include "fs/cache/cache_internal.h"
#include "wrts_journal.h"
#include "pgw_fob.h"                 /* kXR_pgwrite CSE close/sync commit gate */

/*
 * brix_sync_tpc_arm_or_fire — the two-kXR_sync contract shared by BOTH native
 * TPC roles.
 *
 * WHAT: the first sync on a TPC handle ARMS it and answers kXR_ok; the second
 * FIRES the transfer and parks the connection until the worker finishes.
 * WHY: xrdcp's native TPC dialect sends sync twice — once to confirm the
 * rendezvous is set up, once to start the copy — and the F16 push must honour
 * exactly the same contract as the pull, or a client would have to know which
 * direction it asked for before it could drive the handshake. One helper means
 * one arm/fire semantic, not two that can drift.
 * HOW: tpc_armed is the only state; which start_* runs is decided by tpc_push
 * (source of a push) versus tpc_destination (destination of a pull). The two
 * bits are mutually exclusive by construction — open_tpc.c dispatches exactly
 * one role per open — and tpc_push is tested first so a future handle that
 * somehow carried both would still never pull into a file it is streaming out.
 */
static ngx_int_t
brix_sync_tpc_arm_or_fire(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
	ngx_stream_brix_srv_conf_t *conf;

	if (!ctx->files[idx].tpc_armed) {
		ctx->files[idx].tpc_armed = 1;
		BRIX_RETURN_OK(ctx, c, BRIX_OP_SYNC, "SYNC",
						 ctx->files[idx].path,
						 ctx->files[idx].tpc_push ? "tpc-push-arm" : "tpc-arm",
						 0);
	}

	conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);

	if (ctx->files[idx].tpc_push) {
		return brix_tpc_start_push(ctx, c, conf, idx);
	}

	return brix_tpc_start_pull(ctx, c, conf, idx);
}

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

	xrdw_sync_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	idx = (int)(unsigned char) req.fhandle[0];

	if (!brix_validate_file_handle(ctx, c, idx, "SYNC",
									 BRIX_OP_SYNC, &rc)) {
		return rc;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
				   "brix: kXR_sync handle=%d", idx);

	if ((ctx->files[idx].tpc_destination || ctx->files[idx].tpc_push)
	    && !ctx->files[idx].tpc_done)
	{
		return brix_sync_tpc_arm_or_fire(ctx, c, idx);
	}

	/* Whole-object staged-commit adapter (phase-70): a staged write handle has no
	 * fd to fsync — kXR_sync COMMITS the whole object (single backend PUT). The
	 * commit is idempotent so a later kXR_close is a no-op. */
	if (ctx->files[idx].writer != NULL) {
		int cerr = 0;

		/* INVARIANT 1: the kXR_pgwrite CSE close gate (brix_close_pgw_gate)
		 * refuses to publish a handle that still holds pages that failed CRC32c.
		 * A staged commit is an EARLY publish, so it must consult the very same
		 * Fob gate — otherwise a client could pgwrite a corrupt page (registered
		 * in the Fob, accept-then-correct) and then kXR_sync to publish the poison
		 * as complete, sidestepping the close gate entirely. Fail closed. */
		uint32_t bad = brix_pgw_fob_commit_blocked(&ctx->files[idx]);
		if (bad > 0) {
			char emsg[64];

			snprintf(emsg, sizeof(emsg), "%u uncorrected checksum error%s",
			         bad, bad == 1 ? "" : "s");
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_SYNC, "SYNC",
							  ctx->files[idx].path, "-", kXR_ChkSumErr, emsg);
		}

		if (brix_staged_commit_handle(ctx, idx, &cerr) != NGX_OK) {
			/* The commit's errno picks the code (EEXIST = ItExists for a
			 * refused kXR_new; EROFS = fsReadOnly), phase-115 W3.1. */
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_SYNC, "SYNC",
							  ctx->files[idx].path, "-",
							  brix_kxr_from_errno(cerr), strerror(cerr));
		}
		BRIX_RETURN_OK(ctx, c, BRIX_OP_SYNC, "SYNC",
						 ctx->files[idx].path, "-", 0);
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
	    brix_dashboard_get_shm_zone() != NULL)
	{
		brix_transfer_slot_count_op(brix_dashboard_get_shm_zone()->data,
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
