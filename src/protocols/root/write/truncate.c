/*
 * truncate.c — kXR_truncate opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "fs/vfs/vfs.h"   /* path-based truncate via the VFS seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */

#include <fcntl.h>

/*
 * brix_handle_truncate â set the length of a file to the given offset.
 *
 * Wire format (ClientTruncateRequest):
 *   fhandle[4]: open handle (only meaningful when dlen == 0)
 *   offset:     big-endian int64 â the new file length in bytes
 *   dlen:       0 means handle-based truncate; >0 means path-based truncate
 *
 * Handle-based path: uses the fd already open on the slot.
 * Path-based path:   resolves the path, opens it O_WRONLY, calls ftruncate,
 *   then closes the temporary fd.
 *
 * Token scope: write scope is required for both paths.
 */
ngx_int_t
brix_handle_truncate(brix_ctx_t *ctx, ngx_connection_t *c,
						ngx_stream_brix_srv_conf_t *conf)
{
	xrdw_truncate_req_t req;
	int64_t  length;
	char     detail[64];

	xrdw_truncate_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
	length = req.offset;

	snprintf(detail, sizeof(detail), "%lld", (long long) length);

	if (ctx->recv.cur_dlen > 0) {
		/* Path-based truncate */
		char resolved[PATH_MAX];
		char reqpath[BRIX_MAX_PATH + 1];
		if (brix_resolve_op_path(ctx, c, BRIX_OP_TRUNCATE, "TRUNCATE", conf,
								   BRIX_PATH_EITHER,
								   reqpath, sizeof(reqpath),
								   resolved, sizeof(resolved)) != NGX_OK) {
			return ctx->write_rc;
		}
		if (brix_auth_gate(ctx, c, BRIX_OP_TRUNCATE, "TRUNCATE",
							  reqpath, resolved, conf,
							  BRIX_AUTH_UPDATE, 1) != NGX_OK) {
			return ctx->write_rc;
		}
		{
			brix_vfs_ctx_t   vctx;
			brix_vfs_file_t *fh;
			int                vfs_err = 0;

			brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
				conf->common.root_canon, NULL, conf->common.allow_write,
				0 /* is_tls */, ctx->identity, resolved);
			brix_vfs_ctx_bind_backend_cred(&vctx,
				&conf->common.storage_credential_dir,
				conf->common.storage_credential_fallback);
			/* Phase-3 T1: opt-in credential minting, mirroring the davs/S3
			 * PUT mint bind — a write-open touches the origin object. */
			brix_vfs_ctx_bind_backend_mint(&vctx,
				&conf->common.storage_credential_mint_ca_cert,
				&conf->common.storage_credential_mint_ca_key,
				conf->common.storage_credential_mint_ttl);
			brix_root_vfs_bind_deleg(ctx, conf, &vctx);
			fh = brix_vfs_open(&vctx, BRIX_VFS_O_WRITE, &vfs_err);
			if (fh == NULL) {
				/* Map the real errno (ENOENT→kXR_NotFound, EACCES→…) instead of a
				 * blanket kXR_IOError: stock truncate of a missing path returns
				 * 3011 (NotFound), and XrdCl/gfal branch on the code. */
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_TRUNCATE, "TRUNCATE",
								  resolved, detail,
								  brix_kxr_from_errno(vfs_err),
								  strerror(vfs_err));
			}
			if (brix_vfs_truncate(fh, (off_t) length) != NGX_OK) {
				int err = errno;

				brix_vfs_close(fh, c->log);
				BRIX_RETURN_ERR(ctx, c, BRIX_OP_TRUNCATE, "TRUNCATE",
								  resolved, detail,
								  brix_kxr_from_errno(err), strerror(err));
			}
			brix_vfs_close(fh, c->log);
		}
		brix_log_access(ctx, c, "TRUNCATE", resolved, detail,
						  1, 0, NULL, 0);
	} else {
		/* Handle-based truncate bypasses path resolution and uses the already-open fd. */
		int idx = (int)(unsigned char) req.fhandle[0];
		ngx_int_t validate_rc;
		brix_vfs_job_t job;

		if (!brix_validate_file_handle(ctx, c, idx, "TRUNCATE",
										 BRIX_OP_TRUNCATE, &validate_rc)) {
			return validate_rc;
		}
		brix_vfs_job_truncate_init(&job, ctx->files[idx].fd,
									  (off_t) length);
		brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
		brix_vfs_io_execute(&job);
		if (job.io_errno != 0) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_TRUNCATE, "TRUNCATE",
							  ctx->files[idx].path, detail,
							  kXR_IOError, strerror(job.io_errno));
		}
		if (ctx->files[idx].wt_enabled) {
			brix_wt_mark_dirty(ctx, idx,
			                      (length > 0) ? (off_t) length - 1 : 0,
			                      0);
		}
		brix_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
						  1, 0, NULL, 0);
	}

	BRIX_OP_OK(ctx, BRIX_OP_TRUNCATE);
	return brix_send_ok(ctx, c, NULL, 0);
}
