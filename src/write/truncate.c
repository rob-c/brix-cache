/* ------------------------------------------------------------------ */
/* File Truncation — kXR_truncate handler                                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_truncate opcode — setting a file's length to a specified byte offset. Supports two modes: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves path, opens O_WRONLY, calls ftruncate(2), then closes temporary fd. The offset parameter is big-endian int64 representing new file length in bytes — truncating to smaller size discards content beyond that point, truncating to larger size extends file without adding data (creates sparse region). Token scope write gate is required for both paths ensuring only authenticated clients with write permission can modify file boundaries.
 *
 * WHY: File truncation enables operators to reduce file sizes or create sparse regions without requiring filesystem-level intervention. Handle-based mode works on files already opened by the current session, enabling rapid size adjustments during staging operations. Path-based mode provides broader capability — truncate any file within export root regardless of whether it was previously opened by this session, enabling bulk size modifications across multiple files without requiring individual open/close cycles for each target file. Sparse extension (truncating to larger size) creates zero-filled regions useful for pre-allocation scenarios where clients want to reserve filesystem space without actual data content.
 *
 * HOW: Two-mode truncation → parse offset from ClientTruncateRequest wire format (big-endian int64) — if dlen>0: path-based mode (extract/clean/resolve via xrootd_resolve_path_write fallback to xrootd_resolve_path, authdb gate with XROOTD_AUTH_UPDATE privilege, token scope write check, open O_WRONLY, ftruncate(2), close temporary fd); if dlen==0: handle-based mode (validate file handle via xrootd_validate_file_handle, ftruncate(2) on existing fd); errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", ENOENT → kXR_NotFound "file not found", all others → kXR_IOError. Returns kXR_ok on success with access-log detail containing offset value and byte count 0. */

/* ------------------------------------------------------------------ */
/* Section: Handle-Based vs Path-Based Truncation                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Two truncation modes exist based on dlen parameter in ClientTruncateRequest wire format. Handle-based (dlen==0): uses the fd already open on the slot — no path resolution or temporary file opening required, enabling rapid size adjustments during staging operations where file was previously opened via kXR_open. Path-based (dlen>0 with payload containing path): resolves path via xrootd_resolve_path_write (parent must exist, target may not), opens O_WRONLY for ftruncate(2), calls truncation, then closes temporary fd — provides broader capability to truncate any file within export root regardless of whether it was previously opened by this session.
 *
 * WHY: Handle-based mode enables rapid size adjustments during staging operations where file was already opened via kXR_open — no path resolution or temporary opening required reduces overhead in high-frequency truncation scenarios (e.g., checkpoint rollback restoring original file size). Path-based mode provides broader capability — truncate any file within export root regardless of whether it was previously opened by this session, enabling bulk size modifications across multiple files without requiring individual open/close cycles for each target file. */

/* ------------------------------------------------------------------ */
/* Section: Sparse Extension (Truncating to Larger Size)                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Truncating a file to larger than current size creates sparse region — ftruncate(2) extends file boundary without adding actual data content, creating zero-filled gap between original end and new boundary. This sparse extension is useful for pre-allocation scenarios where clients want to reserve filesystem space without actual data content — filesystem allocates blocks but reads return zeros until actual write occurs in sparse region.
 *
 * WHY: Sparse extension enables pre-allocation without wasting storage capacity on zero-filled regions during initial staging operations. Clients can extend file boundaries to expected final size before actual data arrives, enabling filesystem-level resource planning and avoiding reallocation overhead when data eventually fills the sparse region. Some filesystems support hole-punching via fallocate(2) for explicit sparse creation; ftruncate-based extension provides universal compatibility across all POSIX filesystem implementations. */

/* ---- Function: xrootd_handle_truncate() ----
 *
 * WHAT: Handles the kXR_truncate opcode — sets a file's length to a specified byte offset supporting two modes: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_WRONLY, calls ftruncate(2), then closes temporary fd. Offset is big-endian int64 representing new file length in bytes — truncating to smaller size discards content beyond that point, truncating to larger size extends file creating sparse zero-filled region. Token scope write gate required for both paths ensuring only authenticated clients with write permission can modify file boundaries. Returns kXR_ok on success with access-log detail containing offset value and byte count 0.
 *
 * WHY: Enables operators to reduce file sizes or create sparse regions without requiring filesystem-level intervention. Handle-based mode works on files already opened by current session enabling rapid size adjustments during staging operations. Path-based mode provides broader capability — truncate any file within export root regardless of whether it was previously opened by this session, enabling bulk size modifications across multiple files without requiring individual open/close cycles for each target file. Sparse extension (truncating to larger size) creates zero-filled regions useful for pre-allocation scenarios where clients want to reserve filesystem space without actual data content.
 *
 * HOW: Two-mode truncation → parse offset from ClientTruncateRequest wire format (big-endian int64) — if dlen>0: path-based mode (extract/clean/resolve via xrootd_resolve_path_write fallback to xrootd_resolve_path, authdb gate with XROOTD_AUTH_UPDATE privilege, token scope write check, open O_WRONLY, ftruncate(2), close temporary fd); if dlen==0: handle-based mode (validate file handle via xrootd_validate_file_handle, ftruncate(2) on existing fd); errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", ENOENT → kXR_NotFound "file not found", all others → kXR_IOError. Returns kXR_ok on success with access-log detail containing offset value and byte count 0. */

/*
 * truncate.c â kXR_truncate opcode handler.
 */
#include "ngx_xrootd_module.h"
#include "cache/writethrough_metrics.h"

#include <fcntl.h>

/*
 * xrootd_handle_truncate â set the length of a file to the given offset.
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
xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
						ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientTruncateRequest *req = (ClientTruncateRequest *) ctx->hdr_buf;
	int64_t  length = (int64_t) be64toh((uint64_t) req->offset);
	char     detail[64];
	int      rc;

	snprintf(detail, sizeof(detail), "%lld", (long long) length);

	if (ctx->cur_dlen > 0) {
		/* Path-based truncate */
		char resolved[PATH_MAX];
		char reqpath[XROOTD_MAX_PATH + 1];
		if (ctx->payload == NULL) {
			return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
		}
		if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
								 reqpath, sizeof(reqpath), 1)) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE", "-",
							  detail, kXR_ArgInvalid, "invalid path payload");
		}
		if (!xrootd_resolve_path_write(c->log, &conf->common.root,
									   reqpath,
									   resolved, sizeof(resolved))) {
			  /*
			   * write-style resolution handles the common "target may not exist" case.
			   * If that fails, fall back to the normal resolver so existing files with
			   * canonical paths still truncate correctly.
			   */
			if (!xrootd_resolve_path(c->log, &conf->common.root,
									 reqpath,
									 resolved, sizeof(resolved))) {
				XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
								  reqpath, detail, kXR_NotFound, "file not found");
			}
		}
		if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_NotAuthorized, "authdb denied");
		}

		if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
								 ctx->identity) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_NotAuthorized, "VO not authorized");
		}
		if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  reqpath, detail, kXR_NotAuthorized, "token scope denied");
		}
		rc = xrootd_open_confined(c->log, &conf->common.root, resolved,
								  O_WRONLY | O_NOCTTY, 0);
		if (rc < 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_IOError, strerror(errno));
		}
		if (ftruncate(rc, (off_t) length) != 0) {
			int err = errno;
			close(rc);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  resolved, detail, kXR_IOError, strerror(err));
		}
		close(rc);
		xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
						  1, 0, NULL, 0);
	} else {
		/* Handle-based truncate bypasses path resolution and uses the already-open fd. */
		int idx = (int)(unsigned char) req->fhandle[0];
		ngx_int_t validate_rc;

		if (!xrootd_validate_file_handle(ctx, c, idx, "TRUNCATE",
										 XROOTD_OP_TRUNCATE, &validate_rc)) {
			return validate_rc;
		}
		rc = ftruncate(ctx->files[idx].fd, (off_t) length);
		if (rc != 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
							  ctx->files[idx].path, detail,
							  kXR_IOError, strerror(errno));
		}
		if (ctx->files[idx].wt_enabled) {
			xrootd_wt_mark_dirty(ctx, idx,
			                      (length > 0) ? (off_t) length - 1 : 0,
			                      0);
		}
		xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
						  1, 0, NULL, 0);
	}

	XROOTD_OP_OK(ctx, XROOTD_OP_TRUNCATE);
	return xrootd_send_ok(ctx, c, NULL, 0);
}
