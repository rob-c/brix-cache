/* ------------------------------------------------------------------ */
/* File Rename/Move — kXR_mv handler                                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_mv opcode — atomic rename or move of a file or directory within the export root. The wire format payload is src + ' ' (space separator) + dst, where ClientMvRequest.arg1len carries source path length (not null-terminated). Both source and destination are independently validated: extracted, resolved under conf->common.root, VO ACL checked, token scope write gate verified. Source must exist (xrootd_resolve_path canonical resolution); destination uses xrootd_resolve_path_write so non-existent target is accepted. The actual rename performed via xrootd_rename_confined() closes the TOCTOU race between realpath and rename(2) by ensuring confined boundary enforcement during atomic operation.
 *
 * WHY: Atomic rename/move enables clients to relocate files or directories within the export root without requiring intermediate copy/delete cycles. Unlike separate copy-then-delete operations (which risk data loss if partial failure occurs), kXR_mv provides single-atomic operation ensuring either complete success or immediate rejection with no intermediate state. TOCTOU race closure via xrootd_rename_confined() prevents path escape attacks where canonical resolution could return different result than actual rename(2) execution — confined rename ensures both operations use identical boundary enforcement.
 *
 * HOW: Three-phase rename → wire format parsing (arg1len source length, space separator validation at payload[arg1len]) — independent source extraction/canonical resolution/xrootd_resolve_path + destination extraction/write-resolution/xrootd_resolve_path_write — shared security gates (VO ACL + token scope write gate for both paths) — atomic xrootd_rename_confined() enforcing TOCTOU closure — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", ENOENT/EEXIST → kXR_FSError, all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/* ------------------------------------------------------------------ */
/* Section: Wire Format Parsing                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_mv() parses the two-path wire format where payload contains src + space + dst. ClientMvRequest.arg1len carries source path length (NOT including terminator, not null-terminated). The byte at payload[arg1len] must be 0x20 (space separator) — any other separator is rejected with kXR_ArgInvalid error preventing malformed payload processing. Source and destination lengths derived: dst_len = ctx->cur_dlen - src_len - 1 (subtracting arg1len + space separator). Both paths are parsed independently so embedded-NUL and traversal checks apply to each separately, preventing cross-path contamination attacks.
 *
 * WHY: Independent path parsing prevents security issues where one malformed path could affect validation of the other. The space separator requirement ensures clients follow standardized wire format without attempting alternative separators that could confuse payload boundary detection. arg1len (not null-terminated) allows paths containing embedded NUL characters to be correctly parsed by length rather than string termination — critical for paths with special characters or binary data in path names. */

/* ------------------------------------------------------------------ */
/* Section: TOCTOU Race Closure                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_rename_confined() closes the TOCTOU (Time-Of-Check-Time-Of-Use) race between canonical resolution and rename(2) execution. Unlike separate realpath + rename operations where path could change between check and use, confined rename ensures both operations use identical boundary enforcement preventing path escape attacks. The source must exist via xrootd_resolve_path (canonical); destination uses xrootd_resolve_path_write so non-existent target is accepted — enabling move to new locations within export root without requiring pre-existing destination directory.
 *
 * WHY: TOCTOU race closure prevents security vulnerabilities where canonical resolution could return different result than actual rename(2) execution due to filesystem changes between check and use operations. Confined rename ensures both operations use identical boundary enforcement preventing path escape attacks where malicious clients could attempt to move files outside the export root boundary using crafted path payloads. Canonical source resolution + write destination acceptance enables moving files to new locations within export root without requiring pre-existing destination directory structure. */

/* ---- Function: xrootd_handle_mv() ----
 *
 * WHAT: Handles the kXR_mv opcode — atomic rename or move of a file or directory within the export root performing three-phase operation: wire format parsing (arg1len source length, space separator validation at payload[arg1len]), independent source extraction/canonical resolution/xrootd_resolve_path + destination extraction/write-resolution/xrootd_resolve_path_write, shared security gates (VO ACL + token scope write gate for both paths), atomic xrootd_rename_confined() enforcing TOCTOU closure. Source must exist via canonical resolution; destination accepts non-existent target via write resolution enabling move to new locations within export root without pre-existing destination directory. Returns kXR_ok on success with access-log detail "-" and byte count 0.
 *
 * WHY: Atomic rename/move enables clients to relocate files or directories within the export root without requiring intermediate copy-delete cycles (which risk data loss if partial failure occurs). Unlike separate copy-then-delete operations, kXR_mv provides single-atomic operation ensuring either complete success or immediate rejection with no intermediate state. TOCTOU race closure via xrootd_rename_confined() prevents path escape attacks where canonical resolution could return different result than actual rename(2) execution — confined rename ensures both operations use identical boundary enforcement.
 *
 * HOW: Three-phase rename → wire format parsing (arg1len source length, space separator validation at payload[arg1len]) — independent source extraction/canonical resolution/xrootd_resolve_path + destination extraction/write-resolution/xrootd_resolve_path_write — shared security gates (VO ACL + token scope write gate for both paths) — atomic xrootd_rename_confined() enforcing TOCTOU closure — errno-to-kXR mapping: EACCES/EPERM → kXR_NotAuthorized "permission denied", ENOENT/EEXIST → kXR_FSError, all others → kXR_IOError. Returns kXR_ok on success with access-log detail "-" and byte count 0. */

/*
 * mv.c â kXR_mv opcode handler: atomic rename within the export root.
 */
#include "ngx_xrootd_module.h"
#include "../compat/error_mapping.h"

/*
 * xrootd_handle_mv â rename a file or directory.
 *
 * Wire format: the payload is src + ' ' + dst.
 * ClientMvRequest.arg1len carries the source path length (not null-terminated).
 * The byte at payload[arg1len] must be 0x20 (space) — any other separator
 * is rejected with kXR_ArgInvalid.
 *
 * Both source and destination are independently path-extracted, resolved, and
 * VO/token-scope-checked.  The source must exist (xrootd_resolve_path); the
 * destination uses xrootd_resolve_path_write so a non-existent target is
 * accepted.  The actual rename is done via xrootd_rename_confined to close
 * the TOCTOU race between realpath and rename(2).
 */
ngx_int_t
xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
				 ngx_stream_xrootd_srv_conf_t *conf)
{
	ClientMvRequest *req = (ClientMvRequest *) ctx->hdr_buf;
	char src_resolved[PATH_MAX];
	char dst_resolved[PATH_MAX];
	char src_buf[XROOTD_MAX_PATH + 1];
	char dst_buf[XROOTD_MAX_PATH + 1];
	int16_t  src_len;
	size_t   dst_len;

	if (ctx->payload == NULL || ctx->cur_dlen == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
	}

	/*
	 * Wire format (from XrdClFileSystem.cc):
	 *   arg1len = source.length()       (NOT including any terminator)
	 *   dlen    = src.length() + dst.length() + 1
	 *   payload = src[arg1len] + ' ' + dst[...]
	 * The separator between source and destination is a single space (0x20).
	 */
	src_len = (int16_t) ntohs((uint16_t) req->arg1len);
	if (src_len <= 0 || (uint32_t)(src_len + 1) >= ctx->cur_dlen) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid arg1len for mv");
	}

	/* Separator byte at src_len must be a space */
	if (ctx->payload[src_len] != ' ') {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "mv payload separator not a space");
	}
	dst_len = (size_t) ctx->cur_dlen - (size_t) src_len - 1;
	if (dst_len == 0) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "missing destination path");
	}

	/* Parse each half independently so embedded-NUL and traversal checks apply to both. */
	if (!xrootd_extract_path(c->log, ctx->payload, (size_t) src_len,
							 src_buf, sizeof(src_buf), 1)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid source path payload");
	}

	if (!xrootd_extract_path(c->log, ctx->payload + src_len + 1, dst_len,
							 dst_buf, sizeof(dst_buf), 1)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid destination path payload");
	}

	if (!xrootd_resolve_path(c->log, &conf->common.root, src_buf,
							  src_resolved, sizeof(src_resolved))) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "source not found");
	}

	if (xrootd_check_authdb(ctx, src_resolved, XROOTD_AUTH_DELETE) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  kXR_NotAuthorized, "authdb denied for source");
	}

	if (xrootd_check_vo_acl_identity(c->log, src_resolved, conf->vo_rules,
							 ctx->identity) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  kXR_NotAuthorized, "VO not authorized");
	}

	if (xrootd_check_token_scope(ctx, src_buf, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (!xrootd_resolve_path_write(c->log, &conf->common.root, dst_buf,
									dst_resolved, sizeof(dst_resolved))) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "invalid destination path");
	}

	if (xrootd_check_authdb(ctx, dst_resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_resolved, "-",
						  kXR_NotAuthorized, "authdb denied for destination");
	}

	if (xrootd_check_vo_acl_identity(c->log, dst_resolved, conf->vo_rules,
							 ctx->identity) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_resolved, "-",
						  kXR_NotAuthorized, "VO not authorized for destination");
	}

	if (xrootd_check_token_scope(ctx, dst_buf, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_buf, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	/* Rename through root-confined parent fds to close the realpath-to-rename race. */
	if (xrootd_rename_confined(c->log, &conf->common.root, src_resolved,
	                           dst_resolved) != 0) {
		int err = errno;
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  xrootd_kxr_from_errno(err),
						  err == EACCES || err == EPERM ? "permission denied"
						                               : strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MV, "MV", src_resolved, dst_resolved, 0);
}
