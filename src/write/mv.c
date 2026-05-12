/*
 * mv.c â kXR_mv opcode handler: atomic rename within the export root.
 */
#include "ngx_xrootd_module.h"

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
							 src_buf, sizeof(src_buf), 0)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid source path payload");
	}

	if (!xrootd_extract_path(c->log, ctx->payload + src_len + 1, dst_len,
							 dst_buf, sizeof(dst_buf), 0)) {
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								 "invalid destination path payload");
	}

	if (!xrootd_resolve_path(c->log, &conf->root, src_buf,
							  src_resolved, sizeof(src_resolved))) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "source not found");
	}

	if (xrootd_check_authdb(ctx, src_resolved, XROOTD_AUTH_DELETE) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  kXR_NotAuthorized, "authdb denied for source");
	}

	if (xrootd_check_vo_acl(c->log, src_resolved, conf->vo_rules,
							 ctx->vo_list) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  kXR_NotAuthorized, "VO not authorized");
	}

	if (xrootd_check_token_scope(ctx, src_buf, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	if (!xrootd_resolve_path_write(c->log, &conf->root, dst_buf,
									dst_resolved, sizeof(dst_resolved))) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_buf, "-",
						  kXR_NotFound, "invalid destination path");
	}

	if (xrootd_check_authdb(ctx, dst_resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_resolved, "-",
						  kXR_NotAuthorized, "authdb denied for destination");
	}

	if (xrootd_check_vo_acl(c->log, dst_resolved, conf->vo_rules,
							 ctx->vo_list) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_resolved, "-",
						  kXR_NotAuthorized, "VO not authorized for destination");
	}

	if (xrootd_check_token_scope(ctx, dst_buf, 1) != NGX_OK) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", dst_buf, "-",
						  kXR_NotAuthorized, "token scope denied");
	}

	/* Rename through root-confined parent fds to close the realpath-to-rename race. */
	if (xrootd_rename_confined(c->log, &conf->root, src_resolved,
	                           dst_resolved) != 0) {
		int err = errno;
		if (err == EACCES || err == EPERM) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
							  kXR_NotAuthorized, "permission denied");
		}
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
						  kXR_IOError, strerror(err));
	}

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MV, "MV", src_resolved, dst_resolved, 0);
}
