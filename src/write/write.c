/*
 * write.c — kXR_write opcode handler.
 */
#include "ngx_xrootd_module.h"

/*
 * xrootd_handle_write — handle kXR_write: write the request payload to an
 * open file at the specified offset.
 *
 * Wire format (from ClientWriteRequest):
 *   fhandle[4]: open file handle (first byte is the slot index)
 *   offset:     big-endian int64 file position
 *   dlen:       payload byte count (ctx->cur_dlen, already received)
 *
 * When a thread pool is configured, the pwrite is posted asynchronously and
 * the payload buffer is detached from ctx->payload_buf so the main thread can
 * safely begin reading the next request header.  The done callback frees the
 * detached buffer and sends the kXR_ok response.
 *
 * Falls back to synchronous pwrite if no thread pool is configured or the
 * thread pool queue is full.
 *
 * Access-log detail: "<offset>+<requested-bytes>"
 */
ngx_int_t
xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
	ClientWriteRequest           *req  = (ClientWriteRequest *) ctx->hdr_buf;
	int     idx    = (int)(unsigned char) req->fhandle[0];
	int64_t offset = (int64_t) be64toh((uint64_t) req->offset);
	size_t  wlen   = ctx->cur_dlen;
	ngx_int_t rc;
	ssize_t nwritten;
	char    write_detail[64];

	if (!xrootd_validate_write_handle(ctx, c, idx, "WRITE",
									  XROOTD_OP_WRITE, &rc)) {
		return rc;
	}

	if (wlen == 0) {
		/* Zero-length writes are valid no-ops that still count as successful requests. */
		XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
		return xrootd_send_ok(ctx, c, NULL, 0);
	}

#if (NGX_THREADS)
	{
	ngx_flag_t posted;

	rc = xrootd_try_post_write_aio(ctx, c, idx, (off_t) offset,
								   ctx->payload ? ctx->payload : (u_char *) "",
								   wlen, offset, 0, ctx->payload,
								   "xrootd: thread_task_post failed, falling back to sync write",
								   &posted);
	if (rc != NGX_OK) {
		return rc;
	}
	if (posted) {
		ctx->payload = NULL;
		ctx->payload_buf = NULL;
		ctx->payload_buf_size = 0;
		/* Completion callback will restore streamid/state and send the final reply. */
		return NGX_OK;
	}
	} /* end NGX_THREADS block */

#endif /* NGX_THREADS */

	/* Synchronous fallback writes the request payload directly from the recv buffer. */
	nwritten = pwrite(ctx->files[idx].fd,
					  ctx->payload ? ctx->payload : (u_char *) "",
					  wlen, (off_t) offset);

	/* Access log detail format for writes is "<offset>+<requested-bytes>". */
	snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
			 (long long) offset, wlen);

	if (nwritten < 0) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, strerror(errno));
	}

	if ((size_t) nwritten < wlen) {
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_IOError, "short write (disk full?)");
	}

	ctx->files[idx].bytes_written  += (size_t) nwritten;
	ctx->session_bytes_written     += (size_t) nwritten;

	XROOTD_RETURN_OK(ctx, c, XROOTD_OP_WRITE, "WRITE",
					 ctx->files[idx].path, write_detail, (size_t) nwritten);
}
