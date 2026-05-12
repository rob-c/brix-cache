/*
 * pgwrite.c â kXR_pgwrite opcode handler and CRC-decode helper.
 */
#include "ngx_xrootd_module.h"


/*
 * Decode a kXR_pgwrite payload into a flat pwrite() buffer.
 *
 * Payload layout is CRC first:
 *   [XRD_PGWRITE_CKSZ=4 bytes CRC32c][up to XRD_PGWRITE_PAGESZ=4096 bytes data]
 * repeated for each page fragment. The first and last fragments may be shorter
 * when the write offset is unaligned or the request ends mid-page.
 *
 * Returns NGX_OK on success, NGX_DECLINED on checksum mismatch, and NGX_ERROR
 * for malformed framing.
 *
 * Uses xrootd_crc32c_copy() to fuse the CRC verification and data copy into a
 * single pass over each page, avoiding the double-read that separate
 * xrootd_crc32c() + ngx_memcpy() calls would incur.
 */
ngx_int_t
xrootd_pgwrite_decode_payload(const u_char *payload, size_t payload_len,
    int64_t offset, u_char *flat, size_t *flat_len, int64_t *bad_offset)
{
	const u_char *src;
	u_char       *dst;
	size_t        rem;
	size_t        flat_sz;
	int64_t       page_offset;

	if (flat_len == NULL || bad_offset == NULL || offset < 0) {
		return NGX_ERROR;
	}

	*flat_len = 0;
	*bad_offset = offset;

	if (payload == NULL || flat == NULL || payload_len <= XRD_PGWRITE_CKSZ) {
		return NGX_ERROR;
	}

	src = payload;
	dst = flat;
	rem = payload_len;
	flat_sz = 0;
	page_offset = offset;

	while (rem > 0) {
		uint32_t expected;
		uint32_t actual;
		size_t   page_off;
		size_t   page_room;
		size_t   page_data;

		if (rem <= XRD_PGWRITE_CKSZ) {
			*bad_offset = page_offset;
			return NGX_ERROR;
		}

		ngx_memcpy(&expected, src, sizeof(expected));
		expected = ntohl(expected);
		src += XRD_PGWRITE_CKSZ;
		rem -= XRD_PGWRITE_CKSZ;

		page_off = (size_t) (page_offset % XRD_PGWRITE_PAGESZ);
		page_room = XRD_PGWRITE_PAGESZ - page_off;
		page_data = (rem >= page_room) ? page_room : rem;

		/* Copy src→dst and compute CRC in one pass (single read of each byte). */
		actual = xrootd_crc32c_copy(src, dst, page_data);
		if (actual != expected) {
			*bad_offset = page_offset;
			return NGX_DECLINED;
		}

		if (page_offset > INT64_MAX - (int64_t) page_data) {
			*bad_offset = page_offset;
			return NGX_ERROR;
		}

		dst += page_data;
		src += page_data;
		rem -= page_data;
		flat_sz += page_data;
		page_offset += (int64_t) page_data;
	}

	*flat_len = flat_sz;
	return NGX_OK;
}


/*
 * xrootd_handle_pgwrite — handle kXR_pgwrite: decode the CRC-interleaved
 * page-write payload and write the plain data to the file.
 *
 * Wire format: identical to kXR_write but the payload interleaves
 * 4-byte CRC32C records between page fragments.  The CRC is verified via
 * xrootd_pgwrite_decode_payload before any pwrite(2).  A CRC mismatch
 * returns kXR_ChkSumErr with bad_offset in the error message.
 *
 * On success, the response is a kXR_status packet with the next expected
 * file offset (not kXR_ok) — sent via xrootd_send_pgwrite_status.
 */
ngx_int_t
xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
	ClientPgWriteRequest         *req  = (ClientPgWriteRequest *) ctx->hdr_buf;
	ngx_stream_xrootd_srv_conf_t *rconf;
	int     idx    = (int)(unsigned char) req->fhandle[0];
	int64_t offset = (int64_t) be64toh((uint64_t) req->offset);
	size_t  dlen   = ctx->cur_dlen;
	u_char *payload = ctx->payload;
	ngx_int_t rc;
	int64_t write_offset;
	size_t  total_written;
	ssize_t nw;
	char    write_detail[64];

	rconf = ngx_stream_get_module_srv_conf(
	    (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

	if (!xrootd_validate_write_handle(ctx, c, idx, "WRITE",
									  XROOTD_OP_WRITE, &rc)) {
		return rc;
	}
	if (offset < 0 || dlen <= XRD_PGWRITE_CKSZ) {
		snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
				 (long long) offset, dlen);
		xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
						  write_detail, 0, kXR_ArgInvalid,
						  "invalid pgwrite payload", 0);
		XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
		return xrootd_send_error(ctx, c, kXR_ArgInvalid,
								  "invalid pgwrite payload");
	}

	{
		/* Reusable per-session buffer: avoids a malloc/free per request. */
		u_char *flat    = xrootd_get_write_scratch(ctx, c, dlen);
		size_t  flat_sz = 0;
		int64_t bad_offset = offset;

		if (flat == NULL) { return NGX_ERROR; }

		rc = xrootd_pgwrite_decode_payload(payload, dlen, offset, flat,
										   &flat_sz, &bad_offset);
		if (rc != NGX_OK) {
			uint16_t status = (rc == NGX_DECLINED) ? kXR_ChkSumErr
												   : kXR_ArgInvalid;
			const char *msg = (rc == NGX_DECLINED) ? "pgwrite checksum mismatch"
												   : "invalid pgwrite payload";

			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) bad_offset, dlen);
			xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
							  write_detail, 0, status, msg, 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
			return xrootd_send_error(ctx, c, status, msg);
		}

#if (NGX_THREADS)
		{
		ngx_flag_t posted;

		/* Pass NULL as payload_to_free: flat is write_scratch (pool-managed,
		 * not heap-allocated) and must not be freed by the done handler. */
		rc = xrootd_try_post_write_aio(ctx, c, idx, (off_t) offset, flat,
									   flat_sz, offset, 1, NULL,
									   "xrootd: thread_task_post failed, falling back to sync pgwrite",
									   &posted);
		if (rc != NGX_OK) {
			return rc;
		}
		if (posted) {
			/* Async completion sends the mandatory kXR_status pgwrite reply. */
			return NGX_OK;
		}
		} /* end NGX_THREADS block */
#endif /* NGX_THREADS */

		/* Synchronous path: write the entire flat buffer in one syscall. */
		write_offset = offset;
		nw = pwrite(ctx->files[idx].fd, flat, flat_sz, (off_t) write_offset);
		if (nw < 0) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, flat_sz);
			xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
							  write_detail, 0, kXR_IOError, strerror(errno), 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
			return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
		}
		if ((size_t) nw < flat_sz) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, (size_t) nw);
			xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
							  write_detail, 0, kXR_IOError,
							  "short write (disk full?)", 0);
			XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
			return xrootd_send_error(ctx, c, kXR_IOError,
									  "short write (disk full?)");
		}

		total_written  = (size_t) nw;
		write_offset  += (int64_t) nw;

		ctx->files[idx].bytes_written += total_written;
		ctx->session_bytes_written    += total_written;

		if (rconf->access_log_fd != NGX_INVALID_FILE) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, total_written);
			xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
							  write_detail, 1, 0, NULL, total_written);
		}
		XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

		return xrootd_send_pgwrite_status(ctx, c, write_offset);
	}
}
