/* ------------------------------------------------------------------ */
/* Paged Write — kXR_pgwrite with CRC32c Integrity                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_pgwrite opcode — page-mode writes used by xrdcp v5 for high-integrity large-file transfers. The payload interleaves 4-byte CRC32c checksums between each page fragment (up to 4096 bytes), ensuring every byte written is verified against its checksum before pwrite(2). Unlike kXR_write which returns kXR_ok, pgwrite responses use kXR_status with the next expected offset — this allows clients to track write progress precisely through large transfers.
 *
 * WHY: Page-mode writes provide byte-level integrity verification for large file uploads where single-segment kXR_write would offer no checksum protection. CRC32c per-page verification ensures data corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file. The kXR_status response (next expected offset) enables precise progress tracking, critical for resumable transfers and monitoring large uploads in production deployments.
 *
 * HOW: Two-phase flow → payload decode (xrootd_pgwrite_decode_payload): interleaved CRC+data → flat buffer with per-page checksum verification — CRC mismatch returns NGX_DECLINED (kXR_ChkSumErr), malformed framing returns NGX_ERROR) → write handler performs same kXR_write flow plus additional validation: verifies payload integrity via decode(), then writes flat buffer to file using pwrite(2) on worker thread or inline — updates byte counters + tracks write-through dirty state if wt_enabled=1 — returns kXR_status response (not kXR_ok) containing next expected offset for client tracking. */

/* ------------------------------------------------------------------ */
/* Section: Payload Decoding with CRC Verification                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pgwrite_decode_payload() decodes the CRC-interleaved payload into a flat buffer suitable for pwrite(2). Each page fragment is verified independently: CRC must match before data is copied to flat buffer. Checksum mismatch returns NGX_DECLINED (kXR_ChkSumErr); malformed framing returns NGX_ERROR. Uses xrootd_crc32c_copy() to fuse the CRC verification and data copy into a single pass over each page, avoiding the double-read that separate xrootd_crc32c() + ngx_memcpy() calls would incur — this reduces memory bandwidth usage during large transfers.
 *
 * WHY: Single-pass CRC+copy fusion eliminates unnecessary memory reads by combining checksum computation with data extraction in one operation. For large transfers (10GB+ files), this reduction in memory bandwidth can significantly improve throughput on systems where cache pressure is a bottleneck. Per-page verification ensures corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file.
 *
 * HOW: Four-phase decode → parse payload length and offset from wire format — iterate through page fragments (CRC first, then data) — compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to flat buffer — compare computed CRC against stored CRC — return NGX_OK if match, NGX_DECLINED if mismatch, NGX_ERROR for malformed framing. First and last fragments may be shorter when write offset is unaligned or request ends mid-page. */

/* ------------------------------------------------------------------ */
/* Section: Write Handler with Status Response                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_pgwrite() performs the same write flow as kXR_write but with additional validation and different response format. After decoding payload integrity, writes flat buffer to file using pwrite(2) (either AIO thread-pool or inline fallback). Returns kXR_status response (not kXR_ok) containing next expected offset for client progress tracking — this enables precise monitoring of large transfers and supports resumable upload scenarios where clients can resume from the last verified offset.
 *
 * WHY: The kXR_status response format provides clients with exact progress information during large transfers, enabling retry logic if transfer fails mid-way. Unlike kXR_ok (which simply confirms completion), kXR_status tells clients exactly what offset to expect next — critical for resumable uploads where partial failures must be recoverable without complete retransmission. Write-through dirty state tracking uses same logic as write.c: when wt_enabled=1 this handle has a cached DECISION for future close-time write-back, tracking cumulative bytes written and marking dirty offsets.
 *
 * HOW: Three-phase write → validate file handle (xrootd_validate_read_handle for read-side validation) — decode payload integrity via xrootd_pgwrite_decode_payload() — perform pwrite(2) on flat buffer (AIO thread-pool or inline fallback) — update byte counters + track write-through dirty state if wt_enabled=1 — return kXR_status response containing next expected offset for client tracking. */

/* ------------------------------------------------------------------ */
/* Section: Payload Decoding Helper                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pgwrite_decode_payload() decodes a kXR_pgwrite payload into a flat pwrite(2) buffer. Payload layout is CRC first: [XRD_PGWRITE_CKSZ=4 bytes CRC32c][up to XRD_PGWRITE_PAGESZ=4096 bytes data] repeated for each page fragment. The first and last fragments may be shorter when the write offset is unaligned or the request ends mid-page. Returns NGX_OK on success, NGX_DECLINED on checksum mismatch (kXR_ChkSumErr), and NGX_ERROR for malformed framing.
 *
 * WHY: Single-pass CRC+copy fusion via xrootd_crc32c_copy() avoids double-read overhead that separate xrootd_crc32c() + ngx_memcpy() calls would incur — this reduces memory bandwidth usage during large transfers where cache pressure is a bottleneck. Per-page checksum verification ensures data corruption is detected immediately rather than after transfer completion, enabling clients to retry corrupted pages without retransmitting the entire file.
 *
 * HOW: Four-phase decode → parse payload length and offset from wire format — iterate through page fragments (CRC first, then data) — compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to flat buffer — compare computed CRC against stored CRC in each fragment — return NGX_OK if match, NGX_DECLINED if mismatch, NGX_ERROR for malformed framing. */

/* ---- Function: xrootd_pgwrite_decode_payload() ----
 *
 * WHAT: Decodes a kXR_pgwrite payload into a flat pwrite(2) buffer suitable for disk I/O. Payload layout is CRC first: [XRD_PGWRITE_CKSZ=4 bytes CRC32c][up to XRD_PGWRITE_PAGESZ=4096 bytes data] repeated for each page fragment. The first and last fragments may be shorter when the write offset is unaligned or the request ends mid-page. Returns NGX_OK on success, NGX_DECLINED on checksum mismatch (kXR_ChkSumErr), and NGX_ERROR for malformed framing. Uses xrootd_crc32c_copy() to fuse CRC verification and data copy into a single pass over each page, avoiding double-read overhead from separate crc32c() + memcpy calls.
 *
 * WHY: Single-pass CRC+copy fusion eliminates unnecessary memory reads by combining checksum computation with data extraction in one operation. For large transfers (10GB+ files), this reduction in memory bandwidth can significantly improve throughput on systems where cache pressure is a bottleneck. Per-page checksum verification ensures data corruption is detected immediately rather than after transfer completion, enabling clients to retry corrupted pages without retransmitting the entire file.
 *
 * HOW: Four-phase decode → parse payload length and offset from wire format — iterate through page fragments (CRC first, then data) — compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to flat buffer — compare computed CRC against stored CRC in each fragment — return NGX_OK if match, NGX_DECLINED if mismatch, NGX_ERROR for malformed framing. */

/*
 * pgwrite.c — kXR_pgwrite opcode handler and CRC-decode helper.
 *
 * Page-mode writes (kXR_pgwrite) are used by xrdcp v5 for high-integrity transfers.
 * The payload interleaves 4-byte CRC32c checksums between each page fragment:
 *   [CRC32c(4 bytes)][Data(up to 4096 bytes)] repeated per page
 * This ensures every byte written is verified against its checksum before pwrite().
 *
 * Unlike kXR_write which returns kXR_ok, pgwrite responses use kXR_status with the
 * next expected offset — this allows clients to track write progress precisely. */

/* ---- Payload decoding section ----
 *
 * This decodes the CRC-interleaved payload into a flat buffer suitable for pwrite().
 * Each page fragment is verified: CRC must match before data is copied to flat buffer.
 * Checksum mismatch returns NGX_DECLINED (kXR_ChkSumErr); malformed framing returns NGX_ERROR. */

/* ---- Write handler section ----
 *
 * After decoding, this performs the same write flow as kXR_write but with additional
 * validation: verifies payload integrity via decode(), then writes flat buffer to file.
 * Returns kXR_status response (not kXR_ok) containing next expected offset for client tracking. */

/* ---- Write-through dirty state tracking section ----
 *
 * Same logic as write.c: when wt_enabled = 1 this handle has a cached DECISION to propagate
 * writes back to the origin at close time. We track cumulative bytes written and mark the
 * dirty offset so a future close-time write-back implementation knows what data needs flushing. */

#include "ngx_xrootd_module.h"
#include "cache/writethrough_metrics.h"
#include "wrts_journal.h"

/* ---- Payload decoding helper ----
 *
 * Decodes a kXR_pgwrite payload into a flat pwrite() buffer.
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

/* ---- pgwrite handler section ----
 *
 * Handle kXR_pgwrite: decode the CRC-interleaved page-write payload and write
 * the plain data to the file.
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

	/* ---- kXR_recoverWrts replay detection ----
	 *
	 * If the journal already covers this (offset, dlen) range, this is a
	 * replayed write from a recovering XrdCl client.  Note: pgwrite dlen
	 * includes CRC overhead, but we only care about the target range.
	 * The decode loop handles exact byte counts; for replay check we
	 * use the requested offset and the expected flat size.
	 */
	if (ctx->files[idx].wrts_enabled) {
		/* We don't have flat_sz yet, so we use a conservative estimate or
		 * check after decode. Checking after decode is safer since we know
		 * exactly what was recovered. */
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

		/* ---- kXR_recoverWrts replay detection (post-decode) ---- */
		if (ctx->files[idx].wrts_enabled &&
		    xrootd_wrts_is_replay(&ctx->files[idx], offset, (uint32_t) flat_sz))
		{
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "xrootd: pgwrite recovery replay skip offset=%lld len=%zu",
			    (long long) offset, flat_sz);
			XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
			return xrootd_send_pgwrite_status(ctx, c, offset + (int64_t) flat_sz);
		}

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

		/* ---- write-through dirty state tracking (mirrors XrdPfcFile::m_dirtyOffset) ----
		 *
		 * Same logic as in write.c: when wt_enabled = 1 this handle has a cached
		 * DECISION to propagate writes back to the origin at close time. We track
		 * cumulative bytes written and mark the dirty offset so write-back
		 * knows what data needs to be flushed during the close-flush phase.
		 */
		if (ctx->files[idx].wt_enabled) {
			xrootd_wt_mark_dirty(ctx, idx, offset + (int64_t) nw - 1,
			                      total_written);
		}

		if (rconf->access_log_fd != NGX_INVALID_FILE) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, total_written);
			xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
							  write_detail, 1, 0, NULL, total_written);
		}
		XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

		/* Record the committed write in the recovery journal. */
		if (ctx->files[idx].wrts_enabled) {
			xrootd_wrts_record(&ctx->files[idx], offset, (uint32_t) nw);
		}

		return xrootd_send_pgwrite_status(ctx, c, write_offset);
	}
}
