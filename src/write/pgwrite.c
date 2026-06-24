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
#include "pgw_fob.h"          /* CSE uncorrected-page registry */
#include "../compat/pgio.h"   /* shared kXR page-mode decode (libxrdproto) */

/* ---- pgwrite_retry_spans_multiple_pages() ----
 *
 * A kXR_pgRetry resend must correct exactly one page.  Mirrors stock
 * do_PgWIORetry: an unaligned offset may carry at most (bytes-to-boundary + one
 * CRC); an aligned offset at most one page unit (kXR_pgUnitSZ = 4100).  Returns
 * 1 if the wire payload `dlen` is too large to be a single-page retry. */
static int
pgwrite_retry_spans_multiple_pages(int64_t offset, size_t dlen)
{
    size_t in_page = (size_t) (offset & (int64_t) (kXR_pgPageSZ - 1));

    if (in_page != 0) {
        size_t to_boundary = (size_t) kXR_pgPageSZ - in_page;
        return dlen > to_boundary + XRD_PGWRITE_CKSZ;
    }
    return dlen > (size_t) kXR_pgUnitSZ;
}

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
	ssize_t n;

	if (flat_len == NULL || bad_offset == NULL || offset < 0) {
		return NGX_ERROR;
	}

	*flat_len = 0;
	*bad_offset = offset;

	if (payload == NULL || flat == NULL || payload_len <= XRD_PGWRITE_CKSZ) {
		return NGX_ERROR;
	}

	/* Shared single-pass decode (libxrdproto): verify each page's CRC32c while
	 * copying into the flat pwrite buffer — byte-identical to what the native
	 * client encodes. -1 = a page's CRC mismatched (→ kXR_ChkSumErr); -2 =
	 * malformed framing / offset overflow. dstcap = payload_len is a safe upper
	 * bound (decoded data is always < payload by at least one CRC). */
	n = xrdp_pg_decode(payload, payload_len, offset, flat, payload_len,
	                   bad_offset);
	if (n == -1) {
		return NGX_DECLINED;
	}
	if (n < 0) {
		return NGX_ERROR;
	}
	*flat_len = (size_t) n;
	return NGX_OK;
}

/* ---- pgwrite handler section ----
 *
 * WHAT: Handle kXR_pgwrite, the page-mode write with a 4-byte CRC32c before
 *       each ≤4 KiB page.  Implements the stock CSE (checksum-error) retransmit
 *       machine: verify EVERY page (xrdp_pg_decode_collect), write ALL pages —
 *       good and bad — to disk, and on any failure reply with a SUCCESS
 *       kXR_status frame carrying the pgWrCSE retransmit list
 *       (xrootd_send_pgwrite_cse) rather than a hard error.  Each bad page is
 *       registered in the per-handle Fob (pgw_fob.c).
 *
 * WHY:  Accept-then-correct lets a single corrupt page be re-sent without
 *       restarting a multi-GB transfer.  The kXR_close gate (read/close.c)
 *       returns kXR_ChkSumErr while the Fob is non-empty, so a committed file
 *       never retains known-corrupt bytes despite the bad bytes being written.
 *
 * HOW:  A kXR_pgRetry resend (reqflags) is single-page-bounded, must target a
 *       registered offset (else downgraded to a normal write), takes the
 *       synchronous path, and clears its Fob entry on a clean re-verify.  Over
 *       kXR_pgMaxEpr errors in one request, or kXR_pgMaxEos outstanding per
 *       file, → kXR_TooManyErrs; malformed framing → kXR_ArgInvalid.  A clean
 *       write replies via xrootd_send_pgwrite_status (info = request offset).
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
	int     is_retry = (req->reqflags & kXR_pgRetry) != 0;
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
		XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
						  ctx->files[idx].path, write_detail,
						  kXR_ArgInvalid, "invalid pgwrite payload");
	}

	/* ---- kXR_pgRetry correction request ----
	 * A retry must correct exactly one registered page.  Too large → reject.
	 * Not registered (stray/forged retry, or a resend during write recovery)
	 * → drop the retry flag and treat as a normal write so it cannot corrupt
	 * the Fob (matches stock do_PgWIORetry). */
	if (is_retry) {
		size_t page_dlen;

		if (pgwrite_retry_spans_multiple_pages(offset, dlen)) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, dlen);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
							  ctx->files[idx].path, write_detail,
							  kXR_ArgInvalid,
							  "pgwrite retry of more than one page not allowed");
		}
		page_dlen = dlen - XRD_PGWRITE_CKSZ;
		if (!xrootd_pgw_fob_has(&ctx->files[idx], offset,
		                        (uint32_t) page_dlen)) {
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "xrootd: pgwrite retry %zu@%lld not in error — normal write",
			    page_dlen, (long long) offset);
			is_retry = 0;
		}
	}

	{
		/* Reusable per-session buffer: avoids a malloc/free per request. */
		u_char *flat    = XROOTD_GET_SCRATCH(ctx, c, write_scratch,
		                                     write_scratch_size, dlen);
		size_t  flat_sz = 0;
		/* CSE (checksum-error) retransmit: verify ALL pages, copy them all into
		 * flat (accept-then-correct, matching stock), and collect the failures.
		 * A non-empty list yields a SUCCESS kXR_status reply carrying the bad
		 * page offsets — NOT a hard error. */
		xrdp_pg_bad_t bad_pages[kXR_pgMaxEpr];
		size_t        bad_count = 0;
		ssize_t       dn;

		if (flat == NULL) { return NGX_ERROR; }

		dn = xrdp_pg_decode_collect(payload, dlen, offset, flat, dlen,
		                            bad_pages, kXR_pgMaxEpr, &bad_count);
		if (dn == -3) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, dlen);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
							  ctx->files[idx].path, write_detail,
							  kXR_TooManyErrs,
							  "too many checksum errors in pgwrite request");
		}
		if (dn < 0) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, dlen);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
							  ctx->files[idx].path, write_detail,
							  kXR_ArgInvalid, "invalid pgwrite payload");
		}
		flat_sz = (size_t) dn;

		/* ---- kXR_recoverWrts replay detection (post-decode) ----
		 * Only short-circuit a clean replay; a request with bad pages must take
		 * the normal accept-then-correct path so the CSE list is emitted.  A
		 * kXR_pgRetry correction deliberately re-writes a range already in the
		 * journal, so it must NOT be mistaken for a replay (that would skip the
		 * Fob correction and leave the close gate stuck). */
		if (!is_retry && bad_count == 0 && ctx->files[idx].wrts_enabled &&
		    xrootd_wrts_is_replay(&ctx->files[idx], offset, (uint32_t) flat_sz))
		{
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "xrootd: pgwrite recovery replay skip offset=%lld len=%zu",
			    (long long) offset, flat_sz);
			XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
			/* info offset = request offset (stock parity), not offset+len. */
			return xrootd_send_pgwrite_status(ctx, c, offset);
		}

		/* ---- register newly-corrupt pages in the Fob (close-time gate) ----
		 * The data is still written (accept-then-correct); the Fob is what
		 * blocks a clean close until every page is corrected.  Per-file
		 * capacity overflow → kXR_TooManyErrs (matches stock addOffs). */
		if (bad_count > 0) {
			size_t bi;

			xrootd_pgw_fob_open(&ctx->files[idx]);
			for (bi = 0; bi < bad_count; bi++) {
				if (!xrootd_pgw_fob_add(&ctx->files[idx], bad_pages[bi].off,
				                        bad_pages[bi].dlen)) {
					snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
							 (long long) offset, dlen);
					XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
									  ctx->files[idx].path, write_detail,
									  kXR_TooManyErrs,
									  "too many uncorrected checksum errors in file");
				}
			}
		}

		/* Retries are single-page (≤ 4 KiB): take the synchronous path so the
		 * Fob correction (xrootd_pgw_fob_del) commits in-line right after the
		 * write, rather than threading retry state through the AIO callback. */
		if (!is_retry) {
		ngx_flag_t posted;

		/* Pass NULL as payload_to_free: flat is write_scratch (pool-managed,
		 * not heap-allocated) and must not be freed by the done handler.
		 * The CSE bad-page list (if any) rides along so the async completion
		 * sends the retransmit frame. */
		rc = xrootd_try_post_write_aio(ctx, c, idx, (off_t) offset, flat,
									   flat_sz, offset, 1, NULL,
									   bad_count ? bad_pages : NULL, bad_count,
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
		{
			xrootd_vfs_job_t job;

			xrootd_vfs_job_write_init(&job, ctx->files[idx].fd,
									  (off_t) write_offset, flat, flat_sz);
			xrootd_vfs_io_execute(&job);
			nw = job.nio;
			if (job.io_errno != 0) {
				errno = job.io_errno;
			}
		}
		if (nw < 0) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, flat_sz);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
							  ctx->files[idx].path, write_detail,
							  kXR_IOError, strerror(errno));
		}
		if ((size_t) nw < flat_sz) {
			snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
					 (long long) offset, (size_t) nw);
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
							  ctx->files[idx].path, write_detail,
							  kXR_IOError, "short write (disk full?)");
		}

		total_written  = (size_t) nw;
		write_offset  += (int64_t) nw;

		ctx->files[idx].bytes_written += total_written;
		ctx->session_bytes_written    += total_written;
		xrootd_rl_charge_ctx(ctx, total_written);  /* Phase 25 bandwidth */

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

		/* A successful retry whose page now verifies clears it from the Fob.
		 * (A still-bad retry kept bad_count > 0 and was re-added above, so the
		 * close gate still holds.) */
		if (is_retry && bad_count == 0) {
			xrootd_pgw_fob_del(&ctx->files[idx], offset, (uint32_t) flat_sz);
		}

		/* Record the committed write in the recovery journal. */
		if (ctx->files[idx].wrts_enabled) {
			xrootd_wrts_record(&ctx->files[idx], offset, (uint32_t) nw);
		}

		/* The kXR_status "info" offset echoes the REQUEST offset (where the data
		 * was written), matching the reference do_pgWrite — NOT offset+len.  A
		 * next-expected-offset here diverged from stock (test_conf_pgio).
		 * When pages failed CRC32c, the reply is a SUCCESS frame carrying the
		 * CSE retransmit list (accept-then-correct), not a hard error. */
		(void) write_offset;
		if (bad_count > 0) {
			return xrootd_send_pgwrite_cse(ctx, c, offset,
			                               bad_pages, bad_count);
		}
		return xrootd_send_pgwrite_status(ctx, c, offset);
	}
}
