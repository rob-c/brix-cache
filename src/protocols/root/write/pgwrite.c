/*
 * pgwrite.c — kXR_pgwrite opcode.  See each function's docblock below.
 */

#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"
#include "pgw_fob.h"          /* CSE uncorrected-page registry */
#include "core/compat/pgio.h"   /* shared kXR page-mode decode (libxrdproto) */

/* pgwrite_retry_spans_multiple_pages()
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

/* Payload decoding helper
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
 * Uses brix_crc32c_copy() to fuse the CRC verification and data copy into a
 * single pass over each page, avoiding the double-read that separate
 * brix_crc32c() + ngx_memcpy() calls would incur.
 */
ngx_int_t
brix_pgwrite_decode_payload(const u_char *payload, size_t payload_len,
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

/* pgw_state_t
 * WHAT: Per-request working state for one kXR_pgwrite, threaded through the
 *       parse / decode / execute helper sequence.
 * WHY:  Keeps the orchestrator flat and each stage independently testable while
 *       passing state explicitly (no new globals) — the request fields decoded
 *       once at parse time and the CSE bad-page list collected at decode time
 *       are both needed by the execute + reply stage.
 * HOW:  Populated by pgwrite_parse_validate (idx/offset/dlen/is_retry/req),
 *       then by pgwrite_decode_collect (flat/flat_sz/bad_pages/bad_count).
 *       `bad_pages` is a fixed kXR_pgMaxEpr array so no allocation is needed. */
typedef struct {
	xrdw_pgwrite_req_t             req;
	ngx_stream_brix_srv_conf_t    *rconf;
	int                            idx;
	int64_t                        offset;
	size_t                         dlen;
	u_char                        *payload;
	int                            is_retry;

	u_char                        *flat;
	size_t                         flat_sz;
	xrdp_pg_bad_t                  bad_pages[kXR_pgMaxEpr];
	size_t                         bad_count;
} pgw_state_t;

/* pgw_fmt_detail()
 * WHAT: Format the "<offset>+<len>" access-log/error detail string used by every
 *       pgwrite reply path.
 * WHY:  The same snprintf triplet appears at each error and success site; one
 *       helper keeps the wire/log detail bytes identical everywhere.
 * HOW:  Pure formatting into the caller-owned buffer. */
static void
pgw_fmt_detail(char *buf, size_t bufsz, int64_t offset, size_t len)
{
	snprintf(buf, bufsz, "%lld+%zu", (long long) offset, len);
}

/* pgwrite_parse_validate()
 * WHAT: Unpack the kXR_pgwrite request header, validate the file handle and
 *       payload bounds, and classify a kXR_pgRetry correction.
 * WHY:  Rejects malformed/oversized requests up front (kXR_ArgInvalid) and
 *       downgrades a stray/forged/recovery retry to a normal write so it can
 *       never corrupt the per-handle Fob (matches stock do_PgWIORetry).
 * HOW:  Fills *st from ctx->recv, then: (1) handle check via the shared
 *       brix_validate_write_handle helper; (2) offset/dlen bounds; (3) if the
 *       retry flag is set, reject a multi-page span and clear the flag when the
 *       target page is not registered as in-error.  Returns 1 with *rc set when
 *       the caller must return immediately; 0 to continue. */
static ngx_flag_t
pgwrite_parse_validate(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    ngx_int_t *rc)
{
	char write_detail[64];

	xrdw_pgwrite_req_unpack(
	    ((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &st->req);
	st->idx      = (int)(unsigned char) st->req.fhandle[0];
	st->offset   = st->req.offset;
	st->dlen     = ctx->recv.cur_dlen;
	st->payload  = ctx->recv.payload;
	st->is_retry = (st->req.reqflags & kXR_pgRetry) != 0;

	if (!brix_validate_write_handle(ctx, c, st->idx, "WRITE",
	                                  BRIX_OP_WRITE, rc)) {
		return 1;
	}

	if (st->offset < 0 || st->dlen <= XRD_PGWRITE_CKSZ) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
		               st->dlen);
		brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
		                  write_detail, 0, kXR_ArgInvalid,
		                  "invalid pgwrite payload", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
		*rc = brix_send_error(ctx, c, kXR_ArgInvalid, "invalid pgwrite payload");
		return 1;
	}

	/* kXR_pgRetry correction request: a retry must correct exactly one
	 * registered page.  Too large → reject.  Not registered (stray/forged
	 * retry, or a resend during write recovery) → drop the retry flag and
	 * treat as a normal write so it cannot corrupt the Fob. */
	if (st->is_retry) {
		size_t page_dlen;

		if (pgwrite_retry_spans_multiple_pages(st->offset, st->dlen)) {
			pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
			               st->dlen);
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITE, "WRITE",
			                  ctx->files[st->idx].path, write_detail,
			                  kXR_ArgInvalid,
			                  "pgwrite retry of more than one page not allowed");
		}
		page_dlen = st->dlen - XRD_PGWRITE_CKSZ;
		if (!brix_pgw_fob_has(&ctx->files[st->idx], st->offset,
		                        (uint32_t) page_dlen)) {
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			    "brix: pgwrite retry %zu@%lld not in error — normal write",
			    page_dlen, (long long) st->offset);
			st->is_retry = 0;
		}
	}

	return 0;
}

/* pgwrite_register_bad_pages()
 * WHAT: Add every freshly-detected corrupt page to the per-handle Fob.
 * WHY:  The bad bytes are still written (accept-then-correct); the Fob is what
 *       blocks a clean kXR_close until every page is corrected.  Per-file
 *       capacity overflow → kXR_TooManyErrs (matches stock addOffs).
 * HOW:  Opens the Fob then adds each collected offset; on overflow sets *rc to
 *       the error reply and returns 1 (caller returns immediately).  Returns 0
 *       when all pages registered. */
static ngx_flag_t
pgwrite_register_bad_pages(brix_ctx_t *ctx, ngx_connection_t *c,
    pgw_state_t *st, ngx_int_t *rc)
{
	char   write_detail[64];
	size_t bi;

	brix_pgw_fob_open(&ctx->files[st->idx]);
	for (bi = 0; bi < st->bad_count; bi++) {
		if (!brix_pgw_fob_add(&ctx->files[st->idx], st->bad_pages[bi].off,
		                        st->bad_pages[bi].dlen)) {
			pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
			               st->dlen);
			brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
			                  write_detail, 0, kXR_TooManyErrs,
			                  "too many uncorrected checksum errors in file", 0);
			BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
			*rc = brix_send_error(ctx, c, kXR_TooManyErrs,
			    "too many uncorrected checksum errors in file");
			return 1;
		}
	}
	return 0;
}

/* pgwrite_decode_collect()
 * WHAT: Decode+CRC-verify the whole payload into the reusable flat buffer,
 *       collect any CRC failures, short-circuit a clean recovery replay, and
 *       register newly-corrupt pages in the Fob.
 * WHY:  Implements the stock CSE (checksum-error) machine: verify EVERY page and
 *       copy them all (good and bad) into flat, so a single corrupt page can be
 *       re-sent without restarting the transfer.  INVARIANT 1 (per-page CRC32c)
 *       is byte-frozen inside xrdp_pg_decode_collect.
 * HOW:  Borrows the per-session write_scratch buffer, runs the shared collect
 *       decode (dn = -3 → kXR_TooManyErrs, dn < 0 → kXR_ArgInvalid), then only
 *       for a non-retry with zero bad pages checks the recovery journal for a
 *       replay (→ SUCCESS pgwrite_status short-circuit).  Bad pages are added to
 *       the Fob.  Returns 1 with *rc set when the caller must return; 0 to
 *       proceed to the write. */
static ngx_flag_t
pgwrite_decode_collect(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    ngx_int_t *rc)
{
	char    write_detail[64];
	ssize_t dn;

	/* Reusable per-session buffer: avoids a malloc/free per request. */
	st->flat = BRIX_GET_SCRATCH(ctx, c, rd.write_scratch,
	                              rd.write_scratch_size, st->dlen);
	st->flat_sz = 0;
	st->bad_count = 0;

	if (st->flat == NULL) {
		*rc = NGX_ERROR;
		return 1;
	}

	/* CSE retransmit: verify ALL pages, copy them all into flat
	 * (accept-then-correct), and collect the failures.  A non-empty list yields
	 * a SUCCESS kXR_status reply carrying the bad page offsets — NOT an error. */
	dn = xrdp_pg_decode_collect(st->payload, st->dlen, st->offset, st->flat,
	                            st->dlen, st->bad_pages, kXR_pgMaxEpr,
	                            &st->bad_count);
	if (dn == -3) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset, st->dlen);
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITE, "WRITE",
		                  ctx->files[st->idx].path, write_detail,
		                  kXR_TooManyErrs,
		                  "too many checksum errors in pgwrite request");
	}
	if (dn < 0) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset, st->dlen);
		BRIX_RETURN_ERR(ctx, c, BRIX_OP_WRITE, "WRITE",
		                  ctx->files[st->idx].path, write_detail,
		                  kXR_ArgInvalid, "invalid pgwrite payload");
	}
	st->flat_sz = (size_t) dn;

	/* kXR_recoverWrts replay detection (post-decode): only short-circuit a clean
	 * replay; a request with bad pages must take the normal accept-then-correct
	 * path so the CSE list is emitted.  A kXR_pgRetry correction deliberately
	 * re-writes a range already in the journal, so it must NOT be mistaken for a
	 * replay (that would skip the Fob correction and leave the close gate stuck). */
	if (!st->is_retry && st->bad_count == 0 &&
	    ctx->files[st->idx].wrts_enabled &&
	    brix_wrts_is_replay(&ctx->files[st->idx], st->offset,
	                          (uint32_t) st->flat_sz))
	{
		ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
		    "brix: pgwrite recovery replay skip offset=%lld len=%zu",
		    (long long) st->offset, st->flat_sz);
		BRIX_OP_OK(ctx, BRIX_OP_WRITE);
		/* info offset = request offset (stock parity), not offset+len. */
		*rc = brix_send_pgwrite_status(ctx, c, st->offset);
		return 1;
	}

	/* Register newly-corrupt pages in the Fob (close-time gate). */
	if (st->bad_count > 0) {
		if (pgwrite_register_bad_pages(ctx, c, st, rc)) {
			return 1;
		}
	}

	return 0;
}

/* pgwrite_execute_sync()
 * WHAT: Write the decoded flat buffer in one syscall, update accounting and
 *       dirty/journal state, clear a corrected retry from the Fob, and send the
 *       mandatory kXR_status reply (CSE list when pages failed CRC32c).
 * WHY:  This is the synchronous path taken when no AIO task was posted (or for a
 *       single-page retry, which commits its Fob correction in-line right after
 *       the write rather than threading retry state through the AIO callback).
 * HOW:  Runs the write through the VFS core, maps a short/failed write to
 *       kXR_IOError, charges bandwidth + write-through dirty tracking, records
 *       the recovery-journal entry, and replies with brix_send_pgwrite_cse when
 *       bad_count > 0 else brix_send_pgwrite_status (info = request offset, stock
 *       parity).  Always sets *rc and returns 1 (terminal stage). */
static ngx_flag_t
pgwrite_execute_sync(brix_ctx_t *ctx, ngx_connection_t *c, pgw_state_t *st,
    ngx_int_t *rc)
{
	char    write_detail[64];
	size_t  total_written;
	ssize_t nw;
	brix_vfs_job_t job;

	/* Synchronous path: write the entire flat buffer in one syscall. */
	brix_vfs_job_write_init(&job, ctx->files[st->idx].fd,
	                          (off_t) st->offset, st->flat, st->flat_sz);
	job.csi = ctx->files[st->idx].csi;   /* phase-59 W2: update page tags */
	brix_vfs_job_set_obj(&job, &ctx->files[st->idx].sd_obj);
	brix_vfs_io_execute(&job);
	nw = job.nio;
	if (job.io_errno != 0) {
		errno = job.io_errno;
	}

	if (nw < 0) {
		const char *ioerr = strerror(errno);

		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
		               st->flat_sz);
		brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
		                  write_detail, 0, kXR_IOError, ioerr, 0);
		BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
		*rc = brix_send_error(ctx, c, kXR_IOError, ioerr);
		return 1;
	}
	if ((size_t) nw < st->flat_sz) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
		               (size_t) nw);
		*rc = brix_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
		brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
		                  write_detail, 0, kXR_IOError,
		                  "short write (disk full?)", 0);
		BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
		return 1;
	}

	total_written = (size_t) nw;

	ctx->files[st->idx].bytes_written += total_written;
	ctx->totals.bytes_written        += total_written;
	brix_rl_charge_ctx(ctx, total_written);  /* Phase 25 bandwidth */

	/* write-through dirty state tracking (mirrors XrdPfcFile::m_dirtyOffset):
	 * when wt_enabled = 1 this handle has a cached DECISION to propagate writes
	 * back to the origin at close time.  Track cumulative bytes and mark the
	 * dirty offset so write-back knows what to flush during close-flush. */
	if (ctx->files[st->idx].wt_enabled) {
		brix_wt_mark_dirty(ctx, st->idx,
		                      st->offset + (int64_t) nw - 1, total_written);
	}

	if (st->rconf->access_log_fd != NGX_INVALID_FILE) {
		pgw_fmt_detail(write_detail, sizeof(write_detail), st->offset,
		               total_written);
		brix_log_access(ctx, c, "WRITE", ctx->files[st->idx].path,
		                  write_detail, 1, 0, NULL, total_written);
	}
	BRIX_OP_OK(ctx, BRIX_OP_WRITE);

	/* A successful retry whose page now verifies clears it from the Fob.
	 * (A still-bad retry kept bad_count > 0 and was re-added, so the close gate
	 * still holds.) */
	if (st->is_retry && st->bad_count == 0) {
		brix_pgw_fob_del(&ctx->files[st->idx], st->offset,
		                   (uint32_t) st->flat_sz);
	}

	/* Record the committed write in the recovery journal. */
	if (ctx->files[st->idx].wrts_enabled) {
		brix_wrts_record(&ctx->files[st->idx], st->offset, (uint32_t) nw);
	}

	/* The kXR_status "info" offset echoes the REQUEST offset (where the data was
	 * written), matching the reference do_pgWrite — NOT offset+len.  When pages
	 * failed CRC32c, the reply is a SUCCESS frame carrying the CSE retransmit
	 * list (accept-then-correct), not a hard error. */
	if (st->bad_count > 0) {
		*rc = brix_send_pgwrite_cse(ctx, c, st->offset, st->bad_pages,
		                              st->bad_count);
	} else {
		*rc = brix_send_pgwrite_status(ctx, c, st->offset);
	}
	return 1;
}

/* pgwrite handler section
 * WHAT: Handle kXR_pgwrite, the page-mode write with a 4-byte CRC32c before
 *       each ≤4 KiB page.  Implements the stock CSE (checksum-error) retransmit
 *       machine: verify EVERY page (xrdp_pg_decode_collect), write ALL pages —
 *       good and bad — to disk, and on any failure reply with a SUCCESS
 *       kXR_status frame carrying the pgWrCSE retransmit list
 *       (brix_send_pgwrite_cse) rather than a hard error.  Each bad page is
 *       registered in the per-handle Fob (pgw_fob.c).
 *
 * WHY:  Accept-then-correct lets a single corrupt page be re-sent without
 *       restarting a multi-GB transfer.  The kXR_close gate (read/close.c)
 *       returns kXR_ChkSumErr while the Fob is non-empty, so a committed file
 *       never retains known-corrupt bytes despite the bad bytes being written.
 *
 * HOW:  A flat, early-return orchestrator over the parse-validate / decode-
 *       collect / execute-sync helper sequence.  A kXR_pgRetry resend is
 *       single-page-bounded, must target a registered offset (else downgraded to
 *       a normal write), takes the synchronous path, and clears its Fob entry on
 *       a clean re-verify.  Non-retry writes try the AIO thread pool first (the
 *       async completion sends the reply); on no-pool fallback they take the
 *       synchronous path.
 */
ngx_int_t
brix_handle_pgwrite(brix_ctx_t *ctx, ngx_connection_t *c)
{
	pgw_state_t st = { 0 };
	ngx_int_t   rc = NGX_OK;

	st.rconf = ngx_stream_get_module_srv_conf(
	    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

	if (pgwrite_parse_validate(ctx, c, &st, &rc)) {
		return rc;
	}

	if (pgwrite_decode_collect(ctx, c, &st, &rc)) {
		return rc;
	}

	/* Whole-object staged-commit adapter (phase-70): a staged write handle has no
	 * random-write fd — append the decoded plaintext to the staged handle (which
	 * enforces sequential offsets) and reply with the mandatory kXR_status frame.
	 * A CSE bad-page list cannot arise here (bad pages take the accept-then-correct
	 * path above, which needs a real fd); a staged upload is a clean sequential
	 * stream, so any decoded buffer is committed as-is. */
	if (ctx->files[st.idx].staged != NULL) {
		if (brix_staged_append(ctx, c, st.idx, st.offset, st.flat,
		                         st.flat_sz, &rc) != NGX_OK) {
			return rc;   /* error already sent (sequential-append / IO) */
		}
		BRIX_OP_OK(ctx, BRIX_OP_WRITE);
		return brix_send_pgwrite_status(ctx, c, st.offset);
	}

	/* Retries are single-page (≤ 4 KiB): take the synchronous path so the Fob
	 * correction (brix_pgw_fob_del) commits in-line right after the write,
	 * rather than threading retry state through the AIO callback. */
	if (!st.is_retry) {
		ngx_flag_t posted = 0;

		/* Pass NULL as payload_to_free: flat is rd.write_scratch (pool-managed,
		 * not heap-allocated) and must not be freed by the done handler.  The CSE
		 * bad-page list (if any) rides along so the async completion sends the
		 * retransmit frame. */
		rc = brix_try_post_write_aio(ctx, c, st.idx, (off_t) st.offset, st.flat,
		                               st.flat_sz, st.offset, 1, NULL,
		                               st.bad_count ? st.bad_pages : NULL,
		                               st.bad_count,
		                               "brix: thread_task_post failed, falling back to sync pgwrite",
		                               &posted);
		if (rc != NGX_OK) {
			return rc;
		}
		if (posted) {
			/* Async completion sends the mandatory kXR_status pgwrite reply. */
			return NGX_OK;
		}
	}

	(void) pgwrite_execute_sync(ctx, c, &st, &rc);
	return rc;
}
