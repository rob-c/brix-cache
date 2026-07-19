#include "open.h"
#include "fs/vfs/vfs.h"   /* VFS confined open/probe seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */
#include "fs/vfs/vfs_backend_registry.h"  /* per-export storage-driver resolution */
#include "fs/vfs/vfs_internal.h"          /* brix_vfs_export_relative_root key form */
#include "fs/backend/sd.h"            /* Layer 3: driver-backed export open */
#include "core/ngx_brix_module.h"
#include "fs/backend/csi_tagstore.h"
#include "net/ratelimit/throttle_compat.h"  /* phase-59 W3a: open-files cap */
#include "protocols/root/response/async.h"
#include "net/mirror/stream_wmirror.h"
#include "protocols/root/write/wrts_journal.h"
#include "core/compat/tmp_path.h"
#include "fs/cache/writethrough_metrics.h"
#include "fs/cache/cache_storage.h"   /* driver-backed read-cache serve + key helper */
#include "net/manager/registry.h"
#include "net/manager/pending.h"
#include "protocols/root/session/registry.h"
#include "core/compat/codec_core.h"
#include "protocols/root/protocol/open_flags.h"   /* shared kXR_open option-bit semantics */
#include "protocols/root/protocol/stat_flags.h"   /* brix_stat_flags_from_stat (StatGen parity) */
#include "observability/sesslog/sesslog_ngx.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>   /* open(2) flags + fcntl() to clear O_NONBLOCK post-open */
#include "open_resolved_file_internal.h"

/*
 * open_resolved_file.c — kXR_open resolved-file orchestrator + reply assembly
 * (phase-79: pipeline stages split into open_resolved_file_{staging,open,
 * dispatch,finalize}.c; shared state + entry points in
 * open_resolved_file_internal.h).
 *
 * WHAT: brix_open_resolved_file — the top-level pipeline that gathers the
 *       per-open state, runs the staging preflight, dispatches the open,
 *       finalizes the handle, then builds and sends the kXR_ok reply. Also
 *       owns the from-cache detector and the retstat/response assembly it
 *       calls directly.
 *
 * WHY:  The orchestrator and the reply it emits belong together; the heavy
 *       stage logic lives in the sibling split units so this file stays a
 *       short, linear read of the open lifecycle.
 *
 * HOW:  Each stage returns NGX_DECLINED to proceed or a sent-error rc to
 *       abort; the orchestrator early-returns on the latter. No logic moved.
 */

/* True when the resolved path falls under a configured server-managed cache root
 * (brix_cache on + cache_root prefix): such files open raw as the worker, not
 * through the export-confined VFS. Factored out to keep the top-of-open flag
 * setup a single expression. */
static ngx_flag_t
brix_open_is_from_cache(ngx_stream_brix_srv_conf_t *conf, const char *resolved)
{
	return (conf->cache
	        && conf->cache_root.len > 0
	        && ngx_strncmp((u_char *) resolved,
	                       conf->cache_root.data,
	                       conf->cache_root.len) == 0) ? 1 : 0;
}

/* Build the kXR_retstat metadata string for a retstat open: fstat the real-fd
 * path (a driver no-fd handle already has st), format "ino size flags mtime"
 * into statbuf, and clear *want_stat when the stat is unavailable. */
void
brix_open_build_retstat(brix_open_args_t *a)
{
	brix_ctx_t  *ctx        = a->ctx;
	int          idx        = a->idx;
	int          fd         = a->fd;
	struct stat *st         = a->st;
	ngx_flag_t  *want_stat  = &a->want_stat;
	char        *statbuf    = a->statbuf;
	size_t       statbuf_sz = sizeof(a->statbuf);

	statbuf[0] = '\0';
	if (*want_stat) {
		/* A driver-backed no-fd handle (e.g. RADOS) has fd == NGX_INVALID_FILE;
		 * `st` already holds the metadata the driver captured at open (above).
		 * Only the real-fd path needs a fresh fstat. Without this guard,
		 * fstat(-1) fails and we silently drop the retstat the client requested
		 * with kXR_open — which stock clients reject ("invalid response"). */
		int have_st = (fd != NGX_INVALID_FILE) ? (fstat(fd, st) == 0) : 1;

		if (have_st) {
			/* Compute the wire `flags` field through the shared StatGen-mirroring
			 * helper (readable/writable/xset + isDir/other, all euid-relative) so
			 * the kXR_open retstat matches stock XRootD exactly — the hand-rolled
			 * subset here dropped kXR_xset (and the type bits), so an executable
			 * (mode-777) file's open-handle stat diverged from stock by the xset
			 * bit. Same predicate as the plain kXR_stat path (brix_make_stat_body). */
			int stat_flags = brix_stat_flags_from_stat(st, geteuid(), getegid(),
				ctx->files[idx].from_cache ? kXR_cachersp : 0);
			snprintf(statbuf, statbuf_sz, "%llu %lld %d %ld",
					 (unsigned long long) st->st_ino,
					 (long long) st->st_size,
					 stat_flags,
					 (long) st->st_mtime);
		} else {
			*want_stat = 0;
		}
	}
}

/* Finish the successful open: reset byte counters + open time, start the session
 * transfer record, publish the handle (own-session only, never a bound secondary),
 * emit the access log + OK metric, arm the data-write mirror, then send the reply —
 * a kXR_attn(asynresp) on the parked streamid for an async-recall replay, else a
 * plain queued kXR_ok. Returns the send's rc. */
static ngx_int_t
brix_open_send_response(brix_open_args_t *a, u_char *buf, size_t total,
    size_t bodylen)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	int                         idx      = a->idx;
	ngx_flag_t                  is_write = a->is_write;

	ctx->files[idx].bytes_read    = 0;
	ctx->files[idx].bytes_written = 0;
	ctx->files[idx].open_time     = ngx_current_msec;
	brix_sess_xfer_start(ctx->sess, &ctx->files[idx].sess_xfer, resolved,
	                     is_write ? BRIX_SESS_MODE_WRITE
	                              : BRIX_SESS_MODE_READ,
	                     is_write ? -1 : (int64_t) ctx->files[idx].cached_size);

	if (!ctx->is_bound) {
		brix_session_handle_publish(ctx->login.sessid, idx, &ctx->files[idx]);
	}

	brix_log_access(ctx, c, "OPEN", resolved,
					  is_write ? "wr" : "rd", 1, 0, NULL, 0);
	BRIX_OP_OK(ctx, is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD);

	/* Phase 24 W3: begin accumulating this write-open for the data-write mirror.
	 * No-op unless brix_mirror_writes is on and a stream mirror is configured. */
	brix_stream_wmirror_on_open(ctx, c, conf, idx, is_write);

	/* Phase 35 / Phase 3: when this open is the async-recall replay for a parked
	 * client, the answer must travel as kXR_attn(asynresp) on the saved streamid,
	 * not a plain kXR_ok header. The body bytes (ServerOpenBody [+ stat]) sit at
	 * buf + header; asynresp wraps them itself. */
	if (ctx->prepare.stage_async_active) {
		return brix_send_attn_asynresp(ctx, c, ctx->prepare.stage_async_streamid,
		                                 (uint16_t) kXR_ok,
		                                 buf + XRD_RESPONSE_HDR_LEN,
		                                 (uint32_t) bodylen);
	}

	return brix_queue_response(ctx, c, buf, total);
}

/* Build the kXR_open response buffer: the 4-byte fhandle by default, the full
 * 12-byte ServerOpenBody + optional stat tail when the client asked for retstat
 * or an inline codec was negotiated. Allocates from c->pool; on OOM frees the
 * handle and returns NGX_ERROR. Writes the out_buf/out_total/out_bodylen slots. */
static ngx_int_t
brix_open_build_response(brix_open_args_t *a, u_char **out_buf,
    size_t *out_total, size_t *out_bodylen)
{
	brix_ctx_t       *ctx       = a->ctx;
	ngx_connection_t *c         = a->c;
	int               idx       = a->idx;
	ngx_flag_t        want_stat = a->want_stat;
	const char       *statbuf   = a->statbuf;
	ServerOpenBody body;
	uint8_t    sig_codec = ctx->files[idx].read_codec
	    ? ctx->files[idx].read_codec : ctx->files[idx].write_codec;
	ngx_flag_t have_codec = (sig_codec != BRIX_CODEC_IDENTITY);
	ngx_flag_t full_body  = want_stat || have_codec;
	size_t     hbytes     = full_body ? sizeof(ServerOpenBody)
	                                   : sizeof(body.fhandle);  /* 4 */
	size_t     bodylen, total;
	u_char    *buf;

	ngx_memzero(&body, sizeof(body));
	body.fhandle[0] = (u_char) idx;
	body.cpsize     = 0;
	if (have_codec) {
		body.cpsize    = (kXR_int32) htonl(BRIX_INLINE_CMP_MAGIC);
		body.cptype[0] = sig_codec;
	}

	bodylen = hbytes;
	if (want_stat) {
		bodylen += strlen(statbuf) + 1;
	}

	total = XRD_RESPONSE_HDR_LEN + bodylen;
	buf   = ngx_palloc(c->pool, total);
	if (buf == NULL) {
		brix_free_fhandle(ctx, idx);
		return NGX_ERROR;
	}

	brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
						  (uint32_t) bodylen,
						  (ServerResponseHdr *) buf);

	ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, hbytes);

	if (want_stat) {
		size_t slen = strlen(statbuf) + 1;
		ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
				   statbuf, slen);
	}

	*out_buf     = buf;
	*out_total   = total;
	*out_bodylen = bodylen;
	return NGX_OK;
}

/*
 *
 * WHAT: Opens the actual file on disk and allocates a file handle (fhandle). Called after path resolution.
 *       This function performs the POSIX open(2) call with proper security guarantees including:
 *       - POSC mode: staging temp file for persist-on-successful-close writes
 *       - Confined open: brix_open_confined() prevents post-open path escape attacks
 *       - Handle allocation: brix_alloc_fhandle() assigns a slot (0–255) in fd_table.c
 *       - Bookkeeping initialization: readable/writable flags, cache origin, inode/device tracking,
 *         byte counters, timestamps, read-ahead state.
 *
 * WHY: This is the bridge between path resolution and data transfer. The resolved file handle
 *      carries all metadata reused by subsequent opcodes (read/pgread/readv/write/close). POSC
 *      protects against crash loss of partial writes; confined open prevents symlink escapes;
 *      handle allocation enforces the 0–255 fd-table limit.
 *
 * HOW: Determine POSIX flags from options/mode_bits → build POSC staging path if kXR_posc set →
 *      allocate fhandle slot → open via O_CLOEXEC (cache) or brix_open_confined() (non-cache) →
 *      stat the fd to validate regular file and populate handle metadata → set fhandle path field +
 *      posc_final_path if POSC active → apply parent group policy on write opens → evaluate WT
 *      decision policy at open time → build ServerOpenBody with fhandle + optional retstat → queue response.
 */

ngx_int_t
brix_open_resolved_file(brix_ctx_t *ctx, ngx_connection_t *c,
						  ngx_stream_brix_srv_conf_t *conf,
						  const brix_open_request_t *req)
{
	const char        *resolved  = req->resolved;
	uint16_t           options   = req->options;
	uint16_t           mode_bits = req->mode_bits;
	ngx_flag_t         is_write  = req->is_write;
	struct stat        st = {0};
	u_char            *buf;
	size_t             bodylen, total;
	ngx_int_t          rc;
	brix_open_args_t   a;

	/* Gather the per-open pipeline state (POSC/resume staging semantics are
	 * documented on brix_open_args_t; posc_temp_path is the actual filesystem
	 * target of the staged open(2) below). */
	ngx_memzero(&a, sizeof(a));
	a.ctx        = ctx;
	a.c          = c;
	a.conf       = conf;
	a.resolved   = resolved;
	a.options    = options;
	a.is_write   = is_write;
	a.codec      = req->codec;
	a.fd         = -1;
	a.st         = &st;
	a.use_posc   = (is_write && (options & kXR_posc)) ? 1 : 0;
	a.use_resume = (is_write && conf->upload_resume) ? 1 : 0;

	/* P80.2 resume divert: a staged-only primary (ns leaf without
	 * CAP_RANDOM_WRITE or .pwrite) can never publish a local resume skeleton —
	 * the dispatch gate (!use_resume) would route this write to the POSIX
	 * skeleton file and the bytes would silently strand there instead of
	 * reaching the backend. Drop resume for this open so the dispatch takes
	 * the whole-object staged seam; the eligibility predicate is shared with
	 * the dispatch so the two can never disagree. Capability-driven
	 * (phase-71): decided by caps bits, never by backend scheme. */
	if (a.use_resume
	    && brix_open_write_needs_staged(&a,
	           brix_vfs_backend_resolve(conf->common.root_canon, c->log)))
	{
		a.use_resume = 0;
	}

	a.stage      = a.use_posc || a.use_resume;
	a.want_stat  = (options & kXR_retstat) ? 1 : 0;
	a.from_cache = brix_open_is_from_cache(conf, resolved);

	/* Pre-open staging preflight: write-target reject, backpressure, exclusive-
	 * create, temp-path build, resume-in-place decision, read-dir reject (split
	 * out). Mutates a.use_resume/a.stage/a.posc_temp_path. */
	rc = brix_open_stage_preflight(&a);
	if (rc != NGX_DECLINED) {
		return rc;   /* rejected: error already sent, propagate its rc */
	}

	/* The kXR_open option-bit -> POSIX open(2) mapping is the single-sourced
	 * inverse of the client's request builder (protocol/open_flags.h). */
	brix_open_options_to_posix(options, is_write, &a.oflags, &a.is_readable);

	/* Convert XRootD mode bits (Unix permission bits in low 9 bits). */
	a.create_mode = (mode_bits & 0777);
	if (a.create_mode == 0) {
		a.create_mode = 0644;
	}

	a.idx = brix_alloc_fhandle(ctx);
	if (a.idx < 0) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", resolved, is_write ? "wr" : "rd",
						  kXR_ServerError, "too many open files");
	}

	/* Layer 3: a non-default storage driver bound to this export (block-striped
	 * or object store) handles its own opens — POSC/resume staging and the
	 * server-managed cache domain remain on the POSIX-fd path (split out). */
	rc = brix_open_dispatch_open(&a);
	if (rc != NGX_DECLINED) {
		return rc;   /* open failed: mapped error already sent */
	}

	/* Post-fd handle setup: validate fd, init bookkeeping, CSI, throttle,
	 * monitor, path, group policy, retstat, debug, wt-decide (split out). */
	rc = brix_open_finalize_handle(&a);
	if (rc != NGX_DECLINED) {
		return rc;   /* rejected: fd torn down / reply already sent */
	}

	/* Build the open response body.  The reference (XrdXrootdXeq.cc:1501)
	 * returns ONLY the 4-byte file handle by default; the cpsize/cptype tail
	 * (→ the full 12-byte ServerOpenBody) is appended ONLY when the client
	 * requested it via kXR_retstat (want_stat) or kXR_compress — here also when
	 * this gateway has a negotiated inline codec to signal (Phase-42 W4/W5,
	 * details on brix_open_build_response). */
	rc = brix_open_build_response(&a, &buf, &total, &bodylen);
	if (rc != NGX_OK) {
		return rc;
	}

	/* Finish the open: counters, session xfer, publish, log, mirror, send the
	 * kXR_ok reply (or async-recall asynresp) (split out). */
	return brix_open_send_response(&a, buf, total, bodylen);
}
