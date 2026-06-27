#include "open.h"
#include "ngx_xrootd_module.h"
#include "../fs/backend/csi_tagstore.h"
#include "../ratelimit/throttle_compat.h"  /* phase-59 W3a: open-files cap */
#include "../response/async.h"
#include "../mirror/stream_wmirror.h"
#include "../write/wrts_journal.h"
#include "../compat/tmp_path.h"
#include "cache/writethrough_metrics.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../session/registry.h"
#include "../compat/codec_core.h"
#include "../protocol/open_flags.h"   /* shared kXR_open option-bit semantics */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>   /* open(2) flags + fcntl() to clear O_NONBLOCK post-open */

/*
 *
 * WHAT: Opens the actual file on disk and allocates a file handle (fhandle). Called after path resolution.
 *       This function performs the POSIX open(2) call with proper security guarantees including:
 *       - POSC mode: staging temp file for persist-on-successful-close writes
 *       - Confined open: xrootd_open_confined() prevents post-open path escape attacks
 *       - Handle allocation: xrootd_alloc_fhandle() assigns a slot (0–255) in fd_table.c
 *       - Bookkeeping initialization: readable/writable flags, cache origin, inode/device tracking,
 *         byte counters, timestamps, read-ahead state.
 *
 * WHY: This is the bridge between path resolution and data transfer. The resolved file handle
 *      carries all metadata reused by subsequent opcodes (read/pgread/readv/write/close). POSC
 *      protects against crash loss of partial writes; confined open prevents symlink escapes;
 *      handle allocation enforces the 0–255 fd-table limit.
 *
 * HOW: Determine POSIX flags from options/mode_bits → build POSC staging path if kXR_posc set →
 *      allocate fhandle slot → open via O_CLOEXEC (cache) or xrootd_open_confined() (non-cache) →
 *      stat the fd to validate regular file and populate handle metadata → set fhandle path field +
 *      posc_final_path if POSC active → apply parent group policy on write opens → evaluate WT
 *      decision policy at open time → build ServerOpenBody with fhandle + optional retstat → queue response.
 */

ngx_int_t
xrootd_open_resolved_file(xrootd_ctx_t *ctx, ngx_connection_t *c,
						  ngx_stream_xrootd_srv_conf_t *conf,
						  const char *resolved, uint16_t options,
						  uint16_t mode_bits, ngx_flag_t is_write,
						  uint8_t codec)
{
	int                idx, fd, oflags;
	int                is_readable;
	ServerOpenBody     body;
	struct stat        st;
	char               statbuf[256];
	u_char            *buf;
	size_t             bodylen, total;
	ngx_flag_t         want_stat;
	ngx_flag_t         from_cache;
	/*
	 * POSC (persist-on-successful-close): when kXR_posc is set on a write
	 * open we stage writes to a temp file and rename to the final path only
	 * on a clean kXR_close.  If the session drops mid-write the temp file is
	 * unlinked by xrootd_free_fhandle() (via the path field + posc_final_path
	 * sentinel).  We build posc_temp_path here; it is used as the actual
	 * filesystem target for the open(2) call below.
	 */
	char               posc_temp_path[PATH_MAX];
	ngx_flag_t         use_posc   = (is_write && (options & kXR_posc)) ? 1 : 0;
	/*
	 * Upload resume (xrootd_upload_resume on): stage EVERY writable open to a
	 * deterministic identity-keyed partial that survives a disconnect, so a
	 * reconnecting client resumes in place.  This is a superset of POSC staging
	 * (same temp-then-rename commit), so `stage` drives the open + commit and
	 * use_resume only changes (a) the temp path is deterministic, not random,
	 * and (b) the partial is preserved — not unlinked — on a non-clean close.
	 */
	ngx_flag_t         use_resume = (is_write && conf->upload_resume) ? 1 : 0;
	ngx_flag_t         stage      = use_posc || use_resume;

	want_stat = (options & kXR_retstat) ? 1 : 0;
	from_cache = (conf->cache
	              && conf->cache_root.len > 0
	              && ngx_strncmp((u_char *) resolved,
	                             conf->cache_root.data,
	                             conf->cache_root.len) == 0);

	/* A write open of an existing DIRECTORY must be rejected up front with
	 * kXR_isDirectory (stock parity: O_WRONLY on a directory fails EISDIR).
	 * Without this the staging path below would derive a ".part" FILE from the
	 * directory's name, create it, and wrongly report success — diverging from
	 * stock. The read side is rejected symmetrically just below. */
	if (is_write) {
		struct stat dst;
		if (stat(resolved, &dst) == 0 && S_ISDIR(dst.st_mode)) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_isDirectory,
			                  "is a directory");
		}
	}

	/*
	 * Build the POSC staging temp path: same directory as the final path,
	 * with a ".posc.<pid>.<random>" suffix appended.  This keeps the temp
	 * file on the same filesystem as the destination so rename(2) is atomic.
	 */
	/* When staging is active the kXR_new exclusive-create check must run against
	 * the FINAL path, not the staging temp (which is what actually gets O_EXCL):
	 * staging never opens the final, so without this an exclusive create over an
	 * existing object would wrongly succeed and overwrite it on commit.
	 *
	 * This is an EXCLUSIVE-create check, so it only applies when kXR_new is set
	 * WITHOUT kXR_delete — exactly the O_EXCL condition in the direct-open
	 * mapping (open_flags.h: kXR_new adds O_EXCL "unless kXR_delete is also
	 * set"). With kXR_delete also present the client explicitly asked to
	 * truncate/overwrite any existing object (the delete intent wins over the
	 * new intent), so an existing final must NOT be rejected — staging will
	 * replace it on the commit rename. Without this guard a delete+new overwrite
	 * (e.g. xrdcp -f, or a kXR_recoverWrts reopen) was wrongly rejected with
	 * kXR_ItExists. */
	if (stage && (options & kXR_new) && !(options & kXR_delete)) {
		struct stat fst;
		if (stat(resolved, &fst) == 0) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ItExists,
			                  "file already exists");
		}
	}

	if (use_resume) {
		/* Deterministic, identity-keyed: a reconnecting client re-opening the
		 * same final path lands on the SAME partial and resumes from its
		 * offset.  Anonymous (empty dn) shares per-path (no per-user isolation
		 * on such an endpoint anyway).  When xrootd_stage_dir is set the partial
		 * lives on that fast device and the close-time commit moves it to the
		 * destination (cross-device copy). */
		const char *principal = ctx->dn[0] ? ctx->dn : NULL;
		const char *stage_dir = conf->upload_stage_dir_canon[0]
		                        ? conf->upload_stage_dir_canon : NULL;
		if (xrootd_make_resume_path(resolved, principal, stage_dir,
		                            posc_temp_path, sizeof(posc_temp_path))
		    != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ServerError,
			                  "resume temp path too long");
		}
	} else if (use_posc) {
		if (xrootd_make_tmp_path(resolved, posc_temp_path,
		                         sizeof(posc_temp_path)) != NGX_OK) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ServerError,
			                  "POSC temp path too long");
		}
	}

	/*
	 * In-place update vs upload: resume staging assumes a writable open is an
	 * UPLOAD — it starts from an empty partial and commits it over the final path
	 * with a rename.  But a pure update-in-place open (kXR_open_updt, neither
	 * kXR_delete/truncate nor kXR_new/create) on an ALREADY-COMMITTED file is a
	 * read-modify-write that must preserve the bytes the client does not rewrite.
	 * Staged through an empty partial, those bytes are silently lost on the commit
	 * rename (e.g. a 100-byte write at offset 100 of a 200-byte file zero-fills
	 * [0,100)) — a data-integrity bug, and a divergence from stock xrootd which
	 * always edits such a file in place.
	 *
	 * Only stage such an open when a resume partial ALREADY exists — that is a
	 * genuine reconnect continuing an interrupted upload (the partial holds the
	 * bytes received so far).  When no partial exists and the final file is a real
	 * committed regular file, fall through to opening it directly, in place.
	 */
	if (use_resume && !(options & kXR_delete) && !(options & kXR_new)) {
		struct stat pst, fst;

		/* A pure update-in-place open is NOT an upload to stage when no resume
		 * partial is in flight: drop out of resume staging and let the direct
		 * open mapping (O_RDWR, no O_CREAT) decide, matching stock xrootd:
		 *   - final is a committed regular file -> edit it in place (preserve the
		 *     bytes the client does not rewrite);
		 *   - final does not exist              -> fail kXR_NotFound, exactly as
		 *     O_RDWR-without-O_CREAT would.  Staging would otherwise CREATE the
		 *     missing file and return kXR_ok, diverging from stock which derives
		 *     no O_CREAT for kXR_open_updt alone (XrdXrootdXeq.cc:1524). */
		int have_partial = (stat(posc_temp_path, &pst) == 0);
		int final_exists = (stat(resolved, &fst) == 0);
		if (!have_partial && (!final_exists || S_ISREG(fst.st_mode))) {
			use_resume = 0;
			stage = use_posc;
		}
	}

	if (!is_write) {
		if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
			XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
							  resolved, "rd", kXR_isDirectory,
							  "is a directory");
		}
	}

	/* The kXR_open option-bit -> POSIX open(2) mapping is the single-sourced
	 * inverse of the client's request builder (protocol/open_flags.h). */
	xrootd_open_options_to_posix(options, is_write, &oflags, &is_readable);

	/* Convert XRootD mode bits (Unix permission bits in low 9 bits). */
	mode_t create_mode = (mode_bits & 0777);
	if (create_mode == 0) {
		create_mode = 0644;
	}

	idx = xrootd_alloc_fhandle(ctx);
	if (idx < 0) {
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", resolved, is_write ? "wr" : "rd",
						  kXR_ServerError, "too many open files");
	}

	{
		/* When POSC is active, open the staging temp path instead of the
		 * final path.  The O_CREAT flag is forced so the temp file is
		 * always created fresh; O_EXCL is intentionally omitted so that a
		 * previous crash leaving a stale temp file does not block a retry. */
		const char *open_path = stage ? posc_temp_path : resolved;

		/* Staged opens (POSC or resume) always need O_CREAT on the temp path.
		 * O_TRUNC is inherited from `oflags`: a fresh create/truncate open
		 * starts the partial empty; a resume re-open (kXR_open_updt, no trunc)
		 * preserves the already-written bytes. */
		/* O_NONBLOCK guarantees the open(2) cannot park the worker in the
		 * kernel FIFO/device "wait_for_partner" rendezvous (a named pipe in the
		 * export would otherwise freeze the worker's event loop and stall every
		 * connection pinned to it).  It is harmless for the regular files we
		 * serve and is cleared again on the surviving fd once fstat() confirms
		 * S_ISREG below.  Mirrors the central guard in xrootd_open_beneath(). */
		int effective_oflags = oflags | (stage ? O_CREAT : 0) | O_NONBLOCK;

		/* Resume staging on a configured fast device: the partial lives OUTSIDE
		 * root_canon, so it cannot go through the RESOLVE_BENEATH open.  Its
		 * basename is a server-generated hash (no client-controlled component)
		 * inside the operator-trusted, canonicalized stage dir, so a direct open
		 * with O_NOFOLLOW on the final component is safe. */
		ngx_flag_t stage_external = use_resume
		    && conf->upload_stage_dir_canon[0] != '\0';

		if (stage_external) {
			fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,
			          create_mode);
		} else if (from_cache) {
			/* cache_root files are server-managed (filled by the cache worker,
			 * never client-written), but add O_NOFOLLOW as defence-in-depth so a
			 * symlink planted in the cache tree is never followed; O_CLOEXEC
			 * prevents FD leakage into any forked child (e.g. tpc_curl). */
			fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,
			          create_mode);
		} else {
			/* open_path is the absolute resolved path; strip root_canon to
			 * get the path relative to rootfd for openat2 RESOLVE_BENEATH. */
			const char *rel = open_path;
			size_t      root_len = strlen(conf->common.root_canon);
			if (root_len > 0
			    && ngx_strncmp((u_char *) open_path,
			                   (u_char *) conf->common.root_canon,
			                   root_len) == 0
			    && open_path[root_len] == '/')
			{
			    rel = open_path + root_len;
			}
			fd = xrootd_open_beneath(conf->rootfd, rel,
			                         effective_oflags, create_mode);
		}
	}
	if (fd < 0) {
		int err = errno;
		const char *mode_str = is_write ? "wr" : "rd";

		if (err == ENOENT || err == ENOTDIR) {
			XROOTD_RETURN_ERR(ctx, c,
							  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
							  "OPEN", resolved, mode_str,
							  kXR_NotFound, "file not found");
		}
		if (err == EEXIST) {
			/* O_EXCL (kXR_new without kXR_delete) on an existing file → EEXIST,
			 * which the reference maps to kXR_ItExists (the code raised by the
			 * kXR_new flag), NOT kXR_FileLocked. */
			XROOTD_RETURN_ERR(ctx, c,
							  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
							  "OPEN", resolved, mode_str,
							  kXR_ItExists, "file already exists");
		}
		if (err == EACCES) {
			XROOTD_RETURN_ERR(ctx, c,
							  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
							  "OPEN", resolved, mode_str,
							  kXR_NotAuthorized, "permission denied");
		}
		if (err == EISDIR) {
			XROOTD_RETURN_ERR(ctx, c,
							  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
							  "OPEN", resolved, mode_str,
							  kXR_isDirectory, "is a directory");
		}
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", resolved, mode_str,
						  kXR_IOError, strerror(err));
	}

	if (fstat(fd, &st) != 0) {
		int err = errno;

		close(fd);
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", resolved, is_write ? "wr" : "rd",
						  kXR_IOError, strerror(err));
	}

	if (S_ISDIR(st.st_mode)) {
		close(fd);
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", resolved, is_write ? "wr" : "rd",
						  kXR_isDirectory, "is a directory");
	}

	/* Only regular files are servable byte streams.  A FIFO, socket, device or
	 * other special file was opened O_NONBLOCK (so the open could not wedge the
	 * worker); refuse to serve it rather than let a read/write spin on EAGAIN.
	 * A staged write always lands on a freshly O_CREAT'd regular temp, so this
	 * only ever rejects a pre-existing special file at the resolved path. */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		XROOTD_RETURN_ERR(ctx, c,
						  is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
						  "OPEN", resolved, is_write ? "wr" : "rd",
						  kXR_IOError, "not a regular file");
	}

	/* The fd is a confirmed regular file: drop O_NONBLOCK so every downstream
	 * read/write/sendfile sees ordinary blocking semantics (a no-op for local
	 * regular files, but it keeps the fd's flags unsurprising for callers). */
	{
		int fl = fcntl(fd, F_GETFL);
		if (fl != -1 && (fl & O_NONBLOCK)) {
			(void) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
		}
	}

	ctx->files[idx].fd          = fd;
	ctx->files[idx].readable    = is_readable;
	ctx->files[idx].writable    = is_write;
	ctx->files[idx].from_cache  = from_cache;
	ctx->files[idx].is_regular  = S_ISREG(st.st_mode) ? 1 : 0;
	ctx->files[idx].device      = st.st_dev;
	ctx->files[idx].inode       = st.st_ino;
	ctx->files[idx].cached_size = (off_t) st.st_size;
	ctx->files[idx].read_last_end  = -1;
	ctx->files[idx].read_ahead_end = 0;

	/* phase-59 W2: attach a CSI page-checksum tagstore to this handle when
	 * enabled. A write handle creates/uses tags; a read handle verifies against
	 * existing tags. An untagged file with require=on is refused at open. */
	ctx->files[idx].csi = NULL;
	if (conf->csi_enable && S_ISREG(st.st_mode)) {
		const char *crel = resolved;
		size_t      rlen = strlen(conf->common.root_canon);
		xrootd_csi_t *csi;

		if (rlen > 0
		    && ngx_strncmp((u_char *) resolved,
		                   (u_char *) conf->common.root_canon, rlen) == 0
		    && resolved[rlen] == '/')
		{
			crel = resolved + rlen;
		}

		csi = ngx_alloc(sizeof(xrootd_csi_t), c->log);
		if (csi != NULL) {
			int crc;

			ngx_memzero(csi, sizeof(xrootd_csi_t));
			csi->fill    = conf->csi_fill ? 1 : 0;
			csi->require = conf->csi_require ? 1 : 0;
			csi->loose   = conf->csi_loose ? 1 : 0;
			csi->strict  = conf->csi_loose ? 0 : 1;

			crc = xrootd_csi_open(csi, conf->rootfd, crel,
			    (const char *) conf->csi_prefix.data, is_write);
			if (crc == XROOTD_CSI_OK) {
				ctx->files[idx].csi = csi;
			} else {
				xrootd_csi_close(csi);
				ngx_free(csi);
				if (!is_write && crc == XROOTD_CSI_NOTAGS
				    && conf->csi_require)
				{
					close(fd);
					ctx->files[idx].fd = -1;
					XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD,
					    "OPEN", resolved, "rd",
					    kXR_ChkSumErr, "integrity tags missing");
				}
				/* untagged read (require off) or write tag-setup error:
				 * proceed without CSI for this handle (fail-open). */
			}
		}
	}

	/* phase-59 W3a: XrdThrottle per-user open-files cap. Checked after the fd
	 * is open (closed again on rejection); the resolved identity is the key. */
	if (conf->throttle_zone != NULL && conf->throttle_max_open_files > 0) {
		const char *tuser = ctx->dn[0] ? ctx->dn : "anonymous";

		if (!xrootd_throttle_open_inc(conf->throttle_zone, tuser,
		                              conf->throttle_max_open_files))
		{
			close(fd);
			ctx->files[idx].fd = -1;
			if (ctx->files[idx].csi != NULL) {
				xrootd_csi_close(ctx->files[idx].csi);
				ngx_free(ctx->files[idx].csi);
				ctx->files[idx].csi = NULL;
			}
			XROOTD_RETURN_ERR(ctx, c,
			    is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD,
			    "OPEN", resolved, is_write ? "wr" : "rd",
			    kXR_Overloaded, "too many open files for this user");
		}
		ctx->throttle_open_held++;
	}

	/*
	 * Phase-42 W4/W5 — inline compression.  `codec` is the codec negotiated from
	 * the open opaque (0 = none).  Honour it only for a regular file, and store it
	 * in the direction-appropriate slot: read_codec for a read open (W4, compress
	 * kXR_read responses), write_codec for a write open (W5, decompress kXR_write
	 * payloads).  The default (codec==0) leaves both slots 0 / byte-identical.
	 */
	ctx->files[idx].read_codec  = (!is_write && S_ISREG(st.st_mode)
	    && codec != XROOTD_CODEC_IDENTITY) ? codec : (uint8_t) XROOTD_CODEC_IDENTITY;
	ctx->files[idx].write_codec = (is_write && S_ISREG(st.st_mode)
	    && codec != XROOTD_CODEC_IDENTITY) ? codec : (uint8_t) XROOTD_CODEC_IDENTITY;
	ctx->files[idx].wt_enabled = 0;
	ctx->files[idx].wt_policy = XROOTD_WT_DECISION_DENY;
	ctx->files[idx].wt_mode_bits = create_mode;
	ctx->files[idx].wt_dirty_offset = -1;
	ctx->files[idx].wt_bytes_written = 0;
	ctx->files[idx].wt_flush_task = NULL;
	ctx->files[idx].wt_flush_pending = 0;

	/* kXR_recoverWrts journal initialisation
	 * Arm the write-recovery ring when the handle is opened for writing and
	 * the recover_writes directive is on.  Read-only handles get the fields
	 * zeroed (they are zero from xrootd_free_fhandle, but be explicit).
	 */
	{
		ngx_stream_xrootd_srv_conf_t *wrts_conf;
		wrts_conf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
		if (is_write && wrts_conf->recover_writes) {
			xrootd_wrts_open(&ctx->files[idx]);
		} else {
			ctx->files[idx].wrts_enabled = 0;
			ctx->files[idx].wrts_head    = 0;
			ctx->files[idx].wrts_count   = 0;
			ctx->files[idx].wrts_gen     = 0;
		}
	}

	ctx->files[idx].dashboard_slot = -1;

	/* Register the open file with the live transfer monitor. */
	if (ngx_xrootd_dashboard_shm_zone != NULL) {
		xrootd_transfer_table_t *dash_tbl = ngx_xrootd_dashboard_shm_zone->data;
		const char *dash_identity = ctx->dn[0] ? ctx->dn : "anonymous";
		uint8_t     dash_dir = is_write ? XROOTD_XFER_DIR_WRITE
		                                : XROOTD_XFER_DIR_READ;
		ctx->files[idx].dashboard_slot = xrootd_transfer_slot_alloc(
		    dash_tbl, ctx->sessid, ctx->peer_ip,
		    dash_identity, resolved, dash_dir,
		    XROOTD_XFER_PROTO_ROOT, (int64_t) ngx_current_msec);
	}

	/*
	 * POSC: store the temp path in the path field so that a non-clean close
	 * (handled by xrootd_free_fhandle → unlink(path)) discards the partial
	 * upload.  Store the final target in posc_final_path; xrootd_handle_close
	 * will rename() on clean close and then clear this field before freeing.
	 */
	if (stage) {
		if (xrootd_set_fhandle_path(ctx, c, idx, posc_temp_path) != NGX_OK) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ctx->files[idx].posc_final_path = ngx_alloc(strlen(resolved) + 1,
		                                             c->log);
		if (ctx->files[idx].posc_final_path == NULL) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ngx_cpystrn((u_char *) ctx->files[idx].posc_final_path,
		            (u_char *) resolved, strlen(resolved) + 1);
		/* Resume staging: keep the partial on a non-clean close (the difference
		 * from plain POSC, which discards it).  See xrootd_free_fhandle. */
		ctx->files[idx].is_resume = use_resume ? 1 : 0;
	} else {
		if (xrootd_set_fhandle_path(ctx, c, idx, resolved) != NGX_OK) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
	}

	if (is_write && conf->group_rules != NULL) {
		xrootd_apply_parent_group_policy_fd(c->log, fd, resolved,
											conf->group_rules);
	}

	statbuf[0] = '\0';
	if (want_stat) {
		if (fstat(fd, &st) == 0) {
			int stat_flags = 0;
			if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
				stat_flags |= kXR_readable;
			}
			if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
				stat_flags |= kXR_writable;
			}
			if (ctx->files[idx].from_cache) {
				stat_flags |= kXR_cachersp;
			}
			snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
					 (unsigned long long) st.st_ino,
					 (long long) st.st_size,
					 stat_flags,
					 (long) st.st_mtime);
		} else {
			want_stat = 0;
		}
	}

	if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
		char log_path[512];

		xrootd_sanitize_log_string(resolved, log_path, sizeof(log_path));
		ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
					   "xrootd: kXR_open handle=%d path=%s mode=%s retstat=%d",
					   idx, log_path, is_write ? "wr" : "rd",
					   (int) want_stat);
	}

	/* Write-through decision evaluation (mirrors XrdPfc::Cache::Decide())
	 * WHAT: Evaluate write-through policy at kXR_open time and cache the result on the handle.
	 *       This is called once per open — the cached wt_policy determines close-time flush behavior.
	 *
	 * WHY: Mirrors XrdPfcDecision::Decide() from official XRootD PFC module (Cache::Attach()).
	 *      Caching at open time avoids repeated policy evaluation for every write operation,
	 *      reduces latency, and ensures consistent close-time behavior across the session.
	 *
	 * HOW: Policy callback flow (src/cache/writethrough_decision.h):
	 *   1. conf->wt_decision.fn(resolved, options, &conf->wt_decision) — default is xrootd_wt_default_decide()
	 *   2. Default engine checks: size filter → deny prefixes → allow prefixes → ALLOW_ASYNC (default)
	 *   3. Cache result on handle: ctx->files[idx].wt_policy = decision, wt_enabled = (decision != DENY),
	 *      wt_dirty_offset = -1 (clean state), wt_bytes_written = 0
	 *
	 * Decision outcomes are cached for a future close-time write-back implementation:
	 *   DENY       → no write-back; local-only writes, handle treated as non-WT
	 *   ALLOW_SYNC → synchronous flush to origin before closing handle (blocks)
	 *   ALLOW_ASYNC→ schedule async thread-pool flush, return immediately to client */

/* WT decision policy engine (default: prefix-based)
 * WHAT: xrootd_wt_default_decide() — built-in prefix-based policy engine.
 *       External plugins can provide their own fn pointer for custom policies.
 *
 * WHY: Provides sensible defaults for most deployments without requiring external plugin setup.
 *      Prefix-based matching is O(n) where n = prefix length — acceptable for typical paths (/data/, /atlas/).
 *
 * HOW: Decision logic order (src/cache/writethrough_decision.c):
 *   1. Size filter: if file > max_write_through_bytes AND no include regex match → DENY
 *   2. Deny prefixes: any deny_prefix matches → DENY (deny takes precedence)
 *   3. Allow prefixes: if allow list configured AND none match → DENY (whitelist mode)
 *   4. Default: ALLOW_ASYNC (mirrors XrdPfcAllowDecision, sync preferred for local origins) */

	if (is_write && conf->wt_enable) {
		xrootd_wt_decision_t decision = XROOTD_WT_DECISION_DENY;

		if (conf->wt_decision.fn != NULL) {
			decision = conf->wt_decision.fn(resolved, options, &conf->wt_decision);
		}

		ctx->files[idx].wt_enabled  = (decision != XROOTD_WT_DECISION_DENY) ? 1 : 0;
		ctx->files[idx].wt_policy   = decision;
		ctx->files[idx].wt_mode_bits = create_mode;
		ctx->files[idx].wt_dirty_offset = -1; /* no dirty writes yet */
		ctx->files[idx].wt_bytes_written    = 0;

		ctx->files[idx].wt_flush_task     = NULL;
		ctx->files[idx].wt_flush_pending  = 0;

		if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
			char wt_log_path[512];

			xrootd_sanitize_log_string(resolved, wt_log_path,
			                           sizeof(wt_log_path));
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			               "xrootd: wt decision=%s path=%s",
			               decision == XROOTD_WT_DECISION_DENY ? "DENY" :
			               decision == XROOTD_WT_DECISION_ALLOW_SYNC ? "ALLOW_SYNC" : "ALLOW_ASYNC",
			               wt_log_path);
		}
	}

	/*
	 * Build the open response body.  The reference (XrdXrootdXeq.cc:1501) returns
	 * ONLY the 4-byte file handle by default; the cpsize/cptype tail (→ the full
	 * 12-byte ServerOpenBody) is appended ONLY when the client requested it via
	 * kXR_retstat (want_stat) or kXR_compress — here also when this gateway has a
	 * negotiated inline codec to signal.  Always emitting 12 bytes diverged from
	 * every stock client.
	 *
	 * Phase-42 W4/W5: signal the negotiated inline read/write codec via the
	 * (otherwise vestigial) cpsize/cptype fields — at most one of read_codec /
	 * write_codec is set; cpsize is big-endian per the wire convention (the
	 * client keys off cptype[0]).
	 */
	{
		uint8_t    sig_codec = ctx->files[idx].read_codec
		    ? ctx->files[idx].read_codec : ctx->files[idx].write_codec;
		ngx_flag_t have_codec = (sig_codec != XROOTD_CODEC_IDENTITY);
		ngx_flag_t full_body  = want_stat || have_codec;
		size_t     hbytes     = full_body ? sizeof(ServerOpenBody)
		                                   : sizeof(body.fhandle);  /* 4 */

		ngx_memzero(&body, sizeof(body));
		body.fhandle[0] = (u_char) idx;
		body.cpsize     = 0;
		if (have_codec) {
			body.cpsize    = (kXR_int32) htonl(XROOTD_INLINE_CMP_MAGIC);
			body.cptype[0] = sig_codec;
		}

		bodylen = hbytes;
		if (want_stat) {
			bodylen += strlen(statbuf) + 1;
		}

		total = XRD_RESPONSE_HDR_LEN + bodylen;
		buf   = ngx_palloc(c->pool, total);
		if (buf == NULL) {
			xrootd_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}

		xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
							  (uint32_t) bodylen,
							  (ServerResponseHdr *) buf);

		ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, hbytes);

		if (want_stat) {
			size_t slen = strlen(statbuf) + 1;
			ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
					   statbuf, slen);
		}
	}

	ctx->files[idx].bytes_read    = 0;
	ctx->files[idx].bytes_written = 0;
	ctx->files[idx].open_time     = ngx_current_msec;

	if (!ctx->is_bound) {
		xrootd_session_handle_publish(ctx->sessid, idx, &ctx->files[idx]);
	}

	xrootd_log_access(ctx, c, "OPEN", resolved,
					  is_write ? "wr" : "rd", 1, 0, NULL, 0);
	XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);

	/* Phase 24 W3: begin accumulating this write-open for the data-write mirror.
	 * No-op unless xrootd_mirror_writes is on and a stream mirror is configured. */
	xrootd_stream_wmirror_on_open(ctx, c, conf, idx, is_write);

	/* Phase 35 / Phase 3: when this open is the async-recall replay for a parked
	 * client, the answer must travel as kXR_attn(asynresp) on the saved streamid,
	 * not a plain kXR_ok header. The body bytes (ServerOpenBody [+ stat]) sit at
	 * buf + header; asynresp wraps them itself. */
	if (ctx->frm_async_active) {
		return xrootd_send_attn_asynresp(ctx, c, ctx->frm_async_streamid,
		                                 (uint16_t) kXR_ok,
		                                 buf + XRD_RESPONSE_HDR_LEN,
		                                 (uint32_t) bodylen);
	}

	return xrootd_queue_response(ctx, c, buf, total);
}
