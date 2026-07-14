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
#include "observability/sesslog/sesslog_ngx.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>   /* open(2) flags + fcntl() to clear O_NONBLOCK post-open */
#include "open_resolved_file_internal.h"

/*
 * open_resolved_file_finalize.c — post-fd handle finalization for kXR_open
 * (phase-79 split from open_resolved_file.c).
 *
 * WHAT: Everything after a successful open: validate the POSIX fd (type +
 *       clear O_NONBLOCK), initialise the handle bookkeeping, attach the CSI
 *       block-integrity engine, enforce the per-user open-files cap, register
 *       the live-transfer monitor slot, record the on-disk path, build the
 *       kXR_retstat string, and cache the write-through decision.
 *
 * WHY:  These are the per-handle setup steps that share the fd + stat + handle
 *       slot; grouping them keeps the tear-down-on-rejection contracts (fd +
 *       CSI freed on every refusal) together and out of the open-syscall unit.
 *
 * HOW:  brix_open_finalize_handle (the sole cross-file entry) runs the file-
 *       local steps in order; the kXR_retstat string builder lives with the
 *       reply-assembly code (brix_open_build_retstat, declared in the internal
 *       header). Behaviour is byte-identical to the original.
 */

/*
 * brix_open_attach_csi — attach the CSI block-checksum integrity engine to a
 * freshly-opened handle (xmeta P3).  A write handle folds block CRCs and merges
 * them into the file's xmeta record at close; a read handle verifies spanned
 * blocks against the record.  A pure read on a trust_fs backing fs skips the
 * engine; a require=on read with no verifiable record is refused (fd closed).
 * Returns NGX_OK, or the error-response value on refusal.
 */
static ngx_int_t
brix_open_attach_csi(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	int                         idx      = a->idx;
	int                         fd       = a->fd;
	const struct stat          *st       = a->st;
	ngx_flag_t                  is_write = a->is_write;

	ctx->files[idx].csi = NULL;
	if (conf->csi.enable && S_ISREG(st->st_mode)
	    && !(conf->csi.trust_fs && !is_write))
	{
		brix_csi_t *csi = ngx_alloc(sizeof(brix_csi_t), c->log);

		if (csi != NULL) {
			int crc = brix_csi_open(csi, resolved,
			    (uint32_t) conf->csi.block, is_write);

			csi->trust_fs = conf->csi.trust_fs ? 1 : 0;
			if (crc == BRIX_CSI_OK) {
				ctx->files[idx].csi = csi;
			} else {
				brix_csi_close(csi);
				ngx_free(csi);
				if (!is_write && crc == BRIX_CSI_NOTAGS
				    && conf->csi.require)
				{
					close(fd);
					ctx->files[idx].fd = -1;
					BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD,
					    "OPEN", resolved, "rd",
					    kXR_ChkSumErr, "integrity record missing");
				}
				/* unrecorded read (require off) or engine error:
				 * proceed without CSI for this handle (fail-open). */
			}
		}
	}
	return NGX_OK;
}

/*
 * brix_open_apply_throttle — enforce the XrdThrottle per-user open-files cap on a
 * freshly-opened handle (phase-59 W3a).  Checked after the fd is open; on
 * rejection the fd + any CSI engine are torn down.  Returns NGX_OK, or the
 * error-response value when the cap is exceeded.
 */
static ngx_int_t
brix_open_apply_throttle(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	int                         idx      = a->idx;
	int                         fd       = a->fd;
	ngx_flag_t                  is_write = a->is_write;

	/* phase-59 W3a: XrdThrottle per-user open-files cap. Checked after the fd
	 * is open (closed again on rejection); the resolved identity is the key. */
	if (conf->throttle.zone != NULL && conf->throttle.max_open_files > 0) {
		const char *tuser = ctx->login.dn[0] ? ctx->login.dn : "anonymous";

		if (!brix_throttle_open_inc(conf->throttle.zone, tuser,
		                              conf->throttle.max_open_files))
		{
			close(fd);
			ctx->files[idx].fd = -1;
			if (ctx->files[idx].csi != NULL) {
				brix_csi_close(ctx->files[idx].csi);
				ngx_free(ctx->files[idx].csi);
				ctx->files[idx].csi = NULL;
			}
			BRIX_RETURN_ERR(ctx, c,
			    is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
			    "OPEN", resolved, is_write ? "wr" : "rd",
			    kXR_Overloaded, "too many open files for this user");
		}
		ctx->throttle.open_held++;
	}
	return NGX_OK;
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
	 *   1. conf->wt.decision.fn(resolved, options, &conf->wt.decision) — default is brix_wt_default_decide()
	 *   2. Default engine checks: size filter → deny prefixes → allow prefixes → ALLOW_ASYNC (default)
	 *   3. Cache result on handle: ctx->files[idx].wt_policy = decision, wt_enabled = (decision != DENY),
	 *      wt_dirty_offset = -1 (clean state), wt_bytes_written = 0
	 *
	 * Decision outcomes are cached for a future close-time write-back implementation:
	 *   DENY       → no write-back; local-only writes, handle treated as non-WT
	 *   ALLOW_SYNC → synchronous flush to origin before closing handle (blocks)
	 *   ALLOW_ASYNC→ schedule async thread-pool flush, return immediately to client */

/* WT decision policy engine (default: prefix-based)
 * WHAT: brix_wt_default_decide() — built-in prefix-based policy engine.
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
static void
brix_open_decide_writethrough(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx          = a->ctx;
	ngx_connection_t           *c            = a->c;
	ngx_stream_brix_srv_conf_t *conf         = a->conf;
	const char                 *resolved     = a->resolved;
	uint16_t                    options      = a->options;
	int                         idx          = a->idx;
	mode_t                      create_mode  = a->create_mode;
	ngx_flag_t                  is_write     = a->is_write;
	ngx_flag_t                  wt_via_stage = (ngx_flag_t) a->wt_via_stage;

	if (is_write && conf->wt.enable) {
		brix_wt_decision_t decision = BRIX_WT_DECISION_DENY;

		if (conf->wt.decision.fn != NULL) {
			decision = conf->wt.decision.fn(resolved, options, &conf->wt.decision);
		}

		/* wt sd_stage handles flush on the storage path (sync job / close), NOT via
		 * the close-time run_flush — so leave wt_enabled clear for them. */
		ctx->files[idx].wt_enabled  = (!wt_via_stage
		                               && decision != BRIX_WT_DECISION_DENY) ? 1 : 0;
		ctx->files[idx].wt_policy   = decision;
		ctx->files[idx].wt_mode_bits = create_mode;
		ctx->files[idx].wt_dirty_offset = -1; /* no dirty writes yet */
		ctx->files[idx].wt_bytes_written    = 0;

		ctx->files[idx].wt_flush_task     = NULL;
		ctx->files[idx].wt_flush_pending  = 0;

		if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
			char wt_log_path[512];

			brix_sanitize_log_string(resolved, wt_log_path,
			                           sizeof(wt_log_path));
			ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
			               "brix: wt decision=%s path=%s",
			               decision == BRIX_WT_DECISION_DENY ? "DENY" :
			               decision == BRIX_WT_DECISION_ALLOW_SYNC ? "ALLOW_SYNC" : "ALLOW_ASYNC",
			               wt_log_path);
		}
	}
}

/* Register a freshly-opened handle with the live transfer monitor (dashboard
 * slot), so an in-flight read/write shows up in the dashboard SHM table. */
static void
brix_open_register_monitor(brix_ctx_t *ctx, const char *resolved, int idx,
    ngx_flag_t is_write)
{
	if (ngx_brix_dashboard_shm_zone != NULL) {
		brix_transfer_table_t *dash_tbl = ngx_brix_dashboard_shm_zone->data;
		const char *dash_identity = ctx->login.dn[0] ? ctx->login.dn : "anonymous";
		uint8_t     dash_dir = is_write ? BRIX_XFER_DIR_WRITE
		                                : BRIX_XFER_DIR_READ;
		ctx->files[idx].dashboard_slot = brix_transfer_slot_alloc(
		    dash_tbl, ctx->login.sessid, ctx->login.peer_ip,
		    dash_identity, resolved, dash_dir,
		    BRIX_XFER_PROTO_ROOT, (int64_t) ngx_current_msec);
	}
}

	/*
	 * POSC: store the temp path in the path field so that a non-clean close
	 * (handled by brix_free_fhandle → unlink(path)) discards the partial
	 * upload.  Store the final target in posc_final_path; brix_handle_close
	 * will rename() on clean close and then clear this field before freeing.
	 */
static ngx_int_t
brix_open_set_handle_path(brix_open_args_t *a)
{
	brix_ctx_t       *ctx            = a->ctx;
	ngx_connection_t *c              = a->c;
	int               idx            = a->idx;
	const char       *resolved       = a->resolved;
	const char       *posc_temp_path = a->posc_temp_path;
	ngx_flag_t        stage          = a->stage;
	ngx_flag_t        use_resume     = a->use_resume;

	if (stage) {
		if (brix_set_fhandle_path(ctx, c, idx, posc_temp_path) != NGX_OK) {
			brix_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ctx->files[idx].posc_final_path = ngx_alloc(strlen(resolved) + 1,
		                                             c->log);
		if (ctx->files[idx].posc_final_path == NULL) {
			brix_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
		ngx_cpystrn((u_char *) ctx->files[idx].posc_final_path,
		            (u_char *) resolved, strlen(resolved) + 1);
		/* Resume staging: keep the partial on a non-clean close (the difference
		 * from plain POSC, which discards it).  See brix_free_fhandle. */
		ctx->files[idx].is_resume = use_resume ? 1 : 0;
	} else {
		if (brix_set_fhandle_path(ctx, c, idx, resolved) != NGX_OK) {
			brix_free_fhandle(ctx, idx);
			return NGX_ERROR;
		}
	}
	return NGX_OK;
}

	/* The POSIX-fd path stats the fd to validate type and clear O_NONBLOCK. A
	 * driver-backed open already synthesized `st` from the driver snapshot and
	 * its directory/type rejection happens at the driver (EISDIR mapped above)
	 * and the pre-flight VFS probe, so this fd-specific block is skipped. */
static ngx_int_t
brix_open_validate_fd(brix_open_args_t *a)
{
	brix_ctx_t       *ctx      = a->ctx;
	ngx_connection_t *c        = a->c;
	const char       *resolved = a->resolved;
	int               fd       = a->fd;
	struct stat      *st       = a->st;
	int               op       = a->is_write ? BRIX_OP_OPEN_WR
	                                         : BRIX_OP_OPEN_RD;
	const char       *mode_str = a->is_write ? "wr" : "rd";

	if (!a->driver_backed) {
		/* A no-fd handle must never reach the POSIX validation path — the
		 * driver-backed branch owns those (st was synthesized there). */
		if (fd < 0) {
			BRIX_RETURN_ERR(ctx, c, op,
							  "OPEN", resolved, mode_str,
							  kXR_IOError, "open produced no file descriptor");
		}
		if (fstat(fd, st) != 0) {
			int err = errno;

			close(fd);
			BRIX_RETURN_ERR(ctx, c, op,
							  "OPEN", resolved, mode_str,
							  kXR_IOError, strerror(err));
		}

		if (S_ISDIR(st->st_mode)) {
			close(fd);
			BRIX_RETURN_ERR(ctx, c, op,
							  "OPEN", resolved, mode_str,
							  kXR_isDirectory, "is a directory");
		}

		/* Only regular files are servable byte streams.  A FIFO, socket, device
		 * or other special file was opened O_NONBLOCK (so the open could not
		 * wedge the worker); refuse to serve it rather than let a read/write spin
		 * on EAGAIN.  A staged write always lands on a freshly O_CREAT'd regular
		 * temp, so this only ever rejects a pre-existing special file. */
		if (!S_ISREG(st->st_mode)) {
			close(fd);
			BRIX_RETURN_ERR(ctx, c, op,
							  "OPEN", resolved, mode_str,
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
	}
	return NGX_OK;
}

/* Forward declaration: defined below, called by brix_open_finalize_handle. */
static void
brix_open_init_handle(brix_open_args_t *a);


/* Post-fd handle setup: validate the POSIX fd (type + clear O_NONBLOCK), init
 * the handle bookkeeping, attach the CSI integrity engine, enforce the open-files
 * cap, register the live-transfer monitor slot, record the on-disk path, apply
 * the parent group policy, build the kXR_retstat string (may clear *want_stat),
 * emit the debug line, and cache the write-through decision. Returns NGX_DECLINED
 * to proceed; any rejection (fd validate, CSI, throttle, path-alloc) has already
 * torn down the fd/sent its reply and its rc is returned. */
ngx_int_t
brix_open_finalize_handle(brix_open_args_t *a)
{
	ngx_connection_t *c = a->c;
	ngx_int_t         rc;

	/* Stat + validate the POSIX fd (regular file, clear O_NONBLOCK) (split out). */
	rc = brix_open_validate_fd(a);
	if (rc != NGX_OK) {
		return rc;
	}

	brix_open_init_handle(a);

	/* Attach the CSI integrity engine to the handle (xmeta P3, split out). */
	rc = brix_open_attach_csi(a);
	if (rc != NGX_OK) {
		return rc;
	}

	/* Enforce the per-user open-files cap (phase-59 W3a, split out). */
	rc = brix_open_apply_throttle(a);
	if (rc != NGX_OK) {
		return rc;
	}

	/* Register the open file with the live transfer monitor (split out). */
	brix_open_register_monitor(a->ctx, a->resolved, a->idx, a->is_write);

	/* Record the handle's on-disk path (POSC temp vs final) for close-time
	 * rename/unlink (split out). */
	rc = brix_open_set_handle_path(a);
	if (rc != NGX_OK) {
		return rc;
	}

	if (a->is_write && a->conf->group_rules != NULL) {
		brix_apply_parent_group_policy_fd(c->log, a->fd, a->resolved,
											a->conf->group_rules);
	}

	/* Build the kXR_retstat metadata string when requested (split out). */
	brix_open_build_retstat(a);

	if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
		char log_path[512];

		brix_sanitize_log_string(a->resolved, log_path, sizeof(log_path));
		ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
					   "brix: kXR_open handle=%d path=%s mode=%s retstat=%d",
					   a->idx, log_path, a->is_write ? "wr" : "rd",
					   (int) a->want_stat);
	}

	/* Evaluate + cache the write-through policy on the handle (split out). */
	brix_open_decide_writethrough(a);

	return NGX_DECLINED;
}

/* Initialise the freshly-opened handle's bookkeeping fields from the fd + stat:
 * fd/direction/from_cache/type/device/inode/size/read-ahead state, the inline
 * read/write codec slots (regular files only), the write-through fields (cleared
 * to a clean state), and the kXR_recoverWrts journal (armed for a recover-writes
 * write open, else zeroed). Leaves the dashboard_slot at -1 for the monitor. */
static void
brix_open_init_handle(brix_open_args_t *a)
{
	brix_ctx_t        *ctx         = a->ctx;
	ngx_connection_t  *c           = a->c;
	int                idx         = a->idx;
	const struct stat *st          = a->st;
	ngx_flag_t         is_write    = a->is_write;
	uint8_t            codec       = a->codec;

	ctx->files[idx].fd          = a->fd;
	ctx->files[idx].readable    = a->is_readable;
	ctx->files[idx].writable    = is_write;
	ctx->files[idx].from_cache  = a->from_cache;
	ctx->files[idx].is_regular  = S_ISREG(st->st_mode) ? 1 : 0;
	ctx->files[idx].device      = st->st_dev;
	ctx->files[idx].inode       = st->st_ino;
	ctx->files[idx].cached_size = (off_t) st->st_size;
	ctx->files[idx].read_last_end  = -1;
	ctx->files[idx].read_ahead_end = 0;

	/*
	 * Phase-42 W4/W5 — inline compression.  `codec` is the codec negotiated from
	 * the open opaque (0 = none).  Honour it only for a regular file, and store it
	 * in the direction-appropriate slot: read_codec for a read open (W4, compress
	 * kXR_read responses), write_codec for a write open (W5, decompress kXR_write
	 * payloads).  The default (codec==0) leaves both slots 0 / byte-identical.
	 */
	ctx->files[idx].read_codec  = (!is_write && S_ISREG(st->st_mode)
	    && codec != BRIX_CODEC_IDENTITY) ? codec : (uint8_t) BRIX_CODEC_IDENTITY;
	ctx->files[idx].write_codec = (is_write && S_ISREG(st->st_mode)
	    && codec != BRIX_CODEC_IDENTITY) ? codec : (uint8_t) BRIX_CODEC_IDENTITY;
	ctx->files[idx].wt_enabled = 0;
	ctx->files[idx].wt_policy = BRIX_WT_DECISION_DENY;
	ctx->files[idx].wt_mode_bits = a->create_mode;
	ctx->files[idx].wt_dirty_offset = -1;
	ctx->files[idx].wt_bytes_written = 0;
	ctx->files[idx].wt_flush_task = NULL;
	ctx->files[idx].wt_flush_pending = 0;

	/* kXR_recoverWrts journal initialisation
	 * Arm the write-recovery ring when the handle is opened for writing and
	 * the recover_writes directive is on.  Read-only handles get the fields
	 * zeroed (they are zero from brix_free_fhandle, but be explicit).
	 */
	{
		ngx_stream_brix_srv_conf_t *wrts_conf;
		wrts_conf = ngx_stream_get_module_srv_conf(
		    (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
		if (is_write && wrts_conf->caps.recover_writes) {
			brix_wrts_open(&ctx->files[idx]);
		} else {
			ctx->files[idx].wrts_enabled = 0;
			ctx->files[idx].wrts_head    = 0;
			ctx->files[idx].wrts_count   = 0;
			ctx->files[idx].wrts_gen     = 0;
		}
	}

	ctx->files[idx].dashboard_slot = -1;
}
