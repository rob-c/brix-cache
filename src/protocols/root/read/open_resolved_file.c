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

/* kXR_wait retry interval handed to a client whose read-open faulted a nearline
 * (tape) recall - the stream equivalent of the WebDAV 202 Retry-After (§9.2). */
#define BRIX_RECALL_WAIT_SECS  10

/* Confined existence/type probe of an absolute path beneath `root` via the VFS
 * (no metric, no pool). Returns 1 with *vst filled when the path exists, else 0.
 * `nofollow` selects lstat vs stat semantics. Used for the kXR_open pre-flight
 * checks (directory reject, exclusive-create, resume-partial existence), each of
 * which has its own confinement root — the export root for the final path, the
 * upload stage dir for an external resume partial.
 *
 * WHY (phase-70): on a driver-backed (remote root://) export the probe's
 * existence/type check is not a local stat — it opens the ORIGIN to stat, so it
 * must present the same forwarded credential the real open does. Without the
 * deleg the origin refuses ("backend has NO credential") and the probe reports
 * the file absent, which turns a legitimate read into a spurious kXR_NotFound.
 * The actual open path binds the deleg on its own vctx (brix_open_dispatch_open
 * → brix_root_vfs_bind_deleg); the pre-flight probe must do the same. Pass a
 * NULL ctx/conf for a probe of a purely worker-local path (an external upload
 * stage-dir partial), which never routes to the origin. `pool` supplies the
 * deleg bag's allocation (the request pool); NULL leaves the probe deleg-less. */
static int
brix_open_probe(ngx_log_t *log, const char *root, const char *abs,
    int nofollow, brix_vfs_stat_t *vst,
    brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf, ngx_pool_t *pool)
{
    brix_vfs_ctx_t vctx;

    brix_vfs_ctx_init(&vctx, pool, log, BRIX_PROTO_ROOT, root, NULL,
        1 /* allow_write */, 0 /* is_tls */, NULL, abs);
    if (ctx != NULL && conf != NULL && pool != NULL) {
        brix_root_vfs_bind_deleg(ctx, conf, &vctx);
    }
    return brix_vfs_probe(&vctx, nofollow, vst) == NGX_OK;
}

/* The export-root-relative ("logical") form of an absolute path confined under
 * `root`: strips the root prefix + leading '/'. Returns the suffix, or the path
 * unchanged when it is not under root (then the VFS open/probe will reject it).
 * Centralises the rel-strip the kXR_open path repeats for the export-root open
 * (the cache/stage domains open as the worker and need no rel form). */
static const char *
brix_open_logical(const char *abs, const char *root)
{
    size_t root_len = (root != NULL) ? strlen(root) : 0;

    if (root_len > 0
        && ngx_strncmp((u_char *) abs, (u_char *) root, root_len) == 0
        && abs[root_len] == '/')
    {
        return abs + root_len + 1;
    }
    return abs;
}

/* Map the POSIX open(2) flags the kXR_open path computed back to the backend-
 * neutral BRIX_SD_O_* intent the storage driver understands. The driver
 * re-derives its own native flags from these (the POSIX driver re-expands to
 * O_*), so a non-POSIX backend never sees Linux-specific bits. */
static int
brix_open_oflags_to_sd(int oflags, int is_readable, int is_write)
{
    int sd = 0;

    if (is_readable)        { sd |= BRIX_SD_O_READ;   }
    if (is_write)           { sd |= BRIX_SD_O_WRITE;  }
    if (oflags & O_CREAT)   { sd |= BRIX_SD_O_CREATE; }
    if (oflags & O_EXCL)    { sd |= BRIX_SD_O_EXCL;   }
    if (oflags & O_TRUNC)   { sd |= BRIX_SD_O_TRUNC;  }
    if (oflags & O_APPEND)  { sd |= BRIX_SD_O_APPEND; }
    return sd;
}

/*
 * brix_open_args_t — the per-request kXR_open state threaded through the
 * static open pipeline (phase-72 B5 parameter consolidation).
 *
 * WHAT: One file-local carrier for everything brix_open_resolved_file computes
 *       once — the session/config pointers, the decoded kXR_open intent, the
 *       staging decision + POSC/resume temp path, the allocated handle slot,
 *       the open outcome (fd/stat/driver routing) and the kXR_retstat buffer —
 *       so the pipeline stages take this struct instead of 7–21 positional
 *       parameters each.
 *
 * WHY:  The open path is a linear pipeline (preflight → dispatch → finalize →
 *       response) whose stages share one request's state; passing it
 *       positionally bloated every signature past the complexity gate and made
 *       call sites error-prone (runs of adjacent same-typed flags).
 *
 * HOW:  brix_open_resolved_file zeroes the struct, fills the request-constant
 *       fields, then each stage reads what it needs and writes only the fields
 *       it owns (preflight: use_resume/stage/posc_temp_path; dispatch:
 *       fd/st/driver_backed/wt_via_stage; finalize: want_stat/statbuf).
 *       Pure signature consolidation — no logic moved.
 */
typedef struct {
    /* request identity + config (constant for the whole open) */
    brix_ctx_t                 *ctx;
    ngx_connection_t           *c;
    ngx_stream_brix_srv_conf_t *conf;
    const char                 *resolved;    /* canonical absolute final path */
    uint16_t                    options;     /* kXR_open option bits */
    ngx_flag_t                  is_write;
    uint8_t                     codec;       /* negotiated inline codec (0 = none) */

    /* decoded POSIX open(2) intent (open_flags.h mapping) */
    int                         oflags;
    int                         is_readable;
    mode_t                      create_mode;

    /* Staging decision.  use_posc: kXR_posc write — stage to a random temp,
     * rename on clean close, unlink on non-clean close.  use_resume
     * (brix_upload_resume on): stage to a deterministic identity-keyed
     * partial that SURVIVES a non-clean close so a reconnecting client
     * resumes in place — a superset of POSC staging, so `stage` drives the
     * open + commit for both. */
    ngx_flag_t                  use_posc;
    ngx_flag_t                  use_resume;
    ngx_flag_t                  stage;
    ngx_flag_t                  from_cache;  /* server-managed cache-root open */
    char                        posc_temp_path[PATH_MAX];

    /* open outcome */
    int                         idx;         /* allocated fhandle slot */
    int                         fd;          /* POSIX fd / driver block-0 fd / -1 */
    struct stat                *st;          /* caller-owned, zero-initialised */
    ngx_int_t                   driver_backed;
    ngx_int_t                   wt_via_stage;

    /* kXR_retstat */
    ngx_flag_t                  want_stat;   /* cleared when the stat is unavailable */
    char                        statbuf[256];
} brix_open_args_t;

/* Driver-backed kXR_open (Layer 3): open `logical` through the export's storage
 * driver into the handle's sd_obj, then synthesize a struct stat from the
 * driver's captured open snapshot so the rest of the open path (bookkeeping,
 * size reporting) is backend-agnostic. The handle's bare `fd` becomes the
 * driver's representative descriptor (a block-0 fd for CAP_FD backends, or
 * NGX_INVALID_FILE for a pure object store) and all subsequent byte I/O routes
 * through fh->sd_obj.driver. Writes *out_fd and *st on success and returns
 * NGX_OK; on failure sets errno and returns NGX_ERROR (the caller maps errno to
 * the kXR error exactly as for a POSIX open).
 *
 * WHAT: `vctx` carries the per-user backend credential policy (Phase 2 Task 6)
 *       bound by the caller via brix_vfs_ctx_bind_backend_cred(); when the
 *       policy resolves a user credential this open presents it to the
 *       backend driver via brix_sd_open_maybe_cred instead of the static
 *       service credential.
 *
 * WHY:  A root:// session already carries the authenticated brix_identity_t
 *       on brix_ctx_t; without this gate every remote-backed root:// open
 *       (davs/S3 already had this via brix_vfs_open) silently used the
 *       shared service credential for every user, indistinguishable in the
 *       origin's own auth/session log.
 *
 * HOW:  Runs brix_vfs_backend_cred() BEFORE the driver open (deny mode must
 *       refuse before any origin connection is attempted, exactly as the
 *       VFS's own brix_vfs_open does); on NGX_ERROR propagates errno (EACCES)
 *       without touching the driver. */
static ngx_int_t
brix_open_resolved_via_driver(brix_open_args_t *a, brix_vfs_ctx_t *vctx,
    brix_sd_instance_t *sd, const char *logical)
{
    brix_file_t     *fh = &a->ctx->files[a->idx];
    struct stat     *st = a->st;
    int              sd_flags = brix_open_oflags_to_sd(a->oflags,
                                                         a->is_readable,
                                                         a->is_write);
    int              oerr = 0;
    brix_sd_obj_t *obj;
    brix_sd_ucred_t ustore;
    brix_sd_cred_t  ucred;
    int              use_cred = 0;

    ngx_memzero(&ucred, sizeof(ucred));
    if (brix_vfs_backend_cred(vctx, &ustore, &ucred, &use_cred, &oerr)
        != NGX_OK)
    {
        errno = (oerr != 0) ? oerr : EACCES;
        return NGX_ERROR;
    }

    obj = brix_sd_open_maybe_cred(sd, logical, sd_flags, a->create_mode,
        use_cred ? &ucred : NULL, &oerr);
    if (obj == NULL) {
        errno = (oerr != 0) ? oerr : EIO;
        return NGX_ERROR;
    }

    /* Adopt the object by value into the handle. A driver that malloc'd the obj
     * shell (heap_shell) hands ownership of the COPY to us; free the now-
     * redundant shell. The embedded copy is not itself a heap shell. */
    fh->sd_obj = *obj;
    if (obj->heap_shell) {
        free(obj);
    }
    fh->sd_obj.heap_shell = 0;

    /* The driver's open may defer metadata (the POSIX driver deliberately skips
     * the fstat at open — see sd_posix_open). Populate the snapshot now via the
     * driver's own fstat so the synthesized `struct stat` (and hence the handle's
     * cached_size) is correct: a driver-aware fstat reports the LOGICAL object
     * size (e.g. pblock's whole-object size, not block 0). Without this the
     * cached_size stays 0 and the buffered read path — inline read compression,
     * and any non-sendfile serve — sees EOF immediately and returns nothing. */
    if (sd->driver->fstat != NULL && fh->sd_obj.snap.size == 0) {
        (void) sd->driver->fstat(&fh->sd_obj, &fh->sd_obj.snap);
    }

    ngx_memzero(st, sizeof(*st));
    st->st_size  = fh->sd_obj.snap.size;
    st->st_mtime = fh->sd_obj.snap.mtime;
    st->st_ctime = fh->sd_obj.snap.ctime;
    st->st_ino   = fh->sd_obj.snap.ino;
    st->st_mode  = (fh->sd_obj.snap.mode != 0)
                 ? fh->sd_obj.snap.mode
                 : (fh->sd_obj.snap.is_dir ? (S_IFDIR | 0755)
                                           : (S_IFREG | 0644));

    /* The driver snapshot carries no device id, so st_dev would stay 0 and the
     * published-handle table would record device 0. A bound secondary reopens
     * the file for itself (a real fstat, real st_dev) and revalidates device+
     * inode against the published entry — a 0 vs real-device mismatch would then
     * wrongly revoke every bound read (kXR_error). For a driver with a real
     * backing descriptor (the POSIX driver's fd is the file itself), capture the
     * real device here so the published identity matches the secondary's reopen. */
    if (fh->sd_obj.fd >= 0) {
        struct stat rst;
        if (fstat(fh->sd_obj.fd, &rst) == 0) {
            st->st_dev = rst.st_dev;

            /* Anti-wedge parity with the non-driver path's S_ISREG gate: a FIFO,
             * socket, or device is not a servable byte stream. The confined open
             * forced O_NONBLOCK so the open(2) itself could not park the worker,
             * but a subsequent read/write would spin on EAGAIN — refuse it here,
             * where the real st_mode is available (the driver snapshot may not
             * carry a mode). A directory keeps its own handling upstream; only
             * special files are cut. */
            if (!S_ISREG(rst.st_mode) && !S_ISDIR(rst.st_mode)) {
                (void) sd->driver->close(&fh->sd_obj);
                fh->sd_obj.driver = NULL;
                fh->sd_obj.inst   = NULL;
                fh->sd_obj.state  = NULL;
                fh->sd_obj.fd     = -1;
                errno = EINVAL;
                return NGX_ERROR;
            }
        }
    }

    a->fd = fh->sd_obj.fd;   /* block-0 fd, or NGX_INVALID_FILE (-1) */
    return NGX_OK;
}

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


/* Build the kXR_retstat metadata string for a retstat open: fstat the real-fd
 * path (a driver no-fd handle already has st), format "ino size flags mtime"
 * into statbuf, and clear *want_stat when the stat is unavailable. */
static void
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
			int stat_flags = 0;
			if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
				stat_flags |= kXR_readable;
			}
			if (st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
				stat_flags |= kXR_writable;
			}
			if (ctx->files[idx].from_cache) {
				stat_flags |= kXR_cachersp;
			}
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


	/* A write open of an existing DIRECTORY must be rejected up front with
	 * kXR_isDirectory (stock parity: O_WRONLY on a directory fails EISDIR).
	 * Without this the staging path below would derive a ".part" FILE from the
	 * directory's name, create it, and wrongly report success — diverging from
	 * stock. The read side is rejected symmetrically just below. */
static ngx_int_t
brix_open_check_write_target(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *resolved, ngx_flag_t is_write)
{
	if (is_write) {
		brix_vfs_stat_t dst;
		/* A final path that is itself a symlink must be rejected for write: we
		 * never write THROUGH an in-root link. The direct-open mapping enforces
		 * this with O_NOFOLLOW on the final component (ELOOP), but the staging
		 * path opens a randomly-named temp instead of the final and would commit
		 * over the link on rename — so guard it here. lstat (no-follow) reports
		 * the link as itself; resolution is already confined to the export, so
		 * this catches an in-export link with EITHER an in-root or outward target
		 * without following it. */
		if (brix_open_probe(c->log, conf->common.root_canon, resolved, 1,
		                      &dst, ctx, conf, c->pool)
		    && S_ISLNK((mode_t) dst.mode)) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_NotAuthorized,
			                  "refusing to write through a symlink");
		}
		if (brix_open_probe(c->log, conf->common.root_canon, resolved, 0,
		                      &dst, ctx, conf, c->pool)
		    && dst.is_directory) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_isDirectory,
			                  "is a directory");
		}
	}
	/* NGX_DECLINED = allow/continue.  A rejection above sends its own error and
	 * returns that send's rc (NGX_OK on success), so the caller MUST test for
	 * NGX_DECLINED — not NGX_OK — to tell "continue" from "error already sent"
	 * (else it falls through and sends a second, conflicting reply). */
	return NGX_DECLINED;
}


	/* Phase C: two-tier write-back-staging backpressure. When write-through
	 * staging is configured with watermarks, shed new write-opens while the
	 * staging filesystem is full — delay in the soft band (kXR_wait, the client
	 * retries), reject at the hard cap (kXR_Overloaded). Runs before any handle or
	 * staging-temp allocation, so a shed write consumes nothing. Reads never reach
	 * here. */
static ngx_int_t   /* the value to return from the caller, or NGX_DECLINED = allow/continue */
brix_open_stage_backpressure(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *resolved, ngx_flag_t is_write)
{
	if (is_write && conf->wt.enable) {
		switch (brix_wt_stage_admit(conf)) {
		case BRIX_WT_ADMIT_WAIT:
			brix_metric_wt_stage_throttled(0 /* wait */);
			brix_log_access(ctx, c, "OPEN", resolved, "wr-staging-wait",
			                  0, 0, "write-back staging busy; retry", 0);
			return brix_send_wait(ctx, c, BRIX_WT_STAGE_WAIT_SECS);
		case BRIX_WT_ADMIT_REJECT:
			brix_metric_wt_stage_throttled(1 /* reject */);
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN", resolved,
			                  "wr", kXR_Overloaded,
			                  "write-back staging area full");
		case BRIX_WT_ADMIT_ALLOW:
		default:
			break;
		}
	}
	return NGX_DECLINED;
}


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
static ngx_int_t
brix_open_check_exclusive_create(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;

	if (a->stage && (a->options & kXR_new) && !(a->options & kXR_delete)) {
		brix_vfs_stat_t fst;
		if (brix_open_probe(c->log, conf->common.root_canon, resolved, 0,
		                      &fst, ctx, conf, c->pool)) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ItExists,
			                  "file already exists");
		}
	}
	/* NGX_DECLINED = allow/continue; a kXR_ItExists rejection above already sent
	 * its reply and returned that send's rc — the caller tests for NGX_DECLINED,
	 * not NGX_OK, so a sent error stops the open instead of falling through to
	 * open the staging temp and send a second (fhandle) reply. */
	return NGX_DECLINED;
}


/* Build the POSC/resume staging temp path into posc_temp_path (resume = a
 * deterministic identity-keyed partial; POSC = a random ".posc.*" temp on the
 * final path's fs).  Returns NGX_OK, or an error response on a too-long path. */
static ngx_int_t
brix_open_build_stage_temp(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	char                       *posc_temp_path    = a->posc_temp_path;
	size_t                      posc_temp_path_sz = sizeof(a->posc_temp_path);

	if (a->use_resume) {
		/* Deterministic, identity-keyed: a reconnecting client re-opening the
		 * same final path lands on the SAME partial and resumes from its
		 * offset.  Anonymous (empty dn) shares per-path (no per-user isolation
		 * on such an endpoint anyway).  When brix_stage_dir is set the partial
		 * lives on that fast device and the close-time commit moves it to the
		 * destination (cross-device copy). */
		const char *principal = ctx->login.dn[0] ? ctx->login.dn : NULL;
		const char *stage_dir = conf->upload_stage_dir_canon[0]
		                        ? conf->upload_stage_dir_canon : NULL;
		if (brix_make_resume_path(resolved, principal, stage_dir,
		                            posc_temp_path, posc_temp_path_sz)
		    != NGX_OK) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ServerError,
			                  "resume temp path too long");
		}
	} else if (a->use_posc) {
		if (brix_make_tmp_path(resolved, posc_temp_path,
		                         posc_temp_path_sz) != NGX_OK) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_WR, "OPEN",
			                  resolved, "wr", kXR_ServerError,
			                  "POSC temp path too long");
		}
	}
	/* NGX_DECLINED = built OK / nothing to build (continue); a path-too-long
	 * rejection above already sent its reply — caller tests NGX_DECLINED, not
	 * NGX_OK, so a sent error is not mistaken for "continue". */
	return NGX_DECLINED;
}


/* Map a failed open(2)'s errno to the kXR error response the reference raises,
 * sending it and returning that send's rc; EAGAIN on a read is a nearline recall
 * (kXR_wait retry) rather than an error. Reached only when open_failed is set, so
 * it always sends exactly one reply. Returns the value the caller must return. */
static ngx_int_t
brix_open_map_open_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *resolved, int err, ngx_flag_t is_write)
{
	const char *mode_str = is_write ? "wr" : "rd";

	if (err == ENOENT || err == ENOTDIR) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", resolved, mode_str,
						  kXR_NotFound, "file not found");
	}
	if (err == EEXIST) {
		/* O_EXCL (kXR_new without kXR_delete) on an existing file → EEXIST,
		 * which the reference maps to kXR_ItExists (the code raised by the
		 * kXR_new flag), NOT kXR_FileLocked. */
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", resolved, mode_str,
						  kXR_ItExists, "file already exists");
	}
	if (err == EACCES) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", resolved, mode_str,
						  kXR_NotAuthorized, "permission denied");
	}
	if (err == EISDIR) {
		BRIX_RETURN_ERR(ctx, c,
						  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
						  "OPEN", resolved, mode_str,
						  kXR_isDirectory, "is a directory");
	}
	if (err == EAGAIN && !is_write) {
		/* A nearline (tape) recall is in flight (sd_cache/sd_frm, §9.2). Tell
		 * the client to retry with kXR_wait - the stream equivalent of the
		 * WebDAV 202 "staging": the open "parks" via client retry rather than
		 * blocking the worker for the MSS latency. A later re-open re-polls the
		 * recall and, once the object is online in the cache tier, opens +
		 * serves it. */
		brix_log_access(ctx, c, "OPEN", resolved, "rd-recall-wait",
		                  0, 0, "nearline recall in progress; retry", 0);
		return brix_send_wait(ctx, c, BRIX_RECALL_WAIT_SECS);
	}
	BRIX_RETURN_ERR(ctx, c,
					  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
					  "OPEN", resolved, mode_str,
					  kXR_IOError, strerror(err));
}


/* The POSIX-fd open dispatch: open the staging temp / cache / export final path
 * (never a driver-backed export — that is handled by the caller). Forces O_CREAT
 * for a staged open and O_NONBLOCK so the open cannot park the worker; cache and
 * external-stage domains open raw as the worker, the export final opens beneath
 * the export rootfd through the VFS. Writes *out_fd and returns 1 when the open
 * failed (errno set), else 0. */
static int
brix_open_posix_dispatch(brix_open_args_t *a)
{
	ngx_stream_brix_srv_conf_t *conf        = a->conf;
	const char                 *resolved    = a->resolved;
	int                         oflags      = a->oflags;
	mode_t                      create_mode = a->create_mode;
	ngx_flag_t                  stage       = a->stage;
	ngx_flag_t                  use_resume  = a->use_resume;
	ngx_flag_t                  from_cache  = a->from_cache;

	/* When POSC is active, open the staging temp path instead of the
	 * final path.  The O_CREAT flag is forced so the temp file is
	 * always created fresh; O_EXCL is intentionally omitted so that a
	 * previous crash leaving a stale temp file does not block a retry. */
	const char *open_path = stage ? a->posc_temp_path : resolved;
	int         fd;

	/* Staged opens (POSC or resume) always need O_CREAT on the temp path.
	 * O_TRUNC is inherited from `oflags`: a fresh create/truncate open
	 * starts the partial empty; a resume re-open (kXR_open_updt, no trunc)
	 * preserves the already-written bytes. */
	/* O_NONBLOCK guarantees the open(2) cannot park the worker in the
	 * kernel FIFO/device "wait_for_partner" rendezvous (a named pipe in the
	 * export would otherwise freeze the worker's event loop and stall every
	 * connection pinned to it).  It is harmless for the regular files we
	 * serve and is cleared again on the surviving fd once fstat() confirms
	 * S_ISREG below.  Mirrors the central guard in brix_vfs_open_fd_at(). */
	int effective_oflags = oflags | (stage ? O_CREAT : 0) | O_NONBLOCK;

	/* Resume staging on a configured fast device: the partial lives OUTSIDE
	 * root_canon, so it cannot go through the RESOLVE_BENEATH open.  Its
	 * basename is a server-generated hash (no client-controlled component)
	 * inside the operator-trusted, canonicalized stage dir, so a direct open
	 * with O_NOFOLLOW on the final component is safe. */
	ngx_flag_t stage_external = use_resume
	    && conf->upload_stage_dir_canon[0] != '\0';

	if (stage_external) {
		/* vfs-seam-allow: separate storage domain. The partial lives under
		 * the operator-trusted upload stage dir (a different root than the
		 * export, server-generated hash basename, svc-owned), so it is opened
		 * as the worker — NOT through the export-confined, impersonation-aware
		 * VFS (which would resolve under the export rootfd / mapped user).
		 * O_NOFOLLOW guards the final component. */
		fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,  /* vfs-seam-allow: separate svc-owned storage domain (cache/stage), opened as worker */
		          create_mode);
	} else if (from_cache) {
		/* vfs-seam-allow: separate storage domain. cache_root files are
		 * server-managed (filled by the cache worker, never client-written,
		 * svc-owned) in a different root than the export, so they are opened
		 * as the worker rather than through the export-confined VFS. O_NOFOLLOW
		 * is defence-in-depth; O_CLOEXEC prevents FD leak into a forked child. */
		fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,  /* vfs-seam-allow: separate svc-owned storage domain (cache/stage), opened as worker */
		          create_mode);
	} else {
		/* The export final/staged path: open beneath the export root through
		 * the VFS (openat2 RESOLVE_BENEATH, impersonation-aware). The VFS
		 * strips the absolute path to its rootfd-relative form. */
		fd = brix_vfs_open_fd_at(conf->rootfd,
		    brix_open_logical(open_path, conf->common.root_canon),
		    effective_oflags, create_mode);
	}
	a->fd = fd;
	return (fd < 0);
}


/* In-place update vs upload for resume staging: a pure update-in-place open
 * (kXR_open_updt, no delete/new) with NO resume partial in flight is NOT an
 * upload to stage — drop out of resume staging so the direct open mapping edits
 * the committed file in place (or fails kXR_NotFound), matching stock xrootd.
 * Clears *use_resume / recomputes *stage when so. */
static void
brix_open_resume_inplace_decide(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx            = a->ctx;
	ngx_connection_t           *c              = a->c;
	ngx_stream_brix_srv_conf_t *conf           = a->conf;
	const char                 *resolved       = a->resolved;
	const char                 *posc_temp_path = a->posc_temp_path;
	uint16_t                    options        = a->options;
	ngx_flag_t                  use_posc       = a->use_posc;
	ngx_flag_t                 *use_resume     = &a->use_resume;
	ngx_flag_t                 *stage          = &a->stage;

	if (*use_resume && !(options & kXR_delete) && !(options & kXR_new)) {
		brix_vfs_stat_t fst;
		int               have_partial;

		/* A pure update-in-place open is NOT an upload to stage when no resume
		 * partial is in flight: drop out of resume staging and let the direct
		 * open mapping (O_RDWR, no O_CREAT) decide, matching stock xrootd:
		 *   - final is a committed regular file -> edit it in place (preserve the
		 *     bytes the client does not rewrite);
		 *   - final does not exist              -> fail kXR_NotFound, exactly as
		 *     O_RDWR-without-O_CREAT would.  Staging would otherwise CREATE the
		 *     missing file and return kXR_ok, diverging from stock which derives
		 *     no O_CREAT for kXR_open_updt alone (XrdXrootdXeq.cc:1524). */
		/* The partial lives under the upload stage dir when one is configured
		 * (a separate, svc-owned storage domain), else next to the final under
		 * the export root. Probe the export-root partial through the VFS; the
		 * external stage-dir partial is checked as the worker (separate domain,
		 * same reasoning as the open below). */
		if (conf->upload_stage_dir_canon[0] != '\0') {
			struct stat sst;   /* vfs-seam-allow: separate upload stage-dir domain */
			have_partial = (stat(posc_temp_path, &sst) == 0);  /* vfs-seam-allow: separate upload stage-dir domain */
		} else {
			brix_vfs_stat_t pst;
			have_partial = brix_open_probe(c->log, conf->common.root_canon,
			                                 posc_temp_path, 0, &pst,
			                                 ctx, conf, c->pool);
		}
		int final_exists = brix_open_probe(c->log, conf->common.root_canon,
		                                     resolved, 0, &fst,
		                                     ctx, conf, c->pool);
		if (!have_partial && (!final_exists || fst.is_regular)) {
			*use_resume = 0;
			*stage = use_posc;
		}
	}
}


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
static ngx_int_t
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


/* Run the pre-open staging preflight: reject a write onto a symlink/dir, shed
 * write-opens under staging backpressure, enforce kXR_new exclusive-create
 * against the final path, build the POSC/resume temp path, drop resume staging
 * for a pure in-place update with no partial, and reject a read of a directory.
 * Mutates *use_resume / *stage / posc_temp_path. Returns NGX_DECLINED to proceed;
 * on any rejection the error is already sent and its rc is returned. */
static ngx_int_t
brix_open_stage_preflight(brix_open_args_t *a)
{
	brix_ctx_t                 *ctx      = a->ctx;
	ngx_connection_t           *c        = a->c;
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	ngx_int_t                   rc;

	/* Reject a write open onto a symlink or existing directory (split out). */
	rc = brix_open_check_write_target(ctx, c, conf, resolved, a->is_write);
	if (rc != NGX_DECLINED) {
		return rc;   /* rejected: error already sent, propagate its rc */
	}

	/* Two-tier write-back-staging backpressure: shed new write-opens when the
	 * staging fs is full (kXR_wait / kXR_Overloaded) (split out). */
	rc = brix_open_stage_backpressure(ctx, c, conf, resolved, a->is_write);
	if (rc != NGX_DECLINED) {
		return rc;
	}

	/* kXR_new exclusive-create check against the FINAL path when staging: the
	 * staging temp is same-fs of the destination so rename(2) is atomic (split
	 * out). */
	rc = brix_open_check_exclusive_create(a);
	if (rc != NGX_DECLINED) {
		return rc;   /* kXR_ItExists already sent, propagate its rc */
	}

	/* Build the POSC/resume staging temp path (split out). */
	rc = brix_open_build_stage_temp(a);
	if (rc != NGX_DECLINED) {
		return rc;   /* path-too-long error already sent, propagate its rc */
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
	brix_open_resume_inplace_decide(a);

	if (!a->is_write) {
		brix_vfs_stat_t rst;
		if (brix_open_probe(c->log, conf->common.root_canon, resolved, 0,
		                      &rst, ctx, conf, c->pool)
		    && rst.is_directory) {
			BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
							  resolved, "rd", kXR_isDirectory,
							  "is a directory");
		}
	}
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


/* Whole-object staged write open (phase-70): put the freshly-allocated handle in
 * STAGED mode instead of opening a session-writable driver handle a whole-object
 * backend cannot provide. Opens a VFS staged handle on `vctx` (which the caller
 * already bound with the per-user credential + deleg + .sd = the composed
 * instance) via brix_vfs_staged_open — the SAME staged_open_cred + cred gate the
 * WebDAV/S3 PUT bridge uses. The staged handle self-contains its ctx on the
 * connection pool, so it survives across the open→writes→sync/close requests.
 * On success synthesizes a minimal `struct stat` (no bytes yet), sets fd=-1 and
 * driver_backed=1 (so brix_open_validate_fd skips the POSIX-fd checks), records
 * the staged handle + zero append offset on the file slot, and returns
 * NGX_DECLINED (proceed). On failure sends the mapped kXR error and returns its
 * rc. Sequential-append + commit-on-sync/close are handled by the write/sync/
 * close opcode handlers keyed on ctx->files[idx].staged != NULL. */
static ngx_int_t
brix_open_dispatch_staged(brix_open_args_t *a, brix_vfs_ctx_t *vctx,
    brix_sd_instance_t *sd)
{
	brix_ctx_t         *ctx = a->ctx;
	ngx_connection_t   *c   = a->c;
	brix_file_t        *fh  = &ctx->files[a->idx];
	brix_vfs_staged_t  *st;
	int                 serr = 0;

	vctx->sd = sd;   /* brix_vfs_staged_open dispatches on ctx->sd */

	st = brix_vfs_staged_open(vctx, a->create_mode, 16 /* excl-name attempts */,
	                            &serr);
	if (st == NULL) {
		return brix_open_map_open_error(ctx, c, a->resolved,
		    serr != 0 ? serr : EROFS, a->is_write);
	}

	fh->staged              = st;
	fh->staged_expected_off = 0;
	fh->staged_committed    = 0;

	/* No fd, no driver object: byte I/O routes through the staged handle. Mark
	 * driver_backed so the POSIX-fd validation is skipped and synthesize a stat
	 * (a brand-new whole object — zero bytes, regular file with the create mode). */
	a->fd            = NGX_INVALID_FILE;
	a->driver_backed = 1;
	ngx_memzero(a->st, sizeof(*a->st));
	a->st->st_mode = S_IFREG | (a->create_mode ? a->create_mode : 0644);
	return NGX_DECLINED;
}


/* WHAT: Select the storage-driver instance for this open, applying the write-
 * through override.
 * WHY:  Isolates the wt sd_stage selection (Option A) from the dispatch control
 *       flow so the caller reads as a single backend-resolve step.
 * HOW:  Resolves the export backend, then — for a fresh (non-cache/non-resume)
 *       WRITE with wt.enable and a composed wt sd_stage — swaps in the wt
 *       instance and sets a->wt_via_stage. Returns the selected instance (may be
 *       NULL); leaves wt_via_stage untouched (caller pre-zeroes it) when no
 *       override applies. */
static brix_sd_instance_t *
brix_open_select_sd_inst(brix_open_args_t *a)
{
	ngx_stream_brix_srv_conf_t *conf    = a->conf;
	brix_sd_instance_t         *sd_inst =
	    brix_vfs_backend_resolve(conf->common.root_canon, a->c->log);

	if (a->is_write && conf->wt.enable && !a->from_cache && !a->use_resume) {
		brix_sd_instance_t *wt = brix_cache_wt_stage_sd_inst(conf);

		if (wt != NULL) {
			sd_inst          = wt;
			a->wt_via_stage  = 1;
		}
	}
	return sd_inst;
}


/* WHAT: Build the transient per-open VFS ctx that scopes a driver open to the
 *       authenticated client identity.
 * WHY:  The cred/mint/deleg bind sequence is identical to the davs/S3 call sites
 *       and is pure setup — pulling it out of the dispatcher keeps the control
 *       flow legible without changing any bind order.
 * HOW:  Initialises *cred_vctx for the root:// export, binds the credential-dir/
 *       fallback policy, opt-in mint CA, and delegation, then pins the selected
 *       sd instance. No-ops (use_cred/mint stay 0) when the corresponding config
 *       is unset. */
static void
brix_open_build_cred_ctx(brix_open_args_t *a, brix_sd_instance_t *sd_inst,
    brix_vfs_ctx_t *cred_vctx)
{
	brix_ctx_t                 *ctx  = a->ctx;
	ngx_connection_t           *c    = a->c;
	ngx_stream_brix_srv_conf_t *conf = a->conf;

	brix_vfs_ctx_init(cred_vctx, c->pool, c->log, BRIX_PROTO_ROOT,
	    conf->common.root_canon, NULL, conf->common.allow_write,
	    0 /* is_tls */, ctx->identity, a->resolved);
	brix_vfs_ctx_bind_backend_cred(cred_vctx,
	    &conf->common.storage_credential_dir,
	    conf->common.storage_credential_fallback);
	/* Phase-3 T1: opt-in credential minting for GSI/token identities that
	 * have no pre-provisioned proxy — mirrors the davs/S3 mint bind call
	 * sites (Phase-2 T9). No-op unless a mint CA is configured. */
	brix_vfs_ctx_bind_backend_mint(cred_vctx,
	    &conf->common.storage_credential_mint_ca_cert,
	    &conf->common.storage_credential_mint_ca_key,
	    conf->common.storage_credential_mint_ttl);
	brix_root_vfs_bind_deleg(ctx, conf, cred_vctx);
	cred_vctx->sd = sd_inst;
}


/* WHAT: Report whether a WRITE open must use the whole-object staged-commit
 *       adapter instead of a session-writable driver open.
 * WHY:  A whole-object staged backend (sd_http and any driver that advertises NO
 *       BRIX_SD_CAP_RANDOM_WRITE and has no .pwrite — writes are a single commit-
 *       time PUT) cannot satisfy the root:// block-oriented write model; the
 *       plain/cred open slot would refuse with EROFS.
 * HOW:  True only for a WRITE whose ns leaf lacks random-write capability and has
 *       no .pwrite; the caller then routes through brix_open_dispatch_staged. */
static int
brix_open_write_needs_staged(brix_open_args_t *a, brix_sd_instance_t *sd_inst)
{
	brix_sd_instance_t *leaf;

	if (!a->is_write) {
		return 0;
	}
	leaf = brix_vfs_ns_leaf(sd_inst);
	return leaf != NULL
	    && !(brix_sd_caps(leaf) & BRIX_SD_CAP_RANDOM_WRITE)
	    && (leaf->driver == NULL || leaf->driver->pwrite == NULL);
}


/* WHAT: Dispatch a driver-backed open (the sd_inst branch), routing writes that
 *       need the whole-object staged adapter and otherwise opening via the driver.
 * WHY:  Contains the credential-bind + staged-adapter + driver-open decisions so
 *       brix_open_dispatch_open stays a two-way (driver vs POSIX) selector.
 * HOW:  Marks driver_backed, builds the per-open cred ctx, and — for a staged-
 *       write — returns the staged dispatch rc via *out_rc and NGX_DONE. Otherwise
 *       opens through the driver keyed on the export-root-relative name and returns
 *       NGX_OK, writing open_failed (0/1) to *out_failed for the caller to map. */
static ngx_int_t
brix_open_dispatch_driver(brix_open_args_t *a, brix_sd_instance_t *sd_inst,
    ngx_int_t *out_failed, ngx_int_t *out_rc)
{
	ngx_stream_brix_srv_conf_t *conf     = a->conf;
	const char                 *resolved = a->resolved;
	brix_vfs_ctx_t              cred_vctx;

	a->driver_backed = 1;
	/* Per-user backend credential (Phase 2 Task 6): bind the authenticated
	 * root:// session identity + the export's credential-dir/fallback policy so
	 * the driver open scopes the origin session to the CLIENT rather than the
	 * shared service credential — mirrors the davs/S3 brix_vfs_open call sites
	 * (Phase 1). */
	brix_open_build_cred_ctx(a, sd_inst, &cred_vctx);

	/* Whole-object staged-commit adapter (phase-70): open a VFS staged handle
	 * (the same block-body → staged_write+staged_commit bridge WebDAV/S3 PUT use)
	 * and put this file handle in STAGED mode; kXR_write/pgwrite then APPEND, and
	 * kXR_sync/close COMMIT the whole object. brix_open_dispatch_staged binds the
	 * per-user credential + deleg via cred_vctx exactly as the driver open does. */
	if (brix_open_write_needs_staged(a, sd_inst)) {
		*out_rc = brix_open_dispatch_staged(a, &cred_vctx, sd_inst);
		return NGX_DONE;
	}

	/* Key the driver namespace on the export-root-relative ("/sub/file") form —
	 * the same convention WebDAV/S3 and the VFS stat/dirlist/unlink paths use
	 * (brix_vfs_export_relative_root, leading slash retained), so a file written
	 * here is found by every other driver-backed op. */
	*out_failed = brix_open_resolved_via_driver(a, &cred_vctx, sd_inst,
	    brix_vfs_export_relative_root(resolved, conf->common.root_canon))
	    != NGX_OK ? 1 : 0;
	return NGX_OK;
}


/* Open the resolved file, routing between the export's storage driver (Layer 3)
 * and the POSIX-fd path (POSC/resume staging + server-managed cache domain).
 * Resolves the export's backend, selects the composed wt sd_stage for a write-
 * through write, binds the per-user backend credential for a driver open, then
 * dispatches. On success writes *out_fd + *st, sets *driver_backed / *wt_via_stage,
 * and returns NGX_DECLINED (proceed). On open failure sends the mapped kXR error
 * and returns that send's rc. `idx` is the already-allocated handle slot. */
static ngx_int_t
brix_open_dispatch_open(brix_open_args_t *a)
{
	brix_ctx_t          *ctx         = a->ctx;
	ngx_connection_t    *c           = a->c;
	const char          *resolved    = a->resolved;
	ngx_int_t            open_failed = 0;
	brix_sd_instance_t  *sd_inst;

	a->driver_backed = 0;
	a->wt_via_stage  = 0;

	sd_inst = brix_open_select_sd_inst(a);

	/* §14 (phase-64): the legacy driver-backed read cache (cache_storage_backend)
	 * and the legacy slice decorator (cache_slice_inst) are RETIRED — a driver
	 * cache store and slice/partial serving are the tier grammar's composed
	 * sd_cache, reached through the sd_inst branch below. A POSIX `brix_cache
	 * on` cache keeps the raw-fd from_cache path. */
	if (sd_inst != NULL && !a->from_cache && !a->use_resume) {
		ngx_int_t staged_rc = NGX_DECLINED;

		if (brix_open_dispatch_driver(a, sd_inst, &open_failed, &staged_rc)
		    == NGX_DONE) {
			return staged_rc;
		}
	} else {
		open_failed = brix_open_posix_dispatch(a);
	}
	if (open_failed) {
		return brix_open_map_open_error(ctx, c, resolved, errno, a->is_write);
	}
	return NGX_DECLINED;
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
