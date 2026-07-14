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
 * open_resolved_file_staging.c — pre-open staging preflight for kXR_open
 * (phase-79 split from open_resolved_file.c).
 *
 * WHAT: The write-side staging gate that runs BEFORE any handle/temp is
 *       allocated: reject writes onto a symlink/directory, shed write-opens
 *       under write-back-staging backpressure, enforce kXR_new exclusive-create
 *       against the final path, build the POSC/resume temp path, decide
 *       in-place-update vs upload, and reject a read of a directory.
 *
 * WHY:  These checks share the confined VFS probe and mutate the same staging
 *       decision fields (use_resume/stage/posc_temp_path); grouping them keeps
 *       the staging policy in one focused unit, separate from the open ops.
 *
 * HOW:  brix_open_stage_preflight (the sole cross-file entry) composes the
 *       file-local checks in order; each returns NGX_DECLINED to continue or a
 *       sent-error rc to abort. Behaviour is byte-identical to the original.
 */

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

/* Run the pre-open staging preflight: reject a write onto a symlink/dir, shed
 * write-opens under staging backpressure, enforce kXR_new exclusive-create
 * against the final path, build the POSC/resume temp path, drop resume staging
 * for a pure in-place update with no partial, and reject a read of a directory.
 * Mutates *use_resume / *stage / posc_temp_path. Returns NGX_DECLINED to proceed;
 * on any rejection the error is already sent and its rc is returned. */
ngx_int_t
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
