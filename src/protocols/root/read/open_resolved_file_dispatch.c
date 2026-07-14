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
 * open_resolved_file_dispatch.c — backend/credential routing for kXR_open
 * (phase-79 split from open_resolved_file.c).
 *
 * WHAT: Chooses HOW the resolved file is opened: resolve the export backend,
 *       apply the write-through sd_stage override, build the per-user backend
 *       credential VFS ctx, route a whole-object write through the staged-commit
 *       adapter, and otherwise dispatch to the driver or the POSIX-fd open.
 *
 * WHY:  Keeps the backend-selection + credential-bind policy (which mirrors the
 *       davs/S3 call sites) apart from the raw open syscalls, so
 *       brix_open_dispatch_open reads as a two-way driver-vs-POSIX selector.
 *
 * HOW:  brix_open_dispatch_open (the sole cross-file entry) selects the sd
 *       instance then either runs the driver branch (staged adapter or
 *       brix_open_resolved_via_driver) or brix_open_posix_dispatch, mapping any
 *       failure via brix_open_map_open_error. Byte-identical to the original.
 */

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
ngx_int_t
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
