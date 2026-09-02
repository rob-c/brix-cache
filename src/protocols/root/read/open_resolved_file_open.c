#include "open.h"
#include "fs/vfs/vfs.h"   /* VFS confined open/probe seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_session (phase-70) */
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
 * open_resolved_file_open.c — the low-level kXR_open file-open operations
 * (phase-79 split from open_resolved_file.c).
 *
 * WHAT: The actual open of the resolved file — the driver-backed (Layer 3)
 *       open that synthesizes a struct stat from the storage driver, the
 *       POSIX-fd open of the staging temp / cache / export-final path, and the
 *       errno→kXR error mapper shared by both.
 *
 * WHY:  This is the hot syscall core of the open path; isolating it (and its
 *       small POSIX-flag/logical-path helpers) keeps the exact syscall order,
 *       O_NONBLOCK guard, and errno→kXR mapping reviewable in one place, apart
 *       from the backend-routing policy that selects which open to run.
 *
 * HOW:  brix_open_resolved_via_driver, brix_open_posix_dispatch and
 *       brix_open_map_open_error are the cross-file entry points (called by the
 *       dispatch stage); brix_open_logical/brix_open_oflags_to_sd are file-local
 *       helpers. Behaviour is byte-identical to the original.
 */

/* kXR_wait retry interval handed to a client whose read-open faulted a nearline
 * (tape) recall - the stream equivalent of the WebDAV 202 Retry-After (§9.2). */
#define BRIX_RECALL_WAIT_SECS  10

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

/* A composed sd_cache tier stamps its read-open verdict and any write-open
 * eviction size on the adopted object; the stream plane adopts objects here
 * rather than via brix_vfs_open_via_driver, so account the unified cache
 * hit/miss + evicted-bytes counters at this adopt site too (parity with the
 * HTTP planes). NONE = no cache tier consulted this open. open_fill_miss: this
 * open was parked for an offloaded fill — the tier now reports HIT off the
 * just-filled cinfo, but the client-visible outcome of the open is a miss
 * (open_or_fill.c sets and clears the marker). */
static void
brix_open_adopt_cache_accounting(const brix_open_args_t *a,
    brix_vfs_ctx_t *vctx, const brix_file_t *fh)
{
    if (fh->sd_obj.cache_outcome != BRIX_SD_CACHE_OUTCOME_NONE) {
        unsigned hit = (fh->sd_obj.cache_outcome == BRIX_SD_CACHE_OUTCOME_HIT)
                       && !a->ctx->open_fill_miss;
        /* phase-110 W1: metric + the session monitor's $brix_cache_status in
         * one call (the same word on root:// as on WebDAV/S3). */
        brix_vfs_observe_cache_result(vctx, hit);
    }

    brix_metric_cache_evicted(brix_vfs_metrics_proto(vctx),
                                fh->sd_obj.cache_evicted_bytes);
}

/* The driver snapshot carries no device id, so st_dev would stay 0 and the
 * published-handle table would record device 0. A bound secondary reopens the
 * file for itself (a real fstat, real st_dev) and revalidates device+inode
 * against the published entry — a 0 vs real-device mismatch would then wrongly
 * revoke every bound read (kXR_error). For a driver with a real backing
 * descriptor (the POSIX driver's fd is the file itself), capture the real
 * device so the published identity matches the secondary's reopen.
 *
 * Anti-wedge parity with the non-driver path's S_ISREG gate: a FIFO, socket,
 * or device is not a servable byte stream. The confined open forced O_NONBLOCK
 * so the open(2) itself could not park the worker, but a subsequent read/write
 * would spin on EAGAIN — refuse it here, where the real st_mode is available
 * (the driver snapshot may not carry a mode). A directory keeps its own
 * handling upstream; only special files are cut (errno = EINVAL). */
static ngx_int_t
brix_open_capture_fd_identity(brix_file_t *fh, brix_sd_instance_t *sd,
    struct stat *st)
{
    struct stat rst;

    if (fh->sd_obj.fd < 0 || fstat(fh->sd_obj.fd, &rst) != 0) {
        return NGX_OK;           /* no backing fd / no identity to capture */
    }

    st->st_dev = rst.st_dev;

    if (!S_ISREG(rst.st_mode) && !S_ISDIR(rst.st_mode)) {
        (void) sd->driver->close(&fh->sd_obj);
        fh->sd_obj.driver = NULL;
        fh->sd_obj.inst   = NULL;
        fh->sd_obj.state  = NULL;
        fh->sd_obj.fd     = -1;
        errno = EINVAL;
        return NGX_ERROR;
    }
    return NGX_OK;
}

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
ngx_int_t
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
    /* Secret consumed by the origin open; erase the stack copy (A-4/T4). */
    brix_sd_ucred_wipe(&ustore);
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

    brix_open_adopt_cache_accounting(a, vctx, fh);

    /* The driver's open may defer metadata (the POSIX driver deliberately skips
     * the fstat at open — see sd_posix_open). Populate the snapshot now via the
     * OBJECT's own fstat slot so the synthesized `struct stat` (and hence the
     * handle's cached_size) is correct: a driver-aware fstat reports the LOGICAL
     * object size (e.g. pblock's whole-object size, not block 0). Dispatch on
     * fh->sd_obj.driver, NOT sd->driver — a decorator open can adopt its
     * component's obj (the cache decorator serves a COMPLETE hit as the store's
     * own posix obj), and the instance driver's fstat would then misread that
     * foreign obj's state (sd_cache_fstat casts state to the partial struct)
     * and stamp size 0.  Without a correct populate the cached_size stays 0 and
     * every serve path that trusts it — inline read compression, the zero-copy
     * sendfile clamp — sees EOF immediately and returns nothing. */
    if (fh->sd_obj.driver != NULL && fh->sd_obj.driver->fstat != NULL
        && fh->sd_obj.snap.size == 0)
    {
        (void) fh->sd_obj.driver->fstat(&fh->sd_obj, &fh->sd_obj.snap);
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

    if (brix_open_capture_fd_identity(fh, sd, st) != NGX_OK) {
        return NGX_ERROR;        /* special file refused; errno = EINVAL */
    }

    a->fd = fh->sd_obj.fd;   /* block-0 fd, or NGX_INVALID_FILE (-1) */
    return NGX_OK;
}

/*
 * WHAT: Translate an open errno into its protocol code and stable message.
 * WHY:  Error taxonomy should be independent from logging and response emission.
 * HOW:  Map named POSIX cases and fall back to the shared errno translator.
 */
static void
brix_open_error_details(int err, int *kxr, const char **message)
{
    switch (err) {
    case ENOENT:
    case ENOTDIR:
        *kxr = kXR_NotFound;
        *message = "file not found";
        break;
    case EEXIST:
        *kxr = kXR_ItExists;
        *message = "file already exists";
        break;
    case EACCES:
        *kxr = kXR_NotAuthorized;
        *message = "permission denied";
        break;
    case EROFS:
        /* phase-105: the endpoint refuses writes. Distinct from EACCES on
         * purpose — the client's credential is irrelevant, so the reply must
         * not invite it to retry with a different one. */
        *kxr = kXR_fsReadOnly;
        *message = "read-only export";
        break;
    case EISDIR:
        *kxr = kXR_isDirectory;
        *message = "is a directory";
        break;
    case EBUSY:
        *kxr = kXR_FileLocked;
        *message = "file locked";
        break;
    case ENOSPC:
    case EDQUOT:
        /* phase-107 C5: a declared final size (oss.asize) the export cannot
         * hold refuses the OPEN - the reference raises kXR_NoSpace, and the
         * distinct code lets a client fail over to another endpoint instead
         * of retrying a write that can never fit. */
        *kxr = kXR_NoSpace;
        *message = "insufficient space for the declared file size";
        break;
    default:
        *kxr = kXR_IOError;
        *message = strerror(err);
        break;
    }
}

/* Map a failed open(2)'s errno to the kXR error response the reference raises,
 * sending it and returning that send's rc; EAGAIN on a read is a nearline recall
 * (kXR_wait retry) rather than an error. Reached only when open_failed is set, so
 * it always sends exactly one reply. Returns the value the caller must return. */
ngx_int_t
brix_open_map_open_error(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *resolved, int err, ngx_flag_t is_write)
{
	const char *mode_str = is_write ? "wr" : "rd";
	const char *message;
	int         kxr;

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
	brix_open_error_details(err, &kxr, &message);
	BRIX_RETURN_ERR(ctx, c,
					  is_write ? BRIX_OP_OPEN_WR : BRIX_OP_OPEN_RD,
					  "OPEN", resolved, mode_str,
					  kxr, message);
}

/* The POSIX-fd open dispatch: open the staging temp / cache / export final path
 * (never a driver-backed export — that is handled by the caller). Forces O_CREAT
 * for a staged open and O_NONBLOCK so the open cannot park the worker; cache and
 * external-stage domains open raw as the worker, the export final opens beneath
 * the export rootfd through the VFS. Writes *out_fd and returns 1 when the open
 * failed (errno set), else 0. */
int
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
		fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,  /* vfs-seam-allow: DOMAIN_STAGE — separate svc-owned storage domain (cache/stage), opened as worker */
		          create_mode);
	} else if (from_cache) {
		/* vfs-seam-allow: separate storage domain. cache_root files are
		 * server-managed (filled by the cache worker, never client-written,
		 * svc-owned) in a different root than the export, so they are opened
		 * as the worker rather than through the export-confined VFS. O_NOFOLLOW
		 * is defence-in-depth; O_CLOEXEC prevents FD leak into a forked child. */
		fd = open(open_path, effective_oflags | O_NOFOLLOW | O_CLOEXEC,  /* vfs-seam-allow: DOMAIN_CACHE — separate svc-owned storage domain (cache/stage), opened as worker */
		          create_mode);
	} else {
		/* The export final/staged path: open beneath the export root through
		 * the VFS (openat2 RESOLVE_BENEATH, impersonation-aware). The VFS
		 * strips the absolute path to its rootfd-relative form. */
		/* phase-105: the POSIX leg of kXR_open. The staged/driver leg is
		 * already gated through its VFS ctx (brix_vfs_writer_open); this is
		 * the fallback that reaches the export directly, so it takes the same
		 * posture here. A read open is not gated at all — the helper decides
		 * from the flags, so ordinary reads on a read-only export are
		 * untouched, and a create/truncate/append open answers EROFS. */
		brix_vfs_export_op_ctx_t opctx;

		brix_vfs_export_op_ctx_init(&opctx, a->c->log,
		    conf->common.root_canon,
		    brix_vfs_policy_from_write_enable(conf->common.allow_write),
		    BRIX_PROTO_ROOT);
		fd = brix_vfs_export_open_fd_at(&opctx, conf->rootfd,
		    brix_open_logical(open_path, conf->common.root_canon),
		    effective_oflags, create_mode);
	}
	/* C-2 (phase-56): an in-place create-open (no staging temp) materialises
	 * the final path right here, outside brix_vfs_open — drop any per-worker
	 * cached negative so a stat racing the create never sees a stale ENOENT.
	 * Staged opens create only the temp; the final path appears at POSC
	 * commit, which forgets there. */
	if (fd >= 0 && !stage && (effective_oflags & O_CREAT)) {
		brix_vfs_neg_stat_forget(conf->common.root_canon, open_path);
	}

	/* Phase-107 C5: a declared final size (oss.asize) the filesystem cannot
	 * hold fails the OPEN with ENOSPC — before the client streams a byte. The
	 * entry is not unlinked: an O_TRUNC overwrite target must survive, a
	 * resume partial must survive, and a POSC temp is tolerated stale by
	 * design (see the O_EXCL comment above). */
	if (fd >= 0 && a->is_write && a->declared_size > 0
	    && (effective_oflags & (O_CREAT | O_TRUNC)))
	{
		if (brix_vfs_fd_reserve(a->c->log, fd, a->declared_size) != NGX_OK) {
			int err = errno;

			(void) close(fd);
			a->fd = -1;
			errno = err;
			return 1;
		}
	}

	a->fd = fd;
	return (fd < 0);
}
