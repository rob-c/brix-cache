/*
 * vfs_scratch.h — capability-gated "materialize to local POSIX scratch" helper.
 *
 * WHAT: A small VFS-layer primitive that gives a component a LOCAL POSIX working
 *       copy of an object that lives in the (possibly non-POSIX) VFS storage, so
 *       it can use full POSIX semantics — a real kernel fd, random-access
 *       pread/sendfile/mmap, or an external tool that only speaks file paths —
 *       and then move the result back through the storage driver. The local
 *       scratch IS a POSIX SD instance, so no raw data POSIX escapes the seam:
 *       bytes cross storage<->scratch only via the driver.
 *
 * WHY:  Some subsystems cannot operate directly on a block/object backend:
 *         - FRM/tape (PRODUCE): the operator `copycmd` is an external binary that
 *           writes to a path; residency stubs/xattrs need a POSIX file.
 *         - ZIP (CONSUME): stored-member sendfile needs a kernel fd, and a flurry
 *           of small random reads on S3 are per-read round-trips.
 *       The decision is capability-gated: when the storage backend already
 *       exposes a kernel fd (XROOTD_SD_CAP_FD) and no override is set, this is a
 *       no-op (operate in place). It only stages when the backend cannot satisfy
 *       the operation directly (or `force` is set, for tests / explicit policy).
 *
 * HOW:  PRODUCE is stateless (keyed deterministically by `key`, so an async
 *       producer can compute the target at submit and commit it later without
 *       carrying a handle). CONSUME returns a handle (fd + scratch path) to
 *       release. The storage<->scratch move reuses xrootd_commit_staged (produce)
 *       / a driver pread->pwrite copy (consume), both through the SD seam.
 */
#ifndef XROOTD_VFS_SCRATCH_H
#define XROOTD_VFS_SCRATCH_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "backend/sd.h"

/*
 * Does `storage` need a local POSIX scratch copy to be operated on with full
 * POSIX semantics?  Yes if `force` is set, or if the backend exposes no kernel fd
 * (lacks XROOTD_SD_CAP_FD).  `storage == NULL` means the default POSIX backend
 * (has CAP_FD) -> needs scratch only when forced.
 */
ngx_uint_t xrootd_vfs_scratch_needed(const xrootd_sd_instance_t *storage,
    unsigned force);

/* ---- PRODUCE (e.g. FRM copycmd writes the recalled bytes) ------------------ */

/*
 * Compute the LOCAL path an external producer should write `logical_path`'s bytes
 * into.  When no scratch is needed, that is `logical_path` itself (operate in
 * place).  Otherwise it is a deterministic scratch file under `stage_dir`, named
 * from `key` (e.g. an FRM reqid) so a later commit recomputes the same path with
 * no carried state.  *materialized reports which case.  NGX_OK / NGX_ERROR.
 */
ngx_int_t xrootd_vfs_scratch_produce_target(const xrootd_sd_instance_t *storage,
    const char *logical_path, const char *stage_dir, const char *key,
    unsigned force, char *out, size_t outsz, ngx_uint_t *materialized,
    ngx_log_t *log);

/*
 * Publish a produced scratch onto storage: xrootd_commit_staged() moves
 * <stage_dir>/<key>.scratch onto `logical_path` (same-FS rename or cross-device
 * VFS<->VFS copy).  No-op when !materialized.  NGX_OK / NGX_ERROR (errno set).
 */
ngx_int_t xrootd_vfs_scratch_produce_commit(const char *logical_path,
    const char *stage_dir, const char *key, ngx_uint_t materialized,
    ngx_log_t *log);

/* ---- CONSUME (e.g. ZIP random-access / sendfile over the archive) ---------- */

/*
 * Materialize an ALREADY-OPEN source fd (e.g. a confined archive fd) into a local
 * POSIX scratch copy and return a read fd on it.  The scratch file is UNLINKED
 * immediately, so it is anonymous: it survives only as long as the returned fd
 * and the kernel reclaims it on close — no handle/cleanup to track, it rides the
 * consumer's existing fd lifecycle.  Returns the fd, or NGX_INVALID_FILE (errno
 * set).  The caller still owns and must close `src_fd`.  For readers (e.g. zip)
 * that need a real kernel fd for random access / sendfile over an object on a
 * backend that has none.
 */
ngx_fd_t xrootd_vfs_scratch_stage_fd(ngx_fd_t src_fd, const char *stage_dir,
    ngx_log_t *log);

#endif /* XROOTD_VFS_SCRATCH_H */
