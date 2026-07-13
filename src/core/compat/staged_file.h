/*
 * staged_file.h — Atomic temp-file write lifecycle.
 *
 * Provides brix_staged_file_t (a struct tracking fd, tmp_path, active flag) and three
 * operations: open → commit/abort. Used by S3 PUT, WebDAV PUT for crash-safe writes:
 * 1) Open a unique temp file with O_EXCL inside root_canon
 * 2) Write data to the fd
 * 3) Commit (rename temp → final path) or abort (close + unlink)
 */

#ifndef BRIX_COMPAT_STAGED_FILE_H
#define BRIX_COMPAT_STAGED_FILE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <limits.h>
#include <sys/types.h>

/*
 * brix_staged_file_t — Tracks the lifecycle of a staged (temp) file.
 *
 * Fields:
 *   fd     — open file descriptor for the temp file (NGX_INVALID_FILE when closed)
 *   active — 1 while the temp file is open and data can be written; 0 after commit/abort
 *   tmp_path — filesystem path of the temp file (used by commit to rename, abort to unlink)
 */
typedef struct {
    ngx_fd_t   fd;
    ngx_flag_t active;
    char       tmp_path[PATH_MAX];
    mode_t     final_mode;   /* intended mode to publish at commit; the temp is
                              * kept 0600 during the write so a peer mapped uid
                              * cannot read an in-progress upload. */
} brix_staged_file_t;

/*
 * brix_staged_open_req_t — the pure (side-effect-free) inputs that describe WHERE
 * and HOW a staged temp is opened, bundled so the open entry points stay within
 * the argument gate.
 *
 * WHAT: the confinement root + destination path + creation mode shared by both
 *       staged-open variants, plus the variant-specific selectors (open_flags /
 *       attempts for the random O_EXCL temp; principal / stage_dir for the
 *       deterministic identity-keyed resume partial).
 * WHY:  threading these as discrete parameters pushed brix_staged_open (7 args)
 *       and brix_staged_open_resume (8 args) past the 5-argument budget. They are
 *       all read-only request description — no hidden global state — so gathering
 *       them into one value bundle keeps the data flow explicit while the
 *       side-effecting args (log, the output staged/cur_size) stay direct params.
 * HOW:  callers fill the fields relevant to their variant (unused fields are
 *       ignored by that variant) and pass a pointer; the function reads it and
 *       never mutates it.
 *
 * Fields:
 *   root_canon — canonical root the temp must reside within
 *   final_path — destination path (derives the temp name)
 *   mode       — file creation mode to publish at commit
 *   open_flags — [open] base open flags (O_EXCL added internally)
 *   attempts   — [open] max EEXIST retries (0 → 16)
 *   principal  — [resume] identity keying the deterministic partial name
 *   stage_dir  — [resume] fast-device stage dir, or NULL to stage under root
 */
typedef struct {
    const char *root_canon;
    const char *final_path;
    mode_t      mode;
    int         open_flags;
    ngx_uint_t  attempts;
    const char *principal;
    const char *stage_dir;
} brix_staged_open_req_t;

/* brix_staged_open() — See staged_file.c for WHAT/WHY/HOW. Reads req->{root_canon,
 * final_path, open_flags, mode, attempts}. */
ngx_int_t brix_staged_open(ngx_log_t *log, const brix_staged_open_req_t *req,
    brix_staged_file_t *staged);
/* brix_staged_open_resume() — open the DETERMINISTIC identity-keyed upload-
 * resume partial (create-or-resume, preserves bytes, no O_EXCL/O_TRUNC), and
 * report its current size in *cur_size.  For WebDAV Content-Range PUT resume.
 * Reads req->{root_canon, final_path, principal, stage_dir, mode}.
 * See staged_file.c. */
ngx_int_t brix_staged_open_resume(ngx_log_t *log,
    const brix_staged_open_req_t *req, brix_staged_file_t *staged,
    off_t *cur_size);
/* brix_commit_staged() — atomically publish a staged file onto its final path,
 * across filesystems (rename fast-path; copy+rename on EXDEV for a fast-cache
 * stage dir on a different device than the storage).  fd = open staged fd (for
 * the durability fsync) or NGX_INVALID_FILE.  final_mode = the mode to publish
 * on the committed object (the temp is written 0600); pass 0 to leave the temp's
 * current mode untouched (callers whose temp already carries the intended mode).
 * See staged_file.c. */
ngx_int_t brix_commit_staged(ngx_fd_t fd, const char *stage_path,
    const char *final_path, mode_t final_mode, ngx_log_t *log);
/* --- upload stage-out tracking (durable pending-commit markers + reaper) --- */

/* Register a (canonicalized) stage dir so the reaper sweeps it.  Called at config
 * time from each server/location that sets a stage dir; deduped. */
void brix_stage_dir_register(const char *canon);
/* Number of registered stage dirs (>0 => arm the reaper). */
ngx_uint_t brix_stage_dir_count(void);
/* Write/remove the durable "<stage_partial>.commit" marker (content = final path)
 * that records a COMPLETE staged file pending its move to storage. */
ngx_int_t brix_stage_mark_pending(const char *stage_partial,
    const char *final_path, ngx_log_t *log);
void brix_stage_unmark_pending(const char *stage_partial);
/* Finish every pending stage-out in one dir / all registered dirs.  Idempotent;
 * returns the number of commits completed.  See staged_file.c. */
ngx_uint_t brix_stage_reap_dir(const char *stage_dir, ngx_log_t *log);
ngx_uint_t brix_stage_reap_all(ngx_log_t *log);

/* brix_staged_commit() — See staged_file.c for WHAT/WHY/HOW. */
ngx_int_t brix_staged_commit(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, const char *final_path);
/* brix_staged_commit_excl() — atomic create-if-absent commit via
 * renameat2(RENAME_NOREPLACE).  Returns NGX_ERROR with errno==EEXIST when the
 * final path already exists (caller maps to 412). See staged_file.c. */
ngx_int_t brix_staged_commit_excl(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, const char *final_path);
/* brix_staged_abort() — See staged_file.c for WHAT/WHY/HOW. */
void brix_staged_abort(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, ngx_flag_t remove_tmp);

#endif /* BRIX_COMPAT_STAGED_FILE_H */
