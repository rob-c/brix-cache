/*
 * staged_file.h — Atomic temp-file write lifecycle.
 *
 * Provides xrootd_staged_file_t (a struct tracking fd, tmp_path, active flag) and three
 * operations: open → commit/abort. Used by S3 PUT, WebDAV PUT for crash-safe writes:
 * 1) Open a unique temp file with O_EXCL inside root_canon
 * 2) Write data to the fd
 * 3) Commit (rename temp → final path) or abort (close + unlink)
 */

#ifndef XROOTD_COMPAT_STAGED_FILE_H
#define XROOTD_COMPAT_STAGED_FILE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <limits.h>
#include <sys/types.h>

/*
 * xrootd_staged_file_t — Tracks the lifecycle of a staged (temp) file.
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
} xrootd_staged_file_t;

/* xrootd_staged_open() — See staged_file.c for WHAT/WHY/HOW. */
ngx_int_t xrootd_staged_open(ngx_log_t *log, const char *root_canon,
    const char *final_path, int open_flags, mode_t mode, ngx_uint_t attempts,
    xrootd_staged_file_t *staged);
/* xrootd_staged_commit() — See staged_file.c for WHAT/WHY/HOW. */
ngx_int_t xrootd_staged_commit(ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, const char *final_path);
/* xrootd_staged_abort() — See staged_file.c for WHAT/WHY/HOW. */
void xrootd_staged_abort(ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, ngx_flag_t remove_tmp);

#endif /* XROOTD_COMPAT_STAGED_FILE_H */
