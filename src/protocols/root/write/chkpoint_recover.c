#include "core/ngx_brix_module.h"
#include "core/types/tunables.h"         /* BRIX_ROOT_PRIVATE_FILE_MODE */
#include "fs/vfs/vfs.h"   /* confined open/unlink via the VFS seam */
#include "chkpoint_xeq.h"
#include "core/compat/log.h"
#include "core/compat/copy_range.h"
#include "core/compat/staged_file.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * kXR_chkpoint — startup recovery of abandoned .ckp snapshots.
 *
 * Split verbatim from chkpoint.c: scans an export root for stale <path>.ckp
 * files left by worker crashes/hard restarts, copies each snapshot back over
 * its original file and removes it (uncommitted writes must not survive
 * recovery). The single public entry point brix_chkpoint_recover_root is
 * declared in chkpoint.h.
 */

static ngx_flag_t
ckp_name_has_suffix(const char *name)
{
    size_t len;

    len = strlen(name);
    return len > 4 && strcmp(name + len - 4, ".ckp") == 0;
}

/*
 * ckp_validate_path — extract original path from checkpoint path.
 *
 * WHAT: Validates .ckp path format and extracts original path by removing
 *       the .ckp suffix.
 * WHY:  Checkpoint files must end in .ckp; the original path is everything
 *       before that suffix. Invalid lengths are rejected early.
 * HOW:  Checks length bounds, copies all but last 4 chars, null-terminates.
 *       Returns NGX_OK on success, NGX_ERROR on invalid format.
 */
static ngx_int_t
ckp_validate_path(const char *ckp_path, char *orig_path, size_t orig_size)
{
    size_t len = strlen(ckp_path);
    
    if (len <= 4 || len >= orig_size) {
        return NGX_ERROR;
    }
    
    ngx_memcpy(orig_path, ckp_path, len - 4);
    orig_path[len - 4] = '\0';
    return NGX_OK;
}

/*
 * ckp_open_snapshot — open checkpoint file for reading.
 *
 * WHAT: Opens the .ckp snapshot file read-only with security flags.
 * WHY:  Recovery needs to read the abandoned checkpoint; O_NOFOLLOW prevents
 *       symlink attacks, O_CLOEXEC prevents fd leaks.
 * HOW:  Uses brix_vfs_open_fd confined to export root. Returns fd on success,
 *       -1 on failure (logs error).
 */
static int
ckp_open_snapshot(ngx_log_t *log, const char *root_canon, const char *ckp_path)
{
    int ckp_fd = brix_vfs_open_fd(log, root_canon, ckp_path,
                                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (ckp_fd < 0) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery cannot open \"%s\"",
                           ckp_path);
    }
    return ckp_fd;
}

/*
 * ckp_validate_snapshot — verify checkpoint file is a regular file.
 *
 * WHAT: Stats the opened checkpoint fd and verifies it's a regular file.
 * WHY:  Only regular files can be recovered; directories/symlinks are invalid.
 * HOW:  Uses fstat() and S_ISREG check. Closes fd on failure. Returns NGX_OK
 *       on success, NGX_ERROR on failure (logs error, closes fd).
 */
static ngx_int_t
ckp_validate_snapshot(ngx_log_t *log, int ckp_fd, const char *ckp_path,
                      struct stat *st)
{
    if (fstat(ckp_fd, st) != 0 || !S_ISREG(st->st_mode)) {
        ngx_close_file(ckp_fd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery invalid snapshot "
                           "\"%s\"", ckp_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * ckp_stage_original — open original file for staged write.
 *
 * WHAT: Opens the original (non-.ckp) path for staged atomic write.
 * WHY:  Recovery must atomically replace the original file; staged_open
 *       provides safe atomic replacement with proper permissions.
 * HOW:  Builds brix_staged_open_req_t with O_WRONLY, private file mode,
 *       16 attempts. Returns NGX_OK on success, NGX_ERROR on failure.
 */
static ngx_int_t
ckp_stage_original(ngx_log_t *log, const char *root_canon,
                   const char *orig_path, brix_staged_file_t *staged)
{
    brix_staged_open_req_t oreq = {
        .root_canon = root_canon,
        .final_path = orig_path,
        .open_flags = O_WRONLY,
        .mode       = BRIX_ROOT_PRIVATE_FILE_MODE,
        .attempts   = 16,
    };
    
    if (brix_staged_open(log, &oreq, staged) != NGX_OK) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery cannot stage \"%s\"",
                           orig_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * ckp_copy_data — copy checkpoint data to staged file.
 *
 * WHAT: Copies data from checkpoint fd to staged file fd using copy_range.
 * WHY:  Efficient zero-copy transfer of recovered data; skips if size is 0.
 * HOW:  Uses brix_copy_range for the full file size. On failure, aborts
 *       staged file and logs error. Returns NGX_OK on success.
 */
static ngx_int_t
ckp_copy_data(ngx_log_t *log, int ckp_fd, brix_staged_file_t *staged,
              off_t size, const char *ckp_path, const char *root_canon)
{
    if (size > 0
        && brix_copy_range(log, ckp_fd, 0, staged->fd, 0,
                           (size_t) size, ckp_path,
                           staged->tmp_path) != NGX_OK)
    {
        brix_staged_abort(log, root_canon, staged, 1);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery copy failed for "
                           "\"%s\"", staged->final_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * ckp_sync_and_commit — fsync and commit staged file atomically.
 *
 * WHAT: Syncs staged file to disk and commits it to replace original.
 * WHY:  Ensures durability before removing checkpoint journal; atomic commit
 *       prevents partial writes from being visible.
 * HOW:  Uses brix_vfs_io_execute for fsync, then brix_staged_commit for
 *       atomic rename. Returns NGX_OK on success, NGX_ERROR on failure.
 */
static ngx_int_t
ckp_sync_and_commit(ngx_log_t *log, const char *root_canon,
                    brix_staged_file_t *staged, const char *orig_path)
{
    brix_vfs_job_t job;
    
    brix_vfs_job_sync_init(&job, staged->fd);
    brix_vfs_io_execute(&job);
    
    if (brix_staged_commit(log, root_canon, staged, orig_path) != NGX_OK) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery commit failed for "
                           "\"%s\"", orig_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * ckp_cleanup_and_log — close fd, remove checkpoint, log success.
 *
 * WHAT: Cleans up checkpoint fd, removes .ckp journal, logs recovery.
 * WHY:  Journal must be removed after successful recovery to prevent replay;
 *       success logging provides audit trail.
 * HOW:  Closes ckp_fd, unlinks .ckp path (with vfs-mutation-gate-allow
 *       comment explaining why this bypasses normal mutation gates), logs
 *       recovery notice. Returns NGX_OK on success, NGX_ERROR if unlink fails.
 */
static ngx_int_t
ckp_cleanup_and_log(ngx_log_t *log, const char *root_canon,
                    int ckp_fd, const char *ckp_path)
{
    ngx_close_file(ckp_fd);
    
    /* vfs-mutation-gate-allow: startup recovery of THIS server's own .ckp
     * journal, after its snapshot has been committed. The journal's existence
     * is the durable proof that a writable endpoint authorised the checkpoint;
     * no request and no endpoint configuration are in scope here to re-decide
     * against, and leaving the record behind would replay it forever. */
    if (brix_vfs_unlink_path(log, root_canon, ckp_path) != 0) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                           "brix: checkpoint recovery cannot remove \"%s\"",
                           ckp_path);
        return NGX_ERROR;
    }
    
    brix_log_safe_path(log, NGX_LOG_NOTICE, 0,
                       "brix: recovered abandoned checkpoint \"%s\"",
                       ckp_path);
    return NGX_OK;
}

/*
 * ckp_recover_one — recover one abandoned checkpoint file.
 *
 * WHAT: Recovers a single .ckp snapshot by copying it over the original file.
 * WHY:  Worker crashes leave .ckp files behind; recovery restores them at
 *       startup to prevent data loss from abandoned checkpoints.
 * HOW:  Orchestrates 7 single-responsibility helpers:
 *       1. ckp_validate_path — extract original path
 *       2. ckp_open_snapshot — open .ckp read-only
 *       3. ckp_validate_snapshot — verify regular file
 *       4. ckp_stage_original — open original for atomic write
 *       5. ckp_copy_data — zero-copy transfer
 *       6. ckp_sync_and_commit — fsync + atomic rename
 *       7. ckp_cleanup_and_log — remove journal, log success
 */
static ngx_int_t
ckp_recover_one(ngx_log_t *log, const char *root_canon, const char *ckp_path)
{
    char                 orig_path[PATH_MAX];
    struct stat          st;
    int                  ckp_fd;
    brix_staged_file_t   staged;
    ngx_int_t            rc;
    
    /* Step 1: Validate and extract original path */
    if (ckp_validate_path(ckp_path, orig_path, sizeof(orig_path)) != NGX_OK) {
        return NGX_ERROR;
    }
    
    /* Step 2: Open checkpoint snapshot */
    ckp_fd = ckp_open_snapshot(log, root_canon, ckp_path);
    if (ckp_fd < 0) {
        return NGX_ERROR;
    }
    
    /* Step 3: Validate snapshot is regular file */
    if (ckp_validate_snapshot(log, ckp_fd, ckp_path, &st) != NGX_OK) {
        return NGX_ERROR;
    }
    
    /* Step 4: Stage original file for atomic write */
    if (ckp_stage_original(log, root_canon, orig_path, &staged) != NGX_OK) {
        ngx_close_file(ckp_fd);
        return NGX_ERROR;
    }
    
    /* Step 5: Copy data from checkpoint to staged file */
    if (ckp_copy_data(log, ckp_fd, &staged, st.st_size, ckp_path, root_canon) != NGX_OK) {
        ngx_close_file(ckp_fd);
        return NGX_ERROR;
    }
    
    /* Step 6: Sync and commit atomically */
    if (ckp_sync_and_commit(log, root_canon, &staged, orig_path) != NGX_OK) {
        ngx_close_file(ckp_fd);
        return NGX_ERROR;
    }
    
    /* Step 7: Cleanup and log success */
    return ckp_cleanup_and_log(log, root_canon, ckp_fd, ckp_path);
}

/* One opened recovery-scan directory: the stream plus its validated fd. */
typedef struct {
    DIR *dp;        /* open stream — caller owns/closes it */
    int  scan_fd;   /* dirfd(dp), validated >= 0 (safe for fstatat) */
} ckp_scan_dir_t;

/*
 * Open one recovery-scan directory confined to the export root and hand back
 * the DIR stream plus its validated directory fd (used for fstatat).  Returns
 * NGX_OK (caller owns out->dp), NGX_DECLINED for a skippable subdirectory
 * (private/racing-removed — recovery must continue past it), or NGX_ERROR for
 * a fatal condition (inaccessible export root or stream setup failure).
 */
static ngx_int_t
ckp_recover_open_dir(ngx_log_t *log, const char *root_canon, const char *dir,
    ngx_uint_t depth, ckp_scan_dir_t *out)
{
    DIR *dp;
    int  dfd, scan_fd;

    dfd = brix_vfs_open_fd(log, root_canon, dir,
                                     O_RDONLY | O_DIRECTORY | O_CLOEXEC
                                     | O_NOFOLLOW, 0);
    if (dfd < 0) {
        /*
         * A SUBDIRECTORY we cannot enter must NOT abort recovery: under per-request
         * impersonation the export legitimately contains per-user PRIVATE dirs
         * (e.g. 0700) the worker uid cannot read, and a dir can be removed mid-scan.
         * Skip those (recovery only concerns this server's own .ckp temp files,
         * which live in dirs the worker can reach).  Only an inaccessible EXPORT
         * ROOT (depth 0) or an unexpected errno is fatal.
         */
        if (depth > 0 && (ngx_errno == EACCES || ngx_errno == ENOENT
                          || ngx_errno == ENOTDIR || ngx_errno == ELOOP))
        {
            brix_log_safe_path(log, NGX_LOG_INFO, ngx_errno,
                                 "brix: checkpoint recovery skipping "
                                 "inaccessible dir \"%s\"", dir);
            return NGX_DECLINED;
        }
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot scan \"%s\"",
                             dir);
        return NGX_ERROR;
    }

    dp = fdopendir(dfd);
    if (dp == NULL) {
        ngx_close_file(dfd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot scan \"%s\"",
                             dir);
        return NGX_ERROR;
    }

    /* fdopendir owns dfd now; re-derive the scan fd once and refuse to walk on
     * a failed dirfd() so fstatat never sees a negative directory fd. */
    scan_fd = dirfd(dp);
    if (scan_fd < 0) {
        closedir(dp);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot scan \"%s\"",
                             dir);
        return NGX_ERROR;
    }

    out->dp      = dp;
    out->scan_fd = scan_fd;
    return NGX_OK;
}

static ngx_int_t
ckp_recover_scan(ngx_log_t *log, const char *root_canon, const char *dir,
    ngx_uint_t depth)
{
    ckp_scan_dir_t sd;
    struct dirent *de;
    ngx_int_t      rc;

    if (depth > 128) {
        brix_log_safe_path(log, NGX_LOG_ERR, 0,
                             "brix: checkpoint recovery depth exceeded at "
                             "\"%s\"", dir);
        return NGX_ERROR;
    }

    rc = ckp_recover_open_dir(log, root_canon, dir, depth, &sd);
    if (rc == NGX_DECLINED) {
        return NGX_OK;   /* skippable subdirectory — logged by the helper */
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    while ((de = readdir(sd.dp)) != NULL) {
        char        path[PATH_MAX];
        size_t      dlen, nlen;
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        dlen = strlen(dir);
        nlen = strlen(de->d_name);
        if (dlen + 1 + nlen >= sizeof(path)) {
            closedir(sd.dp);
            return NGX_ERROR;
        }

        ngx_memcpy(path, dir, dlen);
        path[dlen] = '/';
        ngx_memcpy(path + dlen + 1, de->d_name, nlen + 1);

        if (fstatat(sd.scan_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            /* A transiently-removed or inaccessible entry: skip it, don't abort
             * the whole recovery (and thus the worker). */
            brix_log_safe_path(log, NGX_LOG_INFO, ngx_errno,
                                 "brix: checkpoint recovery skipping entry "
                                 "\"%s\"", path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (ckp_recover_scan(log, root_canon, path, depth + 1) != NGX_OK) {
                closedir(sd.dp);
                return NGX_ERROR;
            }
            continue;
        }

        if (S_ISREG(st.st_mode) && ckp_name_has_suffix(de->d_name)) {
            if (ckp_recover_one(log, root_canon, path) != NGX_OK) {
                closedir(sd.dp);
                return NGX_ERROR;
            }
        }
    }

    closedir(sd.dp);
    return NGX_OK;
}

ngx_int_t
brix_chkpoint_recover_root(ngx_log_t *log, const char *root_canon)
{
    char      lock_path[PATH_MAX];
    size_t    root_len;
    int       lock_fd;
    ngx_int_t rc;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return NGX_OK;
    }
    /* A pure cache node (no brix_root) anchors at the "/" namespace: there is no
     * local export tree, so no checkpoint journal to recover (and "/" is not a
     * writable place to drop a recovery lock). Nothing to do. */
    if (root_canon[0] == '/' && root_canon[1] == '\0') {
        return NGX_OK;
    }

    root_len = strlen(root_canon);
    if (root_len + sizeof("/.nginx-xrootd-ckp-recovery.lock")
        > sizeof(lock_path))
    {
        return NGX_ERROR;
    }

    ngx_memcpy(lock_path, root_canon, root_len);
    ngx_memcpy(lock_path + root_len, "/.nginx-xrootd-ckp-recovery.lock",
               sizeof("/.nginx-xrootd-ckp-recovery.lock"));

    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, BRIX_ROOT_PRIVATE_FILE_MODE);
    if (lock_fd < 0) {
        /* An export this worker cannot write is not a recovery failure: a .ckp
         * snapshot is only ever produced by a worker writing INTO this root, so
         * a root that refuses our writes cannot hold a journal to roll back.
         * Read-only exports (EROFS) and permission-restricted ones (EACCES /
         * EPERM — e.g. a root-master fleet whose workers drop to an
         * unprivileged user) are legitimate read-serving deployments, so skip
         * recovery and carry on rather than failing worker init and
         * crash-looping the server.
         * Every other errno still fails loudly — it signals a genuinely broken
         * export (ENOTDIR, ENAMETOOLONG, ELOOP from a hostile symlink, …). */
        if (ngx_errno == EACCES || ngx_errno == EPERM || ngx_errno == EROFS) {
            brix_log_safe_path(log, NGX_LOG_WARN, ngx_errno,
                                 "brix: checkpoint recovery skipped — export "
                                 "root is not writable by this worker "
                                 "\"%s\"", lock_path);
            return NGX_OK;
        }
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery lock failed "
                             "\"%s\"", lock_path);
        return NGX_ERROR;
    }

    if (flock(lock_fd, LOCK_EX) != 0) {
        ngx_close_file(lock_fd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot lock "
                             "\"%s\"", lock_path);
        return NGX_ERROR;
    }

    rc = ckp_recover_scan(log, root_canon, root_canon, 0);

    (void) flock(lock_fd, LOCK_UN);
    ngx_close_file(lock_fd);

    return rc;
}
