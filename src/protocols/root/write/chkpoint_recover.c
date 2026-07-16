#include "core/ngx_brix_module.h"
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

static ngx_int_t
ckp_recover_one(ngx_log_t *log, const char *root_canon,
    const char *ckp_path)
{
    char                 orig_path[PATH_MAX];
    size_t               len;
    int                  ckp_fd;
    brix_staged_file_t staged;
    struct stat          st;

    len = strlen(ckp_path);
    if (len <= 4 || len >= sizeof(orig_path)) {
        return NGX_ERROR;
    }

    ngx_memcpy(orig_path, ckp_path, len - 4);
    orig_path[len - 4] = '\0';

    ckp_fd = brix_vfs_open_fd(log, root_canon, ckp_path,
                                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (ckp_fd < 0) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot open \"%s\"",
                             ckp_path);
        return NGX_ERROR;
    }

    if (fstat(ckp_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ngx_close_file(ckp_fd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery invalid snapshot "
                             "\"%s\"", ckp_path);
        return NGX_ERROR;
    }

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = root_canon,
            .final_path = orig_path,
            .open_flags = O_WRONLY,
            .mode       = 0600,
            .attempts   = 16,
        };
        if (brix_staged_open(log, &oreq, &staged) != NGX_OK) {
            ngx_close_file(ckp_fd);
            brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                                 "brix: checkpoint recovery cannot stage "
                                 "\"%s\"", orig_path);
            return NGX_ERROR;
        }
    }

    if (st.st_size > 0
        && brix_copy_range(log, ckp_fd, 0, staged.fd, 0,
                             (size_t) st.st_size, ckp_path,
                             staged.tmp_path) != NGX_OK)
    {
        brix_staged_abort(log, root_canon, &staged, 1);
        ngx_close_file(ckp_fd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery copy failed for "
                             "\"%s\"", orig_path);
        return NGX_ERROR;
    }

    {
        brix_vfs_job_t job;

        brix_vfs_job_sync_init(&job, staged.fd);
        brix_vfs_io_execute(&job);
    }

    if (brix_staged_commit(log, root_canon, &staged, orig_path)
        != NGX_OK)
    {
        ngx_close_file(ckp_fd);
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery commit failed for "
                             "\"%s\"", orig_path);
        return NGX_ERROR;
    }

    ngx_close_file(ckp_fd);

    if (brix_vfs_unlink_path(log, root_canon, ckp_path) != 0) {
        brix_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "brix: checkpoint recovery cannot remove "
                             "\"%s\"", ckp_path);
        return NGX_ERROR;
    }

    brix_log_safe_path(log, NGX_LOG_NOTICE, 0,
                         "brix: recovered abandoned checkpoint \"%s\"",
                         ckp_path);
    return NGX_OK;
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

    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
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
