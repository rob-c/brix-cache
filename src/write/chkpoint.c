#include "ngx_xrootd_module.h"
#include "chkpoint_xeq.h"
#include "../compat/log.h"
#include "../compat/copy_range.h"
#include "../compat/staged_file.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * kXR_chkpoint — checkpoint/transaction write semantics.
 *
 * Opcodes:
 *   kXR_ckpBegin    (0) — snapshot the file into a temp copy
 *   kXR_ckpCommit   (1) — discard the snapshot (writes are permanent)
 *   kXR_ckpRollback (3) — restore the file from the snapshot
 *   kXR_ckpQuery    (2) — report checkpoint capacity and usage
 *   kXR_ckpXeq      (4) — execute a write sub-operation (write/pgwrite/
 *                           truncate/writev) under checkpoint protection
 *
 * The checkpoint is stored as a sibling file: <open-path>.ckp.
 * A non-NULL ckp_path in the xrootd_file_t slot indicates an active checkpoint.
 */

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void
ckp_clear_path(xrootd_file_t *f)
{
    if (f->ckp_path != NULL) {
        ngx_free(f->ckp_path);
        f->ckp_path = NULL;
    }
    f->ckp_size = 0;
}
/* ---- WHY: Clean up checkpoint state when no longer active — prevents memory leaks (ckp_path string) and stale size tracking. Called after unlink() in commit/rollback, on copy failure cleanup, and by ckp_xeq.c to reset the file slot between sub-operations. ---- */

/* ---- HOW: Free f->ckp_path if non-NULL via ngx_free(), set it to NULL; zero out f->ckp_size. No stat() or unlink() — caller handles .ckp file removal before calling this helper. Used exclusively by ckp_commit, ckp_rollback, and ckp_begin failure cleanup paths. */

/* ---- Function: ckp_begin() — kXR_ckpBegin: snapshot current file state ---- */
/* WHAT: Creates a checkpoint snapshot by copying the entire file to <path>.ckp.
 *      Marks f->ckp_path as non-NULL and stores original size in f->ckp_size.
 * WHY: Enables transactional write semantics — writes under ckpXeq are "tentative"
 *      until committed; rollback restores the pre-write state from the snapshot.
 * HOW: 1) Verify no existing checkpoint (f->ckp_path == NULL). 2) Check file size ≤ kXR_ckpMinMax.
 *      3) Allocate .ckp path string. 4) Create .ckp file with O_CREAT|O_TRUNC. 5) Copy full file via xrootd_copy_range(). */

static ngx_int_t
ckp_begin(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    struct stat    st;
    size_t         plen;
    int            ckp_fd;

    if (f->ckp_path != NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_inProgress, "checkpoint already active");
    }

    if (fstat(f->fd, &st) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    if ((int64_t) st.st_size > kXR_ckpMinMax) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_overQuota, "file too large to checkpoint");
    }

    plen = strlen(f->path);
    if (plen + 4 >= PATH_MAX) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                 "path too long for checkpoint");
    }

    f->ckp_path = ngx_alloc(plen + 5, c->log);
    if (f->ckp_path == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "checkpoint path allocation failed");
    }

    ngx_memcpy(f->ckp_path, f->path, plen);
    ngx_memcpy(f->ckp_path + plen, ".ckp", 5); /* includes NUL */

    ckp_fd = open(f->ckp_path,
                  O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (ckp_fd < 0) {
        if (errno == EEXIST) {
            ckp_clear_path(f);
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT",
                              f->path, "begin", kXR_inProgress,
                              "checkpoint already active for file");
        }
        ckp_clear_path(f);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    f->ckp_size = (int64_t) st.st_size;

    if (f->ckp_size > 0) {
        if (xrootd_copy_range(c->log, f->fd, 0, ckp_fd, 0, (size_t) f->ckp_size,
                              f->path, f->ckp_path) != NGX_OK) {
            close(ckp_fd);
            unlink(f->ckp_path);
            ckp_clear_path(f);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "checkpoint copy failed");
        }
    }

    close(ckp_fd);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin", 0);
}

/* ---- Function: ckp_commit() — kXR_ckpCommit: discard checkpoint, writes are permanent ---- */
/* WHAT: Unlinks the .ckp snapshot file and clears f->ckp_path/f->ckp_size. After commit,
 *      all ckpXeq writes become permanent on the original file.
 * WHY: Transactional write semantics require two-phase commitment — tentative writes (ckpXeq)
 *      are only finalized after explicit commit. Committing means "accept these changes" by
 *      deleting the rollback snapshot.
 * HOW: Verify f->ckp_path != NULL, unlink .ckp file, call ckp_clear_path() to reset state. */

/* ---- Function: ckp_rollback() — kXR_ckpRollback: restore file from checkpoint ---- */
/* WHAT: Truncates original file to f->ckp_size, then restores content from .ckp snapshot via xrootd_copy_range().
 *      After rollback, the original file returns to pre-checkpoint state.
 * WHY: Transactional write semantics provide "undo" capability — if writes under ckpXeq should be rejected,
 *      rollback restores the exact original content and length. This is essential for atomic operations where
 *      partial failures must not leave the file in inconsistent state.
 * HOW: 1) Verify f->ckp_path != NULL. 2) ftruncate() to checkpointed size (may shrink). 3) Copy .ckp→original via xrootd_copy_range(). 4) unlink + clear_path. */

/* ---- Function: ckp_query() — kXR_ckpQuery: report checkpoint capacity / current usage ---- */
/* WHAT: Returns ServerResponseBody_ChkPoint with maxCkpSize (kXR_ckpMinMax) and useCkpSize
 *      (size of .ckp file if active, 0 otherwise).
 * WHY: Clients need to know available checkpoint space before beginning a transaction. Large files
 *      may require more disk space for the snapshot than is available.
 * HOW: Check f->ckp_path != NULL; stat() .ckp file for current usage; populate response body with max/usage values. */

/* ------------------------------------------------------------------ */
/* kXR_ckpCommit — discard checkpoint, writes are permanent            */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_commit(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];

    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "commit",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "commit", 0);
}

/* ------------------------------------------------------------------ */
/* kXR_ckpRollback — restore file from checkpoint                      */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_rollback(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    int            ckp_fd;

    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    /* Truncate original to its checkpointed length first. */
    if (ftruncate(f->fd, (off_t) f->ckp_size) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_IOError, strerror(errno));
    }

    /* Restore file content from checkpoint if there was any. */
    if (f->ckp_size > 0) {
        ckp_fd = open(f->ckp_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (ckp_fd < 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                              kXR_IOError, strerror(errno));
        }

        if (xrootd_copy_range(c->log, ckp_fd, 0, f->fd, 0, (size_t) f->ckp_size,
                              f->ckp_path, f->path) != NGX_OK) {
            close(ckp_fd);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "checkpoint restore copy failed");
        }
        close(ckp_fd);
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback", 0);
}

/* ------------------------------------------------------------------ */
/* kXR_ckpQuery — report checkpoint capacity / current usage           */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t              *f = &ctx->files[idx];
    uint32_t                    use_sz = 0;
    ServerResponseBody_ChkPoint body;

    if (f->ckp_path != NULL) {
        struct stat st;
        if (stat(f->ckp_path, &st) == 0) {
            use_sz = (uint32_t) st.st_size;
        }
    }

    body.maxCkpSize = htonl((uint32_t) kXR_ckpMinMax);
    body.useCkpSize = htonl(use_sz);

    xrootd_log_access(ctx, c, "CHKPOINT", f->path, "query",
                      1, kXR_ok, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_CHKPOINT);
    return xrootd_send_ok(ctx, c, &body, (uint32_t) sizeof(body));
}

/* ------------------------------------------------------------------ */
/* Top-level kXR_chkpoint dispatcher                                   */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_handle_chkpoint(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientChkPointRequest *req = (ClientChkPointRequest *) ctx->hdr_buf;
    int                    idx;
    ngx_int_t              validate_rc;

    (void) conf;

    idx = (int)(unsigned char) req->fhandle[0];

    if (!xrootd_validate_write_handle(ctx, c, idx, "CHKPOINT",
                                      XROOTD_OP_CHKPOINT, &validate_rc)) {
        return validate_rc;
    }

    switch ((unsigned char) req->opcode) {

    case kXR_ckpBegin:
        return ckp_begin(ctx, c, idx);

    case kXR_ckpCommit:
        return ckp_commit(ctx, c, idx);

    case kXR_ckpQuery:
        return ckp_query(ctx, c, idx);

    case kXR_ckpRollback:
        return ckp_rollback(ctx, c, idx);

    case kXR_ckpXeq:
        return ckp_xeq(ctx, c, idx);

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_chkpoint unknown opcode=%d",
                       (int)(unsigned char) req->opcode);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "unknown chkpoint opcode");
    }

/* ---- WHAT: Dispatches kXR_chkpoint sub-operations on req->opcode — routes to ckp_begin, ckp_commit, ckp_query, or ckp_rollback; also handles ckpXeq via ckp_xeq(). Validates the write handle before dispatch. ---- */

/* ---- WHY: kXR_chkpoint is a compound opcode with 5 sub-codes (begin/commit/query/rollback/Xeq). The dispatcher extracts the file handle from req->fhandle[0], validates it as an open write handle, then routes to the appropriate handler. ckpXeq is delegated to chkpoint_xeq.c which parses the inner 24-byte sub-header and executes a single write operation under checkpoint protection. ---- */

/* ---- HOW: Extracts idx from req->fhandle[0] as unsigned char; calls xrootd_validate_write_handle() for validation (returns early on failure). switch(req->opcode): kXR_ckpBegin→ckp_begin, kXR_ckpCommit→ckp_commit, kXR_ckpQuery→ckp_query, kXR_ckpRollback→ckp_rollback, kXR_ckpXeq→ckp_xeq. Default case logs debug + returns kXR_ArgInvalid error. */
}

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
    xrootd_staged_file_t staged;
    struct stat          st;

    len = strlen(ckp_path);
    if (len <= 4 || len >= sizeof(orig_path)) {
        return NGX_ERROR;
    }

    ngx_memcpy(orig_path, ckp_path, len - 4);
    orig_path[len - 4] = '\0';

    ckp_fd = xrootd_open_confined_canon(log, root_canon, ckp_path,
                                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (ckp_fd < 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot open \"%s\"",
                             ckp_path);
        return NGX_ERROR;
    }

    if (fstat(ckp_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ngx_close_file(ckp_fd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery invalid snapshot "
                             "\"%s\"", ckp_path);
        return NGX_ERROR;
    }

    if (xrootd_staged_open(log, root_canon, orig_path, O_WRONLY, 0600, 16,
                           &staged) != NGX_OK)
    {
        ngx_close_file(ckp_fd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot stage "
                             "\"%s\"", orig_path);
        return NGX_ERROR;
    }

    if (st.st_size > 0
        && xrootd_copy_range(log, ckp_fd, 0, staged.fd, 0,
                             (size_t) st.st_size, ckp_path,
                             staged.tmp_path) != NGX_OK)
    {
        xrootd_staged_abort(log, root_canon, &staged, 1);
        ngx_close_file(ckp_fd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery copy failed for "
                             "\"%s\"", orig_path);
        return NGX_ERROR;
    }

    (void) fsync(staged.fd);

    if (xrootd_staged_commit(log, root_canon, &staged, orig_path)
        != NGX_OK)
    {
        ngx_close_file(ckp_fd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery commit failed for "
                             "\"%s\"", orig_path);
        return NGX_ERROR;
    }

    ngx_close_file(ckp_fd);

    if (xrootd_unlink_confined_canon(log, root_canon, ckp_path, 0) != 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot remove "
                             "\"%s\"", ckp_path);
        return NGX_ERROR;
    }

    xrootd_log_safe_path(log, NGX_LOG_NOTICE, 0,
                         "xrootd: recovered abandoned checkpoint \"%s\"",
                         ckp_path);
    return NGX_OK;
}

static ngx_int_t
ckp_recover_scan(ngx_log_t *log, const char *root_canon, const char *dir,
    ngx_uint_t depth)
{
    DIR           *dp;
    int            dfd;
    struct dirent *de;

    if (depth > 128) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, 0,
                             "xrootd: checkpoint recovery depth exceeded at "
                             "\"%s\"", dir);
        return NGX_ERROR;
    }

    dfd = xrootd_open_confined_canon(log, root_canon, dir,
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
            xrootd_log_safe_path(log, NGX_LOG_INFO, ngx_errno,
                                 "xrootd: checkpoint recovery skipping "
                                 "inaccessible dir \"%s\"", dir);
            return NGX_OK;
        }
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot scan \"%s\"",
                             dir);
        return NGX_ERROR;
    }

    dp = fdopendir(dfd);
    if (dp == NULL) {
        ngx_close_file(dfd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot scan \"%s\"",
                             dir);
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        char        path[PATH_MAX];
        size_t      dlen, nlen;
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        dlen = strlen(dir);
        nlen = strlen(de->d_name);
        if (dlen + 1 + nlen >= sizeof(path)) {
            closedir(dp);
            return NGX_ERROR;
        }

        ngx_memcpy(path, dir, dlen);
        path[dlen] = '/';
        ngx_memcpy(path + dlen + 1, de->d_name, nlen + 1);

        if (fstatat(dirfd(dp), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            /* A transiently-removed or inaccessible entry: skip it, don't abort
             * the whole recovery (and thus the worker). */
            xrootd_log_safe_path(log, NGX_LOG_INFO, ngx_errno,
                                 "xrootd: checkpoint recovery skipping entry "
                                 "\"%s\"", path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (ckp_recover_scan(log, root_canon, path, depth + 1) != NGX_OK) {
                closedir(dp);
                return NGX_ERROR;
            }
            continue;
        }

        if (S_ISREG(st.st_mode) && ckp_name_has_suffix(de->d_name)) {
            if (ckp_recover_one(log, root_canon, path) != NGX_OK) {
                closedir(dp);
                return NGX_ERROR;
            }
        }
    }

    closedir(dp);
    return NGX_OK;
}

ngx_int_t
xrootd_chkpoint_recover_root(ngx_log_t *log, const char *root_canon)
{
    char      lock_path[PATH_MAX];
    size_t    root_len;
    int       lock_fd;
    ngx_int_t rc;

    if (root_canon == NULL || root_canon[0] == '\0') {
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
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery lock failed "
                             "\"%s\"", lock_path);
        return NGX_ERROR;
    }

    if (flock(lock_fd, LOCK_EX) != 0) {
        ngx_close_file(lock_fd);
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd: checkpoint recovery cannot lock "
                             "\"%s\"", lock_path);
        return NGX_ERROR;
    }

    rc = ckp_recover_scan(log, root_canon, root_canon, 0);

    (void) flock(lock_fd, LOCK_UN);
    ngx_close_file(lock_fd);

    return rc;
}
