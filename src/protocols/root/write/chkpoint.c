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
 * A non-NULL ckp_path in the brix_file_t slot indicates an active checkpoint.
 */


static void
ckp_clear_path(brix_file_t *f)
{
    if (f->ckp_path != NULL) {
        ngx_free(f->ckp_path);
        f->ckp_path = NULL;
    }
    f->ckp_size = 0;
}
/* WHY: Clean up checkpoint state when no longer active — prevents memory leaks (ckp_path string) and stale size tracking. Called after unlink() in commit/rollback, on copy failure cleanup, and by ckp_xeq.c to reset the file slot between sub-operations. */
/* HOW: Free f->ckp_path if non-NULL via ngx_free(), set it to NULL; zero out f->ckp_size. No stat() or unlink() — caller handles .ckp file removal before calling this helper. Used exclusively by ckp_commit, ckp_rollback, and ckp_begin failure cleanup paths. */

/* WHAT: Creates a checkpoint snapshot by copying the entire file to <path>.ckp.
 *      Marks f->ckp_path as non-NULL and stores original size in f->ckp_size.
 * WHY: Enables transactional write semantics — writes under ckpXeq are "tentative"
 *      until committed; rollback restores the pre-write state from the snapshot.
 * HOW: 1) Verify no existing checkpoint (f->ckp_path == NULL). 2) Check file size ≤ kXR_ckpMinMax.
 *      3) Allocate .ckp path string. 4) Create .ckp file with O_CREAT|O_TRUNC. 5) Copy full file via brix_copy_range(). */

static ngx_int_t
ckp_begin(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t *f = &ctx->files[idx];
    struct stat    st;
    size_t         plen;
    int            ckp_fd;

    if (f->ckp_path != NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_inProgress, "checkpoint already active");
    }

    if (fstat(f->fd, &st) != 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    if ((int64_t) st.st_size > kXR_ckpMinMax) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_overQuota, "file too large to checkpoint");
    }

    plen = strlen(f->path);
    if (plen + 4 >= PATH_MAX) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_ArgTooLong,
                                 "path too long for checkpoint");
    }

    f->ckp_path = ngx_alloc(plen + 5, c->log);
    if (f->ckp_path == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_NoMemory,
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
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                              f->path, "begin", kXR_inProgress,
                              "checkpoint already active for file");
        }
        ckp_clear_path(f);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    f->ckp_size = (int64_t) st.st_size;

    if (f->ckp_size > 0) {
        if (brix_copy_range(c->log, f->fd, 0, ckp_fd, 0, (size_t) f->ckp_size,
                              f->path, f->ckp_path) != NGX_OK) {
            close(ckp_fd);
            unlink(f->ckp_path);
            ckp_clear_path(f);
            BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
            return brix_send_error(ctx, c, kXR_IOError,
                                     "checkpoint copy failed");
        }
    }

    close(ckp_fd);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "begin", 0);
}

/* WHAT: Unlinks the .ckp snapshot file and clears f->ckp_path/f->ckp_size. After commit,
 *      all ckpXeq writes become permanent on the original file.
 * WHY: Transactional write semantics require two-phase commitment — tentative writes (ckpXeq)
 *      are only finalized after explicit commit. Committing means "accept these changes" by
 *      deleting the rollback snapshot.
 * HOW: Verify f->ckp_path != NULL, unlink .ckp file, call ckp_clear_path() to reset state. */

/* WHAT: Truncates original file to f->ckp_size, then restores content from .ckp snapshot via brix_copy_range().
 *      After rollback, the original file returns to pre-checkpoint state.
 * WHY: Transactional write semantics provide "undo" capability — if writes under ckpXeq should be rejected,
 *      rollback restores the exact original content and length. This is essential for atomic operations where
 *      partial failures must not leave the file in inconsistent state.
 * HOW: 1) Verify f->ckp_path != NULL. 2) Run a VFS TRUNCATE job to checkpointed size (may shrink). 3) Copy .ckp→original via brix_copy_range(). 4) unlink + clear_path. */

/* WHAT: Returns ServerResponseBody_ChkPoint with maxCkpSize (kXR_ckpMinMax) and useCkpSize
 *      (size of .ckp file if active, 0 otherwise).
 * WHY: Clients need to know available checkpoint space before beginning a transaction. Large files
 *      may require more disk space for the snapshot than is available.
 * HOW: Check f->ckp_path != NULL; stat() .ckp file for current usage; populate response body with max/usage values. */


static ngx_int_t
ckp_commit(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t *f = &ctx->files[idx];

    if (f->ckp_path == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "commit",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "commit", 0);
}


static ngx_int_t
ckp_rollback(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t *f = &ctx->files[idx];
    int            ckp_fd;
    brix_vfs_job_t job;

    if (f->ckp_path == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    /* Truncate original to its checkpointed length first. */
    brix_vfs_job_truncate_init(&job, f->fd, (off_t) f->ckp_size);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_IOError, strerror(job.io_errno));
    }

    /* Restore file content from checkpoint if there was any. */
    if (f->ckp_size > 0) {
        ckp_fd = open(f->ckp_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (ckp_fd < 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                              kXR_IOError, strerror(errno));
        }

        if (brix_copy_range(c->log, ckp_fd, 0, f->fd, 0, (size_t) f->ckp_size,
                              f->ckp_path, f->path) != NGX_OK) {
            close(ckp_fd);
            BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
            return brix_send_error(ctx, c, kXR_IOError,
                                     "checkpoint restore copy failed");
        }
        close(ckp_fd);
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    BRIX_RETURN_OK(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "rollback", 0);
}


static ngx_int_t
ckp_query(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t              *f = &ctx->files[idx];
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

    brix_log_access(ctx, c, "CHKPOINT", f->path, "query",
                      1, kXR_ok, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_CHKPOINT);
    return brix_send_ok(ctx, c, &body, (uint32_t) sizeof(body));
}


ngx_int_t
brix_handle_chkpoint(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_chkpoint_req_t    req;
    int                    idx;
    ngx_int_t              validate_rc;

    (void) conf;

    xrdw_chkpoint_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    idx = (int)(unsigned char) req.fhandle[0];

    if (!brix_validate_write_handle(ctx, c, idx, "CHKPOINT",
                                      BRIX_OP_CHKPOINT, &validate_rc)) {
        return validate_rc;
    }

    /* Checkpoint operates on a real file path. Reject handles that have none — a
     * virtual/path-less handle (e.g. an SSI channel) or any handle opened without
     * a stored path. Guards ckp_begin's strlen(f->path) from a NULL deref. */
    if (ctx->files[idx].path == NULL || ctx->files[idx].ssi != NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "checkpoint not supported on this handle");
    }

    switch ((unsigned char) req.opcode) {

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
                       "brix: kXR_chkpoint unknown opcode=%d",
                       (int)(unsigned char) req.opcode);
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "unknown chkpoint opcode");
    }

/* WHAT: Dispatches kXR_chkpoint sub-operations on req->opcode — routes to ckp_begin, ckp_commit, ckp_query, or ckp_rollback; also handles ckpXeq via ckp_xeq(). Validates the write handle before dispatch. */
/* WHY: kXR_chkpoint is a compound opcode with 5 sub-codes (begin/commit/query/rollback/Xeq). The dispatcher extracts the file handle from req->fhandle[0], validates it as an open write handle, then routes to the appropriate handler. ckpXeq is delegated to chkpoint_xeq.c which parses the inner 24-byte sub-header and executes a single write operation under checkpoint protection. */
/* HOW: Extracts idx from req->fhandle[0] as unsigned char; calls brix_validate_write_handle() for validation (returns early on failure). switch(req->opcode): kXR_ckpBegin→ckp_begin, kXR_ckpCommit→ckp_commit, kXR_ckpQuery→ckp_query, kXR_ckpRollback→ckp_rollback, kXR_ckpXeq→ckp_xeq. Default case logs debug + returns kXR_ArgInvalid error. */
}

/*
 * Startup recovery of abandoned .ckp snapshots (brix_chkpoint_recover_root and
 * its static helpers) lives in the sibling chkpoint_recover.c — split out
 * verbatim to keep this file under the size cap. The public entry point is
 * declared in chkpoint.h.
 */
