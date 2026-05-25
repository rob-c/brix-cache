#include "ngx_xrootd_module.h"
#include "chkpoint_xeq.h"
#include "../compat/copy_range.h"

#include <errno.h>
#include <fcntl.h>
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

    ckp_fd = open(f->ckp_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (ckp_fd < 0) {
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
        ckp_fd = open(f->ckp_path, O_RDONLY | O_CLOEXEC);
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
