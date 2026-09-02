/*
 * write_staged.c — root:// block-write → whole-object staged-commit adapter.
 *
 * WHAT: The write/sync/close hooks for a root:// write handle whose backend LEAF
 *       advertises NO random write (BRIX_SD_CAP_RANDOM_WRITE) and has no pwrite
 *       slot — a whole-object store (sd_http/s3 and any driver whose write is a
 *       single commit-time PUT). brix_open_dispatch_staged put such a handle in
 *       STAGED mode (ctx->files[idx].writer != NULL — a unified brix_vfs_writer
 *       session opened with the per-user credential already resolved). This file
 *       APPENDS each kXR_write/pgwrite block to that session and COMMITS the whole
 *       object on kXR_sync / kXR_close.
 *
 * WHY:  The block-oriented root:// write model (open-for-write → write/pgwrite at
 *       offsets → sync/close → driver pwrite) requires a random-write driver; a
 *       whole-object backend cannot pwrite, so a root:// upload used to fail EROFS.
 *       GridFTP STOR and (via http_body) WebDAV/S3 PUT stream a block body through
 *       the same unified brix_vfs_writer; this routes the root:// path through it
 *       too, so every filesystem shares one verified-write call to the VFS layer.
 *
 * HOW:  Uploads are appended via brix_vfs_writer_write; the writer itself keeps
 *       the sequential contract, spilling an out-of-order extent to local scratch
 *       (phase-107 C1) and refusing only when it cannot (no spill root, capacity,
 *       overlap) — that surfaces here as an I/O error whose errno maps to the
 *       kXR code (ENOSPC → kXR_NoSpace). sync/close
 *       call brix_staged_commit_handle → brix_vfs_writer_commit (one whole-object
 *       PUT, plus the optional read-back CRC check when brix_verify_write is on),
 *       which on success consumes the session; brix_free_fhandle aborts an
 *       uncommitted session so no partial object is published. No goto; each stage
 *       is a small single-purpose function with explicit data flow.
 */

#include "core/ngx_brix_module.h"
#include "write.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_writer_* (via vfs_ops.h) */

/*
 * brix_staged_append — append `len` bytes at `offset` to the write session,
 * WITHOUT sending a success reply (the caller chooses the reply frame: kXR_ok for
 * kXR_write, kXR_status for pgwrite).
 *
 * Ordering is the writer's problem now (phase-107 C1: reordered extents spill to
 * local scratch); a failure — including "cannot spill" ENOSPC — is replied here
 * with the kXR code mapped from errno, and *rc holds the reply's return value.
 * Returns NGX_OK when appended (no reply sent yet); NGX_ERROR when the caller
 * must return *rc immediately.
 */
/*
 * brix_staged_append_raw — the reply-free core of a staged append: forward the
 * block to the write session (which spills a reordered extent to local scratch,
 * phase-107 C1), with the success-path byte accounting.  Returns
 * BRIX_STAGED_APPEND_OK on success or BRIX_STAGED_APPEND_IO on a writer error
 * (errno preserved — ENOSPC when a reordered extent could not be spilled).
 * Sends nothing and touches no metrics
 * — the caller chooses the reply/log framing.  This is the primitive the chunked
 * streaming writer (write_stream.c) applies per chunk without acking mid-stream.
 */
int
brix_staged_append_raw(brix_ctx_t *ctx, int idx, int64_t offset,
    const u_char *buf, size_t len)
{
    brix_file_t *file = &ctx->files[idx];

    if (brix_vfs_writer_write(file->writer, buf, len, offset) != NGX_OK) {
        return BRIX_STAGED_APPEND_IO;
    }

    file->bytes_written       += len;
    ctx->totals.bytes_written += len;
    brix_rl_charge_ctx(ctx, len);

    if (file->dashboard_slot >= 0 && ngx_brix_dashboard_shm_zone != NULL) {
        brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
                                    file->dashboard_slot,
                                    (ngx_atomic_int_t) len,
                                    (int64_t) ngx_current_msec);
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      file->dashboard_slot, "write");
    }
    return BRIX_STAGED_APPEND_OK;
}

ngx_int_t
brix_staged_append(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int64_t offset, const u_char *buf, size_t len, ngx_int_t *rc)
{
    char detail[64];
    int  ar;

    ar = brix_staged_append_raw(ctx, idx, offset, buf, len);
    if (ar == BRIX_STAGED_APPEND_OK) {
        return NGX_OK;
    }

    snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, len);

    {
        /* errno → kXR so a refused spill surfaces as kXR_NoSpace (ENOSPC), not a
         * generic I/O error the client would retry against the same wall. */
        uint16_t    code  = brix_kxr_from_errno(errno);
        const char *ioerr = strerror(errno);

        brix_log_access(ctx, c, "WRITE", ctx->files[idx].path, detail, 0,
                          code, ioerr, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        *rc = brix_send_error(ctx, c, code, ioerr);
    }
    return NGX_ERROR;
}

/*
 * brix_write_staged_buf — append a decoded block and reply kXR_ok. Used by the
 * kXR_write path (the pgwrite path appends then sends its own kXR_status frame).
 */
ngx_int_t
brix_write_staged_buf(brix_ctx_t *ctx, ngx_connection_t *c,
    int idx, int64_t offset, const u_char *buf, size_t len)
{
    ngx_int_t rc = NGX_OK;
    char      detail[64];

    if (brix_staged_append(ctx, c, idx, offset, buf, len, &rc) != NGX_OK) {
        return rc;
    }

    snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, len);
    BRIX_RETURN_OK(ctx, c, BRIX_OP_WRITE, "WRITE", ctx->files[idx].path,
                     detail, len);
}

/*
 * brix_write_staged — kXR_write entry for a staged handle: append the recv
 * payload and reply kXR_ok.
 */
ngx_int_t
brix_write_staged(brix_ctx_t *ctx, ngx_connection_t *c,
    int idx, int64_t offset, size_t wlen)
{
    const u_char *payload = ctx->recv.payload ? ctx->recv.payload
                                              : (const u_char *) "";
    return brix_write_staged_buf(ctx, c, idx, offset, payload, wlen);
}

/*
 * brix_staged_commit_handle — commit the whole staged object (one backend PUT,
 * plus the read-back CRC check when brix_verify_write is on). The kXR_sync /
 * kXR_close hook. Idempotent: once committed, a later call is a no-op success (a
 * client that syncs then closes). On failure sets *err_out and returns NGX_ERROR;
 * brix_vfs_writer_commit already unlinked any published-then-mismatched object, so
 * no partial/corrupt object is left behind.
 */
ngx_int_t
brix_staged_commit_handle(brix_ctx_t *ctx, int idx, int *err_out)
{
    brix_file_t *file = &ctx->files[idx];

    if (file->writer == NULL || file->staged_committed) {
        return NGX_OK;   /* nothing staged, or already published */
    }

    /* staged_excl carries the open's kXR_new intent to the publish: the storage
     * enforces create-if-absent atomically here (EEXIST → kXR_ItExists), rather
     * than trusting the open-time existence check that raced (phase-107 C1). */
    if (brix_vfs_writer_commit_ex(file->writer, file->staged_excl) != NGX_OK) {
        if (err_out != NULL) {
            *err_out = errno ? errno : EIO;
        }
        return NGX_ERROR;
    }

    /* A successful commit published (and optionally verified) the object and
     * consumed the session's staged state; mark committed so brix_free_fhandle's
     * abort is a no-op and no second commit runs. */
    file->staged_committed = 1;
    return NGX_OK;
}
