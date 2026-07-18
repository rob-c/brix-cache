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
 * HOW:  Uploads are sequential appends, which is the only shape a whole-object
 *       store supports. brix_staged_append refuses an out-of-order offset cleanly
 *       with kXR_Unsupported (comparing against brix_vfs_writer_expected_off before
 *       corrupting the object), then appends via brix_vfs_writer_write. sync/close
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
 * Enforces sequential append (offset == the writer's expected offset); an
 * out-of-order offset is refused with kXR_Unsupported. On any failure the error
 * reply is sent here and *rc holds its return value. Returns NGX_OK when appended
 * (no reply sent yet); NGX_ERROR when the caller must return *rc immediately.
 */
ngx_int_t
brix_staged_append(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int64_t offset, const u_char *buf, size_t len, ngx_int_t *rc)
{
    brix_file_t *file = &ctx->files[idx];
    char         detail[64];

    snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, len);

    /* Sequential-append contract: a whole-object backend cannot honour a random
     * offset. Refuse an out-of-order block cleanly — checked against the writer's
     * own cursor so the error is deterministic (kXR_Unsupported) rather than
     * relying on the writer's EINVAL — before corrupting the object (genuinely
     * random-offset writes stay unsupported). */
    if (offset != (int64_t) brix_vfs_writer_expected_off(file->writer)) {
        brix_log_access(ctx, c, "WRITE", file->path, detail, 0,
                          kXR_Unsupported,
                          "random-offset write to whole-object backend unsupported", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        *rc = brix_send_error(ctx, c, kXR_Unsupported,
            "random-offset write to whole-object backend unsupported");
        return NGX_ERROR;
    }

    if (brix_vfs_writer_write(file->writer, buf, len, offset) != NGX_OK) {
        const char *ioerr = strerror(errno);
        brix_log_access(ctx, c, "WRITE", file->path, detail, 0,
                          kXR_IOError, ioerr, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        *rc = brix_send_error(ctx, c, kXR_IOError, ioerr);
        return NGX_ERROR;
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
    return NGX_OK;
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

    if (brix_vfs_writer_commit(file->writer) != NGX_OK) {
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
