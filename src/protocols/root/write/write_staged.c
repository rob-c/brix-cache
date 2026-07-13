/*
 * write_staged.c — root:// block-write → whole-object staged-commit adapter.
 *
 * WHAT: The write/sync/close hooks for a root:// write handle whose backend LEAF
 *       advertises NO random write (BRIX_SD_CAP_RANDOM_WRITE) and has no pwrite
 *       slot — a whole-object store (sd_http and any driver whose write is a
 *       single commit-time PUT). brix_open_dispatch_staged put such a handle in
 *       STAGED mode (ctx->files[idx].staged != NULL, opened via the WebDAV/S3 PUT
 *       staged bridge with the per-user credential already resolved). This file
 *       APPENDS each kXR_write/pgwrite block to that staged handle and COMMITS the
 *       whole object on kXR_sync / kXR_close.
 *
 * WHY:  The block-oriented root:// write model (open-for-write → write/pgwrite at
 *       offsets → sync/close → driver pwrite) requires a random-write driver; a
 *       whole-object backend cannot pwrite, so a root:// upload used to fail EROFS.
 *       WebDAV/S3 PUT already stream a block body into staged_write+staged_commit;
 *       this is the missing root:// equivalent, unblocking forwarding-matrix cells
 *       C RH gsi / C RH token (and backend-side A RH gsi).
 *
 * HOW:  Uploads are sequential appends, which is the only shape a whole-object
 *       store supports. brix_write_staged_buf enforces sequential-append: an
 *       incoming offset != the running expected offset is refused cleanly with
 *       kXR_Unsupported (never corrupting the object). A matching offset appends
 *       via brix_vfs_staged_write and advances the running offset. sync/close call
 *       brix_staged_commit_handle → brix_vfs_staged_commit (one whole-object PUT),
 *       which on success consumes the staged handle; brix_free_fhandle aborts an
 *       uncommitted handle so no partial object is published. No goto; each stage
 *       is a small single-purpose function with explicit data flow.
 */

#include "core/ngx_brix_module.h"
#include "write.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_staged_write / _commit */

/*
 * brix_staged_append — append `len` bytes at `offset` to the staged handle,
 * WITHOUT sending a success reply (the caller chooses the reply frame: kXR_ok for
 * kXR_write, kXR_status for pgwrite).
 *
 * Enforces sequential append (offset == running expected offset); an out-of-order
 * offset is refused with kXR_Unsupported. On any failure the error reply is sent
 * here and *rc holds its return value. Returns NGX_OK when appended (no reply
 * sent yet); NGX_ERROR when the caller must return *rc immediately.
 */
ngx_int_t
brix_staged_append(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int64_t offset, const u_char *buf, size_t len, ngx_int_t *rc)
{
    brix_file_t *file = &ctx->files[idx];
    char         detail[64];

    snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, len);

    /* Sequential-append contract: a whole-object backend cannot honour a random
     * offset. Refuse an out-of-order block cleanly rather than corrupting the
     * object (genuinely random-offset writes stay unsupported). */
    if (offset != (int64_t) file->staged_expected_off) {
        brix_log_access(ctx, c, "WRITE", file->path, detail, 0,
                          kXR_Unsupported,
                          "random-offset write to whole-object backend unsupported", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        *rc = brix_send_error(ctx, c, kXR_Unsupported,
            "random-offset write to whole-object backend unsupported");
        return NGX_ERROR;
    }

    if (brix_vfs_staged_write(file->staged, buf, len, offset) != NGX_OK) {
        const char *ioerr = strerror(errno);
        brix_log_access(ctx, c, "WRITE", file->path, detail, 0,
                          kXR_IOError, ioerr, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        *rc = brix_send_error(ctx, c, kXR_IOError, ioerr);
        return NGX_ERROR;
    }

    file->staged_expected_off += (off_t) len;
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
 * brix_staged_commit_handle — commit the whole staged object (one backend PUT).
 * The kXR_sync / kXR_close hook. Idempotent: once committed, a later call is a
 * no-op success (a client that syncs then closes). On failure sets *err_out and
 * returns NGX_ERROR leaving the staged handle intact (no partial publish).
 */
ngx_int_t
brix_staged_commit_handle(brix_ctx_t *ctx, int idx, int *err_out)
{
    brix_file_t *file = &ctx->files[idx];

    if (file->staged == NULL || file->staged_committed) {
        return NGX_OK;   /* nothing staged, or already published */
    }

    if (brix_vfs_staged_commit(file->staged, 0 /* not excl */) != NGX_OK) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NGX_ERROR;
    }

    /* A successful commit consumed the driver staged handle inside the VFS; mark
     * the handle committed so brix_free_fhandle does not abort/unlink it. */
    file->staged_committed = 1;
    return NGX_OK;
}
