/*
 * zip_member.h — ZIP member virtual-handle I/O (phase-57 W2). See zip_member.c.
 *
 * WHAT: Open/read/cleanup for a ZIP member served as a standalone read handle
 *       over a single archive fd. Stored members (method 0) are pure offset
 *       translation; deflate members (method 8) stream-inflate via codec_core.
 * WHY:  Keeps the read/stat/close opcode handlers thin — they branch once on
 *       fh->zip_mode and delegate here. Read-only by construction.
 * HOW:  brix_zip_open_member opens the archive confined, resolves the member
 *       via brix_zip_find_member (zip_dir.h), allocates a handle with
 *       zip_mode + the zip_* fields, and sends the kXR_open reply (member's
 *       uncompressed size is the logical size). brix_zip_read serves bytes.
 */
#ifndef BRIX_ZIP_MEMBER_H
#define BRIX_ZIP_MEMBER_H

#include "core/ngx_brix_module.h"   /* brix_ctx_t, ngx_stream_brix_srv_conf_t,
                                       brix_file_t */

/*
 * Open ZIP member `member` of the archive at `archive_logical` (root-relative
 * logical path, for the confined open) / `archive_full` (root_canon-prefixed
 * absolute, for logging + the handle path). `options` is the client's kXR_open
 * options (only kXR_retstat is honoured; the handle is always read-only).
 * Sends the kXR_open response or an error; returns the send/queue result.
 */
ngx_int_t brix_zip_open_member(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *archive_logical,
    const char *archive_full, const char *member, uint16_t options);

/* kXR_read on a zip_mode handle (stored = offset add; deflate = inflate). */
ngx_int_t brix_zip_read(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int64_t offset, size_t rlen);

/*
 * Release the inflate stream on a zip_mode handle (deflate members). NULL-safe
 * and idempotent; called from brix_free_fhandle. The archive fd itself is
 * closed by the normal handle-free path.
 */
void brix_zip_handle_cleanup(brix_file_t *fh);

#endif /* BRIX_ZIP_MEMBER_H */
