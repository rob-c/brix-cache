/*
 * writev_staged.c — whole-object staged-handle support for kXR_writev.
 *
 * A staged writer is a live writable handle with fd == -1.  Vector writes must
 * therefore append through brix_vfs_writer instead of entering the fd/AIO path,
 * and kXR_wv_doSync must commit it with the same checksum gate as kXR_sync.
 */

#include "core/compat/error_mapping.h"
#include "core/ngx_brix_module.h"
#include "platform/platform_api.h"
#include "pgw_fob.h"
#include "write.h"
#include "writev_internal.h"

#include <errno.h>
#include <string.h>

ngx_flag_t
writev_has_staged(const writev_run_t *run)
{
    size_t i;

    for (i = 0; i < run->n_segs; i++) {
        int idx = (int) (unsigned char) run->wl[i].fhandle[0];

        if (run->ctx->files[idx].writer != NULL) {
            return 1;
        }
    }
    return 0;
}

ngx_int_t
writev_staged_segment(brix_ctx_t *ctx, ngx_connection_t *c,
    const write_list *seg, const u_char **data_ptr,
    size_t *bytes_written_total)
{
    int      idx = (int) (unsigned char) seg->fhandle[0];
    int64_t  offset = (int64_t) brix_plat_be64toh((uint64_t) seg->offset);
    uint32_t wlen = (uint32_t) ntohl((uint32_t) seg->wlen);
    int      append_rc;

    append_rc = brix_staged_append_raw(ctx, idx, offset, *data_ptr, wlen);
    if (append_rc != BRIX_STAGED_APPEND_OK) {
        uint16_t code = brix_kxr_from_errno(errno);
        ngx_int_t rc;

        BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
        rc = brix_send_error(ctx, c, code, strerror(errno));
        return rc == NGX_OK ? NGX_DONE : rc;
    }
    *data_ptr += wlen;
    *bytes_written_total += wlen;
    return NGX_OK;
}

ngx_int_t
writev_sync_staged(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    uint32_t bad = brix_pgw_fob_commit_blocked(&ctx->files[idx]);
    int      err = 0;

    if (bad > 0) {
        ngx_int_t rc;

        BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
        rc = brix_send_error(ctx, c, kXR_ChkSumErr,
                             "uncorrected checksum error");
        return rc == NGX_OK ? NGX_DONE : rc;
    }
    if (brix_staged_commit_handle(ctx, idx, &err) != NGX_OK) {
        ngx_int_t rc;

        BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
        rc = brix_send_error(ctx, c, brix_kxr_from_errno(err), strerror(err));
        return rc == NGX_OK ? NGX_DONE : rc;
    }
    return NGX_OK;
}
