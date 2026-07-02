/* kXR_clone (3032) — server-side range copy, protocol v5.2.0.
 *
 * Wire format:
 *   Header body: dst_fhandle[4] + reserved[12]
 *   Payload:     array of clone_item (32 bytes each):
 *                  src_fhandle[4] + reserved[4] +
 *                  src_offset(u64be) + src_len(u64be) + dst_offset(u64be)
 *
 * Each item copies src_len bytes from src_offset in the source file to
 * dst_offset in the destination file.  Uses copy_file_range(2) for
 * same-filesystem copies; falls back to pread/pwrite for cross-filesystem.
 *
 * WHAT: Implements kXR_clone (3032), a server-side range-copy operation that copies multiple byte ranges
 * from one source file into a single destination file in a single protocol round-trip.
 *
 * WHY: Clone avoids client-server data transfer — the copy happens entirely on the server using zero-copy
 * syscalls when possible. The batched wire format lets clients specify arbitrary source ranges and
 * destination offsets without multiple individual requests, reducing latency and network bandwidth.
 *
 * HOW: Parse clone_item array from payload (32 bytes each), validate dst_fhandle for write access and each
 * src_fhandle for read access via xrootd_validate_write_handle/xrootd_validate_read_handle, decode big-endian
 * uint64 fields (src_offset, src_len, dst_offset) with be64toh, iterate items calling xrootd_copy_range() for
 * each (which uses copy_file_range when same filesystem or pread/pwrite fallback otherwise), skip zero-length
 * items silently, accumulate total_bytes into file.bytes_written and session_bytes counters, return kXR_OK with
 * byte count via XROOTD_RETURN_OK.
 */

#include "clone.h"
#include "connection/fd_table.h"
#include "core/compat/copy_range.h"

#include <errno.h>
#include <unistd.h>

#define CLONE_ITEM_LEN   32u      /* sizeof(clone_item) */
#define CLONE_MAX_ITEMS  1024u    /* maxClonesz from XProtocol.hh */

ngx_int_t
xrootd_handle_clone(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_clone_req_t    req;
    int                 dst_idx;
    int                 dst_fd;
    const u_char       *p;
    const u_char       *end;
    uint32_t            n_items;
    ngx_int_t           rc;
    uint64_t            total_bytes = 0;

    xrdw_clone_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    dst_idx = (int)(unsigned char) req.dst_fhandle[0];

    if (!xrootd_validate_write_handle(ctx, c, dst_idx, "CLONE",
                                      XROOTD_OP_CLONE, &rc)) {
        return rc;
    }

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgMissing, "clone list is missing");
    }

    if (ctx->cur_dlen % CLONE_ITEM_LEN != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgInvalid, "malformed clone list");
    }

    n_items = ctx->cur_dlen / CLONE_ITEM_LEN;
    if (n_items > CLONE_MAX_ITEMS) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgTooLong, "too many clone items");
    }

    dst_fd = ctx->files[dst_idx].fd;

    p   = ctx->payload;
    end = ctx->payload + ctx->cur_dlen;

    while (p < end) {
        const clone_item *item = (const clone_item *) p;
        int               src_idx;
        uint64_t          src_off_raw, src_len_raw, dst_off_raw;
        off_t             src_off, dst_off;
        size_t            copy_len;

        src_idx = (int)(unsigned char) item->src_fhandle[0];

        if (!xrootd_validate_read_handle(ctx, c, src_idx, "CLONE",
                                         XROOTD_OP_CLONE, &rc)) {
            return rc;
        }

        /* All fields are big-endian uint64. */
        ngx_memcpy(&src_off_raw, &item->src_offset, 8);
        ngx_memcpy(&src_len_raw, &item->src_len,    8);
        ngx_memcpy(&dst_off_raw, &item->dst_offset, 8);

        src_off_raw = be64toh(src_off_raw);
        src_len_raw = be64toh(src_len_raw);
        dst_off_raw = be64toh(dst_off_raw);

        src_off  = (off_t)  src_off_raw;
        dst_off  = (off_t)  dst_off_raw;
        copy_len = (size_t) src_len_raw;

        if (copy_len == 0) {
            p += CLONE_ITEM_LEN;
            continue;
        }

        if (xrootd_copy_range(c->log, ctx->files[src_idx].fd, src_off,
                              dst_fd, dst_off, copy_len,
                              ctx->files[src_idx].path,
                              ctx->files[dst_idx].path) != NGX_OK)
        {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CLONE, "CLONE",
                              ctx->files[src_idx].path,
                              ctx->files[dst_idx].path,
                              kXR_IOError, "clone copy failed");
        }

        total_bytes += copy_len;
        ctx->files[dst_idx].bytes_written += copy_len;
        ctx->session_bytes += copy_len;

        p += CLONE_ITEM_LEN;
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CLONE, "CLONE",
                     ctx->files[dst_idx].path, "-", (size_t) total_bytes);
}
