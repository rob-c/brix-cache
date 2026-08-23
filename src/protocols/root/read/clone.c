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
 * src_fhandle for read access via brix_validate_write_handle/brix_validate_read_handle, decode big-endian
 * uint64 fields (src_offset, src_len, dst_offset) with be64toh, iterate items calling brix_copy_range() for
 * each (which uses copy_file_range when same filesystem or pread/pwrite fallback otherwise), skip zero-length
 * items silently, accumulate total_bytes into file.bytes_written and session_bytes counters, return kXR_OK with
 * byte count via BRIX_RETURN_OK.
 */

#include "clone.h"
#include "fs/backend/csi_tagstore.h"
#include "protocols/root/connection/fd_table.h"
#include "core/compat/copy_range.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#define CLONE_ITEM_LEN   32u      /* sizeof(clone_item) */
#define CLONE_MAX_ITEMS  1024u    /* maxClonesz from XProtocol.hh */

typedef struct {
    int       src_idx;
    uint64_t  src_off_raw;
    uint64_t  len_raw;
    uint64_t  dst_off_raw;
    off_t     src_off;
    off_t     dst_off;
    size_t    len;
} brix_clone_span_t;


/*
 * WHAT: Decode one wire clone item into host-order copy coordinates.
 * WHY: Keep endian conversion and signed-range validation at the protocol edge.
 * HOW: Copy potentially unaligned fields, convert big endian values, and reject
 *      any span which cannot be represented safely by off_t/ssize_t operations.
 */
static ngx_int_t
brix_clone_decode(const clone_item *item, brix_clone_span_t *span)
{
    span->src_idx = (int) (unsigned char) item->src_fhandle[0];
    ngx_memcpy(&span->src_off_raw, &item->src_offset, 8);
    ngx_memcpy(&span->len_raw, &item->src_len, 8);
    ngx_memcpy(&span->dst_off_raw, &item->dst_offset, 8);
    span->src_off_raw = be64toh(span->src_off_raw);
    span->len_raw = be64toh(span->len_raw);
    span->dst_off_raw = be64toh(span->dst_off_raw);
    span->src_off = (off_t) span->src_off_raw;
    span->dst_off = (off_t) span->dst_off_raw;
    span->len = (size_t) span->len_raw;

    if (span->src_off < 0 || span->dst_off < 0
        || span->len_raw > (uint64_t) SSIZE_MAX
        || span->src_off_raw > (uint64_t) SSIZE_MAX - span->len_raw
        || span->dst_off_raw > (uint64_t) SSIZE_MAX - span->len_raw)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * WHAT: Refresh destination CSI state for a successfully cloned range.
 * WHY: Clone bypasses the normal write path's per-block checksum folding.
 * HOW: Read the copied destination in one-block windows and feed each readable
 *      segment to the existing CSI update helper; allocation is best-effort.
 */
static void
brix_clone_fold_csi(brix_ctx_t *ctx, ngx_connection_t *c, int dst_idx,
    off_t dst_off, size_t copy_len)
{
    enum { CLONE_FOLD_WIN = 1 << 20 };
    u_char *buf;
    off_t   offset;
    size_t  left;

    if (ctx->files[dst_idx].csi == NULL) {
        return;
    }
    buf = ngx_alloc(CLONE_FOLD_WIN, c->log);
    if (buf == NULL) {
        return;
    }
    offset = dst_off;
    left = copy_len;
    while (left > 0) {
        size_t  chunk = left < CLONE_FOLD_WIN ? left : CLONE_FOLD_WIN;
        ssize_t n = pread(ctx->files[dst_idx].fd, buf, chunk, offset);

        if (n <= 0) {
            break;
        }
        (void) brix_csi_write_update(
            (brix_csi_t *) ctx->files[dst_idx].csi, buf, offset, (size_t) n);
        offset += n;
        left -= (size_t) n;
    }
    ngx_free(buf);
}


/*
 * WHAT: Validate and execute one decoded clone range.
 * WHY: Give each source handle/range an independent fail-fast boundary.
 * HOW: Validate read access, decode bounded offsets, copy through the shared
 *      range helper, update CSI and accounting, then return bytes copied.
 */
static ngx_int_t
brix_clone_one(brix_ctx_t *ctx, ngx_connection_t *c, int dst_idx,
    const clone_item *item, uint64_t *copied)
{
    brix_clone_span_t span;
    ngx_int_t         rc;

    span.src_idx = (int) (unsigned char) item->src_fhandle[0];
    if (!brix_validate_read_handle(ctx, c, span.src_idx, "CLONE",
                                   BRIX_OP_CLONE, &rc))
    {
        return rc;
    }
    if (brix_clone_decode(item, &span) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CLONE, "CLONE",
                        ctx->files[span.src_idx].path,
                        ctx->files[dst_idx].path, kXR_ArgInvalid,
                        "clone offset/length out of range");
    }
    if (span.len == 0) {
        *copied = 0;
        return NGX_OK;
    }
    if (brix_copy_range(c->log, ctx->files[span.src_idx].fd, span.src_off,
                        ctx->files[dst_idx].fd, span.dst_off, span.len,
                        ctx->files[span.src_idx].path,
                        ctx->files[dst_idx].path) != NGX_OK)
    {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CLONE, "CLONE",
                        ctx->files[span.src_idx].path,
                        ctx->files[dst_idx].path, kXR_IOError,
                        "clone copy failed");
    }
    brix_clone_fold_csi(ctx, c, dst_idx, span.dst_off, span.len);
    ctx->files[dst_idx].bytes_written += span.len;
    ctx->totals.bytes += span.len;
    *copied = span.len;
    return NGX_OK;
}


ngx_int_t
brix_handle_clone(brix_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_clone_req_t    req;
    int                 dst_idx;
    const u_char       *p;
    const u_char       *end;
    uint32_t            n_items;
    ngx_int_t           rc;
    uint64_t            total_bytes = 0;

    xrdw_clone_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    dst_idx = (int)(unsigned char) req.dst_fhandle[0];

    if (!brix_validate_write_handle(ctx, c, dst_idx, "CLONE",
                                      BRIX_OP_CLONE, &rc)) {
        return rc;
    }

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgMissing, "clone list is missing");
    }

    if (ctx->recv.cur_dlen % CLONE_ITEM_LEN != 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgInvalid, "malformed clone list");
    }

    n_items = ctx->recv.cur_dlen / CLONE_ITEM_LEN;
    if (n_items > CLONE_MAX_ITEMS) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CLONE, "CLONE",
                          ctx->files[dst_idx].path, "-",
                          kXR_ArgTooLong, "too many clone items");
    }

    p   = ctx->recv.payload;
    end = ctx->recv.payload + ctx->recv.cur_dlen;

    while (p < end) {
        const clone_item *item = (const clone_item *) p;
        uint64_t          copied = 0;

        rc = brix_clone_one(ctx, c, dst_idx, item, &copied);
        if (rc != NGX_OK) {
            return rc;
        }
        total_bytes += copied;

        p += CLONE_ITEM_LEN;
    }

    BRIX_RETURN_OK(ctx, c, BRIX_OP_CLONE, "CLONE",
                     ctx->files[dst_idx].path, "-", (size_t) total_bytes);
}
