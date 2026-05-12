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
 */

#include "clone.h"
#include "../connection/fd_table.h"

#include <errno.h>
#include <unistd.h>

#define CLONE_ITEM_LEN   32u      /* sizeof(clone_item) */
#define CLONE_MAX_ITEMS  1024u    /* maxClonesz from XProtocol.hh */
#define CLONE_COPY_BUF   (256 * 1024)  /* fallback pread/pwrite chunk */


static ngx_int_t
clone_copy_range(ngx_connection_t *c, int src_fd, off_t src_off,
    int dst_fd, off_t dst_off, size_t len,
    const char *src_path, const char *dst_path)
{
#if defined(__linux__) && defined(__NR_copy_file_range)
    /* Attempt kernel-side copy — zero user-space buffering. */
    while (len > 0) {
        loff_t  si = src_off;
        loff_t  di = dst_off;
        ssize_t n  = syscall(__NR_copy_file_range,
                             src_fd, &si, dst_fd, &di, len, 0u);
        if (n < 0) {
            if (errno == EXDEV || errno == ENOSYS || errno == EOPNOTSUPP) {
                goto fallback;
            }
            ngx_log_error(NGX_LOG_ERR, c->log, errno,
                          "xrootd: clone copy_file_range failed %s->%s",
                          src_path, dst_path);
            return NGX_ERROR;
        }
        if (n == 0) {
            break;  /* src EOF */
        }
        src_off += n;
        dst_off += n;
        len     -= (size_t) n;
    }
    return NGX_OK;

fallback:
#endif
    {
        u_char  buf[CLONE_COPY_BUF];
        while (len > 0) {
            size_t  want = (len < CLONE_COPY_BUF) ? len : CLONE_COPY_BUF;
            ssize_t nr   = pread(src_fd, buf, want, src_off);
            ssize_t nw;

            if (nr < 0) {
                ngx_log_error(NGX_LOG_ERR, c->log, errno,
                              "xrootd: clone pread failed %s", src_path);
                return NGX_ERROR;
            }
            if (nr == 0) {
                break;  /* src EOF */
            }

            nw = pwrite(dst_fd, buf, (size_t) nr, dst_off);
            if (nw != nr) {
                ngx_log_error(NGX_LOG_ERR, c->log, errno,
                              "xrootd: clone pwrite failed %s", dst_path);
                return NGX_ERROR;
            }

            src_off += nr;
            dst_off += nw;
            len     -= (size_t) nr;
        }
    }
    return NGX_OK;
}


ngx_int_t
xrootd_handle_clone(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientCloneRequest *req = (ClientCloneRequest *) ctx->hdr_buf;
    int                 dst_idx;
    int                 dst_fd;
    const u_char       *p;
    const u_char       *end;
    uint32_t            n_items;
    ngx_int_t           rc;
    uint64_t            total_bytes = 0;

    dst_idx = (int)(unsigned char) req->dst_fhandle[0];

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

        if (clone_copy_range(c, ctx->files[src_idx].fd, src_off,
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
