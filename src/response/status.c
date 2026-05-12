#include "ngx_xrootd_module.h"

/*
 * Paged read/write kXR_status responses.
 */

ngx_int_t
xrootd_send_pgwrite_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int64_t write_offset)
{
    ServerStatusResponse_pgWrite *rsp;
    size_t                        crc_len;
    uint32_t                      crc;

    crc_len = sizeof(rsp->bdy) - sizeof(rsp->bdy.crc32c) + sizeof(rsp->pgw);

    rsp = ngx_palloc(c->pool, sizeof(*rsp));
    if (rsp == NULL) {
        return NGX_ERROR;
    }

    rsp->hdr.streamid[0] = ctx->cur_streamid[0];
    rsp->hdr.streamid[1] = ctx->cur_streamid[1];
    rsp->hdr.status = htons(kXR_status);
    rsp->hdr.dlen = htonl((uint32_t) (sizeof(rsp->bdy) + sizeof(rsp->pgw)));

    rsp->bdy.streamID[0] = ctx->cur_streamid[0];
    rsp->bdy.streamID[1] = ctx->cur_streamid[1];
    rsp->bdy.requestid = (kXR_char) (kXR_pgwrite - kXR_1stRequest);
    rsp->bdy.resptype = 0;
    ngx_memzero(rsp->bdy.reserved, sizeof(rsp->bdy.reserved));
    rsp->bdy.dlen = htonl(0);

    rsp->pgw.offset = (kXR_int64) htobe64((uint64_t) write_offset);

    crc = xrootd_crc32c(&rsp->bdy.streamID[0], crc_len);
    rsp->bdy.crc32c = htonl(crc);

    return xrootd_queue_response(ctx, c, (u_char *) rsp, sizeof(*rsp));
}


void
xrootd_build_pgread_status(xrootd_ctx_t *ctx, int64_t file_offset,
    uint32_t total_with_crcs, ServerStatusResponse_pgRead *out)
{
    size_t    crc_len;
    uint32_t  crc;

    crc_len = sizeof(out->bdy) - sizeof(out->bdy.crc32c) + sizeof(out->pgr);

    out->hdr.streamid[0] = ctx->cur_streamid[0];
    out->hdr.streamid[1] = ctx->cur_streamid[1];
    out->hdr.status = htons(kXR_status);
    out->hdr.dlen = htonl((uint32_t) (sizeof(out->bdy) + sizeof(out->pgr)
                                      + total_with_crcs));

    out->bdy.streamID[0] = ctx->cur_streamid[0];
    out->bdy.streamID[1] = ctx->cur_streamid[1];
    out->bdy.requestid = (kXR_char) (kXR_pgread - kXR_1stRequest);
    out->bdy.resptype = 0;
    ngx_memzero(out->bdy.reserved, sizeof(out->bdy.reserved));
    out->bdy.dlen = htonl(total_with_crcs);

    out->pgr.offset = (kXR_int64) htobe64((uint64_t) file_offset);

    crc = xrootd_crc32c(&out->bdy.streamID[0], crc_len);
    out->bdy.crc32c = htonl(crc);
}
