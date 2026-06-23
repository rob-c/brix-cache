#include "ngx_xrootd_module.h"
#include "../compat/alloc_guard.h"

/* ---- Function: xrootd_send_pgwrite_status() — send pgwrite completion status with CRC32c ----
 *
 * WHAT: Sends kXR_status (opcode 4007) response for paged write (kXR_pgwrite, opcode 4016) completion. Allocates ServerStatusResponse_pgWrite structure from connection pool via ngx_palloc(). Sets header fields: streamid from ctx->cur_streamid, status=kXR_status in network byte order via htons(), dlen includes body + pgWrite portion size. Body fields: streamID copied from ctx, requestid = kXR_pgwrite - kXR_1stRequest (offset encoding), resptype=0, reserved zeroed via ngx_memzero(). pgWrite portion contains write_offset as big-endian int64 via htobe64(). Calculates CRC32c checksum over body bytes excluding crc32c field itself using xrootd_crc32c() helper — stores result in network byte order via htonl(). Queues response for wire delivery via xrootd_queue_response() with total size including pgWrite portion. Per AGENTS.md INVARIANT #1: kXR_pgwrite requires kXR_status(4007) framing + per-page CRC32c — this function implements that invariant.
 *
 * WHY: Paged write completion must include offset position and integrity checksum to allow client verification of data delivery — CRC32c ensures the response body was not corrupted during transmission or processing. The kXR_status framing distinguishes pgwrite status from regular opcode responses, enabling clients to parse multi-page write completions correctly. streamid consistency between header and body prevents cross-stream confusion when multiple concurrent writes are active. Thread safety: operates only on local stack variables (rsp) and provided ctx/c connection; no shared state modification during response construction. */

/* ---- Function: xrootd_build_pgread_status() — build pgread status response structure ----
 *
 * WHAT: Builds ServerStatusResponse_pgRead structure for paged read (kXR_pgread, opcode 4015) completion without immediate queueing. Sets header fields: streamid from ctx->cur_streamid, status=kXR_status in network byte order via htons(), dlen includes body + pgRead portion + total_with_crcs (accumulated CRC32c sizes across all pages). Body fields: streamID copied from ctx, requestid = kXR_pgread - kXR_1stRequest (offset encoding), resptype=0, reserved zeroed via ngx_memzero(), dlen set to total_with_crcs value. pgRead portion contains file_offset as big-endian int64 via htobe64(). Calculates CRC32c checksum over body bytes excluding crc32c field itself using xrootd_crc32c() helper — stores result in network byte order via htonl(). Caller must queue response separately after calling this function (unlike pgwrite which queues immediately). Per AGENTS.md INVARIANT #1: kXR_pgread requires kXR_status(4007) framing + per-page CRC32c — this function implements that invariant.
 *
 * WHY: Paged read completion must include offset position and integrity checksum to allow client verification of data delivery across multiple pages — CRC32c ensures each page's status response was not corrupted during transmission or processing. The kXR_status framing distinguishes pgread status from regular opcode responses, enabling clients to parse multi-page read completions correctly. total_with_crcs accumulates all CRC32c field sizes across pages for accurate dlen calculation — critical when multiple pages are delivered sequentially. Thread safety: operates only on local stack variables and provided ctx/out structure; no shared state modification during response construction. */

ngx_int_t
xrootd_send_pgwrite_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int64_t write_offset)
{
    ServerStatusResponse_pgWrite *rsp;
    size_t                        crc_len;
    uint32_t                      crc;

    crc_len = sizeof(rsp->bdy) - sizeof(rsp->bdy.crc32c) + sizeof(rsp->pgw);

    XROOTD_PALLOC_OR_RETURN(rsp, c->pool, sizeof(*rsp), NGX_ERROR);

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
    size_t    hdr_crc_len;
    uint32_t  crc;

    /*
     * Wire format (XRootD kXR_status for pgread):
     *   hdr.dlen  = sizeof(bdy) + sizeof(pgr)   [24 bytes — does NOT include page data]
     *   bdy.dlen  = total_with_crcs              [the page data size the client reads next]
     *
     * Client reads: first (8 + hdr.dlen = 32) bytes as the status header, then
     * reads bdy.dlen more bytes for the actual page data.  This matches the
     * XRootD server srsComplete() implementation in XrdXrootdResponse.cc.
     *
     * CRC covers bdy.streamID through pgr.offset (20 bytes) — no data extension.
     * Client validates: Calc32C(msg+12, hdr.dlen-4) = Calc32C(bdy.streamID, 20).
     */
    hdr_crc_len = sizeof(out->bdy) - sizeof(out->bdy.crc32c) + sizeof(out->pgr);

    out->hdr.streamid[0] = ctx->cur_streamid[0];
    out->hdr.streamid[1] = ctx->cur_streamid[1];
    out->hdr.status = htons(kXR_status);
    out->hdr.dlen = htonl((uint32_t) (sizeof(out->bdy) + sizeof(out->pgr)));

    out->bdy.streamID[0] = ctx->cur_streamid[0];
    out->bdy.streamID[1] = ctx->cur_streamid[1];
    out->bdy.requestid = (kXR_char) (kXR_pgread - kXR_1stRequest);
    out->bdy.resptype = 0;
    ngx_memzero(out->bdy.reserved, sizeof(out->bdy.reserved));
    out->bdy.dlen = htonl(total_with_crcs);

    out->pgr.offset = (kXR_int64) htobe64((uint64_t) file_offset);

    crc = xrootd_crc32c(&out->bdy.streamID[0], hdr_crc_len);
    out->bdy.crc32c = htonl(crc);
}
