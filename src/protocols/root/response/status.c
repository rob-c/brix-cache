#include "core/ngx_brix_module.h"
#include "core/compat/alloc_guard.h"
#include "core/compat/pgio.h"   /* xrdp_pg_bad_t — CSE bad-page descriptor */

/*
 *
 * WHAT: Sends kXR_status (opcode 4007) response for paged write (kXR_pgwrite, opcode 4016) completion. Allocates ServerStatusResponse_pgWrite structure from connection pool via ngx_palloc(). Sets header fields: streamid from ctx->recv.cur_streamid, status=kXR_status in network byte order via htons(), dlen includes body + pgWrite portion size. Body fields: streamID copied from ctx, requestid = kXR_pgwrite - kXR_1stRequest (offset encoding), resptype=0, reserved zeroed via ngx_memzero(). pgWrite portion contains write_offset as big-endian int64 via htobe64(). Calculates CRC32c checksum over body bytes excluding crc32c field itself using brix_crc32c() helper — stores result in network byte order via htonl(). Queues response for wire delivery via brix_queue_response() with total size including pgWrite portion. Per AGENTS.md INVARIANT #1: kXR_pgwrite requires kXR_status(4007) framing + per-page CRC32c — this function implements that invariant.
 *
 * WHY: Paged write completion must include offset position and integrity checksum to allow client verification of data delivery — CRC32c ensures the response body was not corrupted during transmission or processing. The kXR_status framing distinguishes pgwrite status from regular opcode responses, enabling clients to parse multi-page write completions correctly. streamid consistency between header and body prevents cross-stream confusion when multiple concurrent writes are active. Thread safety: operates only on local stack variables (rsp) and provided ctx/c connection; no shared state modification during response construction. */

/*
 *
 * WHAT: Builds ServerStatusResponse_pgRead structure for paged read (kXR_pgread, opcode 4015) completion without immediate queueing. Sets header fields: streamid from ctx->recv.cur_streamid, status=kXR_status in network byte order via htons(), dlen includes body + pgRead portion + total_with_crcs (accumulated CRC32c sizes across all pages). Body fields: streamID copied from ctx, requestid = kXR_pgread - kXR_1stRequest (offset encoding), resptype=0, reserved zeroed via ngx_memzero(), dlen set to total_with_crcs value. pgRead portion contains file_offset as big-endian int64 via htobe64(). Calculates CRC32c checksum over body bytes excluding crc32c field itself using brix_crc32c() helper — stores result in network byte order via htonl(). Caller must queue response separately after calling this function (unlike pgwrite which queues immediately). Per AGENTS.md INVARIANT #1: kXR_pgread requires kXR_status(4007) framing + per-page CRC32c — this function implements that invariant.
 *
 * WHY: Paged read completion must include offset position and integrity checksum to allow client verification of data delivery across multiple pages — CRC32c ensures each page's status response was not corrupted during transmission or processing. The kXR_status framing distinguishes pgread status from regular opcode responses, enabling clients to parse multi-page read completions correctly. total_with_crcs accumulates all CRC32c field sizes across pages for accurate dlen calculation — critical when multiple pages are delivered sequentially. Thread safety: operates only on local stack variables and provided ctx/out structure; no shared state modification during response construction. */

ngx_int_t
brix_send_pgwrite_status(brix_ctx_t *ctx, ngx_connection_t *c,
    int64_t write_offset)
{
    ServerStatusResponse_pgWrite *rsp;
    size_t                        crc_len;
    uint32_t                      crc;

    crc_len = sizeof(rsp->bdy) - sizeof(rsp->bdy.crc32c) + sizeof(rsp->pgw);

    BRIX_PALLOC_OR_RETURN(rsp, c->pool, sizeof(*rsp), NGX_ERROR);

    rsp->hdr.streamid[0] = ctx->recv.cur_streamid[0];
    rsp->hdr.streamid[1] = ctx->recv.cur_streamid[1];
    rsp->hdr.status = htons(kXR_status);
    rsp->hdr.dlen = htonl((uint32_t) (sizeof(rsp->bdy) + sizeof(rsp->pgw)));

    rsp->bdy.streamID[0] = ctx->recv.cur_streamid[0];
    rsp->bdy.streamID[1] = ctx->recv.cur_streamid[1];
    rsp->bdy.requestid = (kXR_char) (kXR_pgwrite - kXR_1stRequest);
    rsp->bdy.resptype = kXR_FinalResult;
    ngx_memzero(rsp->bdy.reserved, sizeof(rsp->bdy.reserved));
    rsp->bdy.dlen = htonl(0);

    rsp->pgw.offset = (kXR_int64) htobe64((uint64_t) write_offset);

    crc = brix_crc32c(&rsp->bdy.streamID[0], crc_len);
    rsp->bdy.crc32c = htonl(crc);

    return brix_queue_response(ctx, c, (u_char *) rsp, sizeof(*rsp));
}

/*
 * pgwrite checksum-error (CSE) retransmit frame.
 *
 * WHAT: Sends the "accept-then-correct" kXR_status reply when one or more pages
 *       failed CRC32c verification. Unlike brix_send_pgwrite_status (the
 *       no-error 32-byte frame), this appends a ServerResponseBody_pgWrCSE
 *       trailer plus a big-endian vector of the corrupt pages' file offsets, so
 *       the client knows exactly which pages to resend with kXR_pgRetry. The
 *       status is SUCCESS (kXR_status / kXR_FinalResult), not kXR_error — the
 *       data has already been written; the client must correct it.
 *
 * WHY: Stock XRootD (XrdXrootdPgwBadCS::boInfo) reports checksum failures via
 *      this in-band list rather than a hard error so a single corrupt page does
 *      not abort a multi-GB transfer. The two CRC32c covers (body crc32c over
 *      streamID..end, cseCRC over dlFirst..bof end) let the client validate the
 *      frame and the list independently.
 *
 * HOW: One pool buffer holds [hdr|bdy|pgw|cse|bof[n]]. bdy.dlen = sizeof(cse) +
 *      n*8 (the trailer the client reads after the 32-byte head); hdr.dlen adds
 *      the same to the base 24. dlFirst/dlLast carry the first/last bad pages'
 *      fragment lengths (short for unaligned first/last pages). Falls back to
 *      brix_send_pgwrite_status when n == 0. */
ngx_int_t
brix_send_pgwrite_cse(brix_ctx_t *ctx, ngx_connection_t *c,
    int64_t write_offset, const xrdp_pg_bad_t *bad, size_t n)
{
    ServerStatusResponse_pgWrite *rsp;
    ServerResponseBody_pgWrCSE   *cse;
    kXR_int64                    *bof;
    u_char   *buf;
    size_t    cse_len, total, body_crc_len, cse_crc_len, i;
    uint32_t  crc;

    if (n == 0 || bad == NULL) {
        return brix_send_pgwrite_status(ctx, c, write_offset);
    }

    cse_len = sizeof(*cse) + n * sizeof(kXR_int64);
    total   = sizeof(*rsp) + cse_len;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    rsp = (ServerStatusResponse_pgWrite *) buf;
    cse = (ServerResponseBody_pgWrCSE *) (buf + sizeof(*rsp));
    bof = (kXR_int64 *) (buf + sizeof(*rsp) + sizeof(*cse));

    /* Stock srsComplete convention: hdr.dlen counts ONLY the fixed status body
     * (bdy + pgw offset = 24).  The CSE trailer follows as separate `data` whose
     * length is advertised in bdy.dlen — exactly like pgread page data — and
     * carries its own cseCRC.  The body crc32c therefore covers only the 20-byte
     * fixed head, never the variable trailer. */
    rsp->hdr.streamid[0] = ctx->recv.cur_streamid[0];
    rsp->hdr.streamid[1] = ctx->recv.cur_streamid[1];
    rsp->hdr.status = htons(kXR_status);
    rsp->hdr.dlen   = htonl((uint32_t) (sizeof(rsp->bdy) + sizeof(rsp->pgw)));

    rsp->bdy.streamID[0] = ctx->recv.cur_streamid[0];
    rsp->bdy.streamID[1] = ctx->recv.cur_streamid[1];
    rsp->bdy.requestid = (kXR_char) (kXR_pgwrite - kXR_1stRequest);
    rsp->bdy.resptype  = kXR_FinalResult;
    ngx_memzero(rsp->bdy.reserved, sizeof(rsp->bdy.reserved));
    rsp->bdy.dlen = htonl((uint32_t) cse_len);

    rsp->pgw.offset = (kXR_int64) htobe64((uint64_t) write_offset);

    cse->dlFirst = (kXR_int16) htons((uint16_t) bad[0].dlen);
    cse->dlLast  = (kXR_int16) htons((uint16_t) bad[n - 1].dlen);
    for (i = 0; i < n; i++) {
        bof[i] = (kXR_int64) htobe64((uint64_t) bad[i].off);
    }

    /* cseCRC covers everything after itself: dlFirst..end of bof[]. */
    cse_crc_len = cse_len - sizeof(cse->cseCRC);
    cse->cseCRC = htonl(brix_crc32c((u_char *) cse + sizeof(cse->cseCRC),
                                      cse_crc_len));

    /* body crc32c covers the 20-byte fixed head only (streamID..pgw.offset). */
    body_crc_len = sizeof(rsp->bdy) - sizeof(rsp->bdy.crc32c) + sizeof(rsp->pgw);
    crc = brix_crc32c(&rsp->bdy.streamID[0], body_crc_len);
    rsp->bdy.crc32c = htonl(crc);

    return brix_queue_response(ctx, c, buf, total);
}

void
brix_build_pgread_status(brix_ctx_t *ctx, int64_t file_offset,
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

    out->hdr.streamid[0] = ctx->recv.cur_streamid[0];
    out->hdr.streamid[1] = ctx->recv.cur_streamid[1];
    out->hdr.status = htons(kXR_status);
    out->hdr.dlen = htonl((uint32_t) (sizeof(out->bdy) + sizeof(out->pgr)));

    out->bdy.streamID[0] = ctx->recv.cur_streamid[0];
    out->bdy.streamID[1] = ctx->recv.cur_streamid[1];
    out->bdy.requestid = (kXR_char) (kXR_pgread - kXR_1stRequest);
    out->bdy.resptype = kXR_FinalResult;
    ngx_memzero(out->bdy.reserved, sizeof(out->bdy.reserved));
    out->bdy.dlen = htonl(total_with_crcs);

    out->pgr.offset = (kXR_int64) htobe64((uint64_t) file_offset);

    crc = brix_crc32c(&out->bdy.streamID[0], hdr_crc_len);
    out->bdy.crc32c = htonl(crc);
}
