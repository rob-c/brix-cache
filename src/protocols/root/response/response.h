#ifndef XROOTD_RESPONSE_H
#define XROOTD_RESPONSE_H

#include "core/ngx_xrootd_module.h"
#include "core/compat/pgio.h"   /* xrdp_pg_bad_t */

/* Fill an 8-byte ServerResponseHdr in-place (all fields big-endian). */
void xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out);

/* Send kXR_ok (status=0) with an optional body blob. */
ngx_int_t xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);

/* Send kXR_error (status=kXR_error) with errcode + human message. */
ngx_int_t xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg);

/* Send kXR_redirect (status=kXR_redirect) with a host:port target. */
ngx_int_t xrootd_send_redirect(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port);

/* Send kXR_redirect with an appended ?tpc.key=<key> opaque qualifier. */
ngx_int_t xrootd_send_redirect_tpc(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port, const char *tpc_key);

/* Send kXR_wait — ask client to retry after <seconds>. */
ngx_int_t xrootd_send_wait(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint32_t seconds);

/* Send kXR_waitresp — ask client to wait for an async completion. */
ngx_int_t xrootd_send_waitresp(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Send kXR_status body for a completed pgwrite chunk. */
ngx_int_t xrootd_send_pgwrite_status(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int64_t write_offset);

/* Send a pgwrite SUCCESS kXR_status frame carrying a CSE (checksum-error)
 * retransmit list: bad[0..n) are the corrupt pages the client must resend with
 * kXR_pgRetry. Falls back to xrootd_send_pgwrite_status when n == 0. */
ngx_int_t xrootd_send_pgwrite_cse(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int64_t write_offset, const xrdp_pg_bad_t *bad, size_t n);

/* Build the kXR_status body for a pgread response.
 * hdr.dlen = sizeof(bdy)+sizeof(pgr) = 24; bdy.dlen = total_with_crcs.
 * CRC covers bdy.streamID..pgr.offset (20 bytes), not the page data. */
void xrootd_build_pgread_status(xrootd_ctx_t *ctx, int64_t file_offset,
    uint32_t total_with_crcs, ServerStatusResponse_pgRead *out);

/* CRC32c checksum (software table implementation). */
uint32_t xrootd_crc32c(const void *buf, size_t len);

/* Extend a running CRC32c checksum with additional data. */
uint32_t xrootd_crc32c_extend(uint32_t crc, const void *buf, size_t len);

/* Fused CRC32c + copy: copies src→dst in one pass, returns CRC of the data. */
uint32_t xrootd_crc32c_copy(const u_char *src, u_char *dst, size_t len);

/* CRC32c of an open file descriptor; returns (uint32_t)-1 on read error. */
uint32_t xrootd_crc32c_file(int fd, const char *path, ngx_log_t *log);

#endif /* XROOTD_RESPONSE_H */
