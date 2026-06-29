#include "cache_internal.h"
#include "../protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */


#if defined(__linux__)
#include <endian.h>
#endif
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* xrootd_cache_origin_bootstrap — three-phase XRootD connection bootstrap on a
 * raw TCP/TLS socket: ClientInitHandShake → kXR_protocol negotiation (a
 * kXR_gotoTLS flag triggers a TLS upgrade when configured) → anonymous kXR_login
 * (user 'xrd', capver kXR_ver005, streamid[1]=1). Every cache fill needs a valid
 * session before reading. Returns 0 on success, -1 on any phase failure. */
int
xrootd_cache_origin_bootstrap(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc)
{
    ClientInitHandShake    hs;
    ClientProtocolRequest  pr;
    ClientLoginRequest     lr;
    uint16_t               status;
    uint32_t               dlen;
    u_char                *body;
    static const uint8_t   sid[2] = { 0, 1 };   /* cache-origin connector streamid */

    xrd_pack_handshake(&hs);

    if (xrootd_cache_io_send(oc, &hs, sizeof(hs)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin handshake write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 64) != 0) {
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin handshake failed");
        return -1;
    }

    xrd_pack_protocol_request(&pr, sid, 0);

    if (xrootd_cache_io_send(oc, &pr, sizeof(pr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin protocol write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   sizeof(ServerProtocolBody)) != 0) {
        return -1;
    }

    if (status != kXR_ok) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin protocol negotiation failed");
        return -1;
    }

    if (dlen >= sizeof(ServerProtocolBody)) {
        ServerProtocolBody *pb;
        uint32_t            flags;

        pb = (ServerProtocolBody *) body;
        flags = (uint32_t) ntohl(pb->flags);

        if ((flags & kXR_gotoTLS) && !t->conf->cache_origin_tls) {
            free(body);
            xrootd_cache_set_error(t, kXR_TLSRequired, 0,
                "cache origin requires TLS; enable xrootd_cache_origin_tls");
            return -1;
        }
    }
    free(body);

    xrd_pack_login_request(&lr, sid, (int32_t) ngx_pid, "xrd", kXR_ver005);

    if (xrootd_cache_io_send(oc, &lr, sizeof(lr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin login write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    free(body);

    if (status == kXR_authmore) {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin requires authentication");
        return -1;
    }
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin anonymous login failed");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_open — kXR_open (read + kXR_retstat) of the source file:
 * parse ServerOpenBody for the fhandle and the appended stat string, so file_size
 * is known before a full download (the admission filter can reject oversized files
 * without fetching them). Returns 0 with fhandle set, -1 on error or redirect. */
int
xrootd_cache_origin_open(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /* kXR_retstat requests an ASCII stat string appended after the fhandle so we
     * can learn the file size before committing to a full download */
    {
        xrdw_open_req_t b = { .options = kXR_open_read | kXR_retstat };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   XROOTD_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        xrootd_cache_set_error(t, kXR_Unsupported, 0,
                               "cache origin redirected open; direct data "
                               "server origin is required");
        return -1;
    }
    if (status != kXR_ok || dlen < sizeof(ServerOpenBody)) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin open returned invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);

    /*
     * If kXR_retstat was honored the stat string follows ServerOpenBody.
     * Format: "<id> <size> <flags> <modtime>" — we only need the size (field 2).
     * The body is always NUL-terminated by xrootd_cache_read_response, so
     * strtoull is safe.
     */
    if (dlen > sizeof(ServerOpenBody)) {
        const char     *stat_str = (const char *) body + sizeof(ServerOpenBody);
        const char     *p;

        p = strchr(stat_str, ' ');
        if (p != NULL) {
            char              *endp;
            unsigned long long  sv;

            errno = 0;
            sv = strtoull(p + 1, &endp, 10);
            if (errno == 0 && endp != p + 1) {
                t->file_size = (off_t) sv;
            }
        }
    }

    free(body);
    return 0;
}

/* xrootd_cache_origin_query_checksum — ask the origin for its stored digest of
 * t->clean_path (path-based kXR_query/kXR_Qcksum), returning "<algo> <hex>" split
 * into the caller buffers. Checksum-on-fill (verify.c) validates downloaded bytes
 * against this before publishing. BEST-EFFORT: an origin with no checksum or a
 * wire hiccup must NOT fail an otherwise-complete fill (data is already on disk) —
 * on ANY failure it restores t's error state and returns 0 with alg_out emptied,
 * so the caller treats it as "no origin digest" and the verify policy decides. */
int
xrootd_cache_origin_query_checksum(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz)
{
    size_t              pathlen, total;
    u_char             *buf;
    ClientQueryRequest *req;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *body;
    char               *sp;
    int                 saved_result, saved_xrd;

    if (alg_sz > 0) {
        alg_out[0] = '\0';
    }
    if (hex_sz > 0) {
        hex_out[0] = '\0';
    }

    /* The download already succeeded; never let a checksum-query failure leak an
     * error onto the task. Snapshot and restore the error triple. */
    saved_result = t->result;
    saved_xrd    = t->xrd_error;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientQueryRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        return 0;       /* best-effort: skip verification on OOM */
    }

    ngx_memzero(buf, total);
    req = (ClientQueryRequest *) buf;
    req->streamid[1] = 6;                       /* unused stream slot */
    req->requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = kXR_Qcksum };  /* fhandle 0 ⇒ path-based */
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return 0;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 512) != 0) {
        t->result    = saved_result;
        t->xrd_error = saved_xrd;
        return 0;
    }

    if (status != kXR_ok || body == NULL || dlen == 0) {
        free(body);                             /* origin has no checksum */
        return 0;
    }

    /* body is NUL-terminated "<algo> <hexvalue>". */
    sp = strchr((char *) body, ' ');
    if (sp != NULL) {
        size_t  an = (size_t) (sp - (char *) body);
        char   *hv = sp + 1;
        char   *end = hv + strlen(hv);
        size_t  hn;

        while (end > hv && (end[-1] == '\n' || end[-1] == '\r'
                            || end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        hn = (size_t) (end - hv);

        if (an > 0 && an < alg_sz && hn > 0 && hn < hex_sz) {
            ngx_memcpy(alg_out, body, an);
            alg_out[an] = '\0';
            ngx_memcpy(hex_out, hv, hn);
            hex_out[hn] = '\0';
        }
    }

    free(body);
    return 0;
}

/* xrootd_cache_origin_open_write — kXR_open (update + delete + mkpath) to mirror a
 * local file onto the origin: truncate the destination and create missing parent
 * dirs (where supported) for an atomic write-through replacement. Returns 0 with
 * fhandle set, -1 on error or redirect. */
int
xrootd_cache_origin_open_write(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (path == NULL || path[0] == '\0') {
        xrootd_cache_set_error(t, kXR_ArgInvalid, 0,
                               "write-through origin path missing");
        return -1;
    }

    pathlen = strlen(path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "write-through origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /*
     * Replace the origin copy atomically from the write-through point of view:
     * open for update, create missing parents if the origin supports mkpath,
     * and truncate the destination before streaming the local contents.
     */
    {
        xrdw_open_req_t b = {
            .mode = (uint16_t) (mode_bits != 0 ? mode_bits : 0644),
            .options = kXR_open_updt | kXR_delete | kXR_mkpath
        };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   XROOTD_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        xrootd_cache_set_error(t, kXR_Unsupported, 0,
                               "write-through origin redirected open; direct "
                               "data server origin is required");
        return -1;
    }
    /* A kXR_open reply is a bare 4-byte fhandle; the cpsize/cptype trailer of
     * ServerOpenBody (12 bytes) only follows when kXR_compress or kXR_retstat was
     * requested — and the write-through open requests neither.  Require only the
     * fhandle (XRD_FHANDLE_LEN), not the full struct, or a conformant origin's
     * minimal 4-byte response is wrongly rejected (which aborted the flush and
     * left the origin file half-written). The cache never uses cpsize/cptype. */
    if (status != kXR_ok || dlen < XRD_FHANDLE_LEN) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin open invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);
    free(body);
    return 0;
}

/* xrootd_cache_origin_close_file — send kXR_close for the fhandle and discard the
 * reply (close status only matters for errors, which don't invalidate data already
 * written to disk). Every opened file must be closed before reconnect/finish. */
void
xrootd_cache_origin_close_file(xrootd_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientCloseRequest req;
    uint16_t           rsp_status;
    uint32_t           dlen;
    u_char            *body;
    xrootd_cache_fill_t dummy;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 2;
    req.requestid = htons(kXR_close);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    (void) xrootd_cache_io_send(oc, &req, sizeof(req));

    ngx_memzero(&dummy, sizeof(dummy));
    dummy.result = NGX_OK;
    body = NULL;
    if (xrootd_cache_read_response(&dummy, oc, &rsp_status, &body, &dlen,
                                   4096) == 0) {
        free(body);
    }
}

/* xrootd_cache_origin_write_chunk — kXR_write a payload at a big-endian 64-bit
 * offset (htobe64, XRootD wire format); the reply must be kXR_ok with dlen=0.
 * Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_write_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len)
{
    ClientWriteRequest req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (len > INT32_MAX) {
        xrootd_cache_set_error(t, kXR_ArgTooLong, 0,
                               "write-through origin write too large");
        return -1;
    }

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_write);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(offset);
    req.dlen = htonl((kXR_int32) len);

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0
        || (len > 0 && xrootd_cache_io_send(oc, data, len) != 0))
    {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin write rejected");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok || dlen != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin write invalid response");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_truncate — kXR_truncate the origin file to a big-endian
 * 64-bit offset (used before write_chunk when the destination is larger than the
 * source); the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_truncate(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t length)
{
    ClientTruncateRequest req;
    uint16_t              status;
    uint32_t              dlen;
    u_char               *body;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 4;
    req.requestid = htons(kXR_truncate);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(length);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin truncate send failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin truncate failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin truncate invalid response");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_sync — kXR_sync the origin file (fsync equivalent) after
 * streaming all chunks, so the mirrored content survives an origin crash before
 * close; the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_sync(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientSyncRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 5;
    req.requestid = htons(kXR_sync);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin sync send failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin sync failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin sync invalid response");
        return -1;
    }

    return 0;
}

/* Positional write into a fill sink: a driver staged-write handle (driver-backed
 * cache) or a raw POSIX fd. Keeps the origin read loop backend-agnostic. */
int
xrootd_cache_sink_pwrite(xrootd_cache_sink_t *sink, const void *buf, size_t len,
    off_t off)
{
    if (sink->mem != NULL) {
        /* In-memory sink: a positional copy into the caller's buffer, bounds-
         * checked against mem_cap. Used by the root:// remote driver's pread. */
        if (off < 0 || (size_t) off + len > sink->mem_cap) {
            errno = EINVAL;
            return -1;
        }
        ngx_memcpy(sink->mem + off, buf, len);
        return 0;
    }
    if (sink->staged != NULL) {
        ssize_t n = sink->staged->inst->driver->staged_write(sink->staged, buf,
                                                             len, off);
        return (n == (ssize_t) len) ? 0 : -1;
    }
    return xrootd_cache_fd_write_all(sink->fd, buf, len, off);
}

/* xrootd_cache_origin_read_chunk — kXR_read at (offset, rlen), writing each reply
 * payload to the sink via xrootd_cache_sink_pwrite and looping over kXR_oksofar
 * until the final kXR_ok. dlen is bounded (<= want, accumulated *got within
 * request bounds) to prevent overflow. Sets *got; returns 0 / -1. */
int
xrootd_cache_origin_read_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    xrootd_cache_sink_t *sink, uint64_t read_off, uint64_t dst_off,
    size_t want, size_t *got)
{
    ClientReadRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    *got = 0;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_read);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(read_off);
    req.rlen = htonl((kXR_int32) want);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin read write failed");
        return -1;
    }

    for (;;) {
        body = NULL;
        if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                       XROOTD_CACHE_FETCH_CHUNK) != 0) {
            return -1;
        }

        if (status == kXR_error) {
            xrootd_cache_set_origin_error(t, body, dlen,
                                          "cache origin read failed");
            free(body);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned invalid status");
            return -1;
        }

        if ((size_t) dlen > want || *got > want - (size_t) dlen) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            /* Write at dst_off + bytes already written this call (*got). dst_off
             * is the caller's WRITE base, decoupled from the origin READ offset:
             * the whole-file fetch passes dst_off==read_off (absolute), a slice
             * fill passes a 0-relative base. Using *got alone restarts at 0 each
             * 1 MiB chunk, so multi-chunk whole-file fetches overwrote at offset 0
             * (corrupting any file > XROOTD_CACHE_FETCH_CHUNK → adler32 mismatch). */
            if (xrootd_cache_sink_pwrite(sink, body, dlen,
                                         (off_t) (dst_off + *got)) != 0) {
                free(body);
                xrootd_cache_set_syserror(t, kXR_IOError,
                                          "cache file write failed");
                return -1;
            }
            *got += (size_t) dlen;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
    }
}

