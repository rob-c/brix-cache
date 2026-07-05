/*
 * cache/origin_write.c — origin-side write-through / mirroring data path.
 *
 * Split out of origin_protocol.c: kXR_open-for-write (truncate + mkpath),
 * chunked kXR_write, kXR_truncate, kXR_sync, close, and the cache-sink writer
 * used to mirror a locally-staged file back onto the upstream origin.  Keeps
 * origin_protocol.c focused on connection bootstrap + the read/fill path.  The
 * public brix_cache_origin_{open_write,close_file,write_chunk,truncate,sync}()
 * and brix_cache_sink_pwrite() are declared in cache_internal.h.
 */

#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared request packers */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode */
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* brix_cache_origin_open_write — kXR_open (update + delete + mkpath) to mirror a
 * local file onto the origin: truncate the destination and create missing parent
 * dirs (where supported) for an atomic write-through replacement. Returns 0 with
 * fhandle set, -1 on error or redirect. */
int
brix_cache_origin_open_write(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (path == NULL || path[0] == '\0') {
        brix_cache_set_error(t, kXR_ArgInvalid, 0,
                               "write-through origin path missing");
        return -1;
    }

    pathlen = strlen(path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
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

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   BRIX_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "write-through origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        brix_cache_set_error(t, kXR_Unsupported, 0,
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
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin open invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);
    free(body);
    return 0;
}

/* brix_cache_origin_close_file — send kXR_close for the fhandle and discard the
 * reply (close status only matters for errors, which don't invalidate data already
 * written to disk). Every opened file must be closed before reconnect/finish. */
void
brix_cache_origin_close_file(brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientCloseRequest req;
    uint16_t           rsp_status;
    uint32_t           dlen;
    u_char            *body;
    brix_cache_fill_t dummy;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 2;
    req.requestid = htons(kXR_close);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    (void) brix_cache_io_send(oc, &req, sizeof(req));

    ngx_memzero(&dummy, sizeof(dummy));
    dummy.result = NGX_OK;
    body = NULL;
    if (brix_cache_read_response(&dummy, oc, &rsp_status, &body, &dlen,
                                   4096) == 0) {
        free(body);
    }
}

/* brix_cache_origin_write_chunk — kXR_write a payload at a big-endian 64-bit
 * offset (htobe64, XRootD wire format); the reply must be kXR_ok with dlen=0.
 * Returns 0 on success, -1 on error. */
int
brix_cache_origin_write_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len)
{
    ClientWriteRequest req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (len > INT32_MAX) {
        brix_cache_set_error(t, kXR_ArgTooLong, 0,
                               "write-through origin write too large");
        return -1;
    }

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_write);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(offset);
    req.dlen = htonl((kXR_int32) len);

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0
        || (len > 0 && brix_cache_io_send(oc, data, len) != 0))
    {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin write failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "write-through origin write rejected");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok || dlen != 0) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin write invalid response");
        return -1;
    }

    return 0;
}

/* brix_cache_origin_truncate — kXR_truncate the origin file to a big-endian
 * 64-bit offset (used before write_chunk when the destination is larger than the
 * source); the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
brix_cache_origin_truncate(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
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

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin truncate send failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "write-through origin truncate failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin truncate invalid response");
        return -1;
    }

    return 0;
}

/* brix_cache_origin_sync — kXR_sync the origin file (fsync equivalent) after
 * streaming all chunks, so the mirrored content survives an origin crash before
 * close; the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
brix_cache_origin_sync(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN])
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

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin sync send failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "write-through origin sync failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin sync invalid response");
        return -1;
    }

    return 0;
}

/* Positional write into a fill sink: a driver staged-write handle (driver-backed
 * cache) or a raw POSIX fd. Keeps the origin read loop backend-agnostic. */
int
brix_cache_sink_pwrite(brix_cache_sink_t *sink, const void *buf, size_t len,
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
    return brix_cache_fd_write_all(sink->fd, buf, len, off);
}
