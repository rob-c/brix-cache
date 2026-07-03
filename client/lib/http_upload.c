/*
 * http_upload.c - extracted concern
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"


/* Stream `clen` bytes to the connected io as the PUT body, pulling them from the
 * source by ABSOLUTE offset (base_off + bytes already sent) so the same source
 * serves a whole-body PUT (base_off 0) and a resumable Content-Range chunk
 * (base_off = chunk start) without a shared file offset. The source shrinking
 * mid-stream is a protocol error (the Content-Length already promised the full
 * size). 0 / -1 (st set on error). */
int
httpx_upload_body(brix_io *io, brix_http_body_src_fn src, void *src_ctx,
                  long long base_off, long long clen, brix_status *st)
{
    uint8_t   buf[XRDC_XFER_BUF];
    long long remaining = clen;

    while (remaining > 0) {
        size_t  want = (remaining < (long long) sizeof(buf))
                       ? (size_t) remaining : sizeof(buf);
        ssize_t r = src(src_ctx, buf, base_off + (clen - remaining), want, st);
        if (r < 0) {
            if (st->kxr == 0 && st->sys_errno == 0) {
                brix_status_set(st, XRDC_ESOCK, 0, "upload: source read failed");
            }
            return -1;
        }
        if (r == 0) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "upload: source shrank (%lld bytes short)", remaining);
            return -1;
        }
        if (brix_write_full(io, buf, (size_t) r, st) != 0) { return -1; }
        remaining -= r;
    }
    return 0;
}


/* Read the PUT response headers and map a 2xx status to success. Owns its scratch
 * header buffer (allocated, used, freed on every path) so the orchestrator's
 * transport teardown stays linear. 0 / -1 (st set on error). */
int
httpx_upload_response(brix_io *io, int timeout_ms, int *http_status,
                      brix_status *st)
{
    char  *hdr;
    size_t total = 0, body_off = 0;
    int    status = 0, rc;

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "http: out of memory");
        return -1;
    }
    if (read_resp_headers(io, hdr, XRDC_HDR_CAP, timeout_ms, &status,
                          &total, &body_off, st) != 0) {
        free(hdr);
        return -1;
    }
    free(hdr);
    if (http_status != NULL) { *http_status = status; }
    if (status >= 200 && status < 300) {
        rc = 0;
    } else {
        brix_status_set(st, XRDC_EPROTO, 0, "upload: server returned status %d", status);
        rc = -1;
    }
    return rc;
}


/* Send the PUT request line + headers, stream the body, and read the response —
 * over an already-connected io. Flat early-return so the orchestrator's transport
 * teardown needs no shared cleanup label. 0 / -1 (st set on error). */
int
httpx_upload_exchange(brix_io *io, const char *host, int port, const char *path,
                      const char *extra_headers, brix_http_body_src_fn src,
                      void *src_ctx, long long clen, int timeout_ms,
                      int *http_status, brix_status *st)
{
    char req[2048];
    int  rlen;

    char hp[300];
    brix_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n%s\r\n",
                    path[0] ? path : "/", hp, clen,
                    extra_headers ? extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (brix_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }
    if (httpx_upload_body(io, src, src_ctx, 0, clen, st) != 0) { return -1; }
    return httpx_upload_response(io, timeout_ms, http_status, st);
}


/* Case-insensitively scan a header block [hdr, hdr+len) for "X-Upload-Offset"
 * and return its value, or -1 if absent/unparsable. */
long long
httpx_parse_upload_offset(const char *hdr, size_t len)
{
    static const char key[] = "x-upload-offset:";
    size_t klen = sizeof(key) - 1;
    size_t i;

    for (i = 0; i + klen <= len; i++) {
        size_t j;
        for (j = 0; j < klen; j++) {
            char c = hdr[i + j];
            if (c >= 'A' && c <= 'Z') { c = (char) (c + 32); }
            if (c != key[j]) { break; }
        }
        if (j == klen) {
            const char *p = hdr + i + klen;
            const char *e = hdr + len;
            long long   v = 0;
            int         any = 0;
            while (p < e && (*p == ' ' || *p == '\t')) { p++; }
            while (p < e && *p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0'); p++; any = 1;
            }
            return any ? v : -1;
        }
    }
    return -1;
}


/* Send one Content-Range PUT chunk [off, off+chunk_len) of a `total`-byte upload
 * over an already-connected io; report the HTTP status and any X-Upload-Offset. */
int
httpx_upload_chunk(brix_io *io, const char *host, int port, const char *path,
                   const char *extra_headers, brix_http_body_src_fn src,
                   void *src_ctx, long long off, long long chunk_len,
                   long long total, int timeout_ms, int *status_out,
                   long long *srv_off_out, brix_status *st)
{
    char  req[2048];
    char  hp[300];
    int   rlen;
    char *hdr;
    size_t hdrtotal = 0, body_off = 0;
    int   status = 0;

    *srv_off_out = -1;
    brix_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n"
                    "Content-Range: bytes %lld-%lld/%lld\r\n%s\r\n",
                    path[0] ? path : "/", hp, chunk_len,
                    off, off + chunk_len - 1, total,
                    extra_headers ? extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (brix_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }
    if (httpx_upload_body(io, src, src_ctx, off, chunk_len, st) != 0) { return -1; }

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "http: out of memory");
        return -1;
    }
    if (read_resp_headers(io, hdr, XRDC_HDR_CAP, timeout_ms, &status,
                          &hdrtotal, &body_off, st) != 0) {
        free(hdr);
        return -1;
    }
    *srv_off_out = httpx_parse_upload_offset(hdr, hdrtotal);
    free(hdr);
    *status_out = status;
    return 0;
}


/*
 * Resumable upload: stream the source as a sequence of Content-Range PUT chunks,
 * each on a fresh connection, so an nginx restart mid-upload is survived — on a
 * transport sever or a 409 (offset-correction) the loop reconnects and continues
 * from the server's durable offset, within a bounded stall window.  Requires the
 * server's brix_webdav_upload_resume; against a server without it the first
 * Content-Range PUT is treated as a whole-body write (commit) and this still
 * works for a single-shot upload.  0 / -1 (st set).
 */
int
brix_http_upload_resumable(const char *host, int port, int tls, const char *path,
                           const char *extra_headers, brix_http_body_src_fn src,
                           void *src_ctx, long long clen, int verify,
                           const char *ca_dir, int timeout_ms, int max_stall_ms,
                           int *http_status, brix_status *st)
{
    long long off = 0;
    unsigned  attempt = 0;
    uint64_t  deadline = brix_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    const long long CHUNK = 8LL * 1024 * 1024;

    if (http_status != NULL) { *http_status = 0; }

    while (off < clen) {
        brix_io   io;
        void     *tls_ctx = NULL;
        long long chunk = (clen - off < CHUNK) ? (clen - off) : CHUNK;
        int       status = 0;
        long long srv_off = -1;
        int       rc;

        if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                          &tls_ctx, st) != 0) {
            if (max_stall_ms <= 0 || !brix_status_retryable(st)
                || brix_mono_ns() >= deadline) {
                return -1;
            }
            brix_backoff_sleep_fast(attempt++);
            continue;
        }

        rc = httpx_upload_chunk(&io, host, port, path, extra_headers, src,
                                src_ctx, off, chunk, clen, timeout_ms,
                                &status, &srv_off, st);
        if (tls) { brix_tls_client_free(&io, tls_ctx); }
        if (io.fd >= 0) { close(io.fd); }

        if (rc != 0) {
            /* transport sever: reconnect and resume from the same offset */
            if (max_stall_ms <= 0 || !brix_status_retryable(st)
                || brix_mono_ns() >= deadline) {
                return -1;
            }
            brix_backoff_sleep_fast(attempt++);
            continue;
        }

        if (http_status != NULL) { *http_status = status; }
        deadline = brix_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
        attempt = 0;

        if (status == 409 && srv_off >= 0) {
            off = srv_off;                 /* server told us the real offset */
            continue;
        }
        if (status == 201 || status == 204) {
            return 0;                      /* committed (final chunk) */
        }
        if (status >= 200 && status < 300) {
            off += chunk;                  /* intermediate chunk accepted */
            continue;
        }
        brix_status_set(st, XRDC_EPROTO, 0,
                        "upload: server returned status %d", status);
        return -1;
    }
    return 0;
}


int
brix_http_upload(const char *host, int port, int tls, const char *path,
                 const char *extra_headers, brix_http_body_src_fn src,
                 void *src_ctx, long long clen, int verify, const char *ca_dir,
                 int timeout_ms, int *http_status, brix_status *st)
{
    brix_io  io;
    void    *tls_ctx = NULL;
    int      rc;

    if (http_status != NULL) { *http_status = 0; }
    if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                      &tls_ctx, st) != 0) {
        return -1;
    }

    rc = httpx_upload_exchange(&io, host, port, path, extra_headers, src, src_ctx,
                               clen, timeout_ms, http_status, st);

    if (tls) { brix_tls_client_free(&io, tls_ctx); }
    if (io.fd >= 0) { close(io.fd); }
    return rc;
}
