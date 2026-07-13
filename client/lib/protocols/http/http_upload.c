/*
 * http_upload.c - extracted concern
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"


/*
 * httpx_upload_ctx_t - file-local bundle for the upload family.
 *
 * WHAT: One value type carrying the endpoint (host/port/tls/path/headers/TLS
 *       verification), the body pull-source callback, the transfer sizing, and
 *       the shared out-params (http_status, status) that every upload helper
 *       needs. Zero-init at the extern entry points; never escapes this file.
 * WHY:  The public/extern upload signatures are frozen (declared in brix_net.h /
 *       http_internal.h with out-of-file callers), so the 11-14 param bloat on
 *       those entry points cannot be removed. Threading THIS ctx through the new
 *       STATIC helpers keeps every decomposed step at a small, honest param
 *       count and lets the resumable driver split its loop body without passing
 *       a dozen scalars per call. The extern PARAM residuals are documented and
 *       accepted; the internal machinery is param-lean.
 * HOW:  Each extern function copies its frozen args into a stack ctx (designated
 *       zero-init) and delegates. Helpers read the endpoint/source/transfer
 *       fields directly and take only the per-step scalars (offsets, lengths).
 */
typedef struct {
    const char           *host;
    int                   port;
    int                   tls;
    const char           *path;
    const char           *extra_headers;
    int                   verify;
    const char           *ca_dir;
    brix_http_body_src_fn src;
    void                 *src_ctx;
    long long             clen;
    int                   timeout_ms;
    int                  *http_status;
    brix_status          *st;
} httpx_upload_ctx_t;


/*
 * httpx_chunk_range_t - one Content-Range chunk's coordinates + out-params.
 *
 * WHAT: The per-chunk values that vary from one resumable PUT to the next:
 *       the byte window [off, off+len) within a `total`-byte object, plus the
 *       two out-slots the exchange writes back (HTTP status, server offset).
 * WHY:  These do NOT belong on the reusable httpx_upload_ctx_t (that describes
 *       the whole upload, not one chunk). Bundling them keeps the chunk helpers
 *       at a lean param count without smuggling chunk state into the ctx.
 * HOW:  The resumable driver fills off/len/total per iteration and reads back
 *       status/srv_off after httpx_chunk_core returns.
 */
typedef struct {
    long long  off;
    long long  len;
    long long  total;
    int       *status_out;
    long long *srv_off_out;
} httpx_chunk_range_t;


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


/* WHAT: Format the PUT request line + headers for a whole-body upload into `req`.
 * WHY:  Isolates the snprintf-and-overflow-check so the exchange helper is flat.
 * HOW:  Content-Length only (no Content-Range) — this is the non-resumable path.
 *       0 / -1 (st set on overflow). */
static int
httpx_fmt_put_request(const httpx_upload_ctx_t *c, char *req, size_t cap,
                      int *rlen_out)
{
    char hp[300];
    int  rlen;

    brix_format_host_port(c->host, (uint16_t) c->port, hp, sizeof(hp));
    rlen = snprintf(req, cap,
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n%s\r\n",
                    c->path[0] ? c->path : "/", hp, c->clen,
                    c->extra_headers ? c->extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= cap) {
        brix_status_set(c->st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    *rlen_out = rlen;
    return 0;
}


/* WHAT: Whole-body PUT exchange over a connected io, driven by the upload ctx.
 * WHY:  The extern httpx_upload_exchange keeps its frozen 11-param signature; this
 *       static core does the work at a lean param count (ctx + io).
 * HOW:  Format request -> write it -> stream the body from offset 0 -> read the
 *       response. Flat early-return; no shared cleanup label. 0 / -1 (st set). */
static int
httpx_exchange_core(const httpx_upload_ctx_t *c, brix_io *io)
{
    char req[2048];
    int  rlen;

    if (httpx_fmt_put_request(c, req, sizeof(req), &rlen) != 0) { return -1; }
    if (brix_write_full(io, req, (size_t) rlen, c->st) != 0) { return -1; }
    if (httpx_upload_body(io, c->src, c->src_ctx, 0, c->clen, c->st) != 0) {
        return -1;
    }
    return httpx_upload_response(io, c->timeout_ms, c->http_status, c->st);
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
    httpx_upload_ctx_t c = {
        .host = host, .port = port, .path = path,
        .extra_headers = extra_headers, .src = src, .src_ctx = src_ctx,
        .clen = clen, .timeout_ms = timeout_ms, .http_status = http_status,
        .st = st,
    };
    return httpx_exchange_core(&c, io);
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


/* WHAT: Format a Content-Range PUT chunk request line + headers into `req`.
 * WHY:  Isolates the (larger) resumable snprintf-and-overflow-check from the
 *       chunk driver so it stays flat.
 * HOW:  Content-Length = chunk_len; Content-Range: bytes off-(off+len-1)/total.
 *       0 / -1 (st set on overflow). */
static int
httpx_fmt_chunk_request(const httpx_upload_ctx_t *c,
                        const httpx_chunk_range_t *rng, char *req,
                        size_t cap, int *rlen_out)
{
    char hp[300];
    int  rlen;

    brix_format_host_port(c->host, (uint16_t) c->port, hp, sizeof(hp));
    rlen = snprintf(req, cap,
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n"
                    "Content-Range: bytes %lld-%lld/%lld\r\n%s\r\n",
                    c->path[0] ? c->path : "/", hp, rng->len,
                    rng->off, rng->off + rng->len - 1, rng->total,
                    c->extra_headers ? c->extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= cap) {
        brix_status_set(c->st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    *rlen_out = rlen;
    return 0;
}


/* WHAT: Read the chunk response headers, publish the HTTP status and any
 *       X-Upload-Offset the server advertised.
 * WHY:  Splits the header-read/parse tail out of the chunk driver; owns and frees
 *       its own scratch header buffer on every path.
 * HOW:  read_resp_headers -> httpx_parse_upload_offset -> set out-params. 0 / -1
 *       (st set on error; *srv_off_out already initialised by the caller). */
static int
httpx_chunk_read_status(const httpx_upload_ctx_t *c, brix_io *io,
                        int *status_out, long long *srv_off_out)
{
    char  *hdr;
    size_t hdrtotal = 0, body_off = 0;
    int    status = 0;

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        brix_status_set(c->st, XRDC_EPROTO, 0, "http: out of memory");
        return -1;
    }
    if (read_resp_headers(io, hdr, XRDC_HDR_CAP, c->timeout_ms, &status,
                          &hdrtotal, &body_off, c->st) != 0) {
        free(hdr);
        return -1;
    }
    *srv_off_out = httpx_parse_upload_offset(hdr, hdrtotal);
    free(hdr);
    *status_out = status;
    return 0;
}


/* WHAT: Send one Content-Range PUT chunk over a connected io, driven by the ctx.
 * WHY:  The extern httpx_upload_chunk keeps its frozen 14-param signature; this
 *       static core runs the request/body/response steps at a lean param count.
 * HOW:  Init srv_off -> format -> write -> stream chunk body -> read status.
 *       0 / -1 (st set). */
static int
httpx_chunk_core(const httpx_upload_ctx_t *c, brix_io *io,
                 const httpx_chunk_range_t *rng)
{
    char req[2048];
    int  rlen;

    *rng->srv_off_out = -1;
    if (httpx_fmt_chunk_request(c, rng, req, sizeof(req), &rlen) != 0) {
        return -1;
    }
    if (brix_write_full(io, req, (size_t) rlen, c->st) != 0) { return -1; }
    if (httpx_upload_body(io, c->src, c->src_ctx, rng->off, rng->len,
                          c->st) != 0) {
        return -1;
    }
    return httpx_chunk_read_status(c, io, rng->status_out, rng->srv_off_out);
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
    httpx_upload_ctx_t c = {
        .host = host, .port = port, .path = path,
        .extra_headers = extra_headers, .src = src, .src_ctx = src_ctx,
        .timeout_ms = timeout_ms, .st = st,
    };
    httpx_chunk_range_t rng = {
        .off = off, .len = chunk_len, .total = total,
        .status_out = status_out, .srv_off_out = srv_off_out,
    };
    return httpx_chunk_core(&c, io, &rng);
}


/* WHAT: Per-chunk connect + transfer for the resumable driver.
 * WHY:  Isolates one attempt's transport lifecycle (connect, chunk exchange,
 *       unconditional TLS/fd teardown) so the driver loop reads as pure policy.
 * HOW:  httpx_connect -> httpx_chunk_core -> free TLS + close fd on every path.
 *       Returns 0 with *status / *srv_off set on a completed exchange, or -1 with
 *       st set on a connect/transport failure. `rng` carries the chunk window
 *       and receives the status/server-offset out-params. */
static int
httpx_resumable_attempt(const httpx_upload_ctx_t *c,
                        const httpx_chunk_range_t *rng)
{
    brix_io io;
    void   *tls_ctx = NULL;
    int     rc;

    if (httpx_connect(&io, c->host, c->port, c->tls, c->verify, c->ca_dir,
                      c->timeout_ms, &tls_ctx, c->st) != 0) {
        return -1;
    }
    rc = httpx_chunk_core(c, &io, rng);
    if (c->tls) { brix_tls_client_free(&io, tls_ctx); }
    if (io.fd >= 0) { close(io.fd); }
    return rc;
}


/* WHAT: Is the current retry budget still open for another attempt?
 * WHY:  The resumable driver's connect-fail and transport-sever branches share
 *       the exact same retry gate; factoring it keeps the loop honest and one
 *       CCN branch instead of two duplicated ladders.
 * HOW:  A retry is allowed only when stalls are enabled, the error is retryable,
 *       and the stall deadline has not passed. */
static int
httpx_resumable_may_retry(const httpx_upload_ctx_t *c, int max_stall_ms,
                          uint64_t deadline)
{
    return max_stall_ms > 0 && brix_status_retryable(c->st)
           && brix_mono_ns() < deadline;
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
    httpx_upload_ctx_t c = {
        .host = host, .port = port, .tls = tls, .path = path,
        .extra_headers = extra_headers, .verify = verify, .ca_dir = ca_dir,
        .src = src, .src_ctx = src_ctx, .clen = clen, .timeout_ms = timeout_ms,
        .http_status = http_status, .st = st,
    };
    long long off = 0;
    unsigned  attempt = 0;
    uint64_t  deadline = brix_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    const long long CHUNK = 8LL * 1024 * 1024;

    if (http_status != NULL) { *http_status = 0; }

    while (off < clen) {
        long long chunk = (clen - off < CHUNK) ? (clen - off) : CHUNK;
        int       status = 0;
        long long srv_off = -1;
        httpx_chunk_range_t rng = {
            .off = off, .len = chunk, .total = clen,
            .status_out = &status, .srv_off_out = &srv_off,
        };

        if (httpx_resumable_attempt(&c, &rng) != 0) {
            /* connect or transport sever: reconnect and resume from `off` */
            if (!httpx_resumable_may_retry(&c, max_stall_ms, deadline)) {
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
    httpx_upload_ctx_t c = {
        .host = host, .port = port, .tls = tls, .path = path,
        .extra_headers = extra_headers, .verify = verify, .ca_dir = ca_dir,
        .src = src, .src_ctx = src_ctx, .clen = clen, .timeout_ms = timeout_ms,
        .http_status = http_status, .st = st,
    };
    brix_io  io;
    void    *tls_ctx = NULL;
    int      rc;

    if (http_status != NULL) { *http_status = 0; }
    if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                      &tls_ctx, st) != 0) {
        return -1;
    }

    rc = httpx_exchange_core(&c, &io);

    if (tls) { brix_tls_client_free(&io, tls_ctx); }
    if (io.fd >= 0) { close(io.fd); }
    return rc;
}
