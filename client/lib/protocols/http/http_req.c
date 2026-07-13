/*
 * http_req.c - extracted concern
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"


/* general HTTP/1.1 client (cleartext or TLS) — for the multi-protocol */
/* deep-dive (https/davs/s3 batteries). Reads to EOF (Connection:close). */


/* Read up to n bytes; branches on TLS. Returns bytes (>0), 0 on EOF, -1 on error. */
ssize_t
httpx_read_some(brix_io *io, void *buf, size_t n, int timeout_ms, brix_status *st)
{
    if (io->ssl != NULL) {
        size_t got = 0;
        if (brix_tls_read_some(io, buf, n, &got, st) != 0) {
            return -1;
        }
        return (ssize_t) got;     /* 0 = EOF */
    }
    {
        struct pollfd pfd;
        ssize_t       r;
        int           pr;
        pfd.fd = io->fd; pfd.events = POLLIN; pfd.revents = 0;
        do { pr = poll(&pfd, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
                            "http read %s", pr == 0 ? "timed out" : "poll failed");
            return -1;
        }
        do { r = read(io->fd, buf, n); } while (r < 0 && errno == EINTR);
        if (r < 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "http read: %s", strerror(errno));
            return -1;
        }
        return r;
    }
}


/* Decide whether the full response body has arrived in buf[0,total) given the
 * header block end (body_off) and the framing parsed from the headers.
 *
 * WHY: Some servers (notably XrdHttp) advertise "Connection: Close" yet keep the
 *      TLS socket open after the body, so reading to EOF blocks until timeout. We
 *      must stop exactly at the framed body length instead. Returns 1 when the
 *      body is complete; 0 means "keep reading" (genuine EOF still terminates). */
int
httpx_body_complete(const char *buf, size_t total, size_t body_off,
                    long long clen, int chunked)
{
    if (clen >= 0) {
        return (total - body_off) >= (size_t) clen;
    }
    if (chunked) {
        const char *b  = buf + body_off;
        size_t      bl = total - body_off;
        /* terminating zero-length chunk: "0\r\n\r\n" (optionally CRLF-prefixed) */
        if (bl >= 5 && memcmp(b, "0\r\n\r\n", 5) == 0) {
            return 1;
        }
        return memmem(b, bl, "\r\n0\r\n\r\n", 7) != NULL;
    }
    return 0;   /* EOF-delimited: only the real EOF (read == 0) completes it */
}


/* ---- File-local request descriptor for one HTTP client exchange ----
 *
 * WHAT: Bundles the immutable inputs of a single request/response exchange
 *       (target host/port, request line + headers, optional body, timeout) so
 *       the exchange helpers take one pointer instead of an 11-argument list.
 *
 * WHY: httpx_exchange's frozen extern signature carries 11 parameters; threading
 *      them one-by-one through the build/send/read split would re-inflate every
 *      helper's parameter count. A file-local descriptor keeps the split helpers
 *      small and their data flow explicit without touching the public header.
 *
 * HOW: httpx_exchange fills one on the stack from its own parameters, then hands
 *      a const pointer to each phase helper; no field is mutated after fill. */
typedef struct {
    const char *host;
    int         port;
    const char *method;
    const char *path;
    const char *extra_headers;
    const void *body;
    size_t      blen;
    int         timeout_ms;
} httpx_exchange_t;


/* ---- Rolling parse state while reading a framed HTTP response ----
 *
 * WHAT: Tracks whether the header block has been seen and, once it has, the
 *       body offset and the framing (Content-Length / chunked) parsed from it.
 *
 * WHY: The read loop must decide, after each read, whether the framed body is
 *      complete. Grouping the framing state keeps the loop body flat and lets
 *      the header-parse step return its result in one place.
 *
 * HOW: Initialised to "no headers yet" (clen -1); httpx_read_frame_headers sets
 *      it once the CRLFCRLF terminator arrives. */
typedef struct {
    int       have_hdrs;
    int       chunked;
    size_t    body_off;
    long long clen;
} httpx_frame_t;


/* ---- Build the HTTP/1.1 request bytes into a caller buffer ----
 *
 * WHAT: Formats the request line, fixed headers, caller-supplied extra headers,
 *       and (when a body is present) the Content-Length header into req[0,cap).
 *       Returns the byte length on success, or -1 (with st set) if it overflows.
 *
 * WHY: Isolating the fixed request-formatting from the send/read phases keeps
 *      httpx_exchange linear and makes the "request too long" guards testable
 *      in one place.
 *
 * HOW: 1. Format the request line + headers, terminating the header block with a
 *         bare CRLF only when there is no body. 2. When a body is present, append
 *         the Content-Length header (which closes the header block). 3. Guard each
 *         snprintf against truncation. */
static int
httpx_build_request(const httpx_exchange_t *ex, char *req, size_t cap,
                    brix_status *st)
{
    char hp[300];
    int  rlen;

    brix_format_host_port(ex->host, (uint16_t) ex->port, hp, sizeof(hp));
    rlen = snprintf(req, cap,
                    "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrddiag\r\n"
                    "Accept: */*\r\nConnection: close\r\n%s%s",
                    ex->method, ex->path[0] ? ex->path : "/", hp,
                    ex->extra_headers ? ex->extra_headers : "",
                    (ex->body != NULL && ex->blen > 0) ? "" : "\r\n");
    if (rlen < 0 || (size_t) rlen >= cap) {
        brix_status_set(st, XRDC_EUSAGE, 0, "http_req: request too long");
        return -1;
    }
    if (ex->body != NULL && ex->blen > 0) {
        char cl[64];
        int  cn = snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n\r\n", ex->blen);
        if (cn < 0 || (size_t) (rlen + cn) >= cap) {
            brix_status_set(st, XRDC_EUSAGE, 0, "http_req: request too long");
            return -1;
        }
        memcpy(req + rlen, cl, (size_t) cn);
        rlen += cn;
    }
    return rlen;
}


/* ---- Send the request head and optional body over io ----
 *
 * WHAT: Writes req[0,rlen) then, if the exchange carries a body, the body bytes.
 *       Returns 0 on success, -1 (with st set) on a write error.
 *
 * WHY: Separates the side-effecting write from request formatting so the
 *      orchestrator reads as a flat build → send → read sequence.
 *
 * HOW: 1. brix_write_full the header block. 2. brix_write_full the body when
 *         one is present. */
static int
httpx_send_request(brix_io *io, const httpx_exchange_t *ex, const char *req,
                   size_t rlen, brix_status *st)
{
    if (brix_write_full(io, req, rlen, st) != 0) {
        return -1;
    }
    if (ex->body != NULL && ex->blen > 0 &&
        brix_write_full(io, ex->body, ex->blen, st) != 0) {
        return -1;
    }
    return 0;
}


/* ---- Parse framing out of a just-completed header block ----
 *
 * WHAT: When buf[0,total) now contains the CRLFCRLF header terminator, records
 *       the body offset and the response framing (chunked vs Content-Length)
 *       into *fr. Leaves *fr untouched if the header block has not fully arrived.
 *
 * WHY: Header framing is parsed exactly once, the first time the terminator is
 *      seen; pulling it out of the read loop keeps the loop body flat and the
 *      temporary NUL-termination of the header block confined to one helper.
 *
 * HOW: 1. Locate CRLFCRLF; return if absent. 2. Temporarily NUL-terminate the
 *         header block so the string-based header readers stay in bounds.
 *         3. Prefer a chunked Transfer-Encoding, else read Content-Length.
 *         4. Restore the clobbered byte. */
static void
httpx_read_frame_headers(char *buf, size_t total, httpx_frame_t *fr)
{
    char *eoh = memmem(buf, total, "\r\n\r\n", 4);
    char  cl[64];
    char *save;
    char  saved;

    if (eoh == NULL) {
        return;
    }
    save  = eoh + 4;
    saved = *save;
    *save = '\0';                                /* NUL-terminate header block */
    fr->have_hdrs = 1;
    fr->body_off  = (size_t) (eoh + 4 - buf);
    if (raw_header(buf, "Transfer-Encoding", cl, sizeof(cl)) &&
        ci_contains(cl, "chunked")) {
        fr->chunked = 1;
    } else if (raw_header(buf, "Content-Length", cl, sizeof(cl))) {
        fr->clen = strtoll(cl, NULL, 10);
    }
    *save = saved;                               /* restore the byte */
}


/* ---- Read the framed response into a freshly allocated buffer and parse it ----
 *
 * WHAT: Allocates an 8 MiB scratch buffer, reads until the framed body is
 *       complete (Content-Length / chunked / EOF), parses it into *resp, and
 *       frees the buffer. Returns 0 on success, -1 (with st set) on error.
 *
 * WHY: Owns its own scratch buffer so the caller's teardown stays linear (no
 *      shared cleanup label). Splitting the read/parse phase out of the
 *      build/send phases keeps each function single-purpose.
 *
 * HOW: 1. Allocate the ceiling buffer. 2. Loop: stop once the framed body is
 *         complete; at the ceiling do one extra read to tell EOF from truncation;
 *         otherwise read more, parsing framing the first time the header block
 *         completes. 3. NUL-terminate, parse, free. */
static int
httpx_read_response(brix_io *io, const httpx_exchange_t *ex,
                    brix_http_resp *resp, brix_status *st)
{
    char         *buf;
    size_t        total = 0, cap = XRDC_HTTPX_MAX;
    httpx_frame_t fr = { 0, 0, 0, -1 };

    buf = (char *) malloc(cap);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "http_req: out of memory");
        return -1;
    }
    for (;;) {
        ssize_t r;
        /* Stop as soon as the framed body is complete — do NOT wait for EOF:
         * XrdHttp advertises "Connection: Close" but keeps the socket open. */
        if (fr.have_hdrs &&
            httpx_body_complete(buf, total, fr.body_off, fr.clen, fr.chunked)) {
            break;
        }
        if (total >= cap - 1) {
            /* At the ceiling: one more read distinguishes a genuine EOF from a
             * truncated body — a silent truncation would corrupt a checksum probe. */
            char    sink[1];
            ssize_t extra = httpx_read_some(io, sink, 1, ex->timeout_ms, st);
            if (extra < 0) { free(buf); return -1; }
            if (extra > 0) {
                free(buf);
                brix_status_set(st, XRDC_EPROTO, 0,
                                "http_req: response body exceeds the 8 MiB diagnostic limit");
                return -1;
            }
            break;   /* extra == 0: EOF exactly at the ceiling */
        }
        r = httpx_read_some(io, buf + total, cap - 1 - total, ex->timeout_ms, st);
        if (r < 0) { free(buf); return -1; }
        if (r == 0) { break; }                       /* genuine EOF */
        total += (size_t) r;
        if (!fr.have_hdrs) {
            httpx_read_frame_headers(buf, total, &fr);
        }
    }
    buf[total] = '\0';
    httpx_parse(buf, total, resp);
    free(buf);
    return 0;
}


/* The protocol exchange over an established (and TLS-wrapped, if any) io: build +
 * send the request, read the framed response (Content-Length / chunked / EOF),
 * parse it. Owns its own scratch buffer
 * so the caller's teardown stays linear (no shared cleanup label). 0 / -1. */
int
httpx_exchange(brix_io *io, const char *host, int port, const char *method,
               const char *path, const char *extra_headers, const void *body,
               size_t blen, int timeout_ms, brix_http_resp *resp, brix_status *st)
{
    httpx_exchange_t ex = { host, port, method, path, extra_headers,
                            body, blen, timeout_ms };
    char             req[2048];
    int              rlen;

    rlen = httpx_build_request(&ex, req, sizeof(req), st);
    if (rlen < 0) {
        return -1;
    }
    if (httpx_send_request(io, &ex, req, (size_t) rlen, st) != 0) {
        return -1;
    }
    return httpx_read_response(io, &ex, resp, st);
}


int
brix_http_req(const char *host, int port, int tls, const char *method,
              const char *path, const char *extra_headers,
              const void *body, size_t blen, int timeout_ms, int verify,
              const char *ca_dir, brix_http_resp *resp, brix_status *st)
{
    brix_io  io;
    void    *tls_ctx = NULL;
    int      rc;

    memset(resp, 0, sizeof(*resp));
    if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                      &tls_ctx, st) != 0) {
        return -1;
    }
    resp->tls = tls;
    if (tls) {
        const char *v = NULL, *c = NULL;
        brix_tls_client_info(&io, &v, &c);
        snprintf(resp->tls_ver, sizeof(resp->tls_ver), "%s", v ? v : "?");
        snprintf(resp->tls_cipher, sizeof(resp->tls_cipher), "%s", c ? c : "?");
    }

    rc = httpx_exchange(&io, host, port, method, path, extra_headers, body, blen,
                        timeout_ms, resp, st);

    if (tls) {
        brix_tls_client_free(&io, tls_ctx);
    }
    close(io.fd);
    if (rc != 0) {
        brix_http_resp_free(resp);
    }
    return rc;
}
