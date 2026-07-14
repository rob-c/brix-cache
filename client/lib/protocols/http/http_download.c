/*
 * http_download.c - extracted concern
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"


/* Stream a Content-Length-bounded body (`remaining` bytes) from src to out_fd. */
int
stream_clen(body_src *src, long long remaining, int out_fd, long long *written,
            brix_status *st)
{
    char buf[XRDC_XFER_BUF];
    while (remaining > 0) {
        size_t  want = (remaining < (long long) sizeof(buf))
                       ? (size_t) remaining : sizeof(buf);
        ssize_t r = bsrc_read(src, buf, want, st);
        if (r < 0) { return -1; }
        if (r == 0) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "http: body truncated (%lld bytes short)", remaining);
            return -1;
        }
        if (write_all_fd(out_fd, buf, (size_t) r, st) != 0) { return -1; }
        remaining -= r;
        *written += r;
    }
    return 0;
}


/* Stream a connection-close-delimited body (read to EOF) from src to out_fd. */
int
stream_eof(body_src *src, int out_fd, long long *written, brix_status *st)
{
    char buf[XRDC_XFER_BUF];
    for (;;) {
        ssize_t r = bsrc_read(src, buf, sizeof(buf), st);
        if (r < 0) { return -1; }
        if (r == 0) { break; }
        if (write_all_fd(out_fd, buf, (size_t) r, st) != 0) { return -1; }
        *written += r;
    }
    return 0;
}


/* Stream a Transfer-Encoding: chunked body from src to out_fd. */
int
stream_chunked(body_src *src, int out_fd, long long *written, brix_status *st)
{
    char buf[XRDC_XFER_BUF];
    for (;;) {
        char  line[64];
        long  csz;
        char *endp = NULL;
        if (bsrc_getline(src, line, sizeof(line), st) != 0) { return -1; }
        csz = strtol(line, &endp, 16);
        if (endp == line || csz < 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "http: bad chunk size");
            return -1;
        }
        if (csz == 0) { break; }                 /* last chunk */
        while (csz > 0) {
            size_t  want = (csz < (long) sizeof(buf)) ? (size_t) csz : sizeof(buf);
            ssize_t r = bsrc_read(src, buf, want, st);
            if (r <= 0) {
                brix_status_set(st, XRDC_EPROTO, 0, "http: chunk truncated");
                return -1;
            }
            if (write_all_fd(out_fd, buf, (size_t) r, st) != 0) { return -1; }
            csz -= r;
            *written += r;
        }
        {
            char crlf[4];   /* consume the CRLF trailing the chunk data */
            (void) bsrc_getline(src, crlf, sizeof(crlf), st);
        }
    }
    return 0;
}


/* Read the response header block into hdr[]; parse status. Sets *total (bytes in
 * hdr buffer), *body_off (offset of first body byte in hdr). 0 / -1. */
int
read_resp_headers(brix_io *io, char *hdr, size_t hdrcap, int timeout_ms,
                  int *status, size_t *total, size_t *body_off, brix_status *st)
{
    size_t n = 0;
    char  *eoh = NULL;
    while (n < hdrcap - 1) {
        ssize_t r = httpx_read_some(io, hdr + n, hdrcap - 1 - n, timeout_ms, st);
        if (r < 0) { return -1; }
        if (r == 0) { break; }
        n += (size_t) r;
        eoh = memmem(hdr, n, "\r\n\r\n", 4);
        if (eoh != NULL) { break; }
    }
    if (eoh == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "http: response headers too large/truncated");
        return -1;
    }
    hdr[n] = '\0';
    *status = 0;
    if (strncmp(hdr, "HTTP/", 5) == 0) {
        char *sp = strchr(hdr, ' ');
        if (sp != NULL) { *status = atoi(sp + 1); }
    }
    *total    = n;
    *body_off = (size_t) (eoh + 4 - hdr);
    return 0;
}


/* Find a header value in a NUL-terminated raw header block (line-anchored,
 * case-insensitive). 1 if found. */
int
raw_header(const char *hdr, const char *name, char *out, size_t outsz)
{
    const char *p = hdr;
    size_t      nl = strlen(name);
    if (outsz == 0) { return 0; }
    out[0] = '\0';
    while (*p != '\0') {
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1, *e;
            size_t      n;
            while (*v == ' ' || *v == '\t') { v++; }
            e = v;
            while (*e != '\0' && *e != '\r' && *e != '\n') { e++; }
            n = (size_t) (e - v);
            if (n >= outsz) { n = outsz - 1; }
            memcpy(out, v, n);
            out[n] = '\0';
            return 1;
        }
        while (*p != '\0' && *p != '\n') { p++; }
        if (*p == '\n') { p++; }
    }
    return 0;
}


/* Stream the 2xx response body to out_fd, picking the framing from the headers.
 *
 * WHAT: Given a parsed header block (hdr/total/body_off) and a status, drive the
 *       chunked / Content-Length / EOF body decoder into out_fd and report bytes.
 * WHY:  Keeps the framing decision out of the orchestrator so the latter stays a
 *       flat connect→exchange→teardown sequence (no shared cleanup label).
 * HOW:  Wrap the leftover header bytes + socket in a body_src, then dispatch on
 *       Transfer-Encoding / Content-Length / neither. 0 / -1 (st set on error). */
int
httpx_download_body(brix_io *io, char *hdr, size_t total, size_t body_off,
                    int out_fd, int timeout_ms, long long *body_len,
                    brix_status *st)
{
    body_src  src;
    char      clbuf[32], tebuf[32];
    long long written = 0;
    int       rc;

    src.io = io; src.lo = hdr; src.lo_len = total; src.lo_off = body_off;
    src.timeout_ms = timeout_ms;
    if (raw_header(hdr, "Transfer-Encoding", tebuf, sizeof(tebuf))
        && strcasecmp(tebuf, "chunked") == 0) {
        rc = stream_chunked(&src, out_fd, &written, st);
    } else if (raw_header(hdr, "Content-Length", clbuf, sizeof(clbuf))) {
        /* Validate the wire value — a negative/garbage length parsed as 0
         * would silently truncate the body and report success. */
        char     *cend = NULL;
        long long cl;
        errno = 0;
        cl = strtoll(clbuf, &cend, 10);
        if (cend == clbuf || cl < 0 || errno == ERANGE
            || (*cend != '\0' && *cend != '\r' && *cend != ' ')) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "http: invalid Content-Length \"%s\"", clbuf);
            rc = -1;
        } else {
            rc = stream_clen(&src, cl, out_fd, &written, st);
        }
    } else {
        rc = stream_eof(&src, out_fd, &written, st);
    }
    /* Report bytes written even on FAILURE: the resilient download wrapper uses
     * it as the resume offset (the next Range GET picks up from there). */
    if (body_len != NULL) { *body_len = written; }
    return rc;
}


/* Send the GET, read the response headers, and stream a 2xx body — over an
 * already-connected io. Owns its scratch header buffer (allocated, used, freed on
 * every path) so the orchestrator's transport teardown stays linear. 0 / -1. */
int
httpx_download_exchange(brix_io *io, const char *host, int port,
                        const char *path, const char *extra_headers,
                        long long start_off, int out_fd,
                        int timeout_ms, int *http_status, long long *body_len,
                        brix_status *st)
{
    char    *hdr;
    char     req[2048];
    char     rangeh[64];
    size_t   total = 0, body_off = 0;
    int      status = 0, rlen, rc;

    char hp[300];
    brix_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    /* Resume from start_off via an open-ended byte range (the server replies 206
     * with the remaining bytes); empty for a fresh download. */
    rangeh[0] = '\0';
    if (start_off > 0) {
        snprintf(rangeh, sizeof(rangeh), "Range: bytes=%lld-\r\n", start_off);
    }
    rlen = snprintf(req, sizeof(req),
                    "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Accept: */*\r\nConnection: close\r\n%s%s\r\n",
                    path[0] ? path : "/", hp, rangeh,
                    extra_headers ? extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (brix_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }

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
    if (http_status != NULL) { *http_status = status; }

    /* Only stream the body for a success status (2xx). For anything else the
     * caller decides; we still drain nothing (Connection: close ends it). */
    if (status >= 200 && status < 300) {
        if (start_off > 0 && status != 206) {
            /* We asked to resume from start_off but the server ignored Range and
             * is streaming the whole object from 0 — appending it at the resume
             * offset would corrupt the file, so refuse rather than overwrite. */
            brix_status_set(st, XRDC_EPROTO, 0,
                            "http: resume Range ignored (status %d)", status);
            rc = -1;
        } else {
            rc = httpx_download_body(io, hdr, total, body_off, out_fd, timeout_ms,
                                     body_len, st);
        }
    } else {
        brix_status_set(st, XRDC_EPROTO, 0, "http: server returned status %d", status);
        rc = -1;
    }
    free(hdr);
    return rc;
}


/* ---- Run one connect -> GET -> stream-body attempt over a fresh transport ----
 *
 * WHAT: Opens a transport to host:port, seeks the destination to total_got when
 *       resuming, issues the GET, streams a 2xx body into out_fd, and tears the
 *       transport down. Reports the bytes written this attempt via *body_this
 *       (always set, including 0 on a connect failure). Returns 0 on a fully
 *       streamed body, -1 on any connect/exchange fault (st set by the callee).
 * WHY:  Isolates the per-attempt transport lifecycle (connect, optional resume
 *       seek, exchange, TLS/fd teardown) so the retry orchestrator stays a flat
 *       loop with no shared cleanup label and a bounded complexity.
 * HOW:  1) Zero *body_this so a connect failure contributes no progress.
 *       2) Connect; bail out -1 if the transport cannot be established.
 *       3) When resuming (total_got > 0) lseek the output to the resume offset.
 *       4) Exchange, forwarding http_status only on the first attempt so the
 *          caller records the ORIGINAL server status, not a resume 206.
 *       5) Free the TLS context and close the socket unconditionally, then
 *          return the exchange result. */
static int
http_download_attempt(const char *host, int port, int tls, const char *path,
                      const char *extra_headers, int verify, const char *ca_dir,
                      int out_fd, int timeout_ms, long long total_got,
                      int *http_status, long long *body_this, brix_status *st)
{
    brix_io  io;
    void    *tls_ctx = NULL;
    int      rc;

    *body_this = 0;
    if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                      &tls_ctx, st) != 0) {
        return -1;
    }
    if (total_got > 0) {
        (void) lseek(out_fd, (off_t) total_got, SEEK_SET);
    }
    rc = httpx_download_exchange(&io, host, port, path, extra_headers,
                                 total_got, out_fd, timeout_ms,
                                 /* report the ORIGINAL status only */
                                 total_got == 0 ? http_status : NULL,
                                 body_this, st);
    if (tls) { brix_tls_client_free(&io, tls_ctx); }
    if (io.fd >= 0) { close(io.fd); }
    return rc;
}


/* ---- Decide whether a faulted download attempt may be retried ----
 *
 * WHAT: Returns 1 when another attempt is permitted, 0 when the download must
 *       fail now. Retry is allowed only for a seekable destination with an
 *       active patience window, a transient (retryable) fault, and time left
 *       before the deadline.
 * WHY:  Keeps the four-way retry gate out of the orchestrator so its loop stays
 *       under the cyclomatic-complexity cap and the policy is stated in one place.
 * HOW:  1) Refuse if the destination is not seekable, the window is disabled
 *          (window_ms <= 0), or the fault is not retryable.
 *       2) Refuse if the time-since-progress deadline has elapsed.
 *       3) Otherwise permit a retry. */
static int
http_download_should_retry(int seekable, int window_ms, uint64_t deadline,
                           brix_status *st)
{
    if (!seekable || window_ms <= 0 || !brix_status_retryable(st)) {
        return 0;
    }
    if (brix_mono_ns() >= deadline) {
        return 0;
    }
    return 1;
}


int
brix_http_download(const char *host, int port, int tls, const char *path,
                   const char *extra_headers, int verify, const char *ca_dir,
                   int out_fd, int timeout_ms, int *http_status,
                   long long *body_len, brix_status *st)
{
    long long    total_got = 0;
    int          window_ms = httpx_window_ms();
    unsigned     attempt = 0;
    uint64_t     deadline;
    int          seekable;
    struct stat  stt;

    if (http_status != NULL) { *http_status = 0; }
    if (body_len != NULL)    { *body_len = 0; }

    /* Resume requires a seekable destination (a regular file); a pipe/stdout
     * cannot be rewound, so there we fall back to a single attempt. */
    seekable = (fstat(out_fd, &stt) == 0 && S_ISREG(stt.st_mode));
    deadline = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;

    /*
     * Deadline-bounded resume (mirrors the root:// resilience window).  On a
     * transport sever mid-download, reconnect and re-issue the GET with
     * Range: bytes=<bytes-already-written>- (server replies 206), appending the
     * remainder — so an HTTP download rides out packet loss instead of dying on
     * the first reset.  The deadline measures time-since-progress (it resets when
     * bytes are written), so a steadily-advancing transfer never times out.
     * window<=0 ($XRDC_MAX_STALL_MS=0) or a non-seekable dst ⇒ a single attempt.
     */
    for (;;) {
        long long  body_this = 0;
        int        rc;

        rc = http_download_attempt(host, port, tls, path, extra_headers, verify,
                                   ca_dir, out_fd, timeout_ms, total_got,
                                   http_status, &body_this, st);
        total_got += body_this;
        if (rc == 0) {
            if (body_len != NULL) { *body_len = total_got; }
            return 0;
        }

        /* Connect or transfer fault.  Retry only if we can resume (seekable),
         * the fault is transient, and the patience window has not elapsed. */
        if (!http_download_should_retry(seekable, window_ms, deadline, st)) {
            return -1;
        }
        if (body_this > 0) {
            deadline = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;
        }
        brix_backoff_sleep_fast(attempt++);
    }
}
