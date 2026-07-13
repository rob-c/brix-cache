/*
 * webfile_io.c - extracted concern
 * Phase-38 split of webfile.c; behavior-identical.
 */
#include "webfile_internal.h"


/* Persistent-connection ranged read (the FUSE read hot path)         */


void
web_disconnect(brix_webfile *wf)
{
    if (!wf->connected) {
        return;
    }
    if (wf->tls) {
        brix_tls_client_free(&wf->io, wf->tls_ctx);
        wf->tls_ctx = NULL;
    }
    if (wf->io.fd >= 0) {
        close(wf->io.fd);
    }
    wf->io.fd = -1;
    wf->connected = 0;
}


int
web_connect(brix_webfile *wf, brix_status *st)
{
    memset(&wf->io, 0, sizeof(wf->io));
    wf->io.fd = brix_tcp_connect(wf->host, wf->port, wf->timeout_ms, st);
    if (wf->io.fd < 0) {
        return -1;
    }
    wf->io.timeout_ms = wf->timeout_ms;
    if (wf->tls && brix_tls_client(&wf->io, wf->host, wf->verify, wf->verify,
                                   wf->ca_dir[0] ? wf->ca_dir : NULL,
                                   &wf->tls_ctx, st) != 0) {
        close(wf->io.fd);
        wf->io.fd = -1;
        return -1;
    }
    wf->connected = 1;
    return 0;
}


/* Read up to n bytes (branches on TLS). >0 bytes, 0 EOF, -1 error. */
ssize_t
web_read_some(brix_webfile *wf, void *buf, size_t n, brix_status *st)
{
    if (wf->io.ssl != NULL) {
        size_t got = 0;
        if (brix_tls_read_some(&wf->io, buf, n, &got, st) != 0) {
            return -1;
        }
        return (ssize_t) got;
    }
    struct pollfd pfd;
    ssize_t       r;
    int           pr;
    pfd.fd = wf->io.fd; pfd.events = POLLIN; pfd.revents = 0;
    do { pr = poll(&pfd, 1, wf->io.timeout_ms); } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
        brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno, "web read");
        return -1;
    }
    do { r = read(wf->io.fd, buf, n); } while (r < 0 && errno == EINTR);
    if (r < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "web read: %s", strerror(errno));
        return -1;
    }
    return r;
}


/* Case-insensitive header value lookup in a NUL-terminated header block. */
long long
hdr_clen(const char *hdrs)
{
    const char *p = hdrs;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            return strtoll(p + 15, NULL, 10);
        }
    }
    if (strncasecmp(hdrs, "Content-Length:", 15) == 0) {
        return strtoll(hdrs + 15, NULL, 10);
    }
    return -1;
}


/*
 * Response-header parse result carried out of web_range_read_headers.
 *
 * WHAT: the status line code plus the location of the CRLFCRLF terminator and
 *       the total header+overflow bytes sitting in the caller's header buffer.
 * WHY:  splitting the header read out of web_get_range means the status code,
 *       the end-of-headers pointer, and the amount already buffered (some of
 *       which is body) must all flow back to the body-streaming step.
 * HOW:  populated only on a 206/200 success; on 416/error the header reader
 *       returns the disposition directly and this struct is not consumed.
 */
typedef struct {
    char     *hbuf;      /* caller's header buffer (headers + any body overflow) */
    char     *eoh;       /* points at the "\r\n\r\n" terminator inside hbuf      */
    size_t    hlen;      /* total bytes read into hbuf (headers + body overflow) */
    long long clen;      /* parsed Content-Length (>= 0 on the success path)     */
    int       status;    /* HTTP status code (206 or 200 on the success path)    */
} web_range_hdr_t;


/*
 * Build and send the ranged GET request over the persistent socket.
 *
 * WHAT: format the keep-alive "GET … Range: bytes=off-end" request and write it.
 * WHY:  isolates request framing (the wire-frozen request line + headers) from
 *       response handling so web_get_range reads as a linear send/read/stream.
 * HOW:  snprintf into a caller-owned buffer; on overflow set EUSAGE, on a write
 *       fault disconnect (so the caller reconnects and retries). Returns 0 on
 *       success, -1 with st set (and wf disconnected on transport fault).
 */
static int
web_range_send_req(brix_webfile *wf, int64_t off, size_t len, brix_status *st)
{
    char req[3200];
    int  rn = snprintf(req, sizeof(req),
                       "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrootdfs\r\n"
                       "Accept: */*\r\nConnection: keep-alive\r\n"
                       "Range: bytes=%lld-%lld\r\n%s\r\n",
                       wf->path[0] ? wf->path : "/", wf->hostport,
                       (long long) off, (long long) (off + (int64_t) len - 1),
                       wf->auth);

    if (rn < 0 || (size_t) rn >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "web GET: request too long");
        return -1;
    }
    if (brix_write_full(&wf->io, req, (size_t) rn, st) != 0) {
        web_disconnect(wf);
        return -1;
    }
    return 0;
}


/*
 * Read response headers and evaluate the status line.
 *
 * WHAT: read up to CRLFCRLF into hbuf, parse the HTTP status, and classify it.
 * WHY:  concentrates the header-buffer loop and the status→disposition mapping
 *       (416 = empty read, 404/401/403/other = error) in one place so the body
 *       stream step only ever runs on a 206/200 with a valid Content-Length.
 * HOW:  fills hbuf (NUL-terminated), locates the terminator, parses the code,
 *       then NUL-terminates the header block and confirms Content-Length. On a
 *       success (206/200) writes *out and returns 1; on the range-past-EOF 416
 *       returns 0 (no bytes); on any error returns -1 with st set. Every non-1
 *       path that leaves the socket unusable disconnects wf.  On success *out
 *       carries hbuf, the terminator, the byte count, Content-Length, and status.
 */
static int
web_range_read_headers(brix_webfile *wf, char *hbuf, brix_status *st,
                       web_range_hdr_t *out)
{
    size_t  hlen = 0;
    char   *eoh = NULL;
    int     status = 0;
    long long clen;

    for (;;) {
        ssize_t r;
        if (hlen >= WEB_HDR_MAX) {
            web_disconnect(wf);
            brix_status_set(st, XRDC_EPROTO, 0, "web GET: header too large");
            return -1;
        }
        r = web_read_some(wf, hbuf + hlen, WEB_HDR_MAX - hlen, st);
        if (r <= 0) {
            web_disconnect(wf);
            if (r == 0) {
                brix_status_set(st, XRDC_ESOCK, 0, "web GET: peer closed");
            }
            return -1;
        }
        hlen += (size_t) r;
        hbuf[hlen] = '\0';
        eoh = strstr(hbuf, "\r\n\r\n");
        if (eoh != NULL) {
            break;
        }
    }

    if (strncmp(hbuf, "HTTP/", 5) == 0) {
        const char *sp = strchr(hbuf, ' ');
        status = sp ? atoi(sp + 1) : 0;
    }
    if (status == 416) {                 /* range past EOF → no bytes */
        return 0;
    }
    if (status != 206 && status != 200) {
        web_disconnect(wf);
        if (status == 404) {
            brix_status_set(st, kXR_NotFound, 0, "not found");
        } else if (status == 401 || status == 403) {
            brix_status_set(st, kXR_NotAuthorized, 0, "HTTP %d", status);
        } else {
            brix_status_set(st, XRDC_EPROTO, 0, "web GET: HTTP %d", status);
        }
        return -1;
    }

    *eoh = '\0';
    clen = hdr_clen(hbuf);
    if (clen < 0) {
        /* No Content-Length (e.g. chunked): we cannot keep the socket aligned;
         * bail and let the caller fall back (rare for a ranged GET). */
        web_disconnect(wf);
        brix_status_set(st, XRDC_EPROTO, 0, "web GET: no Content-Length");
        return -1;
    }

    out->hbuf = hbuf;
    out->eoh = eoh;
    out->hlen = hlen;
    out->clen = clen;
    out->status = status;
    return 1;
}


/*
 * Copy the wanted range bytes out of the parsed response and drain the rest.
 *
 * WHAT: emit up to len bytes of body into buf, reading the remainder past the
 *       header overflow and draining any body beyond what was wanted.
 * WHY:  the body path has its own resume semantics (partial forward progress on
 *       a mid-body sever) and keep-alive alignment (full-body drain) that read
 *       cleanly as one step separate from header parsing.
 * HOW:  seeds `copied` from the overflow already in hbuf, then reads the rest of
 *       `want` INCREMENTALLY so a mid-body sever returns the bytes copied so far
 *       (caller resumes at off+copied); finally drains to Content-Length to keep
 *       the connection aligned. Returns bytes delivered, or -1 with st set.
 */
static ssize_t
web_range_stream_body(brix_webfile *wf, void *buf, size_t len,
                      const web_range_hdr_t *hdr, brix_status *st)
{
    char   *bstart = hdr->eoh + 4;
    size_t  have = hdr->hlen - (size_t) (bstart - hdr->hbuf);
    size_t  want = (hdr->clen < (long long) len) ? (size_t) hdr->clen : len;
    size_t  copied = (have < want) ? have : want;
    size_t  total_body = (size_t) hdr->clen;   /* must fully consume */
    size_t  consumed;

    memcpy(buf, bstart, copied);
    consumed = have;                            /* bytes of body read so far */

    /*
     * Read the remainder of `want` INCREMENTALLY (not all-or-nothing): on a
     * mid-body sever, return the bytes copied SO FAR so the caller advances
     * `off` and resumes the rest with a fresh Range GET — forward progress
     * under repeated severs, instead of discarding the whole range and
     * re-reading it from the start (which never completes under heavy loss).
     */
    while (copied < want) {
        ssize_t br = web_read_some(wf, (char *) buf + copied,
                                   want - copied, st);
        if (br <= 0) {
            web_disconnect(wf);
            if (copied > 0) {
                return (ssize_t) copied;        /* partial; caller resumes */
            }
            if (br == 0) {
                brix_status_set(st, XRDC_ESOCK, 0,
                                "web GET: peer closed mid-body");
            }
            return -1;
        }
        consumed += (size_t) br;
        copied += (size_t) br;
    }
    /* drain any body beyond what we wanted, to keep the connection aligned
     * for the next keep-alive request (status 200 = server ignored Range) */
    while (consumed < total_body) {
        char    sink[8192];
        size_t  chunk = total_body - consumed;
        if (chunk > sizeof(sink)) {
            chunk = sizeof(sink);
        }
        if (brix_read_full(&wf->io, sink, chunk, st) != 0) {
            web_disconnect(wf);
            return (ssize_t) want;   /* have the wanted bytes; lost keep-alive */
        }
        consumed += chunk;
    }
    if (hdr->status == 200) {
        /* Range ignored: keep-alive is fine (we consumed the whole body), but
         * for a large file that is wasteful — leave the connection up; the
         * caller still got the right bytes for this offset. */
    }
    return (ssize_t) want;
}


/* One ranged GET over the (already-connected) persistent socket. Fills up to len
 * bytes at off into buf; returns bytes read (0 = EOF/416), or -1 (st set). On any
 * transport/protocol fault returns -1 AND disconnects so the caller can retry. */
ssize_t
web_get_range(brix_webfile *wf, int64_t off, void *buf, size_t len,
              brix_status *st)
{
    char            hbuf[WEB_HDR_MAX + 1];
    web_range_hdr_t hdr = {0};
    int             hr;

    if (web_range_send_req(wf, off, len, st) != 0) {
        return -1;
    }

    hr = web_range_read_headers(wf, hbuf, st, &hdr);
    if (hr <= 0) {
        return (ssize_t) hr;      /* 0 = 416 (no bytes), -1 = error (st set) */
    }

    return web_range_stream_body(wf, buf, len, &hdr, st);
}


brix_webfile *
brix_webfile_open(const brix_weburl *u, const char *path, const char *bearer,
                  int verify, const char *ca_dir, int timeout_ms,
                  brix_statinfo *si_out, brix_status *st)
{
    brix_webfile *wf;
    brix_statinfo si;

    /* stat first: confirms existence + gives the size (and feeds getattr). */
    if (brix_web_stat(u, path, bearer, verify, ca_dir, &si, st) != 0) {
        return NULL;
    }
    if (si.flags & kXR_isDir) {
        brix_status_set(st, XRDC_EUSAGE, 0, "is a directory");
        return NULL;
    }
    wf = calloc(1, sizeof(*wf));
    if (wf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return NULL;
    }
    snprintf(wf->host, sizeof(wf->host), "%s", u->host);
    wf->port = u->port;
    wf->tls = u->tls;
    wf->verify = verify;
    if (ca_dir != NULL) {
        snprintf(wf->ca_dir, sizeof(wf->ca_dir), "%s", ca_dir);
    }
    snprintf(wf->path, sizeof(wf->path), "%s", path);
    web_auth(bearer, wf->auth, sizeof(wf->auth));
    brix_format_host_port(u->host, (uint16_t) u->port, wf->hostport,
                            sizeof(wf->hostport));
    wf->timeout_ms = timeout_ms > 0 ? timeout_ms : WEB_TIMEOUT_MS;
    wf->size = si.size;
    wf->io.fd = -1;
    if (si_out != NULL) {
        *si_out = si;
    }
    return wf;
}


int64_t
brix_webfile_size(const brix_webfile *wf)
{
    return wf->size;
}


/* Resilience window (ms) for HTTP reads: $XRDC_MAX_STALL_MS when set (>0 widens,
 * <=0 disables = fail fast), else the xrdrc [defaults] max_stall_ms, else the
 * library default — the SAME window the root:// data path uses, so an HTTP
 * download rides out packet loss the same way instead of dying on the first sever. */
int
webfile_window_ms(void)
{
    const char *e = getenv("XRDC_MAX_STALL_MS");
    if (e != NULL && *e != '\0') {
        int v = atoi(e);
        return (v > 0) ? v : 0;
    }
    { int xv; if (brix_xrdrc_default_ms("max_stall_ms", &xv)) { return xv; } }
    return XRDC_DEFAULT_MAX_STALL_MS;
}


ssize_t
brix_webfile_pread(brix_webfile *wf, int64_t off, void *buf, size_t len,
                   brix_status *st)
{
    uint64_t deadline;
    unsigned attempt = 0;
    int      window_ms;
    size_t   got = 0;

    if (off >= wf->size) {
        return 0;                                  /* past EOF */
    }
    if ((int64_t) len > wf->size - off) {
        len = (size_t) (wf->size - off);           /* clamp tail read */
    }
    if (len == 0) {
        return 0;
    }

    /*
     * Deadline-bounded resume (mirrors the root:// resilience window).  On a
     * transport sever, reconnect and re-issue the Range GET from off+got —
     * web_get_range resumes there and returns PARTIAL progress on a mid-body
     * sever, so this loop accumulates `len` bytes across reconnects rather than
     * failing on the first reset.  The deadline measures time-since-progress (it
     * resets on every byte read), so a steadily-advancing transfer never times
     * out — only a true stall (no progress for the whole window) does.  A non-
     * retryable fault (404/403/…) or window<=0 ($XRDC_MAX_STALL_MS=0, fail-fast)
     * returns immediately.
     */
    window_ms = webfile_window_ms();
    deadline = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;

    for (;;) {
        if (wf->connected || web_connect(wf, st) == 0) {
            ssize_t r = web_get_range(wf, off + (int64_t) got,
                                      (char *) buf + got, len - got, st);
            if (r > 0) {
                got += (size_t) r;
                if (got >= len) {
                    return (ssize_t) got;          /* full read */
                }
                attempt = 0;                       /* progress: reset backoff */
                if (window_ms > 0) {
                    deadline = brix_mono_ns()
                             + (uint64_t) window_ms * 1000000ULL;
                }
                continue;                          /* resume at off+got */
            }
            if (r == 0) {
                return (ssize_t) got;              /* genuine EOF */
            }
            /* r < 0: transport/protocol fault — fall through to the retry gate. */
        }
        if (window_ms <= 0 || !brix_status_retryable(st)
            || brix_mono_ns() >= deadline) {
            return (got > 0) ? (ssize_t) got : -1;
        }
        brix_backoff_sleep_fast(attempt++);
    }
}


void
brix_webfile_close(brix_webfile *wf, brix_status *st)
{
    (void) st;
    if (wf == NULL) {
        return;
    }
    web_disconnect(wf);
    free(wf);
}
