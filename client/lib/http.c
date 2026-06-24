/*
 * http.c — a minimal cleartext HTTP/1.0 GET, for xrddiag's observability pulls.
 *
 * WHAT: xrdc_http_get() fetches a URL path over plain HTTP/1.0 and returns the
 *       response body + status code.
 * WHY:  The native client speaks root:// only, but the server's observability
 *       plane (/metrics on :9100, the dashboard /xrootd/api/v1 JSON) is HTTP.
 *       xrddiag correlates what it observes with what the server reports — this
 *       is the one HTTP touch, kept tiny so we add no libcurl/TLS dependency.
 * HOW:  Connect via xrdc_tcp_connect (sock.c), send "GET <path> HTTP/1.0" with
 *       Connection: close, read to EOF (HTTP/1.0 close-delimits the body), parse
 *       the status line, and hand back everything past the blank line.
 *
 * Scope: cleartext only, no chunked-transfer decode, no redirects — sufficient
 * for the loopback metrics/dashboard endpoints. Not a general HTTP client.
 */
#include "xrdc.h"
#include "compat/host_format.h"   /* IPv6-aware Host: header formatting (libxrdproto) */

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define XRDC_HTTP_MAX (1u << 20)   /* 1 MiB response ceiling */

int
xrdc_http_get(const char *host, int port, const char *path, int timeout_ms,
              int *http_status, char *out, size_t outsz, size_t *outlen,
              xrdc_status *st)
{
    char     req[1024];
    char    *resp;
    size_t   total = 0, cap;
    int      fd, rlen;
    char    *body, *eoh;

    if (outsz == 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http_get: zero out buffer");
        return -1;
    }
    if (http_status != NULL) {
        *http_status = 0;
    }

    fd = xrdc_tcp_connect(host, port, timeout_ms, st);
    if (fd < 0) {
        return -1;
    }

    char hp[300];
    xrootd_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                    path, hp);
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        close(fd);
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http_get: request too long");
        return -1;
    }
    /* Blocking write of the (small) request. */
    {
        ssize_t w, off = 0;
        while (off < rlen) {
            w = write(fd, req + off, (size_t) (rlen - off));
            if (w < 0) {
                if (errno == EINTR) { continue; }
                close(fd);
                xrdc_status_set(st, XRDC_ESOCK, errno, "http write: %s",
                                strerror(errno));
                return -1;
            }
            off += w;
        }
    }

    cap = XRDC_HTTP_MAX;
    resp = (char *) malloc(cap);
    if (resp == NULL) {
        close(fd);
        xrdc_status_set(st, XRDC_EPROTO, 0, "http_get: out of memory");
        return -1;
    }

    /* Read to EOF (HTTP/1.0 + Connection: close), bounded by poll + the ceiling. */
    for (;;) {
        struct pollfd pfd;
        ssize_t       r;
        int           pr;

        if (total >= cap - 1) {
            break;   /* hit the ceiling — keep what we have */
        }
        pfd.fd = fd;
        pfd.events = POLLIN;
        do {
            pr = poll(&pfd, 1, timeout_ms);
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            free(resp);
            close(fd);
            xrdc_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
                            "http read %s", pr == 0 ? "timed out" : "poll failed");
            return -1;
        }
        r = read(fd, resp + total, cap - 1 - total);
        if (r == 0) {
            break;   /* EOF — server closed, body complete */
        }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN) { continue; }
            free(resp);
            close(fd);
            xrdc_status_set(st, XRDC_ESOCK, errno, "http read: %s", strerror(errno));
            return -1;
        }
        total += (size_t) r;
    }
    close(fd);
    resp[total] = '\0';

    /* Status line: "HTTP/1.x NNN ...". */
    if (http_status != NULL && strncmp(resp, "HTTP/", 5) == 0) {
        char *sp = strchr(resp, ' ');
        if (sp != NULL) {
            *http_status = atoi(sp + 1);
        }
    }

    /* Body starts past the blank line. Copy binary-safe (memcpy, not snprintf —
     * a NUL byte must not truncate the body) and report the body length so
     * callers can checksum the exact bytes. */
    eoh = strstr(resp, "\r\n\r\n");
    body = eoh ? eoh + 4 : resp;
    {
        size_t bodylen = total - (size_t) (body - resp);
        size_t n = (bodylen < outsz - 1) ? bodylen : outsz - 1;
        memcpy(out, body, n);
        out[n] = '\0';
        if (outlen != NULL) {
            *outlen = n;
        }
    }
    free(resp);
    return 0;
}

/* ------------------------------------------------------------------ */
/* general HTTP/1.1 client (cleartext or TLS) — for the multi-protocol */
/* deep-dive (https/davs/s3 batteries). Reads to EOF (Connection:close). */
/* ------------------------------------------------------------------ */

#define XRDC_HTTPX_MAX (8u << 20)   /* 8 MiB body ceiling for the deep-dive */

/* Read up to n bytes; branches on TLS. Returns bytes (>0), 0 on EOF, -1 on error. */
static ssize_t
httpx_read_some(xrdc_io *io, void *buf, size_t n, int timeout_ms, xrdc_status *st)
{
    if (io->ssl != NULL) {
        size_t got = 0;
        if (xrdc_tls_read_some(io, buf, n, &got, st) != 0) {
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
            xrdc_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
                            "http read %s", pr == 0 ? "timed out" : "poll failed");
            return -1;
        }
        do { r = read(io->fd, buf, n); } while (r < 0 && errno == EINTR);
        if (r < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "http read: %s", strerror(errno));
            return -1;
        }
        return r;
    }
}

/* Case-insensitive substring (for a Transfer-Encoding: chunked check). */
static int
ci_contains(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    for (; *hay != '\0'; hay++) {
        if (strncasecmp(hay, needle, nl) == 0) { return 1; }
    }
    return 0;
}

/* De-chunk a Transfer-Encoding: chunked body in place; returns new length. */
static size_t
dechunk(char *b, size_t len)
{
    size_t in = 0, out = 0;
    while (in < len) {
        char  *endp = NULL;
        long   csz = strtol(b + in, &endp, 16);
        if (endp == NULL || csz < 0) { break; }
        while (in < len && b[in] != '\n') { in++; }   /* skip to end of size line */
        if (in < len) { in++; }                        /* past the '\n' */
        if (csz == 0) { break; }                        /* last chunk */
        if (in + (size_t) csz > len) { csz = (long) (len - in); }
        memmove(b + out, b + in, (size_t) csz);
        out += (size_t) csz;
        in  += (size_t) csz;
        while (in < len && (b[in] == '\r' || b[in] == '\n')) { in++; }  /* trailing CRLF */
    }
    b[out] = '\0';
    return out;
}

void
xrdc_http_resp_free(xrdc_http_resp *resp)
{
    if (resp != NULL && resp->body != NULL) {
        free(resp->body);
        resp->body = NULL;
    }
}

/* The canonical raw-header-block scanner is raw_header() (defined below); both
 * the public lookup and the streaming-download path share that one body. */
static int raw_header(const char *hdr, const char *name, char *out, size_t outsz);

int
xrdc_http_header(const xrdc_http_resp *resp, const char *name, char *out, size_t outsz)
{
    return raw_header(resp->headers, name, out, outsz);
}

/* Parse the read buffer into resp (status line + header block + body). Pure. */
static void
httpx_parse(char *buf, size_t total, xrdc_http_resp *resp)
{
    char *eoh;
    if (strncmp(buf, "HTTP/", 5) == 0) {
        char *sp = strchr(buf, ' ');
        if (sp != NULL) {
            char *r2  = strchr(sp + 1, ' ');
            char *eol = strstr(buf, "\r\n");
            resp->status = atoi(sp + 1);
            if (r2 != NULL && eol != NULL && r2 < eol) {
                size_t n = (size_t) (eol - (r2 + 1));
                if (n >= sizeof(resp->reason)) { n = sizeof(resp->reason) - 1; }
                memcpy(resp->reason, r2 + 1, n);
                resp->reason[n] = '\0';
            }
        }
    }
    eoh = strstr(buf, "\r\n\r\n");
    if (eoh != NULL) {
        size_t hlen    = (size_t) (eoh - buf);
        size_t hn      = (hlen < sizeof(resp->headers) - 1) ? hlen : sizeof(resp->headers) - 1;
        char  *bstart  = eoh + 4;
        size_t bodylen = total - (size_t) (bstart - buf);
        memcpy(resp->headers, buf, hn);
        resp->headers[hn] = '\0';
        resp->body = (char *) malloc(bodylen + 1);
        if (resp->body != NULL) {
            memcpy(resp->body, bstart, bodylen);
            resp->body[bodylen] = '\0';
            resp->body_len = bodylen;
            if (ci_contains(resp->headers, "Transfer-Encoding: chunked")) {
                resp->body_len = dechunk(resp->body, resp->body_len);
            }
        }
    } else {
        size_t hn = (total < sizeof(resp->headers) - 1) ? total : sizeof(resp->headers) - 1;
        memcpy(resp->headers, buf, hn);
        resp->headers[hn] = '\0';
    }
}

/* Decide whether the full response body has arrived in buf[0,total) given the
 * header block end (body_off) and the framing parsed from the headers.
 *
 * WHY: Some servers (notably XrdHttp) advertise "Connection: Close" yet keep the
 *      TLS socket open after the body, so reading to EOF blocks until timeout. We
 *      must stop exactly at the framed body length instead. Returns 1 when the
 *      body is complete; 0 means "keep reading" (genuine EOF still terminates). */
static int
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

/* The protocol exchange over an established (and TLS-wrapped, if any) io: build +
 * send the request, read the framed response (Content-Length / chunked / EOF),
 * parse it. Owns its own scratch buffer
 * so the caller's teardown stays linear (no shared cleanup label). 0 / -1. */
static int
httpx_exchange(xrdc_io *io, const char *host, int port, const char *method,
               const char *path, const char *extra_headers, const void *body,
               size_t blen, int timeout_ms, xrdc_http_resp *resp, xrdc_status *st)
{
    char   req[2048];
    char  *buf;
    size_t total = 0, cap = XRDC_HTTPX_MAX;
    int    rlen;

    char hp[300];
    xrootd_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrddiag\r\n"
                    "Accept: */*\r\nConnection: close\r\n%s%s",
                    method, path[0] ? path : "/", hp,
                    extra_headers ? extra_headers : "",
                    (body != NULL && blen > 0) ? "" : "\r\n");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http_req: request too long");
        return -1;
    }
    if (body != NULL && blen > 0) {
        char cl[64];
        int  cn = snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n\r\n", blen);
        if (cn < 0 || (size_t) (rlen + cn) >= sizeof(req)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "http_req: request too long");
            return -1;
        }
        memcpy(req + rlen, cl, (size_t) cn);
        rlen += cn;
    }
    if (xrdc_write_full(io, req, (size_t) rlen, st) != 0) {
        return -1;
    }
    if (body != NULL && blen > 0 && xrdc_write_full(io, body, blen, st) != 0) {
        return -1;
    }

    buf = (char *) malloc(cap);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "http_req: out of memory");
        return -1;
    }
    {
        int       have_hdrs = 0, chunked = 0;
        size_t    body_off = 0;
        long long clen = -1;
        for (;;) {
            ssize_t r;
            /* Stop as soon as the framed body is complete — do NOT wait for EOF:
             * XrdHttp advertises "Connection: Close" but keeps the socket open. */
            if (have_hdrs &&
                httpx_body_complete(buf, total, body_off, clen, chunked)) {
                break;
            }
            if (total >= cap - 1) {
                /* At the ceiling: one more read distinguishes a genuine EOF from a
                 * truncated body — a silent truncation would corrupt a checksum probe. */
                char    sink[1];
                ssize_t extra = httpx_read_some(io, sink, 1, timeout_ms, st);
                if (extra < 0) { free(buf); return -1; }
                if (extra > 0) {
                    free(buf);
                    xrdc_status_set(st, XRDC_EPROTO, 0,
                                    "http_req: response body exceeds the 8 MiB diagnostic limit");
                    return -1;
                }
                break;   /* extra == 0: EOF exactly at the ceiling */
            }
            r = httpx_read_some(io, buf + total, cap - 1 - total, timeout_ms, st);
            if (r < 0) { free(buf); return -1; }
            if (r == 0) { break; }                       /* genuine EOF */
            total += (size_t) r;
            if (!have_hdrs) {
                char *eoh = memmem(buf, total, "\r\n\r\n", 4);
                if (eoh != NULL) {
                    char  cl[64];
                    char *save = eoh + 4;
                    char  saved = *save;
                    *save = '\0';                        /* NUL-terminate header block */
                    have_hdrs = 1;
                    body_off  = (size_t) (eoh + 4 - buf);
                    if (raw_header(buf, "Transfer-Encoding", cl, sizeof(cl)) &&
                        ci_contains(cl, "chunked")) {
                        chunked = 1;
                    } else if (raw_header(buf, "Content-Length", cl, sizeof(cl))) {
                        clen = strtoll(cl, NULL, 10);
                    }
                    *save = saved;                       /* restore the byte */
                }
            }
        }
    }
    buf[total] = '\0';
    httpx_parse(buf, total, resp);
    free(buf);
    return 0;
}

/* Establish the TCP (and, if tls, TLS) transport for an HTTP request. On success
 * io->fd is open and (for tls) io->ssl is set; *tls_ctx holds the context to free.
 * 0 / -1 (st set; socket closed on failure). */
static int
httpx_connect(xrdc_io *io, const char *host, int port, int tls, int verify,
              const char *ca_dir, int timeout_ms, void **tls_ctx, xrdc_status *st)
{
    memset(io, 0, sizeof(*io));
    *tls_ctx = NULL;
    io->fd = xrdc_tcp_connect(host, port, timeout_ms, st);
    if (io->fd < 0) {
        return -1;
    }
    io->timeout_ms = timeout_ms;
    if (tls && xrdc_tls_client(io, host, verify, verify, ca_dir, tls_ctx, st) != 0) {
        close(io->fd);
        io->fd = -1;
        return -1;
    }
    return 0;
}

int
xrdc_http_req(const char *host, int port, int tls, const char *method,
              const char *path, const char *extra_headers,
              const void *body, size_t blen, int timeout_ms, int verify,
              const char *ca_dir, xrdc_http_resp *resp, xrdc_status *st)
{
    xrdc_io  io;
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
        xrdc_tls_client_info(&io, &v, &c);
        snprintf(resp->tls_ver, sizeof(resp->tls_ver), "%s", v ? v : "?");
        snprintf(resp->tls_cipher, sizeof(resp->tls_cipher), "%s", c ? c : "?");
    }

    rc = httpx_exchange(&io, host, port, method, path, extra_headers, body, blen,
                        timeout_ms, resp, st);

    if (tls) {
        xrdc_tls_client_free(&io, tls_ctx);
    }
    close(io.fd);
    if (rc != 0) {
        xrdc_http_resp_free(resp);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* streaming transfer (production GET/PUT, any size) — body never fully */
/* buffered; bytes flow socket↔fd through a fixed scratch window.        */
/* ------------------------------------------------------------------ */

#define XRDC_XFER_BUF (1u << 16)   /* 64 KiB socket↔fd window */
#define XRDC_HDR_CAP  (1u << 14)   /* 16 KiB response-header ceiling */

/* A byte source that first drains leftover bytes captured while reading the
 * header block, then reads from the socket. Unifies "post-header body already in
 * the header buffer" with "more body on the wire" for the framing decoders. */
typedef struct {
    xrdc_io *io;
    char    *lo;        /* leftover buffer (header buf) */
    size_t   lo_len;    /* valid leftover bytes */
    size_t   lo_off;    /* consumed so far */
    int      timeout_ms;
} body_src;

static ssize_t
bsrc_read(body_src *s, void *buf, size_t n, xrdc_status *st)
{
    if (s->lo_off < s->lo_len) {
        size_t avail = s->lo_len - s->lo_off;
        size_t cp = (avail < n) ? avail : n;
        memcpy(buf, s->lo + s->lo_off, cp);
        s->lo_off += cp;
        return (ssize_t) cp;
    }
    return httpx_read_some(s->io, buf, n, s->timeout_ms, st);
}

/* Read one CRLF-terminated line (e.g. a chunk-size line) into out[outsz]; the
 * trailing CRLF is stripped. 0 / -1. */
static int
bsrc_getline(body_src *s, char *out, size_t outsz, xrdc_status *st)
{
    size_t n = 0;
    for (;;) {
        char    ch;
        ssize_t r = bsrc_read(s, &ch, 1, st);
        if (r < 0) { return -1; }
        if (r == 0) { break; }
        if (ch == '\n') { break; }
        if (ch == '\r') { continue; }
        if (n + 1 < outsz) { out[n++] = ch; }
    }
    out[n] = '\0';
    return 0;
}

static int
write_all_fd(int fd, const char *buf, size_t n, xrdc_status *st)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) { continue; }
            xrdc_status_set(st, XRDC_ESOCK, errno, "local write: %s", strerror(errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* Stream a Content-Length-bounded body (`remaining` bytes) from src to out_fd. */
static int
stream_clen(body_src *src, long long remaining, int out_fd, long long *written,
            xrdc_status *st)
{
    char buf[XRDC_XFER_BUF];
    while (remaining > 0) {
        size_t  want = (remaining < (long long) sizeof(buf))
                       ? (size_t) remaining : sizeof(buf);
        ssize_t r = bsrc_read(src, buf, want, st);
        if (r < 0) { return -1; }
        if (r == 0) {
            xrdc_status_set(st, XRDC_EPROTO, 0,
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
static int
stream_eof(body_src *src, int out_fd, long long *written, xrdc_status *st)
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
static int
stream_chunked(body_src *src, int out_fd, long long *written, xrdc_status *st)
{
    char buf[XRDC_XFER_BUF];
    for (;;) {
        char  line[64];
        long  csz;
        char *endp = NULL;
        if (bsrc_getline(src, line, sizeof(line), st) != 0) { return -1; }
        csz = strtol(line, &endp, 16);
        if (endp == line || csz < 0) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "http: bad chunk size");
            return -1;
        }
        if (csz == 0) { break; }                 /* last chunk */
        while (csz > 0) {
            size_t  want = (csz < (long) sizeof(buf)) ? (size_t) csz : sizeof(buf);
            ssize_t r = bsrc_read(src, buf, want, st);
            if (r <= 0) {
                xrdc_status_set(st, XRDC_EPROTO, 0, "http: chunk truncated");
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
static int
read_resp_headers(xrdc_io *io, char *hdr, size_t hdrcap, int timeout_ms,
                  int *status, size_t *total, size_t *body_off, xrdc_status *st)
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
        xrdc_status_set(st, XRDC_EPROTO, 0, "http: response headers too large/truncated");
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
static int
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
static int
httpx_download_body(xrdc_io *io, char *hdr, size_t total, size_t body_off,
                    int out_fd, int timeout_ms, long long *body_len,
                    xrdc_status *st)
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
            xrdc_status_set(st, XRDC_EPROTO, 0,
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
static int
httpx_download_exchange(xrdc_io *io, const char *host, int port,
                        const char *path, const char *extra_headers,
                        long long start_off, int out_fd,
                        int timeout_ms, int *http_status, long long *body_len,
                        xrdc_status *st)
{
    char    *hdr;
    char     req[2048];
    char     rangeh[64];
    size_t   total = 0, body_off = 0;
    int      status = 0, rlen, rc;

    char hp[300];
    xrootd_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
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
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (xrdc_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "http: out of memory");
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
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "http: resume Range ignored (status %d)", status);
            rc = -1;
        } else {
            rc = httpx_download_body(io, hdr, total, body_off, out_fd, timeout_ms,
                                     body_len, st);
        }
    } else {
        xrdc_status_set(st, XRDC_EPROTO, 0, "http: server returned status %d", status);
        rc = -1;
    }
    free(hdr);
    return rc;
}

/* Resilience window (ms) for HTTP downloads: $XRDC_MAX_STALL_MS when set (>0
 * widens, <=0 disables = fail fast), else the library default — the SAME window
 * the root:// data path uses. */
static int
httpx_window_ms(void)
{
    const char *e = getenv("XRDC_MAX_STALL_MS");
    if (e != NULL && *e != '\0') {
        int v = atoi(e);
        return (v > 0) ? v : 0;
    }
    return XRDC_DEFAULT_MAX_STALL_MS;
}

int
xrdc_http_download(const char *host, int port, int tls, const char *path,
                   const char *extra_headers, int verify, const char *ca_dir,
                   int out_fd, int timeout_ms, int *http_status,
                   long long *body_len, xrdc_status *st)
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
    deadline = xrdc_mono_ns() + (uint64_t) window_ms * 1000000ULL;

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
        xrdc_io    io;
        void      *tls_ctx = NULL;
        long long  body_this = 0;
        int        rc = -1;

        if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                          &tls_ctx, st) == 0) {
            if (total_got > 0) {
                (void) lseek(out_fd, (off_t) total_got, SEEK_SET);
            }
            rc = httpx_download_exchange(&io, host, port, path, extra_headers,
                                         total_got, out_fd, timeout_ms,
                                         /* report the ORIGINAL status only */
                                         total_got == 0 ? http_status : NULL,
                                         &body_this, st);
            if (tls) { xrdc_tls_client_free(&io, tls_ctx); }
            if (io.fd >= 0) { close(io.fd); }
            total_got += body_this;
            if (rc == 0) {
                if (body_len != NULL) { *body_len = total_got; }
                return 0;
            }
        }

        /* Connect or transfer fault.  Retry only if we can resume (seekable),
         * the fault is transient, and the patience window has not elapsed. */
        if (!seekable || window_ms <= 0 || !xrdc_status_retryable(st)
            || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        if (body_this > 0) {
            deadline = xrdc_mono_ns() + (uint64_t) window_ms * 1000000ULL;
        }
        xrdc_backoff_sleep_fast(attempt++);
    }
}

/* Stream `clen` bytes from in_fd to the connected io as the PUT body. The source
 * shrinking mid-stream is a protocol error (the Content-Length already promised
 * the full size). 0 / -1 (st set on error). */
static int
httpx_upload_body(xrdc_io *io, int in_fd, long long clen, xrdc_status *st)
{
    char      buf[XRDC_XFER_BUF];
    long long remaining = clen;

    while (remaining > 0) {
        size_t  want = (remaining < (long long) sizeof(buf))
                       ? (size_t) remaining : sizeof(buf);
        ssize_t r = read(in_fd, buf, want);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            xrdc_status_set(st, XRDC_ESOCK, errno, "local read: %s", strerror(errno));
            return -1;
        }
        if (r == 0) {
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "upload: source shrank (%lld bytes short)", remaining);
            return -1;
        }
        if (xrdc_write_full(io, buf, (size_t) r, st) != 0) { return -1; }
        remaining -= r;
    }
    return 0;
}

/* Read the PUT response headers and map a 2xx status to success. Owns its scratch
 * header buffer (allocated, used, freed on every path) so the orchestrator's
 * transport teardown stays linear. 0 / -1 (st set on error). */
static int
httpx_upload_response(xrdc_io *io, int timeout_ms, int *http_status,
                      xrdc_status *st)
{
    char  *hdr;
    size_t total = 0, body_off = 0;
    int    status = 0, rc;

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "http: out of memory");
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
        xrdc_status_set(st, XRDC_EPROTO, 0, "upload: server returned status %d", status);
        rc = -1;
    }
    return rc;
}

/* Send the PUT request line + headers, stream the body, and read the response —
 * over an already-connected io. Flat early-return so the orchestrator's transport
 * teardown needs no shared cleanup label. 0 / -1 (st set on error). */
static int
httpx_upload_exchange(xrdc_io *io, const char *host, int port, const char *path,
                      const char *extra_headers, int in_fd, long long clen,
                      int timeout_ms, int *http_status, xrdc_status *st)
{
    char req[2048];
    int  rlen;

    char hp[300];
    xrootd_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n%s\r\n",
                    path[0] ? path : "/", hp, clen,
                    extra_headers ? extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (xrdc_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }
    if (httpx_upload_body(io, in_fd, clen, st) != 0) { return -1; }
    return httpx_upload_response(io, timeout_ms, http_status, st);
}

/* Case-insensitively scan a header block [hdr, hdr+len) for "X-Upload-Offset"
 * and return its value, or -1 if absent/unparsable. */
static long long
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
static int
httpx_upload_chunk(xrdc_io *io, const char *host, int port, const char *path,
                   const char *extra_headers, int in_fd, long long off,
                   long long chunk_len, long long total, int timeout_ms,
                   int *status_out, long long *srv_off_out, xrdc_status *st)
{
    char  req[2048];
    char  hp[300];
    int   rlen;
    char *hdr;
    size_t hdrtotal = 0, body_off = 0;
    int   status = 0;

    *srv_off_out = -1;
    if (lseek(in_fd, (off_t) off, SEEK_SET) == (off_t) -1) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "lseek: %s", strerror(errno));
        return -1;
    }
    xrootd_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrdcp\r\n"
                    "Connection: close\r\nContent-Length: %lld\r\n"
                    "Content-Range: bytes %lld-%lld/%lld\r\n%s\r\n",
                    path[0] ? path : "/", hp, chunk_len,
                    off, off + chunk_len - 1, total,
                    extra_headers ? extra_headers : "");
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "http: request too long");
        return -1;
    }
    if (xrdc_write_full(io, req, (size_t) rlen, st) != 0) { return -1; }
    if (httpx_upload_body(io, in_fd, chunk_len, st) != 0) { return -1; }

    hdr = (char *) malloc(XRDC_HDR_CAP);
    if (hdr == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "http: out of memory");
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
 * server's xrootd_webdav_upload_resume; against a server without it the first
 * Content-Range PUT is treated as a whole-body write (commit) and this still
 * works for a single-shot upload.  0 / -1 (st set).
 */
int
xrdc_http_upload_resumable(const char *host, int port, int tls, const char *path,
                           const char *extra_headers, int in_fd, long long clen,
                           int verify, const char *ca_dir, int timeout_ms,
                           int max_stall_ms, int *http_status, xrdc_status *st)
{
    long long off = 0;
    unsigned  attempt = 0;
    uint64_t  deadline = xrdc_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    const long long CHUNK = 8LL * 1024 * 1024;

    if (http_status != NULL) { *http_status = 0; }

    while (off < clen) {
        xrdc_io   io;
        void     *tls_ctx = NULL;
        long long chunk = (clen - off < CHUNK) ? (clen - off) : CHUNK;
        int       status = 0;
        long long srv_off = -1;
        int       rc;

        if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                          &tls_ctx, st) != 0) {
            if (max_stall_ms <= 0 || !xrdc_status_retryable(st)
                || xrdc_mono_ns() >= deadline) {
                return -1;
            }
            xrdc_backoff_sleep_fast(attempt++);
            continue;
        }

        rc = httpx_upload_chunk(&io, host, port, path, extra_headers, in_fd,
                                off, chunk, clen, timeout_ms,
                                &status, &srv_off, st);
        if (tls) { xrdc_tls_client_free(&io, tls_ctx); }
        if (io.fd >= 0) { close(io.fd); }

        if (rc != 0) {
            /* transport sever: reconnect and resume from the same offset */
            if (max_stall_ms <= 0 || !xrdc_status_retryable(st)
                || xrdc_mono_ns() >= deadline) {
                return -1;
            }
            xrdc_backoff_sleep_fast(attempt++);
            continue;
        }

        if (http_status != NULL) { *http_status = status; }
        deadline = xrdc_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
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
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "upload: server returned status %d", status);
        return -1;
    }
    return 0;
}

int
xrdc_http_upload(const char *host, int port, int tls, const char *path,
                 const char *extra_headers, int in_fd, long long clen,
                 int verify, const char *ca_dir, int timeout_ms,
                 int *http_status, xrdc_status *st)
{
    xrdc_io  io;
    void    *tls_ctx = NULL;
    int      rc;

    if (http_status != NULL) { *http_status = 0; }
    if (httpx_connect(&io, host, port, tls, verify, ca_dir, timeout_ms,
                      &tls_ctx, st) != 0) {
        return -1;
    }

    rc = httpx_upload_exchange(&io, host, port, path, extra_headers, in_fd, clen,
                               timeout_ms, http_status, st);

    if (tls) { xrdc_tls_client_free(&io, tls_ctx); }
    if (io.fd >= 0) { close(io.fd); }
    return rc;
}
