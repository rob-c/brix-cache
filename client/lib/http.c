/*
 * http.c - (kept) routing + shared helpers
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"

int
brix_http_get(const char *host, int port, const char *path, int timeout_ms,
              int *http_status, char *out, size_t outsz, size_t *outlen,
              brix_status *st)
{
    char     req[1024];
    char    *resp;
    size_t   total = 0, cap;
    int      fd, rlen;
    char    *body, *eoh;

    if (outsz == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "http_get: zero out buffer");
        return -1;
    }
    if (http_status != NULL) {
        *http_status = 0;
    }

    fd = brix_tcp_connect(host, port, timeout_ms, st);
    if (fd < 0) {
        return -1;
    }

    char hp[300];
    brix_format_host_port(host, (uint16_t) port, hp, sizeof(hp));
    rlen = snprintf(req, sizeof(req),
                    "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                    path, hp);
    if (rlen < 0 || (size_t) rlen >= sizeof(req)) {
        close(fd);
        brix_status_set(st, XRDC_EUSAGE, 0, "http_get: request too long");
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
                brix_status_set(st, XRDC_ESOCK, errno, "http write: %s",
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
        brix_status_set(st, XRDC_EPROTO, 0, "http_get: out of memory");
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
            brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
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
            brix_status_set(st, XRDC_ESOCK, errno, "http read: %s", strerror(errno));
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


/* Case-insensitive substring (for a Transfer-Encoding: chunked check). */
int
ci_contains(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    for (; *hay != '\0'; hay++) {
        if (strncasecmp(hay, needle, nl) == 0) { return 1; }
    }
    return 0;
}


/* De-chunk a Transfer-Encoding: chunked body in place; returns new length. */
size_t
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
brix_http_resp_free(brix_http_resp *resp)
{
    if (resp != NULL && resp->body != NULL) {
        free(resp->body);
        resp->body = NULL;
    }
}


/* The canonical raw-header-block scanner is raw_header() (defined below); both
 * the public lookup and the streaming-download path share that one body. */

int
brix_http_header(const brix_http_resp *resp, const char *name, char *out, size_t outsz)
{
    return raw_header(resp->headers, name, out, outsz);
}


/* Parse the read buffer into resp (status line + header block + body). Pure. */
void
httpx_parse(char *buf, size_t total, brix_http_resp *resp)
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


/* Establish the TCP (and, if tls, TLS) transport for an HTTP request. On success
 * io->fd is open and (for tls) io->ssl is set; *tls_ctx holds the context to free.
 * 0 / -1 (st set; socket closed on failure). */
int
httpx_connect(brix_io *io, const char *host, int port, int tls, int verify,
              const char *ca_dir, int timeout_ms, void **tls_ctx, brix_status *st)
{
    memset(io, 0, sizeof(*io));
    *tls_ctx = NULL;
    io->fd = brix_tcp_connect(host, port, timeout_ms, st);
    if (io->fd < 0) {
        return -1;
    }
    io->timeout_ms = timeout_ms;
    if (tls && brix_tls_client(io, host, verify, verify, ca_dir, tls_ctx, st) != 0) {
        close(io->fd);
        io->fd = -1;
        return -1;
    }
    return 0;
}


/* streaming transfer (production GET/PUT, any size) — body never fully */
/* buffered; bytes flow socket↔fd through a fixed scratch window.        */


/* A byte source that first drains leftover bytes captured while reading the
 * header block, then reads from the socket. Unifies "post-header body already in
 * the header buffer" with "more body on the wire" for the framing decoders. */

ssize_t
bsrc_read(body_src *s, void *buf, size_t n, brix_status *st)
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
int
bsrc_getline(body_src *s, char *out, size_t outsz, brix_status *st)
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


int
write_all_fd(int fd, const char *buf, size_t n, brix_status *st)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) { continue; }
            brix_status_set(st, XRDC_ESOCK, errno, "local write: %s", strerror(errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}


/* Resilience window (ms) for HTTP downloads: $XRDC_MAX_STALL_MS when set (>0
 * widens, <=0 disables = fail fast), else the library default — the SAME window
 * the root:// data path uses. */
int
httpx_window_ms(void)
{
    const char *e = getenv("XRDC_MAX_STALL_MS");
    if (e != NULL && *e != '\0') {
        int v = atoi(e);
        return (v > 0) ? v : 0;
    }
    return XRDC_DEFAULT_MAX_STALL_MS;
}
