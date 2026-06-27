/*
 * http_req.c - extracted concern
 * Phase-38 split of http.c; behavior-identical.
 */
#include "http_internal.h"


/* general HTTP/1.1 client (cleartext or TLS) — for the multi-protocol */
/* deep-dive (https/davs/s3 batteries). Reads to EOF (Connection:close). */


/* Read up to n bytes; branches on TLS. Returns bytes (>0), 0 on EOF, -1 on error. */
ssize_t
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


/* The protocol exchange over an established (and TLS-wrapped, if any) io: build +
 * send the request, read the framed response (Content-Length / chunked / EOF),
 * parse it. Owns its own scratch buffer
 * so the caller's teardown stays linear (no shared cleanup label). 0 / -1. */
int
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
