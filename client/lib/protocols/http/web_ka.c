/*
 * web_ka.c — persistent keep-alive HTTP/1.1 transport + PROPFIND exchange.
 *
 * WHAT: brix_kaconn (connect/disconnect/read-headers/read-body) and brix_webmeta
 *       (a kaconn + fixed auth) with brix_webmeta_propfind. One request in
 *       flight; NOT thread-safe — pool it (brix_cpool) or serialise it.
 * WHY:  the FUSE web-metadata path (getattr/readdir) reconnected per call via
 *       the one-shot brix_http_req. Keep-alive + a small pool removes the
 *       per-op TCP+TLS handshake, matching the read path (webfile_io.c) and the
 *       recent brixcvmfs connection-reuse work.
 * HOW:  the transport/codec mirrors webfile_io.c (web_connect/web_read_some/
 *       header parse); the PROPFIND loop mirrors brix_webfile_pread's deadline-
 *       bounded reconnect-on-sever. No goto.
 *
 * Clean-room: composes the public brix_* connection API only.
 */
#include "web_ka.h"
#include "core/compat/host_format.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

#define KA_HDR_MAX     16384                   /* mirrors WEB_HDR_MAX */
#define KA_BODY_MAX    (4 * 1024 * 1024)       /* a PROPFIND body over 4 MiB is abuse */

/* Defined in webfile_io.c: the shared resilience window (ms). */
int webfile_window_ms(void);

void
brix_kaconn_init(brix_kaconn *k, const char *host, int port, int tls,
                 int verify, const char *ca_dir, int timeout_ms)
{
    memset(k, 0, sizeof(*k));
    k->io.fd = -1;
    snprintf(k->host, sizeof(k->host), "%s", host ? host : "");
    k->port = port;
    k->tls = tls;
    k->verify = verify;
    if (ca_dir != NULL) {
        snprintf(k->ca_dir, sizeof(k->ca_dir), "%s", ca_dir);
    }
    k->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;
    brix_format_host_port(k->host, (uint16_t) k->port, k->hostport,
                          sizeof(k->hostport));
}

void
brix_kaconn_disconnect(brix_kaconn *k)
{
    if (!k->connected) {
        return;
    }
    if (k->tls) {
        brix_tls_client_free(&k->io, k->tls_ctx);
        k->tls_ctx = NULL;
    }
    if (k->io.fd >= 0) {
        close(k->io.fd);
    }
    k->io.fd = -1;
    k->connected = 0;
}

int
brix_kaconn_connect(brix_kaconn *k, brix_status *st)
{
    memset(&k->io, 0, sizeof(k->io));
    k->io.fd = brix_tcp_connect(k->host, k->port, k->timeout_ms, st);
    if (k->io.fd < 0) {
        return -1;
    }
    k->io.timeout_ms = k->timeout_ms;
    if (k->tls && brix_tls_client(&k->io, k->host, k->verify, k->verify,
                                  k->ca_dir[0] ? k->ca_dir : NULL,
                                  &k->tls_ctx, st) != 0) {
        close(k->io.fd);
        k->io.fd = -1;
        return -1;
    }
    k->connected = 1;
    return 0;
}

/* Read up to n bytes (branches on TLS). >0 bytes, 0 EOF, -1 error. Mirrors
 * web_read_some (webfile_io.c:51), keyed on brix_kaconn. */
static ssize_t
kaconn_read_some(brix_kaconn *k, void *buf, size_t n, brix_status *st)
{
    if (k->io.ssl != NULL) {
        size_t got = 0;
        if (brix_tls_read_some(&k->io, buf, n, &got, st) != 0) {
            return -1;
        }
        return (ssize_t) got;
    }
    struct pollfd pfd;
    ssize_t       r;
    int           pr;
    pfd.fd = k->io.fd; pfd.events = POLLIN; pfd.revents = 0;
    do { pr = poll(&pfd, 1, k->io.timeout_ms); } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
        brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno, "ka read");
        return -1;
    }
    do { r = read(k->io.fd, buf, n); } while (r < 0 && errno == EINTR);
    if (r < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "ka read: %s", strerror(errno));
        return -1;
    }
    return r;
}

/* Case-insensitive Content-Length lookup (mirrors hdr_clen). */
static long long
ka_hdr_clen(const char *hdrs)
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

int
brix_kaconn_read_headers(brix_kaconn *k, char *hbuf, size_t hbufsz,
                         brix_ka_hdr *out, brix_status *st)
{
    size_t     hlen = 0;
    char      *eoh = NULL;
    int        status = 0;
    long long  clen;

    for (;;) {
        ssize_t r;
        if (hlen + 1 >= hbufsz) {
            brix_kaconn_disconnect(k);
            brix_status_set(st, XRDC_EPROTO, 0, "ka: header too large");
            return -1;
        }
        r = kaconn_read_some(k, hbuf + hlen, hbufsz - 1 - hlen, st);
        if (r <= 0) {
            brix_kaconn_disconnect(k);
            if (r == 0) {
                brix_status_set(st, XRDC_ESOCK, 0, "ka: peer closed");
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
    /* Parse Content-Length off a NUL-terminated header block, then restore the
     * first body byte. clen stays -1 when absent — the caller decides (a non-2xx
     * response is rejected without needing a body). */
    {
        char saved = eoh[0];
        eoh[0] = '\0';
        clen = ka_hdr_clen(hbuf);
        eoh[0] = saved;
    }
    if (clen > KA_BODY_MAX) {
        brix_kaconn_disconnect(k);
        brix_status_set(st, XRDC_EPROTO, 0, "ka: body too large");
        return -1;
    }
    out->status        = status;
    out->clen          = clen;
    out->body_start    = eoh + 4;
    out->body_buffered = hlen - (size_t) (out->body_start - hbuf);
    return 1;
}

int
brix_kaconn_read_body(brix_kaconn *k, const brix_ka_hdr *hdr,
                      char **body_out, size_t *len_out, brix_status *st)
{
    size_t total = (size_t) hdr->clen;
    char  *body  = malloc(total + 1);
    size_t have  = hdr->body_buffered < total ? hdr->body_buffered : total;

    if (body == NULL) {
        brix_kaconn_disconnect(k);
        brix_status_set(st, XRDC_EPROTO, 0, "ka: out of memory");
        return -1;
    }
    memcpy(body, hdr->body_start, have);
    if (have < total
        && brix_read_full(&k->io, body + have, total - have, st) != 0) {
        brix_kaconn_disconnect(k);   /* sever mid-body → drop the slot */
        free(body);
        return -1;
    }
    body[total] = '\0';
    *body_out = body;
    *len_out  = total;
    return 0;
}

void
brix_webmeta_init(brix_webmeta *m, const char *host, int port, int tls,
                  int verify, const char *ca_dir, const char *bearer,
                  int timeout_ms)
{
    brix_kaconn_init(&m->ka, host, port, tls, verify, ca_dir, timeout_ms);
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(m->auth, sizeof(m->auth),
                 "Authorization: Bearer %s\r\n", bearer);
    } else {
        m->auth[0] = '\0';
    }
}

/* Build + write "PROPFIND path HTTP/1.1 … Depth: d {auth}". On write fault the
 * kaconn is disconnected (caller reconnects + retries). */
static int
webmeta_send_req(brix_webmeta *m, const char *path, int depth, brix_status *st)
{
    char req[3200];
    int  rn = snprintf(req, sizeof(req),
                       "PROPFIND %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrootdfs\r\n"
                       "Accept: */*\r\nConnection: keep-alive\r\nDepth: %d\r\n%s\r\n",
                       path[0] ? path : "/", m->ka.hostport,
                       depth ? 1 : 0, m->auth);
    if (rn < 0 || (size_t) rn >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "PROPFIND: request too long");
        return -1;
    }
    if (brix_write_full(&m->ka.io, req, (size_t) rn, st) != 0) {
        brix_kaconn_disconnect(&m->ka);
        return -1;
    }
    return 0;
}

/* status → kXR (matches web_range_read_headers:206-212). 0 ok, -1 err (st set). */
static int
webmeta_status_map(int status, brix_status *st)
{
    if (status == 207 || status == 200) {
        return 0;
    }
    if (status == 404) {
        brix_status_set(st, kXR_NotFound, 0, "not found");
    } else if (status == 401 || status == 403) {
        brix_status_set(st, kXR_NotAuthorized, 0, "HTTP %d", status);
    } else {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", status);
    }
    return -1;
}

int
brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                      char **body_out, size_t *len_out, brix_status *st)
{
    unsigned attempt = 0;
    int      window_ms = webfile_window_ms();
    uint64_t deadline  = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;

    *body_out = NULL;
    *len_out  = 0;

    for (;;) {
        if (m->ka.connected || brix_kaconn_connect(&m->ka, st) == 0) {
            if (webmeta_send_req(m, path, depth, st) == 0) {
                char        hbuf[KA_HDR_MAX + 1];
                brix_ka_hdr h;
                if (brix_kaconn_read_headers(&m->ka, hbuf, sizeof(hbuf), &h, st)
                    == 1) {
                    if (webmeta_status_map(h.status, st) != 0) {
                        /* non-2xx: the body was not consumed, so the socket is
                         * misaligned — drop it (next checkout reconnects). The
                         * status (NotFound/NotAuthorized/…) is non-retryable, so
                         * the retry gate below returns immediately. */
                        brix_kaconn_disconnect(&m->ka);
                        return -1;
                    }
                    if (h.clen < 0) {
                        brix_kaconn_disconnect(&m->ka);
                        brix_status_set(st, XRDC_EPROTO, 0,
                                        "PROPFIND: no Content-Length");
                        return -1;
                    }
                    if (brix_kaconn_read_body(&m->ka, &h, body_out, len_out, st)
                        == 0) {
                        return 0;               /* success */
                    }
                }
            }
        }
        if (window_ms <= 0 || !brix_status_retryable(st)
            || brix_mono_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);
    }
}
