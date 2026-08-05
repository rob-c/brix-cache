/*
 * ftp_ctl.c — GridFTP client control channel: socket I/O, command send, reply read.
 *
 * WHAT: blocking, poll-bounded reads and writes on the control socket; one
 *       command out, exactly one reply in, with the RFC 2228 protection frame
 *       applied transparently once the GSI security layer is up.
 * WHY:  every other part of the client engine (login, stat, data channel) is a
 *       sequence of "send a verb, inspect a reply"; concentrating the framing and
 *       the timeout discipline here means the security wrap exists in exactly one
 *       place and cannot be forgotten by a caller.
 * HOW:  replies are decoded by the pure kernel gftp_reply_scan() over a rescanned
 *       receive buffer (it is incremental by contract), so multiline blocks and
 *       short reads are handled without a hand-rolled line splitter. When secure,
 *       a command goes out as "ENC <base64>" and the 63x reply's base64 argument
 *       is unwrapped and rescanned through the same kernel.
 */
#include "ftp_client.h"

#include "fs/backend/gsiftp/gftp_reply.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int
ftp_wait(int fd, short events, int timeout_ms, brix_status *st)
{
    struct pollfd pfd;
    int           rc;

    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;
    do {
        rc = poll(&pfd, 1, (timeout_ms > 0) ? timeout_ms : -1);
    } while (rc < 0 && errno == EINTR);

    if (rc == 0) {
        brix_status_set(st, XRDC_ESOCK, ETIMEDOUT, "gsiftp: control timeout");
        return -1;
    }
    if (rc < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "gsiftp: poll: %s",
                        strerror(errno));
        return -1;
    }
    return 0;
}


ssize_t
brix_ftp_io_read(int fd, void *buf, size_t cap, int timeout_ms, brix_status *st)
{
    ssize_t n;

    for (;;) {
        if (ftp_wait(fd, POLLIN, timeout_ms, st) != 0) {
            return -1;
        }
        n = recv(fd, buf, cap, 0);
        if (n >= 0) {
            return n;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        brix_status_set(st, XRDC_ESOCK, errno, "gsiftp: read: %s",
                        strerror(errno));
        return -1;
    }
}


int
brix_ftp_io_write_all(int fd, const void *buf, size_t n, int timeout_ms,
                      brix_status *st)
{
    const uint8_t *p = (const uint8_t *) buf;
    size_t         off = 0;

    while (off < n) {
        ssize_t w;

        if (ftp_wait(fd, POLLOUT, timeout_ms, st) != 0) {
            return -1;
        }
        w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += (size_t) w;
            continue;
        }
        if (w < 0 && (errno == EINTR || errno == EAGAIN
                      || errno == EWOULDBLOCK)) {
            continue;
        }
        brix_status_set(st, XRDC_ESOCK, errno, "gsiftp: write: %s",
                        strerror(errno));
        return -1;
    }
    return 0;
}


/* Record the reply the kernel decoded (code + final-line text). */
static void
ftp_store_reply(brix_ftp_sess *s, const gftp_reply_t *r)
{
    size_t n;

    s->code = r->code;
    n = (r->text_len < sizeof(s->text) - 1) ? r->text_len : sizeof(s->text) - 1;
    if (r->text != NULL && n > 0) {
        memcpy(s->text, r->text, n);
    }
    s->text[n] = '\0';
}


/*
 * A protected reply carries the real reply as base64 in its argument (RFC 2228
 * §3: the 63x code matches the protection verb the server chose). Decode it,
 * unwrap it through the security layer, and rescan the plaintext — which may
 * itself be a multiline block — with the same kernel.
 */
static int
ftp_unwrap_reply(brix_ftp_sess *s, brix_status *st)
{
    uint8_t     *raw, *plain = NULL;
    size_t       raw_len = 0, plain_len = 0;
    gftp_reply_t r;
    long         used;
    const char  *arg = s->text;

    raw = brix_ftp_b64_decode(arg, &raw_len);
    if (raw == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "gsiftp: protected reply is not base64");
        return -1;
    }
    if (brix_ftp_gss_unwrap(s->gss, raw, raw_len, &plain, &plain_len, st) != 0) {
        free(raw);
        return -1;
    }
    free(raw);

    used = gftp_reply_scan((const char *) plain, plain_len, &r);
    if (used <= 0) {
        free(plain);
        brix_status_set(st, XRDC_EPROTO, 0,
                        "gsiftp: malformed reply inside protection frame");
        return -1;
    }
    ftp_store_reply(s, &r);
    free(plain);
    return 0;
}


int
brix_ftp_read_reply(brix_ftp_sess *s, brix_status *st)
{
    for (;;) {
        gftp_reply_t r;
        long         used;
        ssize_t      n;

        used = gftp_reply_scan(s->rbuf, s->rlen, &r);
        if (used < 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: malformed reply");
            return -1;
        }
        if (used > 0) {
            ftp_store_reply(s, &r);
            s->rlen -= (size_t) used;
            memmove(s->rbuf, s->rbuf + used, s->rlen);
            if (s->secure && s->code >= 631 && s->code <= 633) {
                return ftp_unwrap_reply(s, st);
            }
            return 0;
        }
        if (s->rlen >= sizeof(s->rbuf)) {
            brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: reply too long");
            return -1;
        }
        n = brix_ftp_io_read(s->fd, s->rbuf + s->rlen, sizeof(s->rbuf) - s->rlen,
                             s->timeout_ms, st);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            brix_status_set(st, XRDC_ESOCK, 0,
                            "gsiftp: control connection closed by peer");
            return -1;
        }
        s->rlen += (size_t) n;
    }
}


/* Emit one command line, protecting it when the security layer is active. */
static int
ftp_send_line(brix_ftp_sess *s, const char *line, size_t len, brix_status *st)
{
    uint8_t *wrapped = NULL;
    size_t   wlen = 0;
    char    *b64, *frame;
    int      rc;
    size_t   flen;

    if (!s->secure) {
        return brix_ftp_io_write_all(s->fd, line, len, s->timeout_ms, st);
    }
    if (brix_ftp_gss_wrap(s->gss, line, len, &wrapped, &wlen, st) != 0) {
        return -1;
    }
    b64 = brix_ftp_b64_encode(wrapped, wlen);
    free(wrapped);
    if (b64 == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM, "gsiftp: out of memory");
        return -1;
    }
    flen = strlen(b64) + 8;
    frame = malloc(flen);
    if (frame == NULL) {
        free(b64);
        brix_status_set(st, XRDC_EIO, ENOMEM, "gsiftp: out of memory");
        return -1;
    }
    rc = snprintf(frame, flen, "ENC %s\r\n", b64);
    free(b64);
    if (rc < 0 || (size_t) rc >= flen) {
        free(frame);
        brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: command frame overflow");
        return -1;
    }
    rc = brix_ftp_io_write_all(s->fd, frame, (size_t) rc, s->timeout_ms, st);
    free(frame);
    return rc;
}


/* Format one command, terminate it with CRLF, send it, and read its reply. Both
 * public command entry points differ only in what they do with s->code. */
static int
ftp_cmd_v(brix_ftp_sess *s, brix_status *st, const char *fmt, va_list ap)
{
    char line[BRIX_FTP_CMD_MAX];
    int  n = vsnprintf(line, sizeof(line) - 3, fmt, ap);

    if (n < 0 || (size_t) n >= sizeof(line) - 3) {
        brix_status_set(st, XRDC_EUSAGE, 0, "gsiftp: command too long");
        return -1;
    }
    line[n++] = '\r';
    line[n++] = '\n';
    line[n] = '\0';

    if (ftp_send_line(s, line, (size_t) n, st) != 0) {
        return -1;
    }
    return brix_ftp_read_reply(s, st);
}


int
brix_ftp_cmd(brix_ftp_sess *s, brix_status *st, const char *fmt, ...)
{
    va_list ap;
    int     rc;

    va_start(ap, fmt);
    rc = ftp_cmd_v(s, st, fmt, ap);
    va_end(ap);
    return rc;
}


int
brix_ftp_cmd_expect(brix_ftp_sess *s, int lo, int hi, brix_status *st,
                    const char *fmt, ...)
{
    va_list ap;
    int     rc;

    va_start(ap, fmt);
    rc = ftp_cmd_v(s, st, fmt, ap);
    va_end(ap);
    if (rc != 0) {
        return -1;
    }
    if (s->code < lo || s->code > hi) {
        brix_status_set(st, (s->code == 550) ? XRDC_ENOENT : XRDC_EPROTO, 0,
                        "gsiftp: %d %s", s->code, s->text);
        return -1;
    }
    return 0;
}


/* Cache the control peer's numeric address — the data-channel screen compares
 * every passive-mode address against it (ftp_screen.c). */
static void
ftp_record_peer(brix_ftp_sess *s)
{
    struct sockaddr_storage ss;
    socklen_t               sl = sizeof(ss);

    s->peer_ip[0] = '\0';
    if (getpeername(s->fd, (struct sockaddr *) &ss, &sl) != 0) {
        return;
    }
    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *) &ss;
        (void) inet_ntop(AF_INET, &a->sin_addr, s->peer_ip, sizeof(s->peer_ip));
    } else if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *) &ss;
        (void) inet_ntop(AF_INET6, &a6->sin6_addr, s->peer_ip,
                         sizeof(s->peer_ip));
    }
}


int
brix_ftp_connect(brix_ftp_sess *s, const char *host, int port, int timeout_ms,
                 brix_status *st)
{
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->timeout_ms = (timeout_ms > 0) ? timeout_ms : 30000;

    s->fd = brix_tcp_connect(host, port, s->timeout_ms, st);
    if (s->fd < 0) {
        return -1;
    }
    ftp_record_peer(s);

    if (brix_ftp_read_reply(s, st) != 0) {
        brix_ftp_close(s);
        return -1;
    }
    if (s->code < 200 || s->code > 299) {
        brix_status_set(st, XRDC_EPROTO, 0, "gsiftp: greeting %d %s", s->code,
                        s->text);
        brix_ftp_close(s);
        return -1;
    }
    return 0;
}


void
brix_ftp_close(brix_ftp_sess *s)
{
    if (s == NULL) {
        return;
    }
    if (s->fd >= 0) {
        brix_status quit;

        brix_status_clear(&quit);
        (void) brix_ftp_cmd(s, &quit, "QUIT");
        close(s->fd);
        s->fd = -1;
    }
    if (s->gss != NULL) {
        brix_ftp_gss_free(s->gss);
        s->gss = NULL;
    }
    s->secure = 0;
}
