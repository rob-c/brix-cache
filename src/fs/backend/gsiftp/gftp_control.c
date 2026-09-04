/* FTP control-channel transport and RFC 2228 command protection. */

#include "gftp_client.h"
#include "gftp_gsi.h"
#include "gftp_reply.h"
#include "protocols/root/connection/netconnect.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void
gftp_set_error(gftp_session_t *session, int err, const char *fmt, ...)
{
    va_list args;

    errno = err;
    if (session == NULL) {
        return;
    }
    va_start(args, fmt);
    (void) vsnprintf(session->error, sizeof(session->error), fmt, args);
    va_end(args);
}

static int
gftp_wait(gftp_session_t *session, int fd, short events)
{
    struct pollfd pfd = { fd, events, 0 };
    int           rc;

    do {
        rc = poll(&pfd, 1, session->timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc > 0 && (pfd.revents & events)) {
        return 0;
    }
    gftp_set_error(session, (rc == 0) ? ETIMEDOUT : EIO,
        "GridFTP control channel %s", (rc == 0) ? "timed out" : "failed");
    return -1;
}

ssize_t
gftp_socket_read(gftp_session_t *session, int fd, void *buf, size_t cap)
{
    ssize_t n;

    for (;;) {
        if (gftp_wait(session, fd, POLLIN) != 0) {
            return -1;
        }
        n = recv(fd, buf, cap, 0);
        if (n >= 0) {
            return n;
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            gftp_set_error(session, errno, "GridFTP socket read failed");
            return -1;
        }
    }
}

int
gftp_socket_write_all(gftp_session_t *session, int fd, const void *buf,
    size_t len)
{
    const uint8_t *cursor = buf;
    size_t         written = 0;

    while (written < len) {
        ssize_t n;

        if (gftp_wait(session, fd, POLLOUT) != 0) {
            return -1;
        }
        n = send(fd, cursor + written, len - written, MSG_NOSIGNAL);
        if (n > 0) {
            written += (size_t) n;
            continue;
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN
                      || errno == EWOULDBLOCK)) {
            continue;
        }
        gftp_set_error(session, (n < 0) ? errno : EIO,
            "GridFTP socket write failed");
        return -1;
    }
    return 0;
}

static void
gftp_store_reply(gftp_session_t *session, const gftp_reply_t *reply)
{
    size_t n = reply->text_len;

    if (n >= sizeof(session->text)) {
        n = sizeof(session->text) - 1;
    }
    session->code = reply->code;
    if (n != 0) {
        memcpy(session->text, reply->text, n);
    }
    session->text[n] = '\0';
}

static int
gftp_unwrap_reply(gftp_session_t *session)
{
    uint8_t     *raw;
    uint8_t     *plain = NULL;
    size_t       raw_len;
    size_t       plain_len = 0;
    gftp_reply_t reply;
    long         consumed;

    raw = gftp_base64_decode(session->text, &raw_len);
    if (raw == NULL) {
        gftp_set_error(session, EPROTO, "GridFTP protected reply is not base64");
        return -1;
    }
    if (gftp_gsi_unwrap(session->gsi, raw, raw_len, &plain, &plain_len,
                        session) != 0) {
        free(raw);
        return -1;
    }
    free(raw);
    consumed = gftp_reply_scan((const char *) plain, plain_len, &reply);
    if (consumed <= 0) {
        free(plain);
        gftp_set_error(session, EPROTO, "GridFTP protected reply is malformed");
        return -1;
    }
    gftp_store_reply(session, &reply);
    free(plain);
    return 0;
}

int
gftp_read_reply(gftp_session_t *session)
{
    for (;;) {
        gftp_reply_t reply;
        long         consumed;
        ssize_t      n;

        consumed = gftp_reply_scan(session->input, session->buffered, &reply);
        if (consumed < 0) {
            gftp_set_error(session, EPROTO, "malformed GridFTP reply");
            return -1;
        }
        if (consumed > 0) {
            gftp_store_reply(session, &reply);
            session->buffered -= (size_t) consumed;
            memmove(session->input, session->input + consumed,
                    session->buffered);
            if (session->secure && session->code >= 631
                && session->code <= 633) {
                return gftp_unwrap_reply(session);
            }
            return 0;
        }
        if (session->buffered == sizeof(session->input)) {
            gftp_set_error(session, EOVERFLOW, "GridFTP reply exceeds limit");
            return -1;
        }
        n = gftp_socket_read(session, session->fd,
            session->input + session->buffered,
            sizeof(session->input) - session->buffered);
        if (n <= 0) {
            if (n == 0) {
                gftp_set_error(session, ECONNRESET,
                    "GridFTP control channel closed by peer");
            }
            return -1;
        }
        session->buffered += (size_t) n;
    }
}

static int
gftp_send_line(gftp_session_t *session, const char *line, size_t len)
{
    uint8_t *wrapped = NULL;
    size_t   wrapped_len = 0;
    char    *base64;
    char    *frame;
    size_t   cap;
    int      n;
    int      rc;

    if (!session->secure) {
        return gftp_socket_write_all(session, session->fd, line, len);
    }
    if (gftp_gsi_wrap(session->gsi, line, len, &wrapped, &wrapped_len,
                      session) != 0) {
        return -1;
    }
    base64 = gftp_base64_encode(wrapped, wrapped_len);
    free(wrapped);
    if (base64 == NULL) {
        gftp_set_error(session, ENOMEM, "cannot encode GridFTP command");
        return -1;
    }
    cap = strlen(base64) + 8;
    frame = malloc(cap);
    if (frame == NULL) {
        free(base64);
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP command");
        return -1;
    }
    n = snprintf(frame, cap, "ENC %s\r\n", base64);
    free(base64);
    if (n <= 0 || (size_t) n >= cap) {
        gftp_set_error(session, EOVERFLOW, "cannot frame GridFTP command");
        rc = -1;
    } else {
        rc = gftp_socket_write_all(session, session->fd, frame, (size_t) n);
    }
    free(frame);
    return rc;
}

static int
gftp_command_v(gftp_session_t *session, const char *fmt, va_list args)
{
    char line[GFTP_COMMAND_CAP];
    int  n;

    n = vsnprintf(line, sizeof(line) - 3, fmt, args);
    if (n < 0 || (size_t) n >= sizeof(line) - 3) {
        gftp_set_error(session, EOVERFLOW, "GridFTP command exceeds limit");
        return -1;
    }
    line[n++] = '\r';
    line[n++] = '\n';
    line[n] = '\0';
    if (gftp_send_line(session, line, (size_t) n) != 0) {
        return -1;
    }
    return gftp_read_reply(session);
}

int
gftp_command(gftp_session_t *session, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = gftp_command_v(session, fmt, args);
    va_end(args);
    return rc;
}

int
gftp_expect(gftp_session_t *session, int low, int high, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = gftp_command_v(session, fmt, args);
    va_end(args);
    if (rc != 0) {
        return -1;
    }
    if (session->code < low || session->code > high) {
        gftp_set_error(session, (session->code == 550) ? ENOENT : EIO,
            "GridFTP command refused: %d %s", session->code, session->text);
        return -1;
    }
    return 0;
}

static int
gftp_connect(gftp_session_t *session, const char *host, int port)
{
    struct addrinfo  hints;
    struct addrinfo *result;
    struct addrinfo *candidate;
    char             service[16];
    int              fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    (void) snprintf(service, sizeof(service), "%d", port);
    if (getaddrinfo(host, service, &hints, &result) != 0) {
        gftp_set_error(session, EHOSTUNREACH, "cannot resolve GridFTP origin");
        return -1;
    }
    for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {
        fd = socket(candidate->ai_family, candidate->ai_socktype,
                    candidate->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (brix_connect_fd_deadline(fd, candidate->ai_addr,
                candidate->ai_addrlen, session->timeout_ms) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    if (fd < 0) {
        gftp_set_error(session, ECONNREFUSED, "cannot connect to GridFTP origin");
    }
    return fd;
}

static void
gftp_record_peer(gftp_session_t *session)
{
    struct sockaddr_storage address;
    socklen_t               len = sizeof(address);
    void                   *src = NULL;

    if (getpeername(session->fd, (struct sockaddr *) &address, &len) != 0) {
        return;
    }
    if (address.ss_family == AF_INET) {
        src = &((struct sockaddr_in *) &address)->sin_addr;
    } else if (address.ss_family == AF_INET6) {
        src = &((struct sockaddr_in6 *) &address)->sin6_addr;
    }
    if (src != NULL) {
        (void) inet_ntop(address.ss_family, src, session->peer_ip,
                         sizeof(session->peer_ip));
    }
}

int
gftp_session_open(gftp_session_t *session, const gftp_session_cfg_t *cfg)
{
    memset(session, 0, sizeof(*session));
    session->fd = -1;
    session->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 30000;
    session->fd = gftp_connect(session, cfg->host, cfg->port);
    if (session->fd < 0) {
        return -1;
    }
    gftp_record_peer(session);
    if (gftp_read_reply(session) != 0
        || session->code < 200 || session->code > 299) {
        gftp_session_close(session);
        return -1;
    }
    if (gftp_authenticate(session, cfg) != 0) {
        gftp_session_close(session);
        return -1;
    }
    return 0;
}

void
gftp_session_close(gftp_session_t *session)
{
    if (session == NULL) {
        return;
    }
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
    gftp_gsi_free(session->gsi);
    session->gsi = NULL;
    session->secure = 0;
}
