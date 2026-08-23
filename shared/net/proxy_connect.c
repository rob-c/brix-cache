/* proxy_connect.c — HTTP CONNECT tunnel handshake. See proxy_connect.h. */
#include "net/proxy_connect.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int wait_io(int fd, short events, int timeout_ms) {
    struct pollfd pfd = { fd, events, 0 };
    int r;
    do { r = poll(&pfd, 1, timeout_ms); } while (r < 0 && errno == EINTR);
    return r > 0 ? 0 : -1;
}

static int write_all_to(int fd, const char *buf, size_t n, int timeout_ms) {
    size_t off = 0;
    while (off < n) {
        if (wait_io(fd, POLLOUT, timeout_ms) != 0) return -1;
        ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -1; }
        off += (size_t) w;
    }
    return 0;
}

/*
 * WHAT: Read one complete HTTP CONNECT response header block.
 * WHY:  Tunnel bytes must remain unread after the proxy's header terminator.
 * HOW:  Poll and receive into a fixed buffer until CRLF-CRLF or peer close.
 */
static int read_response_headers(int fd, int timeout_ms, char *response,
                                 size_t capacity, char *err, size_t errlen) {
    size_t length = 0;

    while (length < capacity - 1) {
        ssize_t received;

        if (wait_io(fd, POLLIN, timeout_ms) != 0) {
            if (err != NULL)
                snprintf(err, errlen, "proxy read timeout");
            return -1;
        }
        received = recv(fd, response + length, capacity - 1 - length, 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            if (err != NULL)
                snprintf(err, errlen, "proxy read failed");
            return -1;
        }
        if (received == 0)
            break;
        length += (size_t) received;
        response[length] = '\0';
        if (strstr(response, "\r\n\r\n") != NULL)
            break;
    }
    response[length] = '\0';
    return 0;
}

/*
 * WHAT: Validate the HTTP status line returned for a CONNECT request.
 * WHY:  Only a 200 response establishes a usable byte tunnel.
 * HOW:  Parse the status code and retain the first refusal line for diagnostics.
 */
static int response_accepted(char *response, char *err, size_t errlen) {
    int code = 0;

    if (sscanf(response, "HTTP/%*d.%*d %d", &code) != 1) {
        if (err != NULL)
            snprintf(err, errlen, "malformed proxy response");
        return -1;
    }
    if (code != 200) {
        char *end = strpbrk(response, "\r\n");

        if (end != NULL)
            *end = '\0';
        if (err != NULL)
            snprintf(err, errlen, "proxy CONNECT refused (%s)", response);
        return -1;
    }
    return 0;
}

int brix_proxy_connect_tunnel(int fd, const char *host, int port, int timeout_ms,
                              char *err, size_t errlen) {
    char req[600];
    int  rl = snprintf(req, sizeof(req),
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
        "User-Agent: brix\r\nProxy-Connection: keep-alive\r\n\r\n",
        host, port, host, port);
    if (rl <= 0 || (size_t) rl >= sizeof(req)) {
        if (err != NULL)
            snprintf(err, errlen, "bad target");
        return -1;
    }

    if (write_all_to(fd, req, (size_t) rl, timeout_ms) != 0) {
        if (err != NULL)
            snprintf(err, errlen, "proxy write failed");
        return -1;
    }

    /* read response headers up to the blank line (the proxy sends nothing after
     * the 200 until we write, so we won't swallow tunnel bytes). */
    char resp[2048];
    if (read_response_headers(fd, timeout_ms, resp, sizeof(resp), err,
                              errlen) != 0)
        return -1;
    return response_accepted(resp, err, errlen);
}
