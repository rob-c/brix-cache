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

int brix_proxy_connect_tunnel(int fd, const char *host, int port, int timeout_ms,
                              char *err, size_t errlen) {
    char req[600];
    int  rl = snprintf(req, sizeof(req),
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
        "User-Agent: brix\r\nProxy-Connection: keep-alive\r\n\r\n",
        host, port, host, port);
    if (rl <= 0 || (size_t) rl >= sizeof(req)) { if (err) snprintf(err, errlen, "bad target"); return -1; }

    if (write_all_to(fd, req, (size_t) rl, timeout_ms) != 0) {
        if (err) snprintf(err, errlen, "proxy write failed");
        return -1;
    }

    /* read response headers up to the blank line (the proxy sends nothing after
     * the 200 until we write, so we won't swallow tunnel bytes). */
    char   resp[2048];
    size_t rn = 0;
    while (rn < sizeof(resp) - 1) {
        if (wait_io(fd, POLLIN, timeout_ms) != 0) { if (err) snprintf(err, errlen, "proxy read timeout"); return -1; }
        ssize_t k = recv(fd, resp + rn, sizeof(resp) - 1 - rn, 0);
        if (k < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (err) snprintf(err, errlen, "proxy read failed");
            return -1;
        }
        if (k == 0) break;
        rn += (size_t) k;
        resp[rn] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) break;
    }
    resp[rn] = '\0';

    int code = 0;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &code) != 1) {
        if (err) snprintf(err, errlen, "malformed proxy response");
        return -1;
    }
    if (code != 200) {
        char *eol = strpbrk(resp, "\r\n");
        if (eol) *eol = '\0';
        if (err) snprintf(err, errlen, "proxy CONNECT refused (%s)", resp);
        return -1;
    }
    return 0;
}
