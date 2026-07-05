/*
 * proxy_tunnel_harness.c — exercise the exact CONNECT handshake sock.c uses,
 * in isolation: connect to the proxy, tunnel to <target>, GET a path, print the
 * first response line. Exit 0 iff the tunneled GET returns "200".
 *
 * usage: harness <proxy_host> <proxy_port> <target_host> <target_port> <path>
 */
#include "net/proxy_connect.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int dial(const char *host, const char *port) {
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        if (fd >= 0) { close(fd); fd = -1; }
    }
    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 6) { fprintf(stderr, "usage: harness pxhost pxport thost tport path\n"); return 2; }
    int fd = dial(argv[1], argv[2]);
    if (fd < 0) { fprintf(stderr, "cannot reach proxy\n"); return 1; }

    char err[160];
    if (brix_proxy_connect_tunnel(fd, argv[3], atoi(argv[4]), 5000, err, sizeof(err)) != 0) {
        fprintf(stderr, "tunnel failed: %s\n", err); return 1;
    }
    char req[512];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n",
        argv[5], argv[3], argv[4]);
    if (write(fd, req, n) != n) { fprintf(stderr, "write over tunnel failed\n"); return 1; }

    char resp[256]; ssize_t r = read(fd, resp, sizeof(resp) - 1);
    if (r <= 0) { fprintf(stderr, "no response over tunnel\n"); return 1; }
    resp[r] = '\0';
    char *eol = strpbrk(resp, "\r\n"); if (eol) *eol = '\0';
    printf("tunneled response: %s\n", resp);
    close(fd);
    return strstr(resp, "200") ? 0 : 1;
}
