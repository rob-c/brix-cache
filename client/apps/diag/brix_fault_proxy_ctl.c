/*
 * brix_fault_proxy_ctl.c — first-party `ctl` client subcommand (A3).
 *
 * WHAT: `brix-fault-proxy ctl <host:port> "<command>"` (or `-` to stream commands
 *       from stdin) dials the control port, sends the request, prints the reply,
 *       and maps the reply to a scriptable exit code — removing the external `nc`
 *       dependency operators and tests previously shelled out to.
 *
 * WHY:  the control grammar (newline verbs + JSON) is only reachable over a raw
 *       TCP socket, so every caller reimplemented "connect, write, read to EOF".
 *       A built-in client makes the tool self-contained and portable, and gives
 *       scripts a stable exit-code contract instead of parsing `nc` output.
 *
 * HOW:  a minimal non-blocking connect with a bounded timeout (the server's
 *       dial() is a relay.c static, deliberately not shared), a half-close after
 *       the request so the persistent-session control loop (A1) sees EOF and
 *       flushes, then drain the reply. Exit: 0 ok/status · 3 err/{"ok":false} ·
 *       4 connect failure · 2 usage. The server code is untouched.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "brix_fault_proxy_mods.h"

#define CTL_OK       0   /* reply was ok / status */
#define CTL_USAGE    2   /* malformed ctl invocation */
#define CTL_ERRREPLY 3   /* server replied err: / {"ok":false} */
#define CTL_CONNFAIL 4   /* could not reach the control port */

/* Self-contained write loop (the client links no core object, so it cannot use
 * the relay's static write_all).  Returns 0 once all `n` bytes are written. */
static int
ctl_write_all(int fd, const char *buf, ssize_t n)
{
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, (size_t) (n - off));
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += w;
    }
    return 0;
}

/* Connect `fd` to `sa` with an `ms`-millisecond ceiling so a dead port fails
 * fast instead of hanging.  Returns 0 on a completed connection, -1 otherwise. */
static int
ctl_connect_timeout(int fd, const struct sockaddr *sa, socklen_t sl, int ms)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    int rc = connect(fd, sa, sl);
    if (rc != 0 && errno == EINPROGRESS) {
        fd_set          wfds;
        struct timeval  tv = { ms / 1000, (ms % 1000) * 1000 };
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
            return -1;                 /* timeout or select error */
        }
        int       soerr = 0;
        socklen_t elen  = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &elen) < 0
            || soerr != 0) {
            return -1;
        }
        rc = 0;
    }
    if (rc != 0) {
        return -1;
    }
    (void) fcntl(fd, F_SETFL, flags);  /* restore blocking for read/write */
    return 0;
}

/* Parse `host:port` and return a connected fd, or -1 on any failure. */
static int
ctl_dial(const char *hostport)
{
    const char *colon = strrchr(hostport, ':');
    if (colon == NULL || colon == hostport) {
        return -1;
    }
    size_t hlen = (size_t) (colon - hostport);
    char   host[256];
    if (hlen >= sizeof host) {
        return -1;
    }
    memcpy(host, hostport, hlen);
    host[hlen] = '\0';

    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, colon + 1, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (ctl_connect_timeout(fd, ai->ai_addr, ai->ai_addrlen, 3000) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Send `req` (reqlen bytes), half-close, print the reply, map it to an exit
 * code.  Half-close makes the A1 session loop observe EOF and flush its reply. */
static int
ctl_exchange(int fd, const char *req, size_t reqlen)
{
    if (ctl_write_all(fd, req, (ssize_t) reqlen) != 0) {
        return CTL_CONNFAIL;
    }
    shutdown(fd, SHUT_WR);

    char    buf[8192];
    size_t  used = 0;
    ssize_t n;
    while (used < sizeof buf - 1
           && (n = read(fd, buf + used, sizeof buf - 1 - used)) > 0) {
        used += (size_t) n;
    }
    buf[used] = '\0';

    fputs(buf, stdout);
    if (used == 0 || buf[used - 1] != '\n') {
        fputc('\n', stdout);
    }

    if (strstr(buf, "err:") != NULL || strstr(buf, "\"ok\":false") != NULL) {
        return CTL_ERRREPLY;
    }
    return CTL_OK;
}

/* Read all of stdin into a heap buffer (batch/REPL mode). Caller frees. */
static char *
ctl_slurp_stdin(size_t *out_len)
{
    size_t cap = 4096, len = 0;
    char  *buf = malloc(cap);
    if (buf == NULL) {
        return NULL;
    }
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += r;
        if (len == cap) {
            size_t ncap = cap * 2;
            char  *nb   = realloc(buf, ncap);
            if (nb == NULL) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
    }
    *out_len = len;
    return buf;
}

/* Entry point dispatched from main() when argv[1] == "ctl". */
int
fp_ctl_main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s ctl <host:port> \"<command>\" | -\n", argv[0]);
        return CTL_USAGE;
    }

    int fd = ctl_dial(argv[2]);
    if (fd < 0) {
        fprintf(stderr, "brix-fault-proxy: ctl: cannot reach %s\n", argv[2]);
        return CTL_CONNFAIL;
    }

    int rc;
    if (strcmp(argv[3], "-") == 0) {
        size_t len;
        char  *body = ctl_slurp_stdin(&len);
        if (body == NULL) {
            close(fd);
            return CTL_CONNFAIL;
        }
        rc = ctl_exchange(fd, body, len);
        free(body);
    } else {
        size_t clen = strlen(argv[3]);
        char  *req  = malloc(clen + 2);
        if (req == NULL) {
            close(fd);
            return CTL_CONNFAIL;
        }
        memcpy(req, argv[3], clen);
        req[clen]     = '\n';
        req[clen + 1] = '\0';
        rc = ctl_exchange(fd, req, clen + 1);
        free(req);
    }

    close(fd);
    return rc;
}
