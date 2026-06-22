/*
 * fault_proxy.c — a tiny, root-free TCP fault-injection proxy ("toxiproxy-lite").
 *
 * WHAT: Relays TCP from a local listen port to a target host:port, and injects
 *       faults on command via a control port:
 *         latency <ms>  — delay every forwarded chunk (simulate a high-RTT link)
 *         chunk <bytes> — split every forwarded write into <=N-byte segments
 *                         (with egress TCP_NODELAY) to force the peer's recv loop
 *                         to see genuine partial reads / split PDUs
 *         drip <bytes> <ms> — forward <bytes> then sleep <ms>, repeating: a
 *                         slow-drip / low-speed stream.  Combined with NODELAY this
 *                         delivers each piece as its own segment after a real time
 *                         gap, which is what exercises a per-PDU read deadline and
 *                         a low-speed/idle abort (Phase 39).
 *         lossy <pct>   — with probability <pct>% per chunk, sever the connection
 *                         (an application-visible proxy for packet loss = resets)
 *         drop          — forcibly close all live proxied connections now
 *                         (simulate a connection reset / wifi blip)
 *         block         — drop live conns AND refuse new ones (an outage window)
 *         unblock       — resume accepting
 *         clear         — reset all levers (latency/chunk/drip/lossy=0, unblock)
 *         status        — report current state
 * WHY:  The async client's resilience (reconnect + file-handle resumption) needs a
 *       way to inject the exact conditions of "bad wifi from a laptop abroad"
 *       deterministically and WITHOUT root (tc/netem needs CAP_NET_ADMIN). The
 *       mount connects THROUGH this proxy; the test pulls the fault levers.
 * HOW:  Thread-per-connection relay (so per-chunk latency is a simple usleep);
 *       a global drop-epoch counter that, when bumped, makes every live relay
 *       thread close and exit; a control thread parsing newline commands.
 *
 * NOTE: packet LOSS is intentionally not offered — dropping bytes from an already-
 *       ACKed TCP stream corrupts it rather than emulating loss (which lives below
 *       TCP). Latency + disconnect + outage are the faithfully-simulatable faults,
 *       and they are exactly the ones the resilience layer must survive.
 *
 * Usage: fault_proxy <listen_port> <target_host> <target_port> <control_port>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static char         g_target_host[256];
static int          g_target_port;
static volatile int g_latency_ms = 0;
static volatile int g_blocked    = 0;
static volatile unsigned g_drop_epoch = 0;
/* Phase 39 fault levers (0 = off). */
static volatile int g_chunk_bytes = 0;   /* split each forwarded write into <=N-byte segments */
static volatile int g_drip_bytes  = 0;   /* drip: forward N bytes then sleep g_drip_ms */
static volatile int g_drip_ms     = 0;
static volatile int g_lossy_pct   = 0;   /* per-chunk probability (%) of severing the connection */

/* Blocking connect to host:port (best-effort, first address that works). */
static int
dial(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *ai;
    char            portstr[16];
    int             fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int
write_all(int fd, const char *buf, ssize_t n)
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

/*
 * Forward n bytes to `to`, applying the active fault levers.  Returns 0 on
 * success, -1 if the connection should be severed (write error or a lossy drop).
 * With chunk/drip + egress TCP_NODELAY each piece is delivered as its own segment
 * (drip adds a real inter-segment time gap), which is what makes the peer's recv
 * loop observe genuine partial reads / split PDUs — the condition a per-PDU read
 * deadline and a low-speed abort must handle.
 */
static int
forward_faulted(int to, const char *buf, ssize_t n, unsigned epoch)
{
    int     chunk = g_chunk_bytes;
    int     drip  = g_drip_bytes;
    int     dms   = g_drip_ms;
    int     lossy = g_lossy_pct;
    ssize_t off   = 0;
    int     piece = (drip > 0) ? drip : chunk;

    if (g_latency_ms > 0) {
        usleep((useconds_t) g_latency_ms * 1000);
    }

    if (piece <= 0) {
        if (lossy > 0 && (rand() % 100) < lossy) {
            return -1;   /* application-visible "loss" = sever the stream */
        }
        return write_all(to, buf, n);
    }

    while (off < n) {
        ssize_t seg = n - off;
        if (seg > piece) {
            seg = piece;
        }
        if (lossy > 0 && (rand() % 100) < lossy) {
            return -1;
        }
        if (g_blocked || g_drop_epoch != epoch) {
            return -1;
        }
        if (write_all(to, buf + off, seg) != 0) {
            return -1;
        }
        off += seg;
        if (drip > 0 && off < n) {
            usleep((useconds_t) dms * 1000);
        }
    }
    return 0;
}

typedef struct {
    int      client_fd;
    unsigned epoch;
} relay_arg;

static void *
relay_thread(void *arg)
{
    relay_arg *ra = (relay_arg *) arg;
    int        cfd = ra->client_fd;
    unsigned   epoch = ra->epoch;
    free(ra);

    int ufd = dial(g_target_host, g_target_port);
    if (ufd < 0) {
        close(cfd);
        return NULL;
    }
    /* Egress NODELAY on BOTH ends so chunk/drip pieces are delivered as separate
     * segments (otherwise the kernel coalesces them and the peer never sees a
     * partial PDU).  The accept side already set NODELAY on cfd. */
    { int one = 1;
      setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

    struct pollfd pfd[2];
    pfd[0].fd = cfd;
    pfd[1].fd = ufd;
    char buf[65536];

    for (;;) {
        if (g_blocked || g_drop_epoch != epoch) {
            break;   /* dropped / outage — sever both ends */
        }
        pfd[0].events = POLLIN;
        pfd[1].events = POLLIN;
        int pr = poll(pfd, 2, 100);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            continue;   /* re-check fault flags */
        }
        for (int i = 0; i < 2; i++) {
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                continue;
            }
            int from = pfd[i].fd;
            int to   = pfd[i ^ 1].fd;
            ssize_t n = read(from, buf, sizeof(buf));
            if (n <= 0) {
                goto done;
            }
            if (forward_faulted(to, buf, n, epoch) != 0) {
                goto done;
            }
        }
    }
done:
    close(cfd);
    close(ufd);
    return NULL;
}

static void *
control_thread(void *arg)
{
    int lfd = *(int *) arg;
    free(arg);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        char line[256];
        ssize_t n = read(cfd, line, sizeof(line) - 1);
        if (n > 0) {
            line[n] = '\0';
            char reply[128] = "ok\n";
            if (strncmp(line, "latency", 7) == 0) {
                g_latency_ms = atoi(line + 7);
            } else if (strncmp(line, "chunk", 5) == 0) {
                g_chunk_bytes = atoi(line + 5);
            } else if (strncmp(line, "drip", 4) == 0) {
                int b = 0, m = 0;
                sscanf(line + 4, "%d %d", &b, &m);
                g_drip_bytes = b;
                g_drip_ms    = m;
            } else if (strncmp(line, "lossy", 5) == 0) {
                g_lossy_pct = atoi(line + 5);
            } else if (strncmp(line, "drop", 4) == 0) {
                __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
            } else if (strncmp(line, "block", 5) == 0) {
                g_blocked = 1;
                __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
            } else if (strncmp(line, "unblock", 7) == 0) {
                g_blocked = 0;
            } else if (strncmp(line, "clear", 5) == 0) {
                g_latency_ms  = 0;
                g_blocked     = 0;
                g_chunk_bytes = 0;
                g_drip_bytes  = 0;
                g_drip_ms     = 0;
                g_lossy_pct   = 0;
            } else if (strncmp(line, "status", 6) == 0) {
                snprintf(reply, sizeof(reply),
                         "latency=%d chunk=%d drip=%d/%dms lossy=%d%% "
                         "blocked=%d epoch=%u\n",
                         g_latency_ms, g_chunk_bytes, g_drip_bytes, g_drip_ms,
                         g_lossy_pct, g_blocked, g_drop_epoch);
            } else {
                snprintf(reply, sizeof(reply), "err: unknown command\n");
            }
            (void) write_all(cfd, reply, (ssize_t) strlen(reply));
        }
        close(cfd);
    }
    return NULL;
}

static int
listen_on(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t) port);
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0
        || listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int
main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <listen_port> <target_host> <target_port> "
                        "<control_port>\n", argv[0]);
        return 2;
    }
    int listen_port  = atoi(argv[1]);
    snprintf(g_target_host, sizeof(g_target_host), "%s", argv[2]);
    g_target_port    = atoi(argv[3]);
    int control_port = atoi(argv[4]);

    signal(SIGPIPE, SIG_IGN);

    int lfd = listen_on(listen_port);
    int ctlfd = listen_on(control_port);
    if (lfd < 0 || ctlfd < 0) {
        fprintf(stderr, "fault_proxy: bind failed (listen=%d control=%d)\n",
                listen_port, control_port);
        return 1;
    }

    pthread_t ct;
    int *cfd = malloc(sizeof(int));
    *cfd = ctlfd;
    pthread_create(&ct, NULL, control_thread, cfd);

    printf("fault_proxy: :%d -> %s:%d  (control :%d)\n",
           listen_port, g_target_host, g_target_port, control_port);
    fflush(stdout);

    for (;;) {
        int client = accept(lfd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (g_blocked) {
            close(client);     /* outage: refuse */
            continue;
        }
        int one = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        relay_arg *ra = malloc(sizeof(*ra));
        ra->client_fd = client;
        ra->epoch = __atomic_load_n(&g_drop_epoch, __ATOMIC_SEQ_CST);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_thread, ra) != 0) {
            close(client);
            free(ra);
            continue;
        }
        pthread_detach(t);
    }
    return 0;
}
