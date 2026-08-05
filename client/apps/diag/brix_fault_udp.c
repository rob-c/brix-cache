/* brix_fault_udp.c — Phase-99 Wave C: a minimal UDP relay so the "UDP vs TCP"
 * middlebox pathologies (the class where UDP fired ahead of / alongside TCP is
 * silently dropped, held, or reaped) become reproducible from userland.
 *
 * WHAT: `--udp <listen> <host:port>` opens a UDP listener; each distinct client
 *       source address is a flow with its own connected upstream socket. The
 *       levers act on real datagrams: udp-drop (loss), udp-hold-until-tcp (delay
 *       a flow's FIRST datagram — the "allowed only as related to TCP" model),
 *       udp-reap (short flow-map timeout), udp-reorder (per-datagram hold-back).
 *
 * WHY:  the TCP relay cannot express any of this; UDP is a separate data path.
 *
 * HOW:  one poll loop over the listen socket + every live flow's upstream socket.
 *       Root-free. Counters feed the same status/JSON oracle. clear_all() resets
 *       the levers (the listener itself lives for the process, like a route). */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FP_UDP_MAX_FLOWS 64
#define FP_UDP_DGRAM     65536

typedef struct {
    struct sockaddr_storage cli;   /* client source address */
    socklen_t               clilen;
    int                     ufd;   /* connected upstream socket, -1 = free slot */
    struct timespec         last;  /* last activity (for udp-reap) */
} fp_udp_flow;

/* cmd_set_udp — the udp-* control verbs. Returns 1 once one is claimed. */
int
cmd_set_udp(const char *verb, char *args, char *reply, size_t rsz)
{
    (void) reply; (void) rsz;
    if (strcmp(verb, "udp-drop") == 0) {
        int p = atoi(args);
        g_udp_drop_ppm = p < 0 ? 0 : (p > 1000000 ? 1000000 : p);
    } else if (strcmp(verb, "udp-hold-until-tcp") == 0) {
        g_udp_hold_ms = atoi(args);
    } else if (strcmp(verb, "udp-reap") == 0) {
        g_udp_reap_ms = atoi(args);
    } else if (strcmp(verb, "udp-reorder") == 0) {
        int p = 0, ms = 0;
        sscanf(args, "%d %d", &p, &ms);
        g_udp_reorder_ppm = p; g_udp_reorder_ms = ms;
    } else {
        return 0;
    }
    return 1;
}

static long
udp_elapsed_ms(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000;
}

/* Dial a connected UDP socket to host:port; -1 on failure. */
static int
udp_dial(const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Find (or create) the flow for client `sa`; NULL when the table is full. */
static fp_udp_flow *
udp_flow_for(fp_udp_flow *flows, const struct sockaddr_storage *sa, socklen_t sl,
             const fp_udp_cfg *cfg, int *created)
{
    int free_slot = -1;
    for (int i = 0; i < FP_UDP_MAX_FLOWS; i++) {
        if (flows[i].ufd < 0) {
            if (free_slot < 0) { free_slot = i; }
            continue;
        }
        if (flows[i].clilen == sl && memcmp(&flows[i].cli, sa, sl) == 0) {
            *created = 0;
            return &flows[i];
        }
    }
    if (free_slot < 0) {
        return NULL;
    }
    int ufd = udp_dial(cfg->host, cfg->port);
    if (ufd < 0) {
        return NULL;
    }
    fp_udp_flow *f = &flows[free_slot];
    memcpy(&f->cli, sa, sl);
    f->clilen = sl;
    f->ufd    = ufd;
    clock_gettime(CLOCK_MONOTONIC, &f->last);
    *created = 1;
    return f;
}

/* Reap flows idle beyond g_udp_reap_ms (a UDP flow-map timeout far shorter than
 * TCP — long-lived UDP monitoring/streams get evicted early). */
static void
udp_reap_idle(fp_udp_flow *flows)
{
    if (g_udp_reap_ms <= 0) {
        return;
    }
    for (int i = 0; i < FP_UDP_MAX_FLOWS; i++) {
        if (flows[i].ufd >= 0 && udp_elapsed_ms(&flows[i].last) >= g_udp_reap_ms) {
            close(flows[i].ufd);
            flows[i].ufd = -1;
            CBUMP(udp_reaped, 1);
        }
    }
}

/* True (and counts) when this datagram should be dropped per udp-drop. */
static int
udp_should_drop(unsigned *seed)
{
    if (g_udp_drop_ppm > 0 &&
        (unsigned) (rand_r(seed) % 1000000) < (unsigned) g_udp_drop_ppm) {
        CBUMP(udp_dropped, 1);
        return 1;
    }
    return 0;
}

/* Apply the timing levers before forwarding a datagram: first-datagram hold and
 * probabilistic reorder hold-back. */
static void
udp_apply_timing(int is_first, unsigned *seed)
{
    if (is_first && g_udp_hold_ms > 0) {
        usleep((useconds_t) g_udp_hold_ms * 1000);
        CBUMP(udp_held, 1);
    }
    if (g_udp_reorder_ppm > 0 && g_udp_reorder_ms > 0 &&
        (unsigned) (rand_r(seed) % 1000000) < (unsigned) g_udp_reorder_ppm) {
        usleep((useconds_t) g_udp_reorder_ms * 1000);
    }
}

/* Build and bind the UDP listener on the vetted bind template (port only). */
static int
udp_listen(int port)
{
    struct sockaddr_storage ss = g_bind_ss;
    if (ss.ss_family == AF_INET) {
        ((struct sockaddr_in *) &ss)->sin_port = htons((uint16_t) port);
    } else {
        ((struct sockaddr_in6 *) &ss)->sin6_port = htons((uint16_t) port);
    }
    int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *) &ss, g_bind_len) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Upstream -> client (response path): forward each ready flow's datagram back
 * to its client, applying the drop/reorder timing levers. */
static void
udp_pump_upstream(struct pollfd *pf, int nf, const int *idx, fp_udp_flow *flows,
                  int lfd, unsigned char *dg, unsigned *seed)
{
    for (int j = 1; j < nf; j++) {
        if (!(pf[j].revents & POLLIN)) {
            continue;
        }
        fp_udp_flow *f = &flows[idx[j]];
        ssize_t n = recv(f->ufd, dg, FP_UDP_DGRAM, 0);
        if (n <= 0) {
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &f->last);
        if (udp_should_drop(seed)) {
            continue;
        }
        udp_apply_timing(0, seed);
        sendto(lfd, dg, (size_t) n, 0, (struct sockaddr *) &f->cli, f->clilen);
        CBUMP(udp_out, 1);
    }
}

/* Client -> upstream (request path): relay one inbound datagram, creating its
 * flow on demand and applying the first-datagram hold / drop levers. */
static void
udp_pump_client(struct pollfd *pf, fp_udp_flow *flows, int lfd, unsigned char *dg,
                const fp_udp_cfg *cfg, unsigned *seed)
{
    if (!(pf[0].revents & POLLIN)) {
        return;
    }
    struct sockaddr_storage sa;
    socklen_t sl = sizeof(sa);
    ssize_t n = recvfrom(lfd, dg, FP_UDP_DGRAM, 0, (struct sockaddr *) &sa, &sl);
    if (n <= 0) {
        return;
    }
    CBUMP(udp_in, 1);
    if (udp_should_drop(seed)) {
        return;
    }
    int created = 0;
    fp_udp_flow *f = udp_flow_for(flows, &sa, sl, cfg, &created);
    if (!f) {
        return;         /* table full or dial failed — drop */
    }
    clock_gettime(CLOCK_MONOTONIC, &f->last);
    udp_apply_timing(created, seed);
    send(f->ufd, dg, (size_t) n, 0);
}

/* Build the pollfd set: the listener at [0], every live flow's upstream after
 * it (with idx[k] mapping pollfd slot k back to its flow).  Returns the count. */
static int
udp_build_pollset(struct pollfd *pf, int *idx, fp_udp_flow *flows, int lfd)
{
    pf[0].fd = lfd; pf[0].events = POLLIN; pf[0].revents = 0;
    int nf = 1;
    for (int i = 0; i < FP_UDP_MAX_FLOWS; i++) {
        if (flows[i].ufd >= 0) {
            pf[nf].fd = flows[i].ufd; pf[nf].events = POLLIN; pf[nf].revents = 0;
            idx[nf] = i;
            nf++;
        }
    }
    return nf;
}

void *
fp_udp_thread(void *arg)
{
    fp_udp_cfg  *cfg = arg;
    fp_udp_flow  flows[FP_UDP_MAX_FLOWS];
    unsigned     seed = g_seed ? g_seed : 0x1234567u;
    unsigned char dg[FP_UDP_DGRAM];

    for (int i = 0; i < FP_UDP_MAX_FLOWS; i++) {
        flows[i].ufd = -1;
    }
    int lfd = udp_listen(cfg->listen_port);
    if (lfd < 0) {
        fprintf(stderr, "brix-fault-proxy: udp bind failed on port %d\n",
                cfg->listen_port);
        free(cfg);
        return NULL;
    }

    struct pollfd pf[1 + FP_UDP_MAX_FLOWS];
    int           idx[1 + FP_UDP_MAX_FLOWS];
    for (;;) {
        udp_reap_idle(flows);
        int nf = udp_build_pollset(pf, idx, flows, lfd);
        int pr = poll(pf, (nfds_t) nf, 200);
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            break;
        }
        if (pr == 0) {
            continue;
        }
        udp_pump_upstream(pf, nf, idx, flows, lfd, dg, &seed);
        udp_pump_client(pf, flows, lfd, dg, cfg, &seed);
    }
    close(lfd);
    free(cfg);
    return NULL;
}
