/*
 * brix_fault_proxy.c — brix-fault-proxy: a root-free TCP fault-injection proxy.
 *
 * WHAT: Relays TCP from a local listen port to an upstream host:port and injects
 *       network faults on demand — latency, jitter, partial writes, slow-drip,
 *       bandwidth caps, packet-loss (resets), payload corruption, duplication,
 *       deterministic mid-transfer truncation, connection black-holes, and full
 *       outages — set at startup on the command line or live over a control port
 *       while traffic flows.  A "toxiproxy-lite" you can splice in front of any
 *       brix (or stock XRootD/HTTP) endpoint to prove a client survives a bad or
 *       actively hostile network, WITHOUT needing root: tc/netem needs
 *       CAP_NET_ADMIN; this is pure userspace sockets.
 *
 * DIRECTIONALITY: every byte-level lever is per-direction.  `up`   = client ->
 *       upstream (the request/upload path), `down` = upstream -> client (the
 *       response/download path).  A control command with no direction token
 *       applies to BOTH; append ` up`, ` down`, or ` both` to target one.
 *
 * FAULT LEVERS (each off/0 by default; set at startup via the matching --flag or
 *              live by writing the command to the control port):
 *   latency <ms> [dir]        delay every forwarded chunk (a high-RTT link)
 *   jitter <ms> [dir]         delay each chunk by a uniform-random 0..<ms> ms —
 *                             the application signature of IP reordering (see NOTE)
 *   chunk <bytes> [dir]       split each write into <=N-byte segments (egress
 *                             TCP_NODELAY) so the peer sees genuine partial reads
 *   drip <bytes> <ms> [dir]   forward <bytes>, sleep <ms>, repeat (slow stream)
 *   rate <KB/s> [dir]         pace the stream to a bandwidth ceiling (slow link)
 *   lossy <pct> [dir]         with prob <pct>%/chunk, sever the stream (loss=reset)
 *   reorder <pct> [ms] [dir]  with prob <pct>%/chunk, hold that chunk back <ms> ms
 *   corrupt <pct> [dir]       flip a random bit in <pct>% of forwarded BYTES — a
 *                             MITM tamper that a checksum-verifying peer must catch
 *   dup <pct> [dir]           with prob <pct>%/chunk, deliver that chunk twice
 *   truncate-at <bytes> [dir] sever each connection once <bytes> have flowed in
 *                             that direction (deterministic mid-transfer cut)
 *   fail-nth <n>              fail exactly the Nth accepted connection, pass others
 *   heal-after <ms>           auto-clear every lever after <ms> (a transient fault)
 *   one-shot                  self-heal (clear) the moment a sever/truncate fires
 *   drop                      graceful-FIN sever every live connection now
 *   reset                     abortive-RST sever every live connection now, and
 *                             make subsequent lossy/truncate severs use RST too
 *   abortive <0|1>            select RST (1) vs graceful FIN (0) for auto-severs
 *   half-close                FIN the client->upstream path on live conns while the
 *                             upstream->client path keeps flowing (tests half-open)
 *   hang                      accept new connections but never relay (a black hole)
 *   unhang                    resume relaying newly accepted connections
 *   block                     drop live conns AND refuse new ones (an outage window)
 *   unblock                   resume accepting
 *   clear                     reset every lever (levers=0, unblock, unhang)
 *   status                    report lever state and traffic/fault counters
 *
 * WHY:  A client's resilience (reconnect + file-handle resumption, per-PDU read
 *       deadlines, low-speed aborts, checksum-verify-and-retry) needs the exact
 *       conditions of "bad wifi from a laptop abroad" — or an outright tampering
 *       MITM — injected deterministically and without privilege.  The peer
 *       connects THROUGH this proxy; an operator (or a test) pulls the levers.
 *
 * HOW:  Thread-per-connection relay (so per-chunk latency is a simple usleep); a
 *       global drop-epoch counter that, when bumped, makes every live relay thread
 *       sever and exit; a control thread parsing newline commands; an optional
 *       timeline thread replaying a scripted scenario.  All randomness is per-thread
 *       rand_r() seeded from --seed for reproducibility.
 *
 * SECURITY: the control port is UNAUTHENTICATED — anyone who can reach it can pull
 *       the fault levers and reset live connections.  Both the listen and control
 *       sockets therefore bind to loopback by DEFAULT; widening the bind address
 *       (--bind) exposes the control plane and is refused unless you also pass
 *       --insecure-bind, which prints a warning.  Never expose the control port to
 *       an untrusted network.
 *
 * NOTE: packet LOSS is intentionally modelled as a connection sever, not byte
 *       drops: dropping bytes from an already-ACKed TCP stream corrupts it rather
 *       than emulating loss (which lives below TCP).  Likewise true out-of-order
 *       PACKET delivery cannot be emulated by re-ordering bytes — TCP reassembles
 *       in order below us — so `jitter`/`reorder` inject the variable latency that
 *       IP reordering actually imposes on a TCP application.  (True packet
 *       reordering needs `tc qdisc ... netem`, i.e. CAP_NET_ADMIN, which this
 *       avoids.)  `corrupt`, by contrast, IS a real in-band byte mutation: it is
 *       what an active on-path attacker (or a flaky NIC past the TCP checksum)
 *       does, and it is precisely what an application-layer checksum exists to
 *       catch.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
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

#include "core/version.h"

#define FP_OK    0   /* clean terminal action (--help / --version) or success */
#define FP_RUN   1   /* runtime failure (bind failed) */
#define FP_USAGE 2   /* command-line error */
#define FP_CONTINUE (-1) /* internal: argument parsing/setup ok, keep going */

#define FP_MAX_TARGETS 8

/* Per-direction fault levers.  0 = off (reorder_ms defaults to 50). */
typedef struct {
    volatile int latency_ms;
    volatile int jitter_ms;
    volatile int chunk_bytes;
    volatile int drip_bytes;
    volatile int drip_ms;
    volatile int rate_kbps;      /* bandwidth ceiling, KB/s (paced) */
    volatile int lossy_ppm;      /* per-chunk sever probability, ppm (1% = 10000) */
    volatile int reorder_ppm;    /* per-chunk hold-back probability, ppm */
    volatile int reorder_ms;     /* hold-back delay applied to a reordered chunk */
    volatile int corrupt_ppm;    /* per-byte bit-flip probability, ppm */
    volatile int dup_ppm;        /* per-chunk duplicate-delivery probability, ppm */
    volatile long truncate_at;   /* sever after this many bytes this direction; 0=off */
} lever_t;

static volatile lever_t g_up;    /* client   -> upstream (request / upload) */
static volatile lever_t g_down;  /* upstream -> client   (response / download) */

/* Upstream target pool (round-robin with per-connection failover). */
static struct { char host[256]; int port; } g_targets[FP_MAX_TARGETS];
static int      g_ntargets = 0;
static unsigned g_rr       = 0;

/* Global (connection-scoped) state. */
static volatile int      g_blocked  = 0;   /* refuse new + sever live (outage) */
static volatile int      g_hang     = 0;   /* accept new but never relay (black hole) */
static volatile int      g_abortive = 0;   /* 1 = auto-severs use RST, 0 = graceful FIN */
static volatile int      g_one_shot = 0;   /* clear all levers when a sever fires */
static volatile int      g_fail_nth = 0;   /* fail exactly the Nth accepted conn (0=off) */
static volatile unsigned g_drop_epoch      = 0;  /* bump => live relays sever */
static volatile unsigned g_halfclose_epoch = 0;  /* bump => live relays half-close */
static unsigned          g_seed     = 0;   /* base RNG seed (per-thread derived) */
static int               g_max_conns = 0;  /* cap on concurrent relays (0=unlimited) */

/* Traffic / fault counters (test oracle). */
static struct {
    unsigned long conns, active, up_bytes, down_bytes;
    unsigned long severs, corrupt, dups, refused;
} C;
#define CBUMP(f, n) __atomic_add_fetch(&C.f, (n), __ATOMIC_RELAXED)
#define CDEC(f)     __atomic_sub_fetch(&C.f, 1, __ATOMIC_RELAXED)
/* Add one byte-total to a per-connection and the global counter atomically. */
#define CBUMP2(conn_ctr, glob_ctr, n) do {        \
    *(conn_ctr) += (unsigned long) (n);           \
    __atomic_add_fetch((glob_ctr), (unsigned long) (n), __ATOMIC_RELAXED); \
} while (0)

static void reset_lever(volatile lever_t *L);
static void clear_all(void);

static void
usage(FILE *out)
{
    fprintf(out,
"usage: brix-fault-proxy --listen PORT --target HOST:PORT [--target ...] --control PORT [options]\n"
"       brix-fault-proxy LISTEN_PORT TARGET_HOST TARGET_PORT CONTROL_PORT   (positional)\n"
"\n"
"Relay TCP from a local listen port to an upstream, injecting network faults\n"
"on demand — from the command line at startup or live over the control port.\n"
"Byte-level levers are per-direction: 'up' = client->upstream, 'down' = the\n"
"reverse; a control command with no direction token applies to both.\n"
"\n"
"Endpoints:\n"
"  -l, --listen PORT        local port to accept client connections on\n"
"  -t, --target HOST:PORT   upstream to relay to (repeatable / comma-list for\n"
"                           round-robin + per-connection failover)\n"
"  -c, --control PORT       control port for live fault commands\n"
"  -b, --bind ADDR          address to bind listen+control to (default loopback;\n"
"                           IPv4 or IPv6 literal)\n"
"      --insecure-bind      permit a non-loopback --bind (exposes the control port)\n"
"      --max-conns N        cap concurrent relayed connections (0 = unlimited)\n"
"      --seed N             seed the fault RNG for reproducible runs\n"
"      --script FILE        replay a timeline of '<seconds> <command>' lines\n"
"  -q, --quiet              suppress the startup banner\n"
"\n"
"Initial fault levers (also settable live; append up|down to target one way):\n"
"      --latency MS         delay every forwarded chunk by MS milliseconds\n"
"      --jitter MS          delay every chunk by a random 0..MS ms\n"
"      --chunk BYTES        split forwarded writes into <=BYTES segments\n"
"      --drip 'BYTES MS'    forward BYTES, sleep MS, repeat (slow stream)\n"
"      --rate KBPS          pace the stream to KBPS kilobytes/second\n"
"      --lossy PCT          sever the stream with probability PCT%% per chunk\n"
"      --reorder 'PCT [MS]' hold back PCT%% of chunks by MS ms (default 50)\n"
"      --corrupt PCT        flip a bit in PCT%% of forwarded bytes (MITM tamper)\n"
"      --dup PCT            deliver PCT%% of chunks twice\n"
"      --truncate-at BYTES  sever each connection after BYTES have flowed\n"
"      --fail-nth N         fail exactly the Nth accepted connection\n"
"      --heal-after MS      auto-clear all levers after MS milliseconds\n"
"      --hang               start as a black hole (accept but never relay)\n"
"      --block              start blocked (refuse connections — an outage)\n"
"\n"
"  -h, --help               print this help and exit\n"
"  -V, --version            print version and exit\n"
"\n"
"control commands (write one per connection to the control port):\n"
"  latency <ms> | jitter <ms> | chunk <bytes> | drip <bytes> <ms> | rate <kbps>\n"
"  lossy <pct> | reorder <pct> [ms] | corrupt <pct> | dup <pct> | truncate-at <bytes>\n"
"  fail-nth <n> | heal-after <ms> | one-shot | abortive <0|1>\n"
"  drop | reset | half-close | hang | unhang | block | unblock | clear | status\n"
"    (append up|down|both to any byte-level lever to target one direction)\n"
"\n"
"Example:\n"
"  brix-fault-proxy --listen 11940 --target cache.example:1094 --control 11941\n"
"  printf 'corrupt 0.01 down\\n' | nc -q1 127.0.0.1 11941  # tamper the download\n"
"  printf 'truncate-at 5242880 down\\n' | nc -q1 127.0.0.1 11941  # cut at 5 MiB\n"
"\n"
"The control port is UNAUTHENTICATED and binds to loopback by default; do not\n"
"expose it to an untrusted network.  See man brix-fault-proxy(1).\n");
}

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

/* Dial the next target in round-robin order, failing over to the rest. */
static int
dial_any(void)
{
    int n = g_ntargets;
    unsigned start = __atomic_fetch_add(&g_rr, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < n; i++) {
        int idx = (int) ((start + (unsigned) i) % (unsigned) n);
        int fd = dial(g_targets[idx].host, g_targets[idx].port);
        if (fd >= 0) {
            return fd;
        }
    }
    return -1;
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

/* Sever both ends of a relay; abortive (RST via SO_LINGER 0) when requested. */
static void
sever(int cfd, int ufd, int abortive)
{
    if (abortive) {
        struct linger lg = { 1, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        if (ufd >= 0) {
            setsockopt(ufd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        }
    }
    close(cfd);
    if (ufd >= 0) {
        close(ufd);
    }
}

/* Count a severed stream and honour one-shot (clear all levers after firing).
 * Returns -1 so a caller can `return fault_sever();`. */
static int
fault_sever(void)
{
    CBUMP(severs, 1);
    if (g_one_shot) {
        clear_all();
    }
    return -1;
}

/* Clamp the outgoing segment to the chunk `piece` and, if truncation is armed,
 * to the exact remaining distance to the cut. Returns the clamped length, or -1
 * when the truncation point is already reached (caller must sever). */
static ssize_t
fault_clamp_seg(ssize_t seg, int piece, long trunc, unsigned long conn_ctr)
{
    if (seg > piece) {
        seg = piece;
    }
    /* Cap at the truncation boundary so the cut is exact rather than firing
     * only after the whole (possibly 64 KiB) read is delivered. */
    if (trunc > 0) {
        long remaining = trunc - (long) conn_ctr;
        if (remaining <= 0) {
            return -1;
        }
        if (seg > remaining) {
            seg = remaining;
        }
    }
    return seg;
}

/* Apply direction `L`'s pacing/jitter/reorder delays before a segment write. */
static void
fault_delays(ssize_t seg, unsigned *seed, const lever_t *L)
{
    if (L->jitter_ms > 0) {
        usleep((useconds_t) (rand_r(seed) % (unsigned) (L->jitter_ms + 1)) * 1000);
    }
    if (L->reorder_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->reorder_ppm) {
        usleep((useconds_t) L->reorder_ms * 1000);
    }
    if (L->rate_kbps > 0) {
        usleep((useconds_t) ((long long) seg * 1000000
                             / ((long long) L->rate_kbps * 1024)));
    }
}

/* Flip random bits in buf[off, off+seg) at the configured per-byte rate. */
static void
fault_corrupt(char *buf, ssize_t off, ssize_t seg, unsigned *seed, int cor)
{
    if (cor <= 0) {
        return;
    }
    for (ssize_t k = 0; k < seg; k++) {
        if ((int) (rand_r(seed) % 1000000u) < cor) {
            buf[off + k] ^= (char) (1u << (rand_r(seed) % 8u));
            CBUMP(corrupt, 1);
        }
    }
}

/* Deliver one segment starting at buf+off, applying `L`'s active faults. On
 * success writes the delivered length to *wrote and returns 0; returns -1 when
 * the stream should be severed (truncate cut, lossy drop, write error) or
 * silently dropped (block/epoch change). */
static int
forward_segment(int to, char *buf, ssize_t off, ssize_t n, unsigned epoch,
                const lever_t *L, unsigned *seed, unsigned long *conn_ctr,
                unsigned long *glob_ctr, int piece, ssize_t *wrote)
{
    ssize_t seg = fault_clamp_seg(n - off, piece, L->truncate_at, *conn_ctr);
    if (seg < 0) {
        return fault_sever();
    }

    fault_delays(seg, seed, L);

    if (L->lossy_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->lossy_ppm) {
        return fault_sever();   /* application-visible "loss" = sever the stream */
    }
    if (g_blocked || g_drop_epoch != epoch) {
        return -1;
    }

    fault_corrupt(buf, off, seg, seed, L->corrupt_ppm);

    if (write_all(to, buf + off, seg) != 0) {
        return -1;
    }
    if (L->dup_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->dup_ppm) {
        (void) write_all(to, buf + off, seg);   /* duplicate delivery */
        CBUMP(dups, 1);
    }

    CBUMP2(conn_ctr, glob_ctr, seg);
    *wrote = seg;

    if (L->truncate_at > 0 && (long) *conn_ctr >= L->truncate_at) {
        return fault_sever();   /* deterministic mid-transfer cut */
    }
    return 0;
}

/*
 * Forward n bytes to `to`, applying direction `L`'s active fault levers.  Bytes
 * may be mutated in place (corruption).  Returns 0 on success, -1 if the
 * connection should be severed (write error, a lossy drop, or a truncate cut).
 * `seed` is this thread's private rand_r() state; `conn_ctr` the per-connection
 * per-direction running byte total (for truncate-at); `glob_ctr` the process-wide
 * traffic counter for this direction.
 */
static int
forward_faulted(int to, char *buf, ssize_t n, unsigned epoch, volatile lever_t *L,
                unsigned *seed, unsigned long *conn_ctr, unsigned long *glob_ctr)
{
    /* Snapshot the levers once so a mid-buffer control-plane change can't split
     * this read across two fault configurations (matches the original). */
    lever_t snap  = *L;
    int     piece = (snap.drip_bytes > 0) ? snap.drip_bytes
                  : (snap.chunk_bytes > 0 ? snap.chunk_bytes : (int) n);
    ssize_t off   = 0;

    if (piece <= 0) {
        piece = (int) n;   /* n >= 1 (read returned >0) */
    }
    if (snap.latency_ms > 0) {
        usleep((useconds_t) snap.latency_ms * 1000);
    }

    while (off < n) {
        ssize_t wrote = 0;
        if (forward_segment(to, buf, off, n, epoch, &snap, seed,
                            conn_ctr, glob_ctr, piece, &wrote) != 0) {
            return -1;
        }
        off += wrote;
        if (snap.drip_bytes > 0 && off < n) {
            usleep((useconds_t) snap.drip_ms * 1000);
        }
    }
    return 0;
}

typedef struct {
    int      client_fd;
    unsigned epoch;
    unsigned long conn_id;
} relay_arg;

/* Pre-dial dispositions that answer the client without ever reaching upstream:
 * the fail-nth sever and the hang/black-hole hold.  Returns 1 if the connection
 * was handled (closed + CDEC), 0 to proceed with dialling upstream. */
static int
relay_predial(int cfd, unsigned epoch, unsigned long conn_id)
{
    /* fail-nth: sever exactly the Nth accepted connection, then pass the rest. */
    if (g_fail_nth > 0 && conn_id == (unsigned long) g_fail_nth) {
        CBUMP(severs, 1);
        sever(cfd, -1, g_abortive);
        CDEC(active);
        return 1;
    }

    /* hang / black hole: accept but never relay — hold the client open. */
    if (g_hang) {
        struct pollfd hp = { cfd, POLLIN, 0 };
        while (g_hang && g_drop_epoch == epoch && !g_blocked) {
            if (poll(&hp, 1, 100) > 0 && (hp.revents & (POLLHUP | POLLERR))) {
                break;   /* client gave up */
            }
        }
        close(cfd);
        CDEC(active);
        return 1;
    }
    return 0;
}


/* Relay one poll-ready direction through the fault engine.  Returns 0 to keep
 * looping, 1 on EOF/read error (caller closes both ends), 2 if a fault severed
 * the pair (already closed + CDEC, caller just returns). */
static int
relay_pump_dir(int i, struct pollfd *pfd, int cfd, int ufd,
               char *buf, size_t bufsz, unsigned epoch,
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr)
{
    if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
        return 0;
    }
    int from = pfd[i].fd;
    int to   = pfd[i ^ 1].fd;
    ssize_t nr = read(from, buf, bufsz);
    if (nr <= 0) {
        return 1;
    }
    volatile lever_t *L = (i == 0) ? &g_up : &g_down;
    unsigned long *conn_ctr = (i == 0) ? up_ctr : down_ctr;
    unsigned long *glob_ctr = (i == 0) ? &C.up_bytes : &C.down_bytes;
    if (forward_faulted(to, buf, nr, epoch, L, seed, conn_ctr, glob_ctr) != 0) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 2;
    }
    return 0;
}


/* Bidirectional relay loop: shuttle bytes each way through the fault engine
 * until EOF, a control-plane sever, or a poll error.  Closes both ends + CDEC
 * before returning. */
static void
relay_pump(int cfd, int ufd, unsigned epoch, unsigned seed)
{
    struct pollfd pfd[2];
    pfd[0].fd = cfd;   /* client   -> upstream (up)   */
    pfd[1].fd = ufd;   /* upstream -> client   (down) */
    char buf[65536];
    unsigned long up_ctr = 0, down_ctr = 0;
    unsigned hc_epoch = g_halfclose_epoch;
    int      hc_done  = 0;

    for (;;) {
        if (g_blocked || g_drop_epoch != epoch) {
            sever(cfd, ufd, g_abortive);
            CDEC(active);
            return;
        }
        /* half-close: FIN the up path, keep the down path flowing. */
        if (!hc_done && g_halfclose_epoch != hc_epoch) {
            shutdown(cfd, SHUT_RD);
            shutdown(ufd, SHUT_WR);
            hc_done = 1;
        }
        pfd[0].events = hc_done ? 0 : POLLIN;
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
            int r = relay_pump_dir(i, pfd, cfd, ufd, buf, sizeof(buf),
                                   epoch, &seed, &up_ctr, &down_ctr);
            if (r == 2) {
                return;         /* severed + CDEC already done */
            }
            if (r == 1) {
                goto done;      /* EOF */
            }
        }
    }
done:
    close(cfd);
    close(ufd);
    CDEC(active);
}


static void *
relay_thread(void *arg)
{
    relay_arg *ra = (relay_arg *) arg;
    int        cfd = ra->client_fd;
    unsigned   epoch = ra->epoch;
    unsigned long conn_id = ra->conn_id;
    free(ra);

    unsigned seed = g_seed + (unsigned) conn_id * 2654435761u;

    if (relay_predial(cfd, epoch, conn_id)) {
        return NULL;
    }

    int ufd = dial_any();
    if (ufd < 0) {
        close(cfd);
        CDEC(active);
        return NULL;
    }
    /* Egress NODELAY on BOTH ends so chunk/drip pieces are delivered as separate
     * segments (otherwise the kernel coalesces them and the peer never sees a
     * partial PDU).  The accept side already set NODELAY on cfd. */
    { int one = 1;
      setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

    relay_pump(cfd, ufd, epoch, seed);
    return NULL;
}

/* Strip a trailing up|down|both direction token from `args`; return which lever
 * set(s) it names: 0 = both, 1 = up only, 2 = down only. */
static int
dir_of(char *args)
{
    size_t L = strlen(args);
    while (L > 0 && isspace((unsigned char) args[L - 1])) {
        args[--L] = '\0';
    }
    char *sp = strrchr(args, ' ');
    char *tok = sp ? sp + 1 : args;
    int d = -1;
    if (strcmp(tok, "up") == 0)   d = 1;
    else if (strcmp(tok, "down") == 0) d = 2;
    else if (strcmp(tok, "both") == 0) d = 0;
    if (d < 0) {
        return 0;   /* no direction token -> both, leave args untouched */
    }
    if (sp) {
        *sp = '\0';   /* drop the token so numeric parse ignores it */
    } else {
        args[0] = '\0';
    }
    return d;
}

/* d: 0 both / 1 up / 2 down.  Set field `f` to value `v` on the named set(s). */
#define SET_DIR(d, f, v) do {                     \
    if ((d) != 2) g_up.f = (v);                   \
    if ((d) != 1) g_down.f = (v);                 \
} while (0)

static void
reset_lever(volatile lever_t *L)
{
    L->latency_ms = 0; L->jitter_ms = 0; L->chunk_bytes = 0;
    L->drip_bytes = 0; L->drip_ms = 0;   L->rate_kbps = 0;
    L->lossy_ppm = 0;  L->reorder_ppm = 0; L->reorder_ms = 50;
    L->corrupt_ppm = 0; L->dup_ppm = 0;  L->truncate_at = 0;
}

static void
clear_all(void)
{
    reset_lever(&g_up);
    reset_lever(&g_down);
    g_blocked = 0;
    g_hang = 0;
    g_one_shot = 0;
    g_fail_nth = 0;
}

static void *
heal_thread(void *arg)
{
    long ms = (long) (intptr_t) arg;
    if (ms > 0) {
        usleep((useconds_t) ms * 1000);
    }
    clear_all();
    return NULL;
}

/* Directional traffic levers (latency/bandwidth/corruption). Each strips an
 * optional up/down/both token via dir_of() then sets the field on the selected
 * direction(s). `args` is mutated. Returns 1 if `verb` was a lever, else 0. */
static int
cmd_set_lever(const char *verb, char *args)
{
    if (strcmp(verb, "latency") == 0) {
        int d = dir_of(args); SET_DIR(d, latency_ms, atoi(args));
    } else if (strcmp(verb, "jitter") == 0) {
        int d = dir_of(args); SET_DIR(d, jitter_ms, atoi(args));
    } else if (strcmp(verb, "chunk") == 0) {
        int d = dir_of(args); SET_DIR(d, chunk_bytes, atoi(args));
    } else if (strcmp(verb, "rate") == 0) {
        int d = dir_of(args); SET_DIR(d, rate_kbps, atoi(args));
    } else if (strcmp(verb, "drip") == 0) {
        int d = dir_of(args); int b = 0, m = 0;
        sscanf(args, "%d %d", &b, &m);
        SET_DIR(d, drip_bytes, b); SET_DIR(d, drip_ms, m);
    } else if (strcmp(verb, "lossy") == 0) {
        int d = dir_of(args);
        SET_DIR(d, lossy_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "corrupt") == 0) {
        int d = dir_of(args);
        SET_DIR(d, corrupt_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "dup") == 0) {
        int d = dir_of(args);
        SET_DIR(d, dup_ppm, (int) (strtod(args, NULL) * 10000.0 + 0.5));
    } else if (strcmp(verb, "reorder") == 0) {
        int d = dir_of(args); double p = 0; int m = -1;
        sscanf(args, "%lf %d", &p, &m);
        SET_DIR(d, reorder_ppm, (int) (p * 10000.0 + 0.5));
        if (m >= 0) { SET_DIR(d, reorder_ms, m); }
    } else if (strcmp(verb, "truncate-at") == 0) {
        int d = dir_of(args); SET_DIR(d, truncate_at, atol(args));
    } else {
        return 0;
    }
    return 1;
}

/* Connection-lifecycle controls: bump the live epoch (drop/reset/half-close/
 * block) or toggle a persistent outage/hang state. Returns 1 if handled. */
static int
cmd_set_epoch(const char *verb)
{
    if (strcmp(verb, "drop") == 0) {
        g_abortive = 0;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "reset") == 0) {
        g_abortive = 1;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "half-close") == 0) {
        __atomic_add_fetch(&g_halfclose_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "hang") == 0) {
        g_hang = 1;
    } else if (strcmp(verb, "unhang") == 0) {
        g_hang = 0;
    } else if (strcmp(verb, "block") == 0) {
        g_blocked = 1;
        __atomic_add_fetch(&g_drop_epoch, 1, __ATOMIC_SEQ_CST);
    } else if (strcmp(verb, "unblock") == 0) {
        g_blocked = 0;
    } else {
        return 0;
    }
    return 1;
}

/* One-off controls: fault counters, the deferred heal timer, reset-all.
 * Returns 1 if handled. */
static int
cmd_set_misc(const char *verb, const char *args)
{
    if (strcmp(verb, "fail-nth") == 0) {
        g_fail_nth = atoi(args);
    } else if (strcmp(verb, "heal-after") == 0) {
        pthread_t h;
        if (pthread_create(&h, NULL, heal_thread,
                           (void *) (intptr_t) atol(args)) == 0) {
            pthread_detach(h);
        }
    } else if (strcmp(verb, "one-shot") == 0) {
        g_one_shot = 1;
    } else if (strcmp(verb, "abortive") == 0) {
        g_abortive = atoi(args) ? 1 : 0;
    } else if (strcmp(verb, "clear") == 0) {
        clear_all();
    } else {
        return 0;
    }
    return 1;
}

/* Emit the full lever + counter snapshot into `reply` (no-op if NULL/empty). */
static void
cmd_status_report(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    snprintf(reply, rsz,
"up[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld] "
"down[lat=%d jit=%d chunk=%d drip=%d/%dms rate=%d lossy=%.4f%% reorder=%.4f%%/%dms "
"corrupt=%.4f%% dup=%.4f%% trunc=%ld] "
"blocked=%d hang=%d abortive=%d one_shot=%d fail_nth=%d epoch=%u | "
"conns=%lu active=%lu up=%luB down=%luB severs=%lu corrupt=%lu dups=%lu refused=%lu\n",
        g_up.latency_ms, g_up.jitter_ms, g_up.chunk_bytes, g_up.drip_bytes,
        g_up.drip_ms, g_up.rate_kbps, g_up.lossy_ppm / 10000.0,
        g_up.reorder_ppm / 10000.0, g_up.reorder_ms, g_up.corrupt_ppm / 10000.0,
        g_up.dup_ppm / 10000.0, g_up.truncate_at,
        g_down.latency_ms, g_down.jitter_ms, g_down.chunk_bytes, g_down.drip_bytes,
        g_down.drip_ms, g_down.rate_kbps, g_down.lossy_ppm / 10000.0,
        g_down.reorder_ppm / 10000.0, g_down.reorder_ms, g_down.corrupt_ppm / 10000.0,
        g_down.dup_ppm / 10000.0, g_down.truncate_at,
        g_blocked, g_hang, g_abortive, g_one_shot, g_fail_nth, g_drop_epoch,
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused);
}

/* Parse and apply one control command.  `line` is mutated.  `reply` (may be NULL)
 * receives a human-readable response of up to `rsz` bytes. */
static void
apply_command(char *line, char *reply, size_t rsz)
{
    char verb[32] = "", args[224] = "";
    sscanf(line, "%31s %223[^\n]", verb, args);
    if (reply && rsz) {
        snprintf(reply, rsz, "ok\n");
    }

    if (cmd_set_lever(verb, args) || cmd_set_epoch(verb)
        || cmd_set_misc(verb, args)) {
        return;
    }
    if (strcmp(verb, "status") == 0) {
        cmd_status_report(reply, rsz);
    } else if (verb[0] != '\0' && reply && rsz) {
        snprintf(reply, rsz, "err: unknown command\n");
    }
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
            char reply[768];
            apply_command(line, reply, sizeof(reply));
            (void) write_all(cfd, reply, (ssize_t) strlen(reply));
        }
        close(cfd);
    }
    return NULL;
}

/* Replay a '<seconds> <command>' timeline file (relative to start). */
static void *
script_thread(void *arg)
{
    FILE *fp = fopen((const char *) arg, "r");
    if (fp == NULL) {
        fprintf(stderr, "brix-fault-proxy: cannot open --script '%s'\n",
                (const char *) arg);
        return NULL;
    }
    char   line[256];
    double prev = 0.0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }
        double t = 0.0;
        int    off = 0;
        if (sscanf(p, "%lf %n", &t, &off) < 1) {
            continue;
        }
        double dt = t - prev;
        if (dt > 0) {
            usleep((useconds_t) (dt * 1e6));
        }
        prev = t;
        apply_command(p + off, NULL, 0);
    }
    fclose(fp);
    return NULL;
}

/* Add one "host:port" (or a comma-separated list) to the target pool. */
static int
add_target(const char *spec)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    for (char *tok = strtok(tmp, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (g_ntargets >= FP_MAX_TARGETS) {
            fprintf(stderr, "brix-fault-proxy: too many --target (max %d)\n",
                    FP_MAX_TARGETS);
            return -1;
        }
        const char *colon = strrchr(tok, ':');
        if (colon == NULL || colon == tok || colon[1] == '\0') {
            fprintf(stderr, "brix-fault-proxy: invalid --target '%s' "
                            "(expected HOST:PORT)\n", tok);
            return -1;
        }
        size_t hlen = (size_t) (colon - tok);
        if (hlen >= sizeof(g_targets[0].host)) {
            return -1;
        }
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "brix-fault-proxy: invalid target port in '%s'\n", tok);
            return -1;
        }
        memcpy(g_targets[g_ntargets].host, tok, hlen);
        g_targets[g_ntargets].host[hlen] = '\0';
        g_targets[g_ntargets].port = p;
        g_ntargets++;
    }
    return 0;
}

static int
sa_is_loopback(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        uint32_t a = ntohl(((const struct sockaddr_in *) sa)->sin_addr.s_addr);
        return (a >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        return IN6_IS_ADDR_LOOPBACK(
            &((const struct sockaddr_in6 *) sa)->sin6_addr) ? 1 : 0;
    }
    return 0;
}

/* Bind+listen on a copy of `tmpl` (family-agnostic) with `port` substituted. */
static int
listen_sa(const struct sockaddr_storage *tmpl, socklen_t slen, int port)
{
    struct sockaddr_storage ss = *tmpl;
    if (ss.ss_family == AF_INET) {
        ((struct sockaddr_in *) &ss)->sin_port = htons((uint16_t) port);
    } else {
        ((struct sockaddr_in6 *) &ss)->sin6_port = htons((uint16_t) port);
    }
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(fd, (struct sockaddr *) &ss, slen) != 0 || listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Parsed command-line configuration for the proxy run. Lever options
 * (--latency, --block, …) are not carried here: they mutate the global
 * fault levers via apply_command() as they are parsed. */
typedef struct {
    int         listen_port;
    int         control_port;
    const char *bind_str;
    const char *script_path;
    int         insecure;
    int         quiet;
} fp_config;

/* Route an initial-lever long option (--latency, --block, …) through the same
 * command parser as the live control port. Returns 1 if `opt` was a lever
 * option (handled), 0 otherwise so the core option switch can claim it. */
static int
fp_apply_lever_opt(int opt, const char *optarg)
{
    static const struct { int code; const char *name; } lever[] = {
        {1000, "latency"}, {1001, "jitter"},  {1002, "chunk"},   {1003, "drip"},
        {1004, "lossy"},   {1005, "reorder"}, {1007, "corrupt"}, {1008, "dup"},
        {1009, "rate"},    {1010, "truncate-at"}, {1011, "fail-nth"},
        {1012, "heal-after"},
    };
    char   cmd[256];
    size_t i;

    if (opt == 1006) { apply_command((char[]){"block"}, NULL, 0); return 1; }
    if (opt == 1013) { apply_command((char[]){"hang"},  NULL, 0); return 1; }

    for (i = 0; i < sizeof(lever) / sizeof(lever[0]); i++) {
        if (lever[i].code == opt) {
            snprintf(cmd, sizeof(cmd), "%s %s", lever[i].name, optarg);
            apply_command(cmd, NULL, 0);
            return 1;
        }
    }
    return 0;
}

/* Apply a single core (non-lever) option to `cfg`. Returns FP_CONTINUE to keep
 * parsing, or a terminal exit code (FP_OK for --help/--version, FP_USAGE on
 * an unknown option or a rejected --target). */
static int
fp_apply_core_opt(int opt, fp_config *cfg)
{
    switch (opt) {
    case 'l': cfg->listen_port = atoi(optarg); break;
    case 't':
        if (add_target(optarg) != 0) {
            return FP_USAGE;
        }
        break;
    case 'c': cfg->control_port = atoi(optarg); break;
    case 'b': cfg->bind_str = optarg; break;
    case 'I': cfg->insecure = 1; break;
    case 'q': cfg->quiet = 1; break;
    case 1014: g_seed = (unsigned) strtoul(optarg, NULL, 0); break;
    case 1015: g_max_conns = atoi(optarg); break;
    case 1016: cfg->script_path = optarg; break;
    case 'h': usage(stdout); return FP_OK;
    case 'V':
        printf("brix-fault-proxy (BriX-Cache client) %s\n", brix_client_version());
        return FP_OK;
    default:
        usage(stderr);
        return FP_USAGE;
    }
    return FP_CONTINUE;
}

/* Fold any positional arguments into `cfg` and validate the required config.
 *
 * Positional back-compat: `brix-fault-proxy LISTEN HOST PORT CONTROL`.
 * Accepted only when no --listen/--target/--control were given, so the two
 * calling conventions never half-mix into a confusing partial config. */
static int
fp_finalize_config(int argc, char **argv, fp_config *cfg)
{
    int npos = argc - optind;

    if (cfg->listen_port == 0 && cfg->control_port == 0 && g_ntargets == 0
        && npos == 4) {
        cfg->listen_port = atoi(argv[optind]);
        char hp[512];
        snprintf(hp, sizeof(hp), "%s:%s", argv[optind + 1], argv[optind + 2]);
        if (add_target(hp) != 0) {
            return FP_USAGE;
        }
        cfg->control_port = atoi(argv[optind + 3]);
    } else if (npos != 0) {
        fprintf(stderr, "brix-fault-proxy: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return FP_USAGE;
    }

    if (cfg->listen_port <= 0 || cfg->control_port <= 0 || g_ntargets == 0) {
        fprintf(stderr, "brix-fault-proxy: --listen, --target and --control "
                        "are all required\n");
        usage(stderr);
        return FP_USAGE;
    }
    return FP_CONTINUE;
}

/* Parse argv into `cfg`, applying lever options as a side effect. Returns
 * FP_CONTINUE when the caller should proceed to run, otherwise a terminal
 * exit code. */
static int
fp_parse_args(int argc, char **argv, fp_config *cfg)
{
    static const struct option longopts[] = {
        {"listen",        required_argument, NULL, 'l'},
        {"target",        required_argument, NULL, 't'},
        {"control",       required_argument, NULL, 'c'},
        {"bind",          required_argument, NULL, 'b'},
        {"insecure-bind", no_argument,       NULL, 'I'},
        {"max-conns",     required_argument, NULL, 1015},
        {"seed",          required_argument, NULL, 1014},
        {"script",        required_argument, NULL, 1016},
        {"quiet",         no_argument,       NULL, 'q'},
        {"latency",       required_argument, NULL, 1000},
        {"jitter",        required_argument, NULL, 1001},
        {"chunk",         required_argument, NULL, 1002},
        {"drip",          required_argument, NULL, 1003},
        {"lossy",         required_argument, NULL, 1004},
        {"reorder",       required_argument, NULL, 1005},
        {"block",         no_argument,       NULL, 1006},
        {"corrupt",       required_argument, NULL, 1007},
        {"dup",           required_argument, NULL, 1008},
        {"rate",          required_argument, NULL, 1009},
        {"truncate-at",   required_argument, NULL, 1010},
        {"fail-nth",      required_argument, NULL, 1011},
        {"heal-after",    required_argument, NULL, 1012},
        {"hang",          no_argument,       NULL, 1013},
        {"help",          no_argument,       NULL, 'h'},
        {"version",       no_argument,       NULL, 'V'},
        {0, 0, 0, 0},
    };
    int opt, rc;

    while ((opt = getopt_long(argc, argv, "l:t:c:b:qhV", longopts, NULL)) != -1) {
        if (fp_apply_lever_opt(opt, optarg)) {
            continue;
        }
        if ((rc = fp_apply_core_opt(opt, cfg)) != FP_CONTINUE) {
            return rc;
        }
    }
    return fp_finalize_config(argc, argv, cfg);
}

/* Resolve `bind_str` into `bind_ss`/`bind_len` and enforce the loopback gate.
 * The control port is unauthenticated, so a non-loopback bind must be a
 * deliberate, explicit act (--insecure-bind). Returns FP_CONTINUE or FP_USAGE. */
static int
fp_setup_bind(const char *bind_str, int insecure,
    struct sockaddr_storage *bind_ss, socklen_t *bind_len)
{
    struct addrinfo hints, *bres = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;
    if (getaddrinfo(bind_str, "0", &hints, &bres) != 0 || bres == NULL) {
        fprintf(stderr, "brix-fault-proxy: invalid --bind address '%s'\n", bind_str);
        return FP_USAGE;
    }
    *bind_len = bres->ai_addrlen;
    memcpy(bind_ss, bres->ai_addr, bres->ai_addrlen);
    freeaddrinfo(bres);

    /* Fail closed on a non-loopback bind unless the operator opts in. */
    if (!sa_is_loopback((struct sockaddr *) bind_ss) && !insecure) {
        fprintf(stderr, "brix-fault-proxy: refusing to bind the unauthenticated "
                        "control port to non-loopback '%s' without "
                        "--insecure-bind\n", bind_str);
        return FP_USAGE;
    }
    if (!sa_is_loopback((struct sockaddr *) bind_ss)) {
        fprintf(stderr, "brix-fault-proxy: WARNING binding control port to %s — "
                        "the control plane is UNAUTHENTICATED\n", bind_str);
    }
    return FP_CONTINUE;
}

/* Accept clients on `lfd` forever, spawning a detached relay thread per
 * connection (subject to the outage/connection-cap levers). Returns FP_OK when
 * the accept loop terminates on a non-EINTR error. */
static int
fp_accept_loop(int lfd)
{
    for (;;) {
        int client = accept(lfd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (g_blocked) {
            CBUMP(refused, 1);
            close(client);        /* outage: refuse */
            continue;
        }
        if (g_max_conns > 0
            && __atomic_load_n(&C.active, __ATOMIC_RELAXED) >= (unsigned long) g_max_conns) {
            CBUMP(refused, 1);
            close(client);        /* connection cap reached */
            continue;
        }
        int one = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        relay_arg *ra = malloc(sizeof(*ra));
        ra->client_fd = client;
        ra->epoch = __atomic_load_n(&g_drop_epoch, __ATOMIC_SEQ_CST);
        ra->conn_id = CBUMP(conns, 1);
        CBUMP(active, 1);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_thread, ra) != 0) {
            close(client);
            CDEC(active);
            free(ra);
            continue;
        }
        pthread_detach(t);
    }
    return FP_OK;
}

/* Print the startup banner (target chain + control endpoint). */
static void
fp_print_banner(const fp_config *cfg)
{
    printf("brix-fault-proxy: %s:%d -> %s:%d", cfg->bind_str, cfg->listen_port,
           g_targets[0].host, g_targets[0].port);
    for (int i = 1; i < g_ntargets; i++) {
        printf(",%s:%d", g_targets[i].host, g_targets[i].port);
    }
    printf("  (control %s:%d)\n", cfg->bind_str, cfg->control_port);
    fflush(stdout);
}

int
main(int argc, char **argv)
{
    fp_config               cfg = { .bind_str = "127.0.0.1" };
    struct sockaddr_storage bind_ss;
    socklen_t               bind_len;
    int                     rc;

    reset_lever(&g_up);
    reset_lever(&g_down);

    if ((rc = fp_parse_args(argc, argv, &cfg)) != FP_CONTINUE) {
        return rc;
    }
    if ((rc = fp_setup_bind(cfg.bind_str, cfg.insecure, &bind_ss, &bind_len))
        != FP_CONTINUE) {
        return rc;
    }

    signal(SIGPIPE, SIG_IGN);

    int lfd   = listen_sa(&bind_ss, bind_len, cfg.listen_port);
    int ctlfd = listen_sa(&bind_ss, bind_len, cfg.control_port);
    if (lfd < 0 || ctlfd < 0) {
        fprintf(stderr, "brix-fault-proxy: bind failed (listen=%d control=%d)\n",
                cfg.listen_port, cfg.control_port);
        return FP_RUN;
    }

    pthread_t ct;
    int *cfdp = malloc(sizeof(int));
    *cfdp = ctlfd;
    pthread_create(&ct, NULL, control_thread, cfdp);

    if (cfg.script_path != NULL) {
        pthread_t st;
        if (pthread_create(&st, NULL, script_thread, (void *) cfg.script_path) == 0) {
            pthread_detach(st);
        }
    }

    if (!cfg.quiet) {
        fp_print_banner(&cfg);
    }

    return fp_accept_loop(lfd);
}
