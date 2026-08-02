/*
 * brix_fault_proxy_relay.c — brix-fault-proxy data plane.
 *
 * WHAT: the thread-per-connection relay and the byte-level fault engine it runs
 *       through — upstream dialling/failover, the per-segment latency, jitter,
 *       reorder, rate-cap, corruption, duplication, truncation and loss levers,
 *       and the bidirectional poll pump that shuttles bytes each way until EOF,
 *       a control-plane sever, or a poll error.
 *
 * WHY:  this is the hot path: every forwarded byte flows through here, and it is
 *       the part that actually reproduces "bad network" for a peer.  Isolating
 *       it from the control-plane parser and the CLI keeps the fault mechanics
 *       in one place with no argument-parsing or lifecycle noise.
 *
 * HOW:  each accepted connection gets a detached relay_thread; per-thread
 *       rand_r() state (seeded from --seed + conn id) makes every fault
 *       reproducible; a snapshot of the volatile levers is taken once per read
 *       so a mid-buffer control change can't split one read across two fault
 *       configs; the global drop/half-close epoch counters let the control
 *       plane sever or half-close live relays without touching their fds.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "brix_fault_proxy_internal.h"

/* Per-direction token-bucket state for the `rate` gate (B5).  Lives on the
 * relay_pump stack — never global — so two connections never share credit. */
typedef struct {
    double          tokens;   /* bytes of send credit currently available */
    struct timespec last;     /* CLOCK_MONOTONIC of the last refill        */
    int             primed;   /* 0 until the first gate call seeds `last`   */
} rate_bucket;

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

/* Dial the next target in round-robin order, failing over to the rest.  With a
 * route, use that route's own target pool + cursor; otherwise the globals. */
static int
dial_route(fp_route *rt)
{
    fp_target *pool = (rt && rt->ntargets > 0) ? rt->targets : g_targets;
    int        n    = (rt && rt->ntargets > 0) ? rt->ntargets : g_ntargets;
    unsigned  *cur  = (rt && rt->ntargets > 0) ? &rt->rr : &g_rr;
    if (n <= 0) {
        return -1;
    }
    unsigned start = __atomic_fetch_add(cur, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < n; i++) {
        int idx = (int) ((start + (unsigned) i) % (unsigned) n);
        int fd = dial(pool[idx].host, pool[idx].port);
        if (fd >= 0) {
            return fd;
        }
    }
    return -1;
}

int
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
    } else {
        /* slow-close: delay the graceful FIN so a peer that depends on prompt
         * teardown is exercised. RST (abortive) is immediate and wins. */
        int sc = g_up.slow_close_ms > g_down.slow_close_ms
               ? g_up.slow_close_ms : g_down.slow_close_ms;
        if (sc > 0) {
            usleep((useconds_t) sc * 1000);
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

/* Sample this direction's jitter delay in ms: uniform 0..jitter_ms (default), or
 * normal(jitter_ms, sigma) built from an Irwin-Hall sum of 12 uniforms (no libm),
 * clamped to >=0. sigma defaults to jitter_ms/4 when unset. */
static int
fault_sample_jitter_ms(unsigned *seed, const lever_t *L)
{
    if (L->lat_dist == 1) {
        double sum = 0.0;
        for (int k = 0; k < 12; k++) {
            sum += (double) (rand_r(seed) % 1000000u) / 1000000.0;
        }
        double sigma = (L->lat_sigma_ms > 0) ? (double) L->lat_sigma_ms
                                             : (double) L->jitter_ms / 4.0;
        double v = (double) L->jitter_ms + (sum - 6.0) * sigma;
        return (v > 0.0) ? (int) v : 0;
    }
    return (int) (rand_r(seed) % (unsigned) (L->jitter_ms + 1));
}

/* Token-bucket bandwidth gate (B5): refill `bucket` by the credit earned since
 * the last call (elapsed * rate, capped at the burst depth), then usleep only for
 * the deficit if this segment overdraws.  A monotonic clock makes it immune to the
 * WSL2 backward-clock step ([[wsl2-clock-backwards-steps]]) — a negative elapsed
 * clamps to 0 credit rather than stalling.  Burst defaults to one MTU so the
 * default path tracks the old per-segment usleep but smoother. */
static void
fault_rate_gate(ssize_t seg, rate_bucket *b, const lever_t *L)
{
    if (L->rate_kbps <= 0) {
        return;                                  /* pacing disabled */
    }
    double          rate  = (double) L->rate_kbps * 1024.0;   /* bytes / second */
    double          depth = (L->burst_bytes > 0) ? (double) L->burst_bytes : 1500.0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (!b->primed) {
        b->tokens = depth;                       /* start full: burst credit */
        b->last   = now;
        b->primed = 1;
    } else {
        double elapsed = (double) (now.tv_sec - b->last.tv_sec)
                       + (double) (now.tv_nsec - b->last.tv_nsec) / 1e9;
        if (elapsed > 0.0) {                     /* clock step-back => no credit */
            b->tokens += elapsed * rate;
            if (b->tokens > depth) {
                b->tokens = depth;
            }
        }
        b->last = now;
    }

    if (b->tokens >= (double) seg) {
        b->tokens -= (double) seg;               /* covered by credit */
    } else {
        double deficit = (double) seg - b->tokens;
        b->tokens = 0.0;                         /* spend all, wait for the rest */
        usleep((useconds_t) (deficit / rate * 1e6));
    }
}

/* Apply direction `L`'s pacing/jitter/reorder delays before a segment write. */
static void
fault_delays(ssize_t seg, unsigned *seed, const lever_t *L, rate_bucket *rb)
{
    if (L->jitter_ms > 0) {
        usleep((useconds_t) fault_sample_jitter_ms(seed, L) * 1000);
    }
    if (L->reorder_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->reorder_ppm) {
        usleep((useconds_t) L->reorder_ms * 1000);
    }
    fault_rate_gate(seg, rb, L);
}

/* Flip random bits in buf[off, off+seg) at the configured per-byte rate.
 * Returns the number of bytes actually corrupted (for the batched event log). */
static long
fault_corrupt(char *buf, ssize_t off, ssize_t seg, unsigned *seed, int cor)
{
    long flipped = 0;
    if (cor <= 0) {
        return 0;
    }
    for (ssize_t k = 0; k < seg; k++) {
        if ((int) (rand_r(seed) % 1000000u) < cor) {
            buf[off + k] ^= (char) (1u << (rand_r(seed) % 8u));
            CBUMP(corrupt, 1);
            flipped++;
        }
    }
    return flipped;
}

/* Per-read fault outcome, accumulated for the optional JSONL event log (D2).
 * `reason` bubbles the sever cause up to relay_pump_dir where the direction and
 * connection id are known; corrupt/dup counts are batched (never per-byte). */
enum { FR_OK = 0, FR_SEV_TRUNCATE, FR_SEV_LOSSY, FR_SEV_DROP, FR_SEV_WRITE };
typedef struct { long corrupt; int dups; long trunc_at; } fault_tally;

/* Deliver one segment starting at buf+off, applying `L`'s active faults. On
 * success writes the delivered length to *wrote and returns 0; returns -1 when
 * the stream should be severed (truncate cut, lossy drop, write error) or
 * silently dropped (block/epoch change). */
static int
forward_segment(int to, char *buf, ssize_t off, ssize_t n, unsigned epoch,
                const lever_t *L, unsigned *seed, unsigned long *conn_ctr,
                unsigned long *glob_ctr, int piece, ssize_t *wrote,
                fault_tally *ft, rate_bucket *rb)
{
    ssize_t seg = fault_clamp_seg(n - off, piece, L->truncate_at, *conn_ctr);
    if (seg < 0) {
        ft->trunc_at = L->truncate_at;
        fault_sever();
        return FR_SEV_TRUNCATE;
    }

    fault_delays(seg, seed, L, rb);

    if (L->lossy_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->lossy_ppm) {
        fault_sever();          /* application-visible "loss" = sever the stream */
        return FR_SEV_LOSSY;
    }
    if (g_blocked || g_drop_epoch != epoch) {
        return FR_SEV_DROP;     /* silent drop (outage / epoch bump) */
    }

    ft->corrupt += fault_corrupt(buf, off, seg, seed, L->corrupt_ppm);

    if (write_all(to, buf + off, seg) != 0) {
        return FR_SEV_WRITE;
    }
    if (L->dup_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->dup_ppm) {
        (void) write_all(to, buf + off, seg);   /* duplicate delivery */
        CBUMP(dups, 1);
        ft->dups++;
    }

    CBUMP2(conn_ctr, glob_ctr, seg);
    *wrote = seg;

    if (L->truncate_at > 0 && (long) *conn_ctr >= L->truncate_at) {
        ft->trunc_at = L->truncate_at;
        fault_sever();          /* deterministic mid-transfer cut */
        return FR_SEV_TRUNCATE;
    }
    return FR_OK;
}

/*
 * Forward n bytes to `to`, applying direction `L`'s active fault levers.  Bytes
 * may be mutated in place (corruption).  Returns FR_OK on success, or an FR_SEV_*
 * reason code if the connection should be severed (write error, a lossy drop, a
 * silent outage drop, or a truncate cut); `ft` accumulates the batched corrupt/
 * dup counts and the truncate offset for the optional event log.
 * `seed` is this thread's private rand_r() state; `conn_ctr` the per-connection
 * per-direction running byte total (for truncate-at); `glob_ctr` the process-wide
 * traffic counter for this direction.
 */
static int
forward_faulted(int to, char *buf, ssize_t n, unsigned epoch, volatile lever_t *L,
                unsigned *seed, unsigned long *conn_ctr, unsigned long *glob_ctr,
                fault_tally *ft, rate_bucket *rb, int dir_i)
{
    /* Snapshot the levers once so a mid-buffer control-plane change can't split
     * this read across two fault configurations (matches the original). */
    lever_t snap  = *L;
    /* Fold any named toxics for this direction on top of the default levers.
     * Fast path: nothing composed (and no lock taken) when the table is empty. */
    if (g_ntoxics > 0) {
        fp_toxic_compose(&snap, dir_i);
    }
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
        int     r = forward_segment(to, buf, off, n, epoch, &snap, seed,
                                    conn_ctr, glob_ctr, piece, &wrote, ft, rb);
        if (r != FR_OK) {
            return r;
        }
        off += wrote;
        if (snap.drip_bytes > 0 && off < n) {
            usleep((useconds_t) snap.drip_ms * 1000);
        }
    }
    return FR_OK;
}

/* Pre-dial dispositions that answer the client without ever reaching upstream:
 * the fail-nth sever and the hang/black-hole hold.  Returns 1 if the connection
 * was handled (closed + CDEC), 0 to proceed with dialling upstream. */
static int
relay_predial(int cfd, unsigned epoch, unsigned long conn_id)
{
    /* fail-nth: sever exactly the Nth accepted connection, then pass the rest. */
    if (g_fail_nth > 0 && conn_id == (unsigned long) g_fail_nth) {
        CBUMP(severs, 1);
        brix_fp_event(conn_id, NULL, "sever", "fail-nth", NULL, 0);
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
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr,
               int afflict, unsigned long conn_id, rate_bucket *rb)
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
    const char    *dir      = (i == 0) ? "up" : "down";
    unsigned long *conn_ctr = (i == 0) ? up_ctr : down_ctr;
    unsigned long *glob_ctr = (i == 0) ? &C.up_bytes : &C.down_bytes;
    if (!afflict) {
        /* toxicity gate: this connection/direction is not afflicted — relay the
         * bytes untouched (still accounted) so the levers apply to only a
         * fraction of connections. */
        if (write_all(to, buf, nr) != 0) {
            brix_fp_event(conn_id, dir, "sever", "write-error", NULL, 0);
            sever(cfd, ufd, g_abortive);
            CDEC(active);
            return 2;
        }
        CBUMP2(conn_ctr, glob_ctr, nr);
        return 0;
    }
    volatile lever_t *L = (i == 0) ? &g_up : &g_down;
    fault_tally       ft = { 0, 0, 0 };
    int reason = forward_faulted(to, buf, nr, epoch, L, seed,
                                 conn_ctr, glob_ctr, &ft, rb, i);
    if (fp_event_enabled()) {
        if (ft.corrupt > 0) {
            brix_fp_event(conn_id, dir, "corrupt", NULL, "count", ft.corrupt);
        }
        if (ft.dups > 0) {
            brix_fp_event(conn_id, dir, "dup", NULL, "count", ft.dups);
        }
        if (reason == FR_SEV_TRUNCATE) {
            brix_fp_event(conn_id, dir, "truncate", NULL, "at", ft.trunc_at);
        } else if (reason == FR_SEV_LOSSY) {
            brix_fp_event(conn_id, dir, "sever", "lossy", NULL, 0);
        } else if (reason == FR_SEV_DROP) {
            brix_fp_event(conn_id, dir, "sever", "drop", NULL, 0);
        } else if (reason == FR_SEV_WRITE) {
            brix_fp_event(conn_id, dir, "sever", "write-error", NULL, 0);
        }
    }
    if (reason != FR_OK) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 2;
    }
    return 0;
}


/* Bidirectional relay loop: shuttle bytes each way through the fault engine
 * until EOF, a control-plane sever, or a poll error.  Closes both ends + CDEC
 * before returning. */
/* Fold this connection's byte totals into its route's independent counters. */
#define ROUTE_FOLD() do { if (route != NULL) {                                    \
    __atomic_add_fetch(&route->counters.up_bytes,   up_ctr,   __ATOMIC_RELAXED);  \
    __atomic_add_fetch(&route->counters.down_bytes, down_ctr, __ATOMIC_RELAXED);  \
} } while (0)

static void
relay_pump(int cfd, int ufd, unsigned epoch, unsigned seed,
           int afflict_up, int afflict_down, unsigned long conn_id, fp_route *route)
{
    struct pollfd pfd[2];
    pfd[0].fd = cfd;   /* client   -> upstream (up)   */
    pfd[1].fd = ufd;   /* upstream -> client   (down) */
    char buf[65536];
    unsigned long up_ctr = 0, down_ctr = 0;
    rate_bucket rb[2] = { { 0.0, { 0, 0 }, 0 }, { 0.0, { 0, 0 }, 0 } };
    unsigned hc_epoch = g_halfclose_epoch;
    int      hc_done  = 0;

    for (;;) {
        if (g_blocked || g_drop_epoch != epoch) {
            sever(cfd, ufd, g_abortive);
            ROUTE_FOLD();
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
                                   epoch, &seed, &up_ctr, &down_ctr,
                                   (i == 0) ? afflict_up : afflict_down,
                                   conn_id, &rb[i]);
            if (r == 2) {
                ROUTE_FOLD();
                return;         /* severed + CDEC already done */
            }
            if (r == 1) {
                goto done;      /* EOF */
            }
        }
    }
done:
    {   /* slow-close on the graceful EOF path too (RST path handled in sever). */
        int sc = g_up.slow_close_ms > g_down.slow_close_ms
               ? g_up.slow_close_ms : g_down.slow_close_ms;
        if (sc > 0) {
            usleep((useconds_t) sc * 1000);
        }
    }
    ROUTE_FOLD();
    close(cfd);
    close(ufd);
    CDEC(active);
}
#undef ROUTE_FOLD


void *
relay_thread(void *arg)
{
    relay_arg *ra = (relay_arg *) arg;
    int        cfd = ra->client_fd;
    unsigned   epoch = ra->epoch;
    unsigned long conn_id = ra->conn_id;
    fp_route  *route = ra->route;
    free(ra);

    unsigned seed = g_seed + (unsigned) conn_id * 2654435761u;
    /* toxicity: decide once, per direction, from a seed stream SEPARATE from the
     * fault RNG so the common 100% default leaves the corruption sequence
     * bit-for-bit identical to a build without this gate. */
    unsigned tseed = seed ^ 0x9E3779B9u;
    int afflict_up   = (int) (rand_r(&tseed) % 1000000u) < g_toxicity_up_ppm;
    int afflict_down = (int) (rand_r(&tseed) % 1000000u) < g_toxicity_down_ppm;

    if (relay_predial(cfd, epoch, conn_id)) {
        return NULL;
    }
    if (g_connect_delay_ms > 0) {
        usleep((useconds_t) g_connect_delay_ms * 1000);  /* slow connection setup */
    }

    int ufd = dial_route(route);
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

    relay_pump(cfd, ufd, epoch, seed, afflict_up, afflict_down, conn_id, route);
    return NULL;
}
