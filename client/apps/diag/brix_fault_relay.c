/* brix_fault_relay.c — data-path fault application and byte forwarding.
 *
 * WHAT: The per-segment fault kernels — clamp, delay, corrupt, the aggregate rate
 *       gate — and the two forwarding entry points every relayed byte passes
 *       through, plus the config snapshots (ext/TLS/HTTP/trigger/mangle) the
 *       hot path takes under g_ext_lock.
 *
 * WHY:  Split out of brix_fault_proxy.c, which was far over the 600-line cap
 *       (coding-standards §1). The program's shared lever state stayed where
 *       it was defined; see brix_fault_proxy_state.h for the seam.
 *
 * HOW:  Same behaviour as before the split — this is a pure move. Levers are
 *       read lock-free; wide config is snapshotted under g_ext_lock. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include "brix_fault_proxy_mods.h"
#include "brix_fault_toxic.h"
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Blocking connect to host:port (best-effort, first address that works). */
int
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
void
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
 * `reason` (truncate/lossy/…) is recorded to the optional JSONL event log,
 * attributed to this thread's connection.  Returns -1 so a caller can
 * `return fault_sever(reason);`. */
int
fault_sever(const char *reason)
{
    CBUMP(severs, 1);
    brix_fp_event(t_conn_id, NULL, "sever", reason, NULL, 0);
    if (g_one_shot) {
        clear_all();
    }
    return -1;
}

/* Clamp the outgoing segment to the chunk `piece` and, if truncation is armed,
 * to the exact remaining distance to the cut. Returns the clamped length, or -1
 * when the truncation point is already reached (caller must sever). */
ssize_t
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
void
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
void
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

/* Aggregate token-bucket gate: pace this segment against a single uplink ceiling
 * shared across ALL relays (simulates a saturated shared link / upstream link).
 * Briefly holds g_gr_lock to update the shared tokens, then sleeps unlocked. */
void
global_rate_gate(ssize_t seg)
{
    int kbps = g_global_rate_kbps;
    if (kbps <= 0) {
        return;
    }
    double rate = (double) kbps * 1024.0;   /* bytes / second */
    pthread_mutex_lock(&g_gr_lock);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!g_gr_init) {
        g_gr_last = now;
        g_gr_tokens = 0.0;
        g_gr_init = 1;
    }
    double elapsed = (now.tv_sec - g_gr_last.tv_sec)
                   + (now.tv_nsec - g_gr_last.tv_nsec) / 1e9;
    g_gr_tokens += elapsed * rate;
    if (g_gr_tokens > rate) {
        g_gr_tokens = rate;   /* cap the burst at ~1s of credit */
    }
    g_gr_last = now;
    g_gr_tokens -= (double) seg;
    double deficit = g_gr_tokens < 0.0 ? -g_gr_tokens : 0.0;
    pthread_mutex_unlock(&g_gr_lock);
    if (deficit > 0.0) {
        usleep((useconds_t) (deficit / rate * 1e6));
    }
}

/* Deliver one segment starting at buf+off, applying `L`'s active faults. On
 * success writes the delivered length to *wrote and returns 0; returns -1 when
 * the stream should be severed (truncate cut, lossy drop, write error) or
 * silently dropped (block/epoch change). */
int
forward_segment(int to, char *buf, ssize_t off, ssize_t n, unsigned epoch,
                const lever_t *L, unsigned *seed, unsigned long *conn_ctr,
                unsigned long *glob_ctr, int piece, ssize_t *wrote)
{
    ssize_t seg = fault_clamp_seg(n - off, piece, L->truncate_at, *conn_ctr);
    if (seg < 0) {
        return fault_sever("truncate");
    }

    fault_delays(seg, seed, L);

    if (L->lossy_ppm > 0 && (int) (rand_r(seed) % 1000000u) < L->lossy_ppm) {
        return fault_sever("lossy");   /* application-visible "loss" = sever the stream */
    }
    if (g_blocked || g_drop_epoch != epoch) {
        return -1;
    }

    fault_corrupt(buf, off, seg, seed, L->corrupt_ppm);
    global_rate_gate(seg);

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
        return fault_sever("truncate");   /* deterministic mid-transfer cut */
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
int
forward_faulted(int to, char *buf, ssize_t n, unsigned epoch, volatile lever_t *L,
                unsigned *seed, unsigned long *conn_ctr, unsigned long *glob_ctr)
{
    /* Snapshot the levers once so a mid-buffer control-plane change can't split
     * this read across two fault configurations (matches the original). */
    lever_t snap  = *L;
    /* Fold any named toxics for this direction onto the snapshot (never the live
     * levers).  The lock-free gate keeps the zero-toxic path free of the lock. */
    int     is_up = (L == &g_up);
    if (fp_toxic_active(is_up)) {
        fp_toxic_compose(is_up, &snap);
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

/* Dial this route's target pool in round-robin order with failover. */
int
dial_route(fp_route *route)
{
    int n = fp_route_target_count(route);
    if (n <= 0) {
        return -1;
    }
    unsigned start = fp_route_rr_next(route);
    for (int i = 0; i < n; i++) {
        char host[256];
        int  port = 0;
        fp_route_get_target(route, start + (unsigned) i, host, sizeof host, &port);
        int fd = dial(host, port);
        if (fd >= 0) {
            return fd;
        }
    }
    return -1;
}

/* Pre-dial dispositions that answer the client without ever reaching upstream:
 * the fail-nth sever and the hang/black-hole hold.  Returns 1 if the connection
 * was handled (closed + CDEC), 0 to proceed with dialling upstream. */
int
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

/* Snapshot the (locked) payload-mutation config for one direction into caller
 * storage, CONSUMING any pending one-shot inject.  Returns 1 if a mutation is
 * active (caller should run fp_ext_mutate), 0 to forward bytes untouched. */
int
ext_snapshot(int is_up, volatile lever_t *L, fp_ext_mut *mut,
             unsigned char *fbuf, unsigned char *rbuf, unsigned char *ibuf)
{
    struct fp_mutbuf *M = is_up ? &g_up_mut : &g_down_mut;
    pthread_mutex_lock(&g_ext_lock);
    memcpy(fbuf, M->find, (size_t) M->find_len);
    memcpy(rbuf, M->repl, (size_t) M->repl_len);
    memcpy(ibuf, M->inject, (size_t) M->inject_len);
    mut->find = fbuf;   mut->find_len   = (size_t) M->find_len;
    mut->repl = rbuf;   mut->repl_len   = (size_t) M->repl_len;
    mut->inject = ibuf; mut->inject_len = (size_t) M->inject_len;
    M->inject_len = 0;               /* one-shot: consumed */
    pthread_mutex_unlock(&g_ext_lock);
    mut->drop_ppm   = L->drop_ppm;
    mut->repeat_ppm = L->repeat_ppm;
    return fp_ext_mut_active(mut);
}

/* Content trigger: if this direction's armed pattern appears in the just-read
 * buffer, run its stored control command (a targeted, protocol-state fault). */
void
trig_check(int is_up, const char *buf, ssize_t nr)
{
    struct fp_trigger *T = is_up ? &g_trig_up : &g_trig_down;
    if (T->pat_len <= 0 || (T->once && T->fired)) {
        return;
    }
    char cmd[256];
    int  hit = 0;
    pthread_mutex_lock(&g_ext_lock);
    if (T->pat_len > 0 && !(T->once && T->fired) &&
        memmem(buf, (size_t) nr, T->pat, (size_t) T->pat_len) != NULL) {
        memcpy(cmd, T->cmd, sizeof(cmd));
        if (T->once) {
            T->fired = 1;
        }
        hit = 1;
    }
    pthread_mutex_unlock(&g_ext_lock);
    if (hit) {
        CBUMP(triggered, 1);
        apply_command(cmd, NULL, 0);
    }
}

/* Length-prefix lie: if the armed big-endian uint32 offset lies wholly within
 * this buffer, rewrite it (set/add/sub) — a framing attack on binary protocols. */
void
mangle_apply(int is_up, char *buf, ssize_t nr, unsigned long base)
{
    struct fp_mangle *M = is_up ? &g_mangle_up : &g_mangle_down;
    if (!M->active) {
        return;
    }
    long off = M->offset;
    if (off < (long) base || off + 4 > (long) base + nr) {
        return;   /* the 4-byte field is not fully contained in this read */
    }
    unsigned char *p = (unsigned char *) buf + (off - (long) base);
    unsigned long  v = ((unsigned long) p[0] << 24) | ((unsigned long) p[1] << 16)
                     | ((unsigned long) p[2] << 8) | (unsigned long) p[3];
    long nv = (M->op == 0) ? M->val
            : (M->op == 1) ? (long) v + M->val
            :                (long) v - M->val;
    unsigned long u = (unsigned long) nv & 0xFFFFFFFFUL;
    p[0] = (unsigned char) (u >> 24); p[1] = (unsigned char) (u >> 16);
    p[2] = (unsigned char) (u >> 8);  p[3] = (unsigned char) u;
    CBUMP(mangled, 1);
}

/* Milliseconds elapsed since the monotonic reference `t0`. */
unsigned long long
now_ms_since(struct timespec t0)
{
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (unsigned long long) ((n.tv_sec - t0.tv_sec) * 1000LL
                                 + (n.tv_nsec - t0.tv_nsec) / 1000000LL);
}

/* Snapshot this direction's (locked) TLS-surgery config and rewrite the record
 * stream in `in` into `out` (cap FP_SCRATCH).  Consumes a one-shot forged alert.
 * Returns the produced length. */
size_t
apply_tls(int is_up, const char *in, ssize_t n, unsigned char *out)
{
    fp_tls_cfg  *TC = is_up ? &g_tls_up : &g_tls_down;
    fp_tls_cfg   snap;
    fp_tls_stats st = { 0, 0, 0, 0, 0, 0 };
    pthread_mutex_lock(&g_ext_lock);
    snap = *TC;
    if (TC->alert_level >= 0) {
        TC->alert_level = -1;              /* one-shot alert consumed */
    }
    pthread_mutex_unlock(&g_ext_lock);
    size_t on = fp_tls_rewrite((const unsigned char *) in, (size_t) n,
                               out, FP_SCRATCH, &snap, &st);
    CBUMP(tls_rewrites, 1);
    return on;
}

/* Snapshot this direction's (locked) HTTP-smuggling config and rewrite the
 * message in `in` into `out`.  *applied is 0 (forward original) when the buffer
 * held no header block.  Returns the produced length. */
size_t
apply_http(int is_up, const char *in, ssize_t n, unsigned char *out, int *applied)
{
    fp_http_cfg  *HC = is_up ? &g_http_up : &g_http_down;
    fp_http_cfg   snap;
    fp_http_stats st = { 0, 0, 0, 0, 0 };
    pthread_mutex_lock(&g_ext_lock);
    snap = *HC;
    pthread_mutex_unlock(&g_ext_lock);
    size_t on = fp_http_rewrite((const unsigned char *) in, (size_t) n,
                                out, FP_SCRATCH, &snap, &st, applied);
    if (*applied) {
        CBUMP(http_rewrites, 1);
    }
    return on;
}
