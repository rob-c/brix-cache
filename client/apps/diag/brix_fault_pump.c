/* brix_fault_pump.c — the poll loop and per-connection relay thread.
 *
 * WHAT: The bidirectional poll pump, its per-direction step (with the DPI/
 *       middlebox stall levers), and the connection tuning + PROXY-header forgery
 *       applied at dial time.  The per-connection relay thread and replay playback
 *       that drive this pump live in brix_fault_relay.c.
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
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Milliseconds elapsed since `t0` on the monotonic clock. */
static long
pump_elapsed_ms(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000;
}

/* The control-plane conditions that end a connection abruptly: a global block,
 * a drop-epoch bump, or the max-lifetime guillotine.  Returns 1 when it severed
 * (both ends closed and the active count already decremented). */
static int
pump_severed(int cfd, int ufd, unsigned epoch, const struct timespec *t0)
{
    if (g_blocked || g_drop_epoch != epoch) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 1;
    }
    if (g_max_life_ms > 0 && pump_elapsed_ms(t0) >= g_max_life_ms) {
        CBUMP(severs, 1);
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 1;
    }
    /* rst-after <ms>: classify-and-kill — the flow works for a while, then dies
     * (forged RST or clean FIN per g_rst_after_abortive). */
    if (g_rst_after_ms > 0 && pump_elapsed_ms(t0) >= g_rst_after_ms) {
        CBUMP(classify_kills, 1);
        sever(cfd, ufd, g_rst_after_abortive);
        CDEC(active);
        return 1;
    }
    return 0;
}

/* Arm the poll events for one step: a stalled (or half-closed) direction stops
 * being read so the peer's send buffer fills — real TCP backpressure, without
 * ever severing. */
static void
pump_arm_events(struct pollfd *pfd, int hc_done, const int *eof, int frozen)
{
    pfd[0].events = (frozen || eof[0] || hc_done || g_stall_up) ? 0 : POLLIN;
    pfd[1].events = (frozen || eof[1] || g_stall_down) ? 0 : POLLIN;
}

/* idle-reap: a conntrack-style eviction of an idle flow — either a forged RST or
 * a silent black-hole (*frozen: no bytes, no teardown).  Returns 1 when it RST-
 * severed (both ends closed + CDEC); sets *frozen for the black-hole case. */
static int
pump_idle_reap(int cfd, int ufd, const struct timespec *act, int *frozen)
{
    if (*frozen || g_idle_reap_ms <= 0 || pump_elapsed_ms(act) < g_idle_reap_ms) {
        return 0;
    }
    CBUMP(reaped, 1);
    if (g_idle_reap_rst) {
        sever(cfd, ufd, 1);
        CDEC(active);
        return 1;
    }
    *frozen = 1;                 /* black-hole: stop forwarding, never close */
    return 0;
}

/* rst-after <bytes>: byte-volume classify-and-kill across both directions.
 * Returns 1 when it severed (both ends closed + CDEC). */
static int
pump_rst_after_bytes(int cfd, int ufd, unsigned long up, unsigned long down)
{
    if (g_rst_after_bytes > 0 && (long) (up + down) >= g_rst_after_bytes) {
        CBUMP(classify_kills, 1);
        sever(cfd, ufd, g_rst_after_abortive);
        CDEC(active);
        return 1;
    }
    return 0;
}

/* half-close: on a halfclose-epoch bump, FIN the up path while the down path
 * keeps flowing (tests half-open handling).  Latches via *hc_done. */
static void
pump_halfclose(int cfd, int ufd, int *hc_done, unsigned hc_epoch)
{
    if (!*hc_done && g_halfclose_epoch != hc_epoch) {
        shutdown(cfd, SHUT_RD);
        shutdown(ufd, SHUT_WR);
        *hc_done = 1;
    }
}

/* Handle a direction's EOF.  drop-fin swallows it (asymmetric teardown) so the
 * peer never learns the other end closed; returns 1 when the loop should stop
 * (EOF not suppressed, or both ends now closed). */
static int
pump_eof_stops(int i, int *eof)
{
    int df = (i == 0) ? g_drop_fin_up : g_drop_fin_down;
    if (df && !eof[i]) {
        eof[i] = 1;
        CBUMP(fin_dropped, 1);
        return (eof[0] && eof[1]);
    }
    return 1;
}

/* Run both poll-ready directions once.  Returns 2 if a fault severed the pair
 * (caller returns), 1 on EOF that ends the connection (caller breaks), else 0. */
static int
pump_both_dirs(struct pollfd *pfd, int cfd, int ufd, char *buf, size_t bufsz,
               unsigned char *scratch, unsigned char *scratch2, unsigned epoch,
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr,
               int *first, int *eof)
{
    int r = 0, done = 0;
    for (int i = 0; i < 2 && r == 0; i++) {
        r = relay_pump_dir(i, pfd, cfd, ufd, buf, bufsz, scratch, scratch2,
                           epoch, seed, up_ctr, down_ctr, &first[i]);
        if (r == 1) {
            if (pump_eof_stops(i, eof)) {
                done = 1;       /* r stays 1 -> inner loop halts, outer breaks */
            } else {
                r = 0;          /* suppressed -> keep looping */
            }
        }
    }
    if (r == 2) {
        return 2;
    }
    return done ? 1 : 0;
}

/* ---- Abortive-teardown checks run before every poll cycle ----
 *
 * WHAT: Returns 1 when a control-plane lever has already torn the connection
 *       down (both fds closed, CDEC done) and the pump must return at once;
 *       0 to keep pumping.
 *
 * WHY:  All three levers end the connection the same way — without the graceful
 *       teardown at the bottom of relay_pump — so grouping them makes that
 *       "already closed, do not close again" contract a single fact rather than
 *       three separate ones the loop has to remember.
 *
 * HOW:  1. sever: the drop epoch moved past this connection.
 *       2. idle-reap: no activity within the window.
 *       3. rst-after-bytes: the byte budget for this connection is spent.
 */
static int
pump_torn_down(int cfd, int ufd, unsigned epoch, struct timespec *t0,
               struct timespec *act, int *frozen,
               unsigned long up_ctr, unsigned long down_ctr)
{
    if (pump_severed(cfd, ufd, epoch, t0)) {
        return 1;
    }
    if (pump_idle_reap(cfd, ufd, act, frozen)) {
        return 1;
    }

    return pump_rst_after_bytes(cfd, ufd, up_ctr, down_ctr) ? 1 : 0;
}


/* ---- Wait one poll cycle ----
 *
 * WHAT: Returns 1 when at least one side is readable and the caller should
 *       forward, 0 when this cycle has nothing to do, -1 when poll() failed
 *       for real.
 *
 * WHY:  A 100 ms cap (not an indefinite wait) is what makes the fault levers
 *       take effect on an idle connection — the loop has to come back and
 *       re-read them.  EINTR is not a failure; folding it in here keeps the
 *       caller's error path honest.
 *
 * HOW:  1. poll both ends with the short cap.
 *       2. Map EINTR to "nothing to do", any other error to failure.
 *       3. A frozen (black-holed) connection forwards nothing even when
 *          readable, but still stamps no activity — it must reap on schedule.
 *       4. Stamp last-activity only on a readable end, so a writable-only
 *          wakeup cannot hold the idle reaper off forever.
 */
static int
pump_wait(struct pollfd *pfd, int frozen, struct timespec *act)
{
    int  pr = poll(pfd, 2, 100);

    if (pr < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
    if (pr == 0 || frozen) {
        return 0;   /* re-check fault flags / black-holed: forward nothing */
    }

    if (pfd[0].revents & POLLIN || pfd[1].revents & POLLIN) {
        clock_gettime(CLOCK_MONOTONIC, act);
    }

    return 1;
}


/* ---- Graceful teardown after EOF ----
 *
 * WHAT: Applies the slow-close delay, closes both ends and drops the active
 *       count.
 *
 * WHY:  slow-close delays the FIN so a peer sees a connection that lingers
 *       after its last byte; it is contradictory with an abortive RST, which
 *       wins.  This path is reached only from the loop's EOF exit — the
 *       lever-driven exits close their own fds.
 *
 * HOW:  1. Take the larger of the two per-direction delays.
 *       2. Sleep it unless an abortive close is armed.
 *       3. Close both ends and CDEC.
 */
static void
pump_teardown(int cfd, int ufd)
{
    int  sc = g_up.slow_close_ms > g_down.slow_close_ms
              ? g_up.slow_close_ms : g_down.slow_close_ms;

    if (sc > 0 && !g_abortive) {
        usleep((useconds_t) sc * 1000);
    }

    close(cfd);
    close(ufd);
    CDEC(active);
}


/* Bidirectional relay loop: shuttle bytes each way through the fault engine
 * until EOF, a control-plane sever, or a poll error.  Closes both ends + CDEC
 * before returning. */
void
relay_pump(int cfd, int ufd, unsigned epoch, unsigned seed,
           unsigned long *up_ctr, unsigned long *down_ctr)
{
    struct pollfd pfd[2];
    pfd[0].fd = cfd;   /* client   -> upstream (up)   */
    pfd[1].fd = ufd;   /* upstream -> client   (down) */
    char buf[65536];
    /* Two ping-pong transform buffers (uninit; only written) so the TLS/HTTP/MITM
     * stages can chain without a stage overwriting its own input.  Plain stack
     * locals (not _Thread_local — avoids the TLS zero-init latency).  The byte
     * totals are caller-owned so per-route accounting survives every exit path. */
    unsigned char scratch[FP_SCRATCH];
    unsigned char scratch2[FP_SCRATCH];
    unsigned hc_epoch = g_halfclose_epoch;
    int      hc_done  = 0;
    int      first[2] = { 1, 1 };
    int      eof[2]   = { 0, 0 };   /* per-direction EOF swallowed by drop-fin */
    int      frozen   = 0;          /* idle-reap black-hole: no teardown, no flow */
    struct timespec t0, act;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    act = t0;                       /* last-activity (either direction) */

    for (;;) {
        if (pump_torn_down(cfd, ufd, epoch, &t0, &act, &frozen,
                           *up_ctr, *down_ctr)) {
            return;         /* closed + CDEC already done by the lever */
        }
        pump_halfclose(cfd, ufd, &hc_done, hc_epoch);
        pump_arm_events(pfd, hc_done, eof, frozen);

        int ready = pump_wait(pfd, frozen, &act);
        if (ready < 0) {
            break;
        }
        if (ready == 0) {
            continue;
        }

        int outcome = pump_both_dirs(pfd, cfd, ufd, buf, sizeof(buf), scratch,
                                     scratch2, epoch, &seed, up_ctr, down_ctr,
                                     first, eof);
        if (outcome == 2) {
            return;         /* severed + CDEC already done */
        }
        if (outcome == 1) {
            break;          /* EOF (both ends, or not suppressed) */
        }
    }

    pump_teardown(cfd, ufd);
}

/* Format a socket address as "ip:port" (v6 bracketed) for a PROXY header. */
void
sa_to_hostport(const struct sockaddr *sa, socklen_t sl, char *out, size_t cap)
{
    char host[INET6_ADDRSTRLEN] = "", serv[16] = "";
    if (getnameinfo(sa, sl, host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        out[0] = '\0';
        return;
    }
    if (sa->sa_family == AF_INET6) {
        snprintf(out, cap, "[%s]:%s", host, serv);
    } else {
        snprintf(out, cap, "%s:%s", host, serv);
    }
}

/* Apply the socket-level stress levers (small MSS / squeezed buffers) to a new
 * relay pair.  Best-effort: a kernel that clamps the value is fine. */
void
apply_conn_tuning(int cfd, int ufd)
{
    if (g_mss > 0) {
        int m = g_mss;
        setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &m, sizeof(m));
        setsockopt(ufd, IPPROTO_TCP, TCP_MAXSEG, &m, sizeof(m));
    }
    if (g_rcvbuf > 0) {
        int b = g_rcvbuf;
        setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &b, sizeof(b));
        setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &b, sizeof(b));
    }
    if (g_sndbuf > 0) {
        int b = g_sndbuf;
        setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &b, sizeof(b));
        setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &b, sizeof(b));
    }
}

/* Prepend a forged PROXY-protocol header to the upstream stream, spoofing the
 * client source the service will attribute the connection to. */
void
send_proxy_header(int ufd, int cfd)
{
    int mode = g_proxy_mode;
    if (mode == 0) {
        return;
    }
    char src[128], dst[128];
    pthread_mutex_lock(&g_ext_lock);
    snprintf(src, sizeof(src), "%s", g_proxy_src);
    snprintf(dst, sizeof(dst), "%s", g_proxy_dst);
    pthread_mutex_unlock(&g_ext_lock);
    if (dst[0] == '\0') {
        struct sockaddr_storage ss;
        socklen_t               sl = sizeof(ss);
        if (getsockname(cfd, (struct sockaddr *) &ss, &sl) == 0) {
            sa_to_hostport((struct sockaddr *) &ss, sl, dst, sizeof(dst));
        }
    }
    unsigned char hdr[256];
    int n = (mode == 1) ? fp_ext_proxy_v1((char *) hdr, sizeof(hdr), src, dst)
                        : fp_ext_proxy_v2(hdr, sizeof(hdr), src, dst);
    if (n > 0) {
        (void) write_all(ufd, (char *) hdr, n);
        CBUMP(injected, (unsigned long) n);
    }
}
