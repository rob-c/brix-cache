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

#define FP_PSWAP(a, b) do { unsigned char *fp_t_ = (a); (a) = (b); (b) = fp_t_; } while (0)

/* One direction's bytes as they travel the transform chain.  `cur`/`n` are the
 * current payload; `dst`/`alt` are the two ping-pong scratch buffers, so a
 * length-changing stage never overwrites its own input. */
typedef struct {
    const char    *cur;
    ssize_t        n;
    unsigned char *dst;
    unsigned char *alt;
} pump_chain;

/* Adopt the `n` bytes a stage just wrote to `dst` as the new payload, and flip
 * the scratch buffers so the next stage writes to the other one. */
static void
chain_take(pump_chain *ch, size_t n)
{
    ch->n   = (ssize_t) n;
    ch->cur = (const char *) ch->dst;
    FP_PSWAP(ch->dst, ch->alt);
}

/* The protocol-aware rewriters: TLS record surgery, then HTTP request
 * smuggling.  Both may change the payload length. */
static void
pump_rewrite(int is_up, pump_chain *ch)
{
    if (fp_tls_active(is_up ? &g_tls_up : &g_tls_down)) {
        chain_take(ch, apply_tls(is_up, ch->cur, ch->n, ch->dst));
    }
    if (fp_http_active(is_up ? &g_http_up : &g_http_down)) {
        int    applied = 0;
        size_t on = apply_http(is_up, ch->cur, ch->n, ch->dst, &applied);
        if (applied) {
            chain_take(ch, on);
        }
    }
}

/* Byte-level MITM mutation (drop/repeat/inject/replace).  Returns 1 when every
 * byte was dropped, i.e. there is nothing left to forward. */
static int
pump_mutate(int is_up, volatile lever_t *L, pump_chain *ch, unsigned *seed)
{
    fp_ext_mut    mut;
    unsigned char fbuf[128], rbuf[256], ibuf[512];

    if (!ext_snapshot(is_up, L, &mut, fbuf, rbuf, ibuf)) {
        return 0;
    }
    fp_ext_stats st = { 0, 0, 0, 0 };
    size_t on = fp_ext_mutate((const unsigned char *) ch->cur, (size_t) ch->n,
                              ch->dst, FP_SCRATCH, &mut, seed, &st);
    chain_take(ch, on);
    if (st.dropped)  { CBUMP(dropped,  st.dropped); }
    if (st.repeated) { CBUMP(repeated, st.repeated); }
    if (st.injected) { CBUMP(injected, st.injected); }
    if (st.replaced) { CBUMP(replaced, st.replaced); }
    return ch->n == 0;
}

/* eat-100-continue: on the down path, splice out a leading "HTTP/1.x 100 ...
 * CRLFCRLF" interim response so an Expect: 100-continue upload hangs waiting for
 * a 100 the middlebox ate.  Returns 1 when a 100 was removed (ch flipped). */
static int
pump_eat_100(pump_chain *ch)
{
    const unsigned char *in = (const unsigned char *) ch->cur;
    size_t n = (size_t) ch->n;
    /* "HTTP/1.x 100": "HTTP/1." at [0..6], minor version at [7], SP at [8],
     * status "100" at [9..11]. */
    if (n < 12 || memcmp(in, "HTTP/1.", 7) != 0 || in[8] != ' ' ||
        memcmp(in + 9, "100", 3) != 0) {
        return 0;
    }
    for (size_t i = 0; i + 3 < n; i++) {
        if (in[i] == '\r' && in[i + 1] == '\n' &&
            in[i + 2] == '\r' && in[i + 3] == '\n') {
            size_t drop = i + 4;
            memcpy(ch->dst, in + drop, n - drop);
            chain_take(ch, n - drop);
            return 1;
        }
    }
    return 0;
}

/* hello-split-reset: true when `buf` opens a TLS handshake ClientHello whose
 * DECLARED record length is >= `thresh` — caught from the record header even
 * when the ClientHello is split across TCP segments (post-quantum keyshares,
 * fat SNI/cert lists blow past one MSS and a first-segment-only DPI resets). */
static int
tls_hello_oversized(const char *buf, ssize_t nr, int thresh)
{
    const unsigned char *b = (const unsigned char *) buf;
    if (thresh <= 0 || nr < 6) {
        return 0;
    }
    if (b[0] != 0x16 || b[5] != 0x01) {   /* handshake record, ClientHello */
        return 0;
    }
    int rec_len = (b[3] << 8) | b[4];     /* TLSPlaintext.length (BE16) */
    return rec_len >= thresh;
}

/* hello-split-reset: an oversized TLS ClientHello on the request path is RST by
 * a DPI that only inspects the first segment.  Returns 2 (severed + CDEC) or 0. */
static int
pump_hello_reset(int is_up, const char *buf, ssize_t nr, int cfd, int ufd)
{
    if (is_up && tls_hello_oversized(buf, nr, g_hello_reset_thresh)) {
        CBUMP(hello_reset, 1);
        sever(cfd, ufd, 1);
        CDEC(active);
        return 2;
    }
    return 0;
}

/* delay-first: hold back only the opening chunk of this direction, then clear
 * the per-direction first-chunk flag. */
static void
pump_delay_first(volatile lever_t *L, int *firstflag)
{
    if (L->delayfirst_ms > 0 && *firstflag) {
        usleep((useconds_t) L->delayfirst_ms * 1000);
    }
    *firstflag = 0;
}

/* eat-100-continue on the down path.  Returns 1 when nothing remains to forward
 * (the whole payload was an interim 100 that got swallowed). */
static int
pump_eat_100_dir(int is_up, pump_chain *ch)
{
    if (!is_up && g_eat_100 && pump_eat_100(ch)) {
        CBUMP(ate_100, 1);
        if (ch->n == 0) {
            return 1;
        }
    }
    return 0;
}

/* DPI stall levers applied just before forwarding: HTTP header-size hold, body
 * hold (store-and-forward), and volume classify-throttle.  Each hold forwards
 * any withheld prefix itself and trims `ch` to the remainder.  Returns 2 if a
 * forward error severed the pair (already closed + CDEC), else 0. */
static int
pump_dpi_stalls(int is_up, pump_chain *ch, int to, int cfd, int ufd,
                unsigned epoch, volatile lever_t *L, unsigned *seed,
                unsigned long *conn_ctr, unsigned long *glob_ctr)
{
    fp_http_cfg *HC  = is_up ? &g_http_up : &g_http_down;
    size_t       rel = 0;
    if (fp_http_hold_active(HC) &&
        fp_http_hold_decide(HC, (const unsigned char *) ch->cur,
                            (size_t) ch->n, &rel)) {
        if (rel > 0 &&
            forward_faulted(to, (char *) ch->cur, (ssize_t) rel, epoch, L,
                            seed, conn_ctr, glob_ctr) != 0) {
            sever(cfd, ufd, g_abortive);
            CDEC(active);
            return 2;
        }
        usleep((useconds_t) HC->hold_ms * 1000);
        CBUMP(held, 1);
        ch->cur += rel;
        ch->n   -= (ssize_t) rel;      /* forward the withheld remainder below */
    }
    rel = 0;
    if (fp_http_body_hold_active(HC) &&
        fp_http_body_hold_decide(HC, (const unsigned char *) ch->cur,
                                 (size_t) ch->n, &rel)) {
        if (rel > 0 &&
            forward_faulted(to, (char *) ch->cur, (ssize_t) rel, epoch, L,
                            seed, conn_ctr, glob_ctr) != 0) {
            sever(cfd, ufd, g_abortive);
            CDEC(active);
            return 2;
        }
        usleep((useconds_t) HC->body_hold_ms * 1000);
        CBUMP(held, 1);
        ch->cur += rel;
        ch->n   -= (ssize_t) rel;
    }
    /* classify-throttle: once a direction crosses the volume heuristic the flow
     * is shunted to a <kbps> slow lane (misclassified bulk = "exfiltration"). */
    if (g_classify_kbps > 0 && g_classify_bytes > 0 && ch->n > 0 &&
        *conn_ctr + (unsigned long) ch->n > (unsigned long) g_classify_bytes) {
        long us = (long) ((double) ch->n * 1000000.0 /
                          ((double) g_classify_kbps * 1024.0));
        CBUMP(throttled, 1);
        if (us > 0) {
            usleep((useconds_t) us);
        }
    }
    return 0;
}

/* Relay one poll-ready direction through the fault engine.  Returns 0 to keep
 * looping, 1 on EOF/read error (caller closes both ends), 2 if a fault severed
 * the pair (already closed + CDEC, caller just returns). */
int
relay_pump_dir(int i, struct pollfd *pfd, int cfd, int ufd,
               char *buf, size_t bufsz, unsigned char *scratch,
               unsigned char *scratch2, unsigned epoch,
               unsigned *seed, unsigned long *up_ctr, unsigned long *down_ctr,
               int *firstflag)
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
    int is_up = (i == 0);
    volatile lever_t *L = is_up ? &g_up : &g_down;
    unsigned long *conn_ctr = is_up ? up_ctr : down_ctr;

    if (pump_hello_reset(is_up, buf, nr, cfd, ufd) == 2) {
        return 2;
    }

    /* Stateful, content-addressed faults on the RAW bytes (before any mutation
     * changes their length/offset). */
    trig_check(is_up, buf, nr);
    mangle_apply(is_up, buf, nr, *conn_ctr);

    pump_delay_first(L, firstflag);

    /* Transform chain: each length-changing stage ping-pongs between scratch A
     * and B so it never overwrites its own input — TLS record surgery, then HTTP
     * request smuggling, then byte-level MITM mutation. */
    pump_chain ch = { buf, nr, scratch, scratch2 };

    pump_rewrite(is_up, &ch);
    if (pump_mutate(is_up, L, &ch, seed)) {
        return 0;       /* every byte was dropped — nothing to forward */
    }

    if (pump_eat_100_dir(is_up, &ch)) {
        return 0;       /* nothing left after the 100 was removed */
    }

    /* Session recording: capture exactly what we are about to forward. */
    if (fp_replay_recording()) {
        fp_replay_record(is_up, now_ms_since(g_t0),
                         (const unsigned char *) ch.cur, (size_t) ch.n);
        CBUMP(recorded, (unsigned long) ch.n);
    }

    unsigned long *glob_ctr = is_up ? &C.up_bytes : &C.down_bytes;

    /* DPI header/body-size holds and classify-throttle — a complete,
     * over-threshold header block (e.g. a fat client-cert PEM in an XrdHttp
     * request) stalls, as does bulk that crosses the volume heuristic. */
    if (pump_dpi_stalls(is_up, &ch, to, cfd, ufd, epoch, L, seed,
                        conn_ctr, glob_ctr) == 2) {
        return 2;
    }

    if (forward_faulted(to, (char *) ch.cur, ch.n, epoch, L, seed,
                        conn_ctr, glob_ctr) != 0) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 2;
    }
    return 0;
}

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
        if (pump_severed(cfd, ufd, epoch, &t0)) {
            return;
        }
        if (pump_idle_reap(cfd, ufd, &act, &frozen)) {
            return;
        }
        if (pump_rst_after_bytes(cfd, ufd, *up_ctr, *down_ctr)) {
            return;
        }
        pump_halfclose(cfd, ufd, &hc_done, hc_epoch);
        pump_arm_events(pfd, hc_done, eof, frozen);
        int pr = poll(pfd, 2, 100);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0 || frozen) {
            continue;   /* re-check fault flags / black-holed: forward nothing */
        }
        if (pfd[0].revents & POLLIN || pfd[1].revents & POLLIN) {
            clock_gettime(CLOCK_MONOTONIC, &act);
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
    close(cfd);
    close(ufd);
    CDEC(active);
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
