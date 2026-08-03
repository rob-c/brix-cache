/* brix_fault_pump.c — the poll loop and per-connection relay thread.
 *
 * WHAT: The bidirectional poll pump, its per-direction step, the connection tuning
 *       and PROXY-header forgery applied at dial time, replay playback, and the
 *       relay thread that owns one accepted client end to end.
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

    /* Stateful, content-addressed faults on the RAW bytes (before any mutation
     * changes their length/offset). */
    trig_check(is_up, buf, nr);
    mangle_apply(is_up, buf, nr, *conn_ctr);

    /* delay-first: hold back only the opening chunk of this direction. */
    if (L->delayfirst_ms > 0 && *firstflag) {
        usleep((useconds_t) L->delayfirst_ms * 1000);
    }
    *firstflag = 0;

    /* Transform chain: each length-changing stage ping-pongs between scratch A
     * and B so it never overwrites its own input — TLS record surgery, then HTTP
     * request smuggling, then byte-level MITM mutation. */
    pump_chain ch = { buf, nr, scratch, scratch2 };

    pump_rewrite(is_up, &ch);
    if (pump_mutate(is_up, L, &ch, seed)) {
        return 0;       /* every byte was dropped — nothing to forward */
    }

    /* Session recording: capture exactly what we are about to forward. */
    if (fp_replay_recording()) {
        fp_replay_record(is_up, now_ms_since(g_t0),
                         (const unsigned char *) ch.cur, (size_t) ch.n);
        CBUMP(recorded, (unsigned long) ch.n);
    }

    unsigned long *glob_ctr = is_up ? &C.up_bytes : &C.down_bytes;
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
    return 0;
}

/* Arm the poll events for one step: a stalled (or half-closed) direction stops
 * being read so the peer's send buffer fills — real TCP backpressure, without
 * ever severing. */
static void
pump_arm_events(struct pollfd *pfd, int hc_done)
{
    pfd[0].events = (hc_done || g_stall_up) ? 0 : POLLIN;
    pfd[1].events = g_stall_down ? 0 : POLLIN;
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
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        if (pump_severed(cfd, ufd, epoch, &t0)) {
            return;
        }
        /* half-close: FIN the up path, keep the down path flowing. */
        if (!hc_done && g_halfclose_epoch != hc_epoch) {
            shutdown(cfd, SHUT_RD);
            shutdown(ufd, SHUT_WR);
            hc_done = 1;
        }
        pump_arm_events(pfd, hc_done);
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
        int r = 0;
        for (int i = 0; i < 2 && r == 0; i++) {
            r = relay_pump_dir(i, pfd, cfd, ufd, buf, sizeof(buf), scratch,
                               scratch2, epoch, &seed, up_ctr, down_ctr,
                               &first[i]);
        }
        if (r == 2) {
            return;         /* severed + CDEC already done */
        }
        if (r == 1) {
            break;          /* EOF */
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

/* Replay mode: act as a synthetic peer, feeding the client the recorded byte
 * timeline (the g_replay_updir direction) with the original inter-segment
 * timing.  No live upstream is dialled.  The store is immutable while replay is
 * active, so it is read lock-free. */
void
replay_to_client(int cfd, unsigned epoch)
{
    int                want = g_replay_updir ? 1 : 0;
    unsigned long long last = 0;
    int                started = 0;
    for (size_t k = 0; k < g_replay_store.n; k++) {
        fp_replay_rec *r = &g_replay_store.recs[k];
        if (r->is_up != want) {
            continue;
        }
        if (started) {
            long long d = (long long) r->ts_ms - (long long) last;
            if (d > 0 && d < 60000) {          /* honour original gaps, cap at 60s */
                usleep((useconds_t) d * 1000);
            }
        }
        last = r->ts_ms;
        started = 1;
        if (g_blocked || g_drop_epoch != epoch) {
            break;
        }
        if (r->len > 0 &&
            write_all(cfd, (const char *) r->bytes, (ssize_t) r->len) != 0) {
            break;
        }
        CBUMP(replayed, (unsigned long) r->len);
    }
}

void *
relay_thread(void *arg)
{
    relay_arg *ra = (relay_arg *) arg;
    int        cfd = ra->client_fd;
    unsigned   epoch = ra->epoch;
    unsigned long conn_id = ra->conn_id;
    fp_route  *route = ra->route;
    free(ra);

    t_conn_id = conn_id;   /* attribute deep-path fault events to this connection */
    fp_event_set_route(fp_route_name(route));   /* tag this thread's events */

    unsigned seed = g_seed + (unsigned) conn_id * 2654435761u;

    if (relay_predial(cfd, epoch, conn_id)) {
        return NULL;
    }

    /* Replay: synthesise the response from a recorded session, no upstream. */
    if (g_replay_active) {
        replay_to_client(cfd, epoch);
        close(cfd);
        CDEC(active);
        return NULL;
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

    apply_conn_tuning(cfd, ufd);
    send_proxy_header(ufd, cfd);   /* forged PROXY header, before any client bytes */

    /* fanout: open (and hold) extra upstream connections per client connection to
     * drain the server's accept/worker pool — a connection-amplification attack. */
    int extra[16];
    int nextra = 0;
    int fo = g_fanout;
    if (fo > 0) {
        if (fo > 16) {
            fo = 16;
        }
        for (int k = 0; k < fo; k++) {
            int f = dial_route(route);
            if (f >= 0) {
                extra[nextra++] = f;
                CBUMP(fanout_conns, 1);
            }
        }
    }

    /* Own the per-direction byte totals here so per-route accounting survives
     * every relay_pump exit path (sever / max-life / EOF). */
    unsigned long up_ctr = 0, down_ctr = 0;
    relay_pump(cfd, ufd, epoch, seed, &up_ctr, &down_ctr);
    fp_route_add_bytes(route, up_ctr, down_ctr);

    for (int k = 0; k < nextra; k++) {
        close(extra[k]);
    }
    return NULL;
}
