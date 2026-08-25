/* brix_fault_pump_dir.c — the per-direction transform chain and pump step.
 *
 * WHAT: One direction's journey from read() to write(): the ping-pong buffer
 *       chain, the payload rewrite/inject and bit-mutation stages, the HTTP 100-
 *       continue eater, the TLS ClientHello reset trigger, the DPI/middlebox
 *       stall levers, and relay_pump_dir() which drives them for one poll hit.
 *
 * WHY:  Split out of brix_fault_pump.c on the 600-line file cap
 *       (coding-standards §1). The transform chain is one concept — it never
 *       touches poll state, timers or teardown; the sibling TU owns the loop
 *       that calls it once per readable direction.
 *
 * HOW:  Same behaviour as before the split — this is a pure move. The shared
 *       state and relay_pump_dir's prototype stayed in brix_fault_proxy_state.h,
 *       so the seam needed no new header. Levers are read lock-free; wide
 *       config is snapshotted under g_ext_lock.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include "brix_fault_proxy_mods.h"
#include <errno.h>
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

/* One store-and-forward hold lever (header-size or body-size): if armed and
 * triggered, forward the withheld prefix, sleep `hold_ms`, then trim `ch` to
 * the remainder. Returns 2 if a forward error severed the pair (already closed
 * + CDEC), 1 if the hold fired, 0 if it did not apply. */
static int
pump_apply_hold(fp_http_cfg *HC, int (*active)(const fp_http_cfg *),
                int (*decide)(const fp_http_cfg *, const unsigned char *, size_t, size_t *),
                int hold_ms, pump_chain *ch, int to, int cfd, int ufd,
                unsigned epoch, volatile lever_t *L, unsigned *seed,
                unsigned long *conn_ctr, unsigned long *glob_ctr)
{
    size_t rel = 0;
    if (!active(HC) ||
        !decide(HC, (const unsigned char *) ch->cur, (size_t) ch->n, &rel)) {
        return 0;
    }
    if (rel > 0 &&
        forward_faulted(to, (char *) ch->cur, (ssize_t) rel, epoch, L,
                        seed, conn_ctr, glob_ctr) != 0) {
        sever(cfd, ufd, g_abortive);
        CDEC(active);
        return 2;
    }
    usleep((useconds_t) hold_ms * 1000);
    CBUMP(held, 1);
    ch->cur += rel;
    ch->n   -= (ssize_t) rel;          /* forward the withheld remainder below */
    return 1;
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
    if (pump_apply_hold(HC, fp_http_hold_active, fp_http_hold_decide,
                        HC->hold_ms, ch, to, cfd, ufd, epoch, L, seed,
                        conn_ctr, glob_ctr) == 2) {
        return 2;
    }
    if (pump_apply_hold(HC, fp_http_body_hold_active, fp_http_body_hold_decide,
                        HC->body_hold_ms, ch, to, cfd, ufd, epoch, L, seed,
                        conn_ctr, glob_ctr) == 2) {
        return 2;
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
    t_fwd_up = is_up;   /* so a deep truncate event can name its direction */
    volatile lever_t *L = is_up ? &g_up : &g_down;
    unsigned long *conn_ctr = is_up ? up_ctr : down_ctr;

    /* toxicity: an unafflicted direction gets a clean-lever pass-through, so
     * armed byte levers (corrupt/latency/…) do not fire on this connection. */
    static const lever_t g_clean_lever;
    if (!(is_up ? t_afflict_up : t_afflict_down)) {
        L = (volatile lever_t *) &g_clean_lever;
    }

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
