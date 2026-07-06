/*
 * nettmo.c — network timeout tunables + retry backoff for the native client.
 *
 * WHAT: Two process-wide timeout knobs and one backoff helper, the controls that
 *       keep a client usable on a flaky / hostile network (a misbehaving inline
 *       firewall that hangs, RST-injects, or intermittently drops connections):
 *         - connect timeout: caps the whole bring-up phase (TCP connect +
 *           protocol handshake + TLS + login). A firewall that completes the TCP
 *           handshake then black-holes the protocol bytes would otherwise hang
 *           the caller for the full data timeout; bounding bring-up turns that
 *           into a prompt, retryable failure.
 *         - io timeout: the steady-state per-operation read/write cap once a
 *           session is up (unchanged default).
 *         - backoff sleep: exponential + jitter between retries, so intermittent
 *           failures do not become a tight reconnect storm and many threads do
 *           not re-hammer a flapping firewall in lockstep.
 * WHY:  bring-up and steady-state want very different patience: a stalled
 *       handshake should fail in seconds (the reconnect machinery then rides over
 *       it), while a legitimate large read may take much longer. One blanket
 *       timeout cannot serve both.
 * HOW:  Each knob resolves once, lazily: an explicit setter (a CLI flag) wins,
 *       else the env var, else the compiled default. State is process-wide (a
 *       client process talks to one endpoint) and reached only through these
 *       accessors — same encapsulated-global pattern as netpref.c.
 *
 * Env vars (EXPANDED — client-only extensions, not vanilla XRootD variables):
 *   XRDC_CONNECT_TIMEOUT_MS, XRDC_IO_TIMEOUT_MS.
 *
 * Clean-room: C library + <stdatomic.h> only.
 */
#include "brix.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

#define XRDC_TMO_CONNECT_DEFAULT_MS 15000   /* bring-up: connect+handshake+login */
#define XRDC_TMO_IO_DEFAULT_MS      30000   /* steady-state read/write */

/* 0 = unresolved; >0 = the resolved/overridden value. */
static atomic_int g_connect_ms = 0;
static atomic_int g_io_ms       = 0;

/*
 * resolve_ms — layered timeout resolver for connect and io timeouts.
 *
 * WHAT: Resolves `slot` once: setter (already in slot) > env var > xrdrc
 *       [defaults] > compiled default. Caches the result back in `slot`
 *       so the resolution is a single atomic load on every subsequent call.
 * WHY:  Connect and io timeouts should be consistent across all sessions in
 *       a process, and the resolution order must be deterministic.
 * HOW:  Checks the cached slot first (set by an earlier call or by a CLI
 *       setter via brix_tmo_set_*), then falls through env → xrdrc → dflt.
 */
static int
resolve_ms(atomic_int *slot, const char *env, const char *xrdrc_key, int dflt)
{
    int v = atomic_load_explicit(slot, memory_order_relaxed);
    if (v > 0) {
        return v;
    }
    const char *e = getenv(env);
    int parsed = (e != NULL && e[0] != '\0') ? atoi(e) : 0;
    if (parsed > 0) {
        atomic_store_explicit(slot, parsed, memory_order_relaxed);
        return parsed;
    }
    int xv;
    if (brix_xrdrc_default_ms(xrdrc_key, &xv)) {
        atomic_store_explicit(slot, xv, memory_order_relaxed);
        return xv;
    }
    atomic_store_explicit(slot, dflt, memory_order_relaxed);
    return dflt;
}

int
brix_tmo_connect_ms(void)
{
    return resolve_ms(&g_connect_ms, "XRDC_CONNECT_TIMEOUT_MS",
                      "connect_timeout_ms", XRDC_TMO_CONNECT_DEFAULT_MS);
}

int
brix_tmo_io_ms(void)
{
    return resolve_ms(&g_io_ms, "XRDC_IO_TIMEOUT_MS",
                      "io_timeout_ms", XRDC_TMO_IO_DEFAULT_MS);
}

void
brix_tmo_set_connect_ms(int ms)
{
    if (ms > 0) {
        atomic_store_explicit(&g_connect_ms, ms, memory_order_relaxed);
    }
}

void
brix_tmo_set_io_ms(int ms)
{
    if (ms > 0) {
        atomic_store_explicit(&g_io_ms, ms, memory_order_relaxed);
    }
}

unsigned
brix_backoff_delay_ms(unsigned attempt, uint64_t *seed)
{
    /* Exponential base 100ms<<attempt, capped at 5s; attempt exponent clamped so
     * a long-running retry loop cannot overflow the shift. */
    unsigned shift = (attempt < 6) ? attempt : 6;
    uint64_t base  = 100ULL << shift;
    if (base > 5000) {
        base = 5000;
    }
    /* xorshift64 jitter in [0, base/2] decorrelates concurrent retriers so they
     * do not all wake and reconnect on the same tick. */
    uint64_t s = (*seed != 0) ? *seed : 0x9e3779b97f4a7c15ULL;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *seed = s;
    unsigned jitter = (unsigned) (s % (base / 2 + 1));
    return (unsigned) base + jitter;
}

/* Transport-fault backoff base (ms), tunable via $XRDC_BACKOFF_BASE_MS (default
 * 25). On a lossy-but-connected link the reconnect itself is sub-millisecond, so
 * the backoff sleep dominates recovery latency; lowering it (e.g. =1) maximises
 * throughput under heavy reset-style loss at the cost of a tighter retry loop
 * against a genuinely-down peer. Read once and cached. */
/*
 * backoff_base_ms — resolve the transport-fault backoff base once and cache it.
 *
 * WHAT: Returns the number of milliseconds to use as the backoff base for
 *       transport-fault retries. Resolution order: env XRDC_BACKOFF_BASE_MS >
 *       xrdrc [defaults] backoff_base_ms > compiled default (25 ms).
 * WHY:  On a lossy link the default may be tuned site-wide via .xrdrc without
 *       requiring every operator to set an env var in their shell profile.
 * HOW:  Uses a sentinel-initialized atomic (−1 = not yet resolved) so the
 *       resolution happens only once per process lifetime.
 */
static unsigned
backoff_base_ms(void)
{
    static atomic_int cached = -1;
    int v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v < 0) {
        const char *e = getenv("XRDC_BACKOFF_BASE_MS");
        long parsed;
        if (e != NULL && *e != '\0') {
            parsed = strtol(e, NULL, 10);
        } else {
            int xv;
            parsed = brix_xrdrc_default_ms("backoff_base_ms", &xv) ? (long) xv : 25L;
        }
        if (parsed < 0) {
            parsed = 0;
        }
        if (parsed > 10000) {
            parsed = 10000;
        }
        v = (int) parsed;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    return (unsigned) v;
}

unsigned
brix_backoff_delay_fast_ms(unsigned attempt, uint64_t *seed)
{
    /* Fast backoff for TRANSPORT faults (a connection reset/EOF is instant and
     * not a sign of server overload): BASE<<attempt capped at 10x BASE (>=250ms
     * for the 25ms default), plus jitter. A short cap lets many retries fit inside
     * the patience window, which is what rides out a high packet-loss link — where
     * each large read/reconnect is frequently severed and must simply be
     * re-attempted promptly. BASE is $XRDC_BACKOFF_BASE_MS (default 25). */
    unsigned base_ms = backoff_base_ms();
    unsigned shift = (attempt < 4) ? attempt : 4;
    uint64_t base  = (uint64_t) base_ms << shift;   /* e.g. 25,50,100,200,400→cap */
    uint64_t cap   = (base_ms >= 25) ? 250ULL : (uint64_t) base_ms * 10ULL;
    if (base > cap) {
        base = cap;
    }
    uint64_t s = (*seed != 0) ? *seed : 0x2545f4914f6cdd1dULL;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *seed = s;
    unsigned jitter = (unsigned) (s % (base / 2 + 1));
    return (unsigned) base + jitter;
}

/* Sleep `ms` in <=50ms slices, observing a cooperative cancel between slices. */
static void
sleep_ms_cancelable(unsigned ms)
{
    while (ms > 0) {
        if (brix_copy_quit_requested()) {
            return;
        }
        unsigned        slice = (ms > 50) ? 50 : ms;
        struct timespec ts = { (time_t) (slice / 1000),
                               (long) (slice % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        ms -= slice;
    }
}

void
brix_backoff_sleep(unsigned attempt)
{
    static _Thread_local uint64_t seed = 0;
    if (seed == 0) {
        seed = (uint64_t) brix_mono_ns() ^ (uint64_t) (uintptr_t) &seed;
    }
    sleep_ms_cancelable(brix_backoff_delay_ms(attempt, &seed));
}

void
brix_backoff_sleep_fast(unsigned attempt)
{
    static _Thread_local uint64_t seed = 0;
    if (seed == 0) {
        seed = (uint64_t) brix_mono_ns() ^ (uint64_t) (uintptr_t) &seed ^ 0x55;
    }
    sleep_ms_cancelable(brix_backoff_delay_fast_ms(attempt, &seed));
}
