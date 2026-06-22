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
#include "xrdc.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

#define XRDC_TMO_CONNECT_DEFAULT_MS 15000   /* bring-up: connect+handshake+login */
#define XRDC_TMO_IO_DEFAULT_MS      30000   /* steady-state read/write */

/* 0 = unresolved; >0 = the resolved/overridden value. */
static atomic_int g_connect_ms = 0;
static atomic_int g_io_ms       = 0;

static int
resolve_ms(atomic_int *slot, const char *env, int dflt)
{
    int v = atomic_load_explicit(slot, memory_order_relaxed);
    if (v > 0) {
        return v;
    }
    const char *e = getenv(env);
    int parsed = (e != NULL && e[0] != '\0') ? atoi(e) : 0;
    v = (parsed > 0) ? parsed : dflt;
    atomic_store_explicit(slot, v, memory_order_relaxed);
    return v;
}

int
xrdc_tmo_connect_ms(void)
{
    return resolve_ms(&g_connect_ms, "XRDC_CONNECT_TIMEOUT_MS",
                      XRDC_TMO_CONNECT_DEFAULT_MS);
}

int
xrdc_tmo_io_ms(void)
{
    return resolve_ms(&g_io_ms, "XRDC_IO_TIMEOUT_MS", XRDC_TMO_IO_DEFAULT_MS);
}

void
xrdc_tmo_set_connect_ms(int ms)
{
    if (ms > 0) {
        atomic_store_explicit(&g_connect_ms, ms, memory_order_relaxed);
    }
}

void
xrdc_tmo_set_io_ms(int ms)
{
    if (ms > 0) {
        atomic_store_explicit(&g_io_ms, ms, memory_order_relaxed);
    }
}

unsigned
xrdc_backoff_delay_ms(unsigned attempt, uint64_t *seed)
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

unsigned
xrdc_backoff_delay_fast_ms(unsigned attempt, uint64_t *seed)
{
    /* Fast backoff for TRANSPORT faults (a connection reset/EOF is instant and
     * not a sign of server overload): 25ms<<attempt capped at 250ms, plus jitter.
     * A short cap lets many retries fit inside the patience window, which is what
     * rides out a high packet-loss link — where each large read/reconnect is
     * frequently severed and must simply be re-attempted promptly. */
    unsigned shift = (attempt < 4) ? attempt : 4;
    uint64_t base  = 25ULL << shift;            /* 25,50,100,200,400→cap */
    if (base > 250) {
        base = 250;
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
        if (xrdc_copy_quit_requested()) {
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
xrdc_backoff_sleep(unsigned attempt)
{
    static _Thread_local uint64_t seed = 0;
    if (seed == 0) {
        seed = (uint64_t) xrdc_mono_ns() ^ (uint64_t) (uintptr_t) &seed;
    }
    sleep_ms_cancelable(xrdc_backoff_delay_ms(attempt, &seed));
}

void
xrdc_backoff_sleep_fast(unsigned attempt)
{
    static _Thread_local uint64_t seed = 0;
    if (seed == 0) {
        seed = (uint64_t) xrdc_mono_ns() ^ (uint64_t) (uintptr_t) &seed ^ 0x55;
    }
    sleep_ms_cancelable(xrdc_backoff_delay_fast_ms(attempt, &seed));
}
