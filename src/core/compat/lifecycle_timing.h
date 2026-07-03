/*
 * lifecycle_timing.h — one-line phase timing for process lifecycle events.
 *
 * WHAT: a tiny monotonic stopwatch that accumulates a sequence of named phase
 * deltas into a single fixed-size buffer and emits ONE summary log line at the
 * end of a lifecycle event (master postconfiguration, per-worker init_process,
 * worker exit). Example output:
 *
 *     xrootd init_process[w0]: uring=812us servers=43120us keypool=15003us total=59102us
 *
 * WHY: startup/shutdown cost was previously un-instrumented — there was no way
 * to tell whether boot latency lived in cert/CA parsing, SHM init, uring bring-up,
 * or per-server-block preparation without an ad-hoc strace. A permanent, greppable
 * one-liner (`grep 'init_process\[' error.log`) gives operators and developers an
 * honest per-phase breakdown on every boot and reload, and is the parse target for
 * tests/profile_lifecycle.sh.
 *
 * HOW: CLOCK_MONOTONIC via clock_gettime() — vDSO-backed (~20 ns/call), so the two
 * reads per marked phase are lost in the syscalls each phase already makes. Deltas
 * are reported in MICROseconds (integer; no floats, matching the VFS latency
 * convention) so sub-millisecond phases are not quantised to 0. The accumulator is
 * a stack struct owned by the caller — no allocation, no globals, nothing on the
 * request hot path: a lifecycle event fires this once, never per connection.
 *
 * USAGE:
 *     brix_phase_timer_t t;
 *     brix_phase_timer_start(&t);
 *     ... phase 1 ...   brix_phase_mark(&t, "uring");
 *     ... phase 2 ...   brix_phase_mark(&t, "servers");
 *     brix_phase_timer_log(&t, cycle->log, "xrootd init_process[w0]");
 *
 * Each mark records the delta since the PREVIOUS mark (or since _start for the
 * first). _log appends a final "total=<since start>" and emits at NOTICE.
 */
#ifndef BRIX_COMPAT_LIFECYCLE_TIMING_H
#define BRIX_COMPAT_LIFECYCLE_TIMING_H

#include <ngx_core.h>
#include <stdint.h>

/* Summary buffer holds roughly a dozen "name=NNNNNNus " tokens — generously
 * sized so marks are never silently dropped; overflow is clamped, not an error. */
#define BRIX_PHASE_SUMMARY_CAP  512

typedef struct {
    uint64_t  start_ns;                         /* snapshot at _start            */
    uint64_t  last_ns;                          /* snapshot at the previous mark */
    u_char    summary[BRIX_PHASE_SUMMARY_CAP];/* accumulated "name=Xus " tokens*/
    u_char   *pos;                              /* write cursor into summary     */
} brix_phase_timer_t;

/* Monotonic nanoseconds — the single time source for all phase math. */
uint64_t brix_phase_now_ns(void);

/* Begin a timing run: snapshot the clock and reset the summary buffer. */
void brix_phase_timer_start(brix_phase_timer_t *t);

/* Record the delta since the previous mark (or _start) under `name`. `name` is a
 * short string literal; non-literal callers must keep it printf-%s-safe. */
void brix_phase_mark(brix_phase_timer_t *t, const char *name);

/* Emit the accumulated summary plus a trailing total=<since _start> at NOTICE,
 * prefixed with `context` (e.g. "xrootd init_process[w0]"). No-op if log is NULL. */
void brix_phase_timer_log(brix_phase_timer_t *t, ngx_log_t *log,
                            const char *context);

#endif /* BRIX_COMPAT_LIFECYCLE_TIMING_H */
