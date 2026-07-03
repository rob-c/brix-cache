/*
 * lifecycle_timing.c — implementation of the lifecycle phase stopwatch.
 *
 * See lifecycle_timing.h for the WHAT/WHY/HOW. This file is deliberately tiny and
 * dependency-free beyond ngx_core: it is linked into the module so the permanent
 * one-line phase summaries are always available, with no per-request cost.
 */

#include "lifecycle_timing.h"
#include <time.h>

/*
 * brix_phase_now_ns — monotonic clock in nanoseconds.
 *
 * CLOCK_MONOTONIC (not _COARSE): vDSO-backed and ~ns-resolution, so a sub-ms phase
 * is measured honestly instead of being rounded to a millisecond tick. On the
 * (effectively impossible) clock failure we return 0; callers clamp negative
 * deltas to 0, so a bad reading degrades to "0us", never to a garbage figure.
 */
uint64_t
brix_phase_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

/* Begin a run: snapshot the clock as both the absolute start and the first
 * per-mark baseline, and empty the summary buffer. */
void
brix_phase_timer_start(brix_phase_timer_t *t)
{
    if (t == NULL) {
        return;
    }

    t->start_ns   = brix_phase_now_ns();
    t->last_ns    = t->start_ns;
    t->pos        = t->summary;
    t->summary[0] = '\0';
}

/*
 * us_since — microseconds elapsed from `from_ns` to now, clamped at 0 if the
 * monotonic clock appears to have gone backwards (or was unreadable).
 */
static uint64_t
us_since(uint64_t from_ns, uint64_t now_ns)
{
    if (now_ns <= from_ns) {
        return 0;
    }

    return (now_ns - from_ns) / 1000ull;
}

/*
 * brix_phase_mark — append "<name>=<delta>us " for the time since the previous
 * mark, then advance the per-mark baseline. Writes are bounded by the buffer
 * capacity; once full, further marks are dropped rather than overflowing (the
 * total in _log still reflects real elapsed time, so no information is fabricated).
 */
void
brix_phase_mark(brix_phase_timer_t *t, const char *name)
{
    uint64_t  now_ns;
    u_char   *end;

    if (t == NULL || name == NULL) {
        return;
    }

    now_ns = brix_phase_now_ns();
    end    = t->summary + sizeof(t->summary) - 1;

    /* ngx_snprintf never writes past `end` and returns the new cursor, but it does
     * NOT null-terminate — so terminate explicitly (t->pos <= end leaves room at
     * summary[cap-1]) to keep the buffer a valid C string for the "%s" in _log. */
    t->pos  = ngx_snprintf(t->pos, (size_t) (end - t->pos), "%s=%uLus ",
                           name, us_since(t->last_ns, now_ns));
    *t->pos = '\0';

    t->last_ns = now_ns;
}

/*
 * brix_phase_timer_log — emit the accumulated per-phase summary plus a trailing
 * total at NOTICE. NOTICE (not INFO) so it survives the default log level: an
 * operator gets a boot-cost breakdown without raising verbosity, yet it is one
 * line per lifecycle event so it never spams.
 */
void
brix_phase_timer_log(brix_phase_timer_t *t, ngx_log_t *log,
                       const char *context)
{
    uint64_t total_us;

    if (t == NULL || log == NULL) {
        return;
    }

    total_us = us_since(t->start_ns, brix_phase_now_ns());

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s: %stotal=%uLus",
                  context != NULL ? context : "xrootd lifecycle",
                  t->summary, total_us);
}
