/*
 * cli_hint.c — TTY-gated usability hint helpers (spec §2 C3, WS-1).
 *
 * WHAT: brix_cli_hints_enabled() / brix_cli_hint() / brix_cli_hint_once().
 * WHY:  one place to audit the C3 compatibility gate so hints never leak into
 *       scripts, pipelines, or cron jobs (non-TTY stderr = unchanged output).
 * HOW:  isatty(STDERR_FILENO) && (BRIX_NO_HINTS unset or "0") — computed once
 *       per process (static lazy flag).  brix_cli_hint_once uses a fixed 16-
 *       slot table of seen keys to suppress repeats within a process.
 *       Callers own the "hint: " / "note: " prefix; this module prints verbatim
 *       so there is no sanitization here — callers pass pre-sanitized strings.
 */
#include "cli/cli_hint.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Maximum distinct keys tracked by brix_cli_hint_once per process. */
#define HINT_ONCE_MAX 16

/*
 * WHAT: test whether BRIX_NO_HINTS suppresses all hints.
 * WHY:  two spellings accepted: unset (hints on) or the string "0" (hints on);
 *       any other value, including "" and "1", suppresses hints.
 * HOW:  getenv returns NULL when unset; the string "0" is the only set value
 *       that leaves hints on (following the common shell boolean convention).
 */
static int
no_hints_env(void)
{
    const char *v = getenv("BRIX_NO_HINTS");
    if (v == NULL) {
        return 0;   /* unset → hints are ON */
    }
    if (v[0] == '0' && v[1] == '\0') {
        return 0;   /* "0" → hints are ON */
    }
    return 1;       /* any other value → suppress hints */
}

int
brix_cli_hints_enabled(void)
{
    /*
     * WHAT: lazy, per-process computation of the hint gate.
     * WHY:  isatty() and getenv() are cheap but called at every log site; a
     *       static cache avoids repeated syscalls and makes the gate consistent
     *       even if BRIX_NO_HINTS is mutated mid-process.
     * HOW:  0 = unknown, 1 = enabled, -1 = disabled (tristate).
     */
    static int cached = 0;

    if (cached == 0) {
        cached = (isatty(STDERR_FILENO) && !no_hints_env()) ? 1 : -1;
    }
    return cached > 0;
}

void
brix_cli_hint(const char *fmt, ...)
{
    /*
     * WHAT: emit a formatted hint line to stderr when hints are enabled.
     * WHY:  all hints go through this one function so C3 audits touch one site.
     * HOW:  guard → vfprintf → done; callers include their own "hint: " prefix.
     */
    va_list ap;

    if (!brix_cli_hints_enabled()) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void
brix_cli_hint_once(const char *key, const char *fmt, ...)
{
    /*
     * WHAT: emit at most one hint per (process, key).
     * WHY:  hints fired inside loops (e.g. per-file divergence warnings) would
     *       flood an interactive session; once-per-key suppresses duplicates.
     * HOW:  fixed 16-slot static table of seen key pointers/strings.  strcmp
     *       match so string-literal and heap keys both work.  When the table
     *       is full (16 distinct keys seen), new keys are silently dropped
     *       (resource-bounded, no malloc): spec WS-1 contract is to emit at
     *       most once per distinct key among the first 16 keys.
     */
    static const char *seen[HINT_ONCE_MAX];
    static int         seen_count = 0;
    va_list            ap;
    int                i;

    if (!brix_cli_hints_enabled()) {
        return;
    }
    /* Check whether this key was already emitted. */
    for (i = 0; i < seen_count; i++) {
        if (strcmp(seen[i], key) == 0) {
            return;
        }
    }
    /* Register the key (silently drop if table is full). */
    if (seen_count < HINT_ONCE_MAX) {
        seen[seen_count++] = key;
    } else {
        return;  /* table full: drop new keys silently (spec WS-1 contract) */
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
