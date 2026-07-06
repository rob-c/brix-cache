#ifndef BRIX_CLI_HINT_H
#define BRIX_CLI_HINT_H
/*
 * cli_hint.h — TTY-gated usability hint helpers (spec §2 C3, WS-1).
 *
 * WHAT: emit one-line hints/notes to stderr only when stderr is an interactive
 *       terminal and the caller has not opted out via BRIX_NO_HINTS.
 * WHY:  single auditable gate for the C3 compatibility contract: every script,
 *       cron job, and pipeline receives byte-identical output — hints are
 *       strictly additive on interactive terminals only.
 * HOW:  isatty(STDERR_FILENO) && (BRIX_NO_HINTS unset || "0"); gate computed
 *       once per process (static lazy init).  Callers include their own
 *       prefix ("hint: " / "note: ") — the helper prints fmt verbatim.
 */

/* 1 if hints are enabled for this process (stderr is a TTY and BRIX_NO_HINTS
 * is unset or "0"), 0 otherwise.  The result is computed once on first call. */
int brix_cli_hints_enabled(void);

/* Emit a formatted line to stderr when hints are enabled.  Callers include
 * their own "hint: " / "note: " prefix.  Never touches stdout or exit codes. */
void brix_cli_hint(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Same gate as brix_cli_hint, but emits at most once per (process, key).
 * key is a short ASCII identifier (e.g. "url-double-slash"); silently drops
 * beyond 16 distinct keys. */
void brix_cli_hint_once(const char *key, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif /* BRIX_CLI_HINT_H */
