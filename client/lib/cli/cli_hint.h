#ifndef BRIX_CLI_HINT_H
#define BRIX_CLI_HINT_H
/*
 * cli_hint.h — TTY-gated usability hint helpers (spec §2 C3, WS-1/WS-3/WS-7).
 *
 * WHAT: emit one-line hints/notes to stderr only when stderr is an interactive
 *       terminal and the caller has not opted out via BRIX_NO_HINTS; plus
 *       URL sanitization and the WS-3/WS-7 canned hints.
 * WHY:  single auditable gate for the C3 compatibility contract: every script,
 *       cron job, and pipeline receives byte-identical output — hints are
 *       strictly additive on interactive terminals only.
 * HOW:  isatty(STDERR_FILENO) && (BRIX_NO_HINTS unset || "0"); gate computed
 *       once per process (static lazy init).  Callers include their own
 *       prefix ("hint: " / "note: ") — the helper prints fmt verbatim.
 *       brix_hint_sanitize_url() sanitizes a URL string for safe terminal output.
 *       Include brix.h before this header if you need brix_url / brix_status
 *       types — or just include brix.h, which already pulls in brix_ops.h which
 *       declares brix_cli_connect; cli_hint.h is included by cli code directly.
 */

#include <stddef.h>   /* size_t */

/* brix_url and brix_status are typedef'd in brix.h (anonymous structs).
 * Include brix.h here so WS-3/WS-7 helpers can use the concrete types.
 * cli_hint.h is NOT included by brix.h itself, so there is no circular
 * dependency. */
#include "brix.h"

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

/* --- WS-3/WS-7 canned hint helpers ---------------------------------------- */

/* Sanitize url_str into out[outsz]: escape control / non-printable bytes
 * (< 0x20 or > 0x7e) as "\xNN" (lowercase hex); consider at most 128 input
 * bytes.  Worst case output is 128*4 bytes, so size out at 128*4+1 = 513.
 * out[0]='\0' on NULL url_str or empty outsz. */
void brix_hint_sanitize_url(const char *url_str, char *out, size_t outsz);

/* Emit the double-slash URL hint (spec WS-3) once per process when st is a
 * not-found-class failure (kXR_NotFound / sys_errno==ENOENT) AND url has
 * single_slash_path set.  No-op otherwise (NULL args included). */
void brix_hint_url_double_slash(const brix_status *st, const brix_url *url);

/* Emit a "diagnose with: xrddiag check <url_str>" hint (spec WS-7) once per
 * process when st carries an auth-class failure.  url_str is sanitized before
 * printing; pass NULL to omit the URL. */
void brix_hint_doctor_referral(const brix_status *st, const char *url_str);

#endif /* BRIX_CLI_HINT_H */
