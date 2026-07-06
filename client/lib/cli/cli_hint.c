/*
 * cli_hint.c — TTY-gated usability hint helpers (spec §2 C3, WS-1/WS-3/WS-7).
 *
 * WHAT: brix_cli_hints_enabled() / brix_cli_hint() / brix_cli_hint_once() +
 *       brix_hint_sanitize_url() / brix_hint_url_double_slash() /
 *       brix_hint_doctor_referral().
 * WHY:  one place to audit the C3 compatibility gate so hints never leak into
 *       scripts, pipelines, or cron jobs (non-TTY stderr = unchanged output).
 * HOW:  isatty(STDERR_FILENO) && (BRIX_NO_HINTS unset or "0") — computed once
 *       per process (static lazy flag).  brix_cli_hint_once uses a fixed 16-
 *       slot table of seen keys to suppress repeats within a process.
 *       Callers own the "hint: " / "note: " prefix; this module prints verbatim
 *       so there is no sanitization here — callers pass pre-sanitized strings.
 *       brix_hint_sanitize_url() sanitizes a URL string for safe terminal output
 *       (replaces control bytes with '?' and caps at 128 bytes).
 */
#include "cli/cli_hint.h"
#include "brix.h"           /* brix_url, brix_status, XRDC_EAUTH */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Maximum URL length accepted by brix_hint_sanitize_url (spec WS-7). */
#define HINT_URL_MAX 128

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

void
brix_hint_sanitize_url(const char *url_str, char *out, size_t outsz)
{
    /*
     * WHAT: copy url_str into out, replacing control bytes with '?' and
     *       hard-capping at HINT_URL_MAX bytes (+ NUL).
     * WHY:  spec WS-7 / WS-3: URLs in hint output must not carry terminal
     *       escape sequences (a hostile URL like "root://\x1b[31m…" could
     *       inject ANSI escapes into the terminal if printed verbatim).
     * HOW:  copy byte-by-byte; any byte < 0x20 or >= 0x7f becomes '?'; stop
     *       at HINT_URL_MAX or NUL, whichever comes first.
     */
    size_t limit;
    size_t i;

    if (out == NULL || outsz == 0) {
        return;
    }
    limit = (outsz - 1) < HINT_URL_MAX ? (outsz - 1) : HINT_URL_MAX;
    if (url_str == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < limit && url_str[i] != '\0'; i++) {
        unsigned char c = (unsigned char) url_str[i];
        out[i] = (c < 0x20 || c >= 0x7f) ? '?' : (char) c;
    }
    out[i] = '\0';
}

void
brix_hint_url_double_slash(const brix_url *url)
{
    /*
     * WHAT: emit the double-slash convention hint once per process when the
     *       parsed URL had a single slash between authority and path.
     * WHY:  spec WS-3: users who type root://host/path instead of
     *       root://host//path see a not-found error with no indication of the
     *       conventional double-slash requirement; this hint fixes that gap.
     * HOW:  check url->single_slash_path (set by url.c when collapse did NOT
     *       fire); emit via brix_cli_hint_once so it fires at most once per
     *       process across repeated failures (e.g. multi-file batches).
     */
    if (url == NULL || !url->single_slash_path) {
        return;
    }
    brix_cli_hint_once("url-double-slash",
        "hint: XRootD URLs take a double slash before absolute paths —\n"
        "      try root://HOST//PATH (you wrote a single '/'); see man xrd, URLS.\n");
}

void
brix_hint_doctor_referral(const brix_status *st, const char *url_str)
{
    /*
     * WHAT: emit a "diagnose with: xrddiag check <url>" hint once per process
     *       when a failure is auth-class (kXR_NotAuthorized / kXR_AuthFailed /
     *       XRDC_EAUTH).
     * WHY:  spec WS-7: auth failures are rarely self-diagnosable from the
     *       error message alone; xrddiag check exercises the full credential
     *       + auth handshake and reports the root cause.
     * HOW:  check st->kxr for auth codes; sanitize url_str before printing;
     *       use brix_cli_hint_once("doctor") to suppress repeats.
     */
    char safe_url[HINT_URL_MAX + 1];
    int  is_auth;

    if (st == NULL) {
        return;
    }
    is_auth = (st->kxr == kXR_NotAuthorized
               || st->kxr == kXR_AuthFailed
               || st->kxr == XRDC_EAUTH);
    if (!is_auth) {
        return;
    }
    brix_hint_sanitize_url(url_str, safe_url, sizeof(safe_url));
    if (safe_url[0] != '\0') {
        brix_cli_hint_once("doctor",
            "hint: diagnose with: xrddiag check %s\n", safe_url);
    } else {
        brix_cli_hint_once("doctor",
            "hint: diagnose with: xrddiag check <endpoint>\n");
    }
}
