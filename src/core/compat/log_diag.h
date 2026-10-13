/*
 * log_diag.h — admin-friendly diagnostic logging helpers.
 *
 * WHAT: turn a terse one-line error into a self-explanatory, three-part
 * diagnostic that an operator who has never seen this module before can act on:
 *
 *     summary; cause: reason; fix: actionable operator next step
 *
 * The macros wrap BRIX_LOG() with a single-line message shape:
 *
 *     <summary>; cause: <cause>; fix: <fix>
 *
 * WHY: this module fronts grid storage (GSI/x509, CRLs, tokens, SSS keytabs,
 * CMS clustering, tape/FRM, disk I/O). When something breaks at 3am the error
 * log is the only thing the on-call admin has. A bare "frm: pread failed" or
 * "EVP_DecryptFinal failed" tells them nothing; a message that names the cause
 * and the fix turns a 2-hour outage into a 2-minute one. Centralising the shape
 * also keeps the whole module's diagnostics uniform and greppable
 * (`grep 'fix:'` surfaces every actionable line).
 *
 * HOW: `summary`, `cause`, and `fix` are string literals, concatenated at
 * compile time with the single-line "cause:/fix:" scaffolding. The shared
 * adapter bounds and escapes the final record. Dynamic context goes in
 * the trailing varargs and is consumed by printf-style specifiers in `summary`
 * (nginx's %V/%s/%d/%ui/etc). `err` is an errno (or 0) exactly as ngx_log_error
 * expects; when non-zero nginx appends the OS string, so disk/network failures
 * carry the kernel's own truth ("(28: No space left on device)") after the fix.
 *
 * Convention for callers:
 *   - Begin `summary` with the subsystem tag: "xrootd[<sub>]: ...".
 *   - Keep `cause`/`fix` literal; fold any dynamic value into `summary` instead.
 *   - Use the level that matches operator impact:
 *       EMERG — startup/config; nginx -t fails, nothing serves yet.
 *       CRIT  — running service degraded for everyone (store reload failed).
 *       ERR   — one request/connection failed; service otherwise healthy.
 *       WARN  — working but mis-tuned or insecure; admin should look.
 *   - For untrusted, wire-supplied strings sanitise first
 *     (brix_sanitize_log_string) before passing as a vararg.
 *
 * For failures with no operator action (internal invariant violations) keep a
 * plain BRIX_LOG — a "fix:" line you can't honour is worse than none.
 */
#ifndef BRIX_COMPAT_LOG_DIAG_H
#define BRIX_COMPAT_LOG_DIAG_H

#include "core/compat/log_event.h"
#include <ngx_core.h>

/*
 * BRIX_DIAG — emit a three-part diagnostic at an explicit level.
 *
 * Expands to a single structured BRIX_LOG() record; the message body is the
 * compile-time concatenation of summary and same-line cause/fix clauses.
 */
#define BRIX_DIAG(level, log, err, summary, cause, fix, ...)                  \
    BRIX_LOG((level), (log), (err),                                       \
        summary "; cause: " cause "; fix: " fix, ##__VA_ARGS__)

/* Level-specific shorthands — pick by operator impact (see header comment). */
#define BRIX_DIAG_EMERG(log, err, summary, cause, fix, ...)                  \
    BRIX_DIAG(NGX_LOG_EMERG, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define BRIX_DIAG_CRIT(log, err, summary, cause, fix, ...)                   \
    BRIX_DIAG(NGX_LOG_CRIT, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define BRIX_DIAG_ERR(log, err, summary, cause, fix, ...)                    \
    BRIX_DIAG(NGX_LOG_ERR, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define BRIX_DIAG_WARN(log, err, summary, cause, fix, ...)                   \
    BRIX_DIAG(NGX_LOG_WARN, (log), (err), summary, cause, fix, ##__VA_ARGS__)

/*
 * BRIX_DIAG_CONF — same three-part shape for the config-parse phase, where
 * the available context is an ngx_conf_t* (cf) rather than an ngx_log_t*.
 * nginx prefixes these with the config file and line number, so a directive
 * mistake points the admin straight at the offending line. Use NGX_LOG_EMERG
 * to make `nginx -t` fail.
 */
#define BRIX_DIAG_CONF(level, cf, err, summary, cause, fix, ...)             \
    BRIX_CONF_LOG((level), (cf), (err),                                  \
        summary "; cause: " cause "; fix: " fix, ##__VA_ARGS__)

#endif /* BRIX_COMPAT_LOG_DIAG_H */
