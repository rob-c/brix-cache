/*
 * log_diag.h — admin-friendly diagnostic logging helpers.
 *
 * WHAT: turn a terse one-line error into a self-explanatory, three-part
 * diagnostic that an operator who has never seen this module before can act on:
 *
 *     xrootd[pki]: no CRLs found in "/etc/grid-security/certificates"
 *       cause: CRL directory is empty or the path is wrong
 *       fix:   run fetch-crl (or set xrootd_crl_path); until then revoked
 *              certificates are ACCEPTED
 *
 * The macros wrap ngx_log_error() with a fixed message shape:
 *
 *     <summary>            — what happened, in plain language, with context
 *       cause: <cause>     — the most likely reason, named explicitly
 *       fix:   <fix>       — the concrete next step the admin should take
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
 * compile time with the indented "cause:/fix:" scaffolding — zero runtime cost,
 * nothing built on the stack. Dynamic context (paths, addresses, sizes) goes in
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
 *     (xrootd_sanitize_log_string) before passing as a vararg.
 *
 * For failures with no operator action (internal invariant violations) keep a
 * plain ngx_log_error — a "fix:" line you can't honour is worse than none.
 */
#ifndef XROOTD_COMPAT_LOG_DIAG_H
#define XROOTD_COMPAT_LOG_DIAG_H

#include <ngx_core.h>

/*
 * XROOTD_DIAG — emit a three-part diagnostic at an explicit level.
 *
 * Expands to a single ngx_log_error() call; the message body is the
 * compile-time concatenation of the summary and the indented cause/fix lines.
 */
#define XROOTD_DIAG(level, log, err, summary, cause, fix, ...)                  \
    ngx_log_error((level), (log), (err),                                       \
        summary "\n  cause: " cause "\n  fix:   " fix, ##__VA_ARGS__)

/* Level-specific shorthands — pick by operator impact (see header comment). */
#define XROOTD_DIAG_EMERG(log, err, summary, cause, fix, ...)                  \
    XROOTD_DIAG(NGX_LOG_EMERG, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define XROOTD_DIAG_CRIT(log, err, summary, cause, fix, ...)                   \
    XROOTD_DIAG(NGX_LOG_CRIT, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define XROOTD_DIAG_ERR(log, err, summary, cause, fix, ...)                    \
    XROOTD_DIAG(NGX_LOG_ERR, (log), (err), summary, cause, fix, ##__VA_ARGS__)

#define XROOTD_DIAG_WARN(log, err, summary, cause, fix, ...)                   \
    XROOTD_DIAG(NGX_LOG_WARN, (log), (err), summary, cause, fix, ##__VA_ARGS__)

/*
 * XROOTD_DIAG_CONF — same three-part shape for the config-parse phase, where
 * the available context is an ngx_conf_t* (cf) rather than an ngx_log_t*.
 * nginx prefixes these with the config file and line number, so a directive
 * mistake points the admin straight at the offending line. Use NGX_LOG_EMERG
 * to make `nginx -t` fail.
 */
#define XROOTD_DIAG_CONF(level, cf, err, summary, cause, fix, ...)             \
    ngx_conf_log_error((level), (cf), (err),                                  \
        summary "\n  cause: " cause "\n  fix:   " fix, ##__VA_ARGS__)

#endif /* XROOTD_COMPAT_LOG_DIAG_H */
