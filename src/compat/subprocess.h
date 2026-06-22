/*
 * subprocess.h — capture a child process's stdout (shared).
 *
 * WHAT: fork/exec a command, drain its stdout into a caller buffer, reap it.
 * WHY:  the oidc-agent / RFC-8693 token fetch is done by fork/exec'ing
 *       `oidc-token` or `curl` and reading stdout — the SAME pipe→fork→dup2→
 *       drain→waitpid skeleton appears in the native client (credrefresh.c) and
 *       the module's TPC token paths (tpc/tpc_token.c, webdav/tpc_cred.c). Both
 *       run the fork SYNCHRONOUSLY (the module does it off the event loop), so —
 *       unusually for resilience code — the mechanism itself is genuinely shared.
 * HOW:  blocks SIGCHLD across fork+waitpid so a host SIGCHLD handler (nginx's)
 *       can't reap the child first; the child restores the mask before exec. The
 *       helper is status-agnostic — it returns the child's exit code + the raw
 *       bytes; each caller maps to its own error type and parses (JSON vs plain).
 *       ngx-free; libc only. (libxrdproto)
 */
#ifndef XROOTD_COMPAT_SUBPROCESS_H
#define XROOTD_COMPAT_SUBPROCESS_H

#include <stddef.h>

/*
 * Run argv[] (argv[0] resolved via PATH), capturing up to outsz-1 bytes of its
 * stdout into out (always NUL-terminated). *out_len = bytes captured (excl NUL);
 * *exit_code = the child's exit status (WEXITSTATUS). Both out-params may be NULL.
 * Returns 0 if the child ran to a normal exit (check *exit_code for its result),
 * -1 on pipe/fork failure or if the child was killed by a signal.
 */
int xrootd_subprocess_capture(char *const argv[], char *out, size_t outsz,
                              size_t *out_len, int *exit_code);

/* Strip trailing \n \r \t and spaces from s in place; returns the new length. */
size_t xrootd_rstrip(char *s);

#endif /* XROOTD_COMPAT_SUBPROCESS_H */
