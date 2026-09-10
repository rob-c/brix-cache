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
 * HOW:  runs the command under a double-forked, reparented agent (the
 *       xfer_spawn.c shape) that waits for it and relays the raw wait status
 *       over a socketpair, so a host SIGCHLD handler (nginx's, on the worker's
 *       MAIN thread — a sigprocmask block is per-thread and does not reach it)
 *       can never reap the command first and leave a stolen status reading as
 *       "exit 0" (history-testing-and-incidents §24.15). The helper is
 *       status-agnostic — it returns the child's exit code + the raw bytes; each
 *       caller maps to its own error type and parses (JSON vs plain).
 *       ngx-free; libc only. (libxrdproto) Unit test: subprocess_unittest.c.
 */
#ifndef BRIX_COMPAT_SUBPROCESS_H
#define BRIX_COMPAT_SUBPROCESS_H

#include <stddef.h>

/*
 * One command run under the reparented agent, in its general form.
 *
 * out == NULL runs the command with the caller's own stdout (no capture pipe);
 * timeout_ms > 0 arms a deadline the AGENT enforces — it SIGKILLs the command's
 * whole process group (the command is a session leader) and the run reports
 * -1 with errno == ETIMEDOUT. brix_subprocess_capture() is this struct with a
 * buffer and no deadline.
 */
typedef struct {
    char *const  *argv;        /* NULL-terminated; argv[0] resolved via PATH  */
    char         *out;         /* stdout capture buffer, or NULL to inherit   */
    size_t        outsz;       /* its size incl. the NUL (0 iff out == NULL)  */
    unsigned      timeout_ms;  /* 0 = wait as long as the command takes       */
} brix_subprocess_req_t;

/*
 * Run argv[] (argv[0] resolved via PATH), capturing up to outsz-1 bytes of its
 * stdout into out (always NUL-terminated). *out_len = bytes captured (excl NUL);
 * *exit_code = the child's exit status (WEXITSTATUS). Both out-params may be NULL.
 * Returns 0 if the child ran to a normal exit (check *exit_code for its result),
 * -1 on pipe/fork failure, if the child was killed by a signal, or if its exit
 * status could not be obtained — never a fabricated 0.
 */
int brix_subprocess_capture(char *const argv[], char *out, size_t outsz,
                              size_t *out_len, int *exit_code);

/*
 * The general form of the above: optional capture, optional deadline. Returns 0
 * if the command ran to a normal exit (check *exit_code), -1 otherwise — with
 * errno == ETIMEDOUT when the deadline expired and the command's process group
 * was killed, and errno == EINVAL for a malformed request. Both out-params may
 * be NULL. Never a fabricated 0.
 */
int brix_subprocess_run(const brix_subprocess_req_t *req, size_t *out_len,
                          int *exit_code);

/* Strip trailing \n \r \t and spaces from s in place; returns the new length. */
size_t brix_rstrip(char *s);

#endif /* BRIX_COMPAT_SUBPROCESS_H */
