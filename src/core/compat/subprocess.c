/*
 * subprocess.c — capture a child's stdout (see subprocess.h).
 *
 * Shared by the native client's oidc-token fetch and the module's TPC token
 * paths. ngx-free; libc/POSIX only.
 */
#include "subprocess.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>

/* ---- Validate the capture arguments ----
 *
 * WHAT: Returns 1 when argv, argv[0], and the output buffer are all usable
 * (non-NULL argv/argv[0]/out and a non-zero outsz); returns 0 otherwise.
 *
 * WHY: Keeps the argument-guard branch ladder out of the orchestrator so the
 * top-level function stays a flat, low-complexity sequence of steps.
 *
 * HOW:
 *   1. Reject a NULL argv, a NULL argv[0], a NULL out, or a zero outsz.
 *   2. Otherwise report the arguments as valid.
 */
static int
brix_subprocess_args_ok(char *const argv[], const char *out, size_t outsz)
{
    if (argv == NULL || argv[0] == NULL || out == NULL || outsz == 0) {
        return 0;
    }
    return 1;
}

/* ---- Run the forked child: wire stdout to the pipe and exec ----
 *
 * WHAT: In the child process, redirects stdout to the pipe write end and execs
 * argv. Never returns to the caller: on any failure it calls _exit(127), and on
 * success control passes to the executed image.
 *
 * WHY: The child half of the fork is a distinct, self-contained responsibility;
 * isolating it keeps the fd wiring and mask restore linear and auditable.
 *
 * HOW:
 *   1. Close the pipe read end (the child only writes).
 *   2. dup2 the pipe write end onto STDOUT_FILENO; _exit(127) if that fails.
 *   3. Close the now-redundant original write-end fd. The dup'd stdout stays
 *      open across execvp — it IS the capture channel; the kernel reclaims it at
 *      _exit. (gcc >= 13 -fanalyzer reports it as an fd leak: it does not model
 *      exec/_exit ending the image — known false positive.)
 *   4. Restore the inherited signal mask so the mask is not leaked to the exec'd
 *      program.
 *   5. execvp argv; on failure (command not installed) _exit(127).
 */
static void
brix_subprocess_child(int pfd[2], char *const argv[], const sigset_t *old)
{
    close(pfd[0]);
    if (dup2(pfd[1], STDOUT_FILENO) < 0) {
        _exit(127);
    }
    close(pfd[1]);
    sigprocmask(SIG_SETMASK, old, NULL);   /* don't leak the mask to the child */
    execvp(argv[0], argv);
    _exit(127);   /* exec failed (command not installed) */
}

/* ---- Drain the child's stdout into the output buffer ----
 *
 * WHAT: Reads from fd into out until the buffer is full (leaving room for a
 * trailing NUL), EOF, or a non-EINTR error; NUL-terminates out and returns the
 * number of bytes captured.
 *
 * WHY: The bounded read loop is the parent's only real work and has its own
 * EINTR/EOF handling; keeping it separate isolates that control flow from the
 * fork/reap plumbing.
 *
 * HOW:
 *   1. While at least one byte of space remains before the reserved NUL, read
 *      into out at the current offset.
 *   2. On a negative return, retry on EINTR, else stop.
 *   3. On a zero return (EOF), stop.
 *   4. Otherwise advance the captured-byte count.
 *   5. NUL-terminate at the captured length and return that length.
 */
static size_t
brix_subprocess_drain(int fd, char *out, size_t outsz)
{
    size_t got = 0;

    while (got + 1 < outsz) {
        ssize_t r = read(fd, out + got, outsz - 1 - got);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        got += (size_t) r;
    }
    out[got] = '\0';
    return got;
}

/* ---- Reap the child and report its exit status ----
 *
 * WHAT: waitpid()s for pid (retrying on EINTR), then returns 0 and, when
 * exit_code is non-NULL, stores the child's exit status; returns -1 if the child
 * did not exit normally (killed by a signal, etc.).
 *
 * WHY: Collapsing the waitpid retry loop and the WIFEXITED decoding into one
 * helper keeps the status semantics in a single place and out of the
 * orchestrator's branch count.
 *
 * HOW:
 *   1. waitpid for the child, retrying while it fails with EINTR.
 *   2. If the child did not exit normally, return -1.
 *   3. Otherwise store WEXITSTATUS into exit_code when provided and return 0.
 */
static int
brix_subprocess_reap(pid_t pid, int *exit_code)
{
    int status = 0;

    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    if (!WIFEXITED(status)) {
        return -1;   /* killed by a signal, etc. */
    }
    if (exit_code != NULL) {
        *exit_code = WEXITSTATUS(status);
    }
    return 0;
}

/* ---- Capture a child command's stdout ----
 *
 * WHAT: Forks and execs argv, capturing its stdout into out (up to outsz-1 bytes
 * plus a NUL). Returns 0 on a normal child exit (storing the byte count in
 * out_len and the exit status in exit_code when non-NULL), or -1 on any setup
 * failure or abnormal child termination.
 *
 * WHY: Gives ngx-free callers a single, side-effect-honest primitive for running
 * a helper command and reading its output without leaking fds, child processes,
 * or a modified signal mask.
 *
 * HOW:
 *   1. Zero the caller's out_len/exit_code and validate the arguments.
 *   2. Create the capture pipe.
 *   3. Block SIGCHLD so a host reaper cannot steal our child before waitpid();
 *      the mask is restored before every return.
 *   4. fork; on failure restore the mask, close both pipe ends, and fail.
 *   5. In the child, hand off to brix_subprocess_child (never returns).
 *   6. In the parent, close the write end, drain stdout, close the read end.
 *   7. Reap the child, restore the signal mask, publish out_len, and return the
 *      reap result.
 */
int
brix_subprocess_capture(char *const argv[], char *out, size_t outsz,
                          size_t *out_len, int *exit_code)
{
    int      pfd[2];
    pid_t    pid;
    size_t   got;
    int      rc;
    sigset_t block, old;

    if (out_len != NULL)   { *out_len = 0; }
    if (exit_code != NULL) { *exit_code = -1; }
    if (!brix_subprocess_args_ok(argv, out, outsz)) {
        return -1;
    }
    if (pipe(pfd) != 0) {
        return -1;
    }
    /* Block SIGCHLD so a host SIGCHLD handler (e.g. nginx's child reaper) cannot
     * reap our child before waitpid(); the child restores the mask before exec so
     * the executed program is unaffected. Restored before every return. */
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old);

    pid = fork();
    if (pid < 0) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        brix_subprocess_child(pfd, argv, &old);
    }

    close(pfd[1]);
    got = brix_subprocess_drain(pfd[0], out, outsz);
    close(pfd[0]);

    rc = brix_subprocess_reap(pid, exit_code);
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (out_len != NULL) {
        *out_len = got;
    }
    return rc;
}

/* ---- Strip trailing whitespace from a C string ----
 *
 * WHAT: Removes trailing newline, carriage-return, space, and tab characters
 * from s in place and returns the resulting length; returns 0 for a NULL s.
 *
 * WHY: Command output captured by brix_subprocess_capture routinely carries a
 * trailing newline that callers must not treat as part of a token or value.
 *
 * HOW:
 *   1. Return 0 immediately for a NULL string.
 *   2. Measure the current length.
 *   3. While the last character is a trailing whitespace byte, overwrite it with
 *      NUL and shrink the length.
 *   4. Return the trimmed length.
 */
size_t
brix_rstrip(char *s)
{
    size_t n;

    if (s == NULL) {
        return 0;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'
                     || s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
    return n;
}
