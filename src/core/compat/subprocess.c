/*
 * subprocess.c — capture a child's stdout (see subprocess.h).
 *
 * Shared by the native client's oidc-token fetch and the module's TPC token
 * paths. ngx-free; libc/POSIX only.
 *
 * The command runs under a double-forked agent (the shape of
 * src/fs/xfer/xfer_spawn.c): the intermediate exits at once so the agent
 * reparents to init; the agent forks the command with its stdout on the capture
 * pipe, waitpid()s it, and relays the raw wait status over a one-shot socketpair.
 * The caller drains the pipe, then reads the status.
 *
 * WHY an agent: blocking SIGCHLD around a plain fork() is per-THREAD. On an nginx
 * thread-pool thread it never stopped the worker's MAIN thread from taking the
 * signal and reaping our direct child first (ngx_process_get_status →
 * waitpid(-1, WNOHANG)); the helper's own waitpid() then failed with ECHILD,
 * which the old retry loop read as "exit 0" — a dead token endpoint surfaced as a
 * token-parse failure instead of "curl exit 7" (the rhB42 fast-tier halt,
 * history-testing-and-incidents §24.15). With the agent the only process the
 * host can ever reap is the intermediate, whose status nobody needs.
 * No goto; early-return.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE          /* pipe2, SOCK_CLOEXEC, F_DUPFD_CLOEXEC */
#endif

#include "subprocess.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Relayed by the agent in place of a wait status when it never obtained one,
 * and in place of the (unwanted) SIGKILL status when the deadline expired. A
 * real wait status is never negative, so neither can collide with one. */
#define BRIX_SUBPROCESS_NO_STATUS   (-1)
#define BRIX_SUBPROCESS_TIMED_OUT   (-2)

/* close_range(2): Linux ≥ 5.9, the same number on every architecture. glibc
 * here ships no wrapper, so it is a raw syscall; the number normally comes from
 * <sys/syscall.h>. Already on the seccomp allowlist (seccomp_core.c). */
#ifndef __NR_close_range
#define __NR_close_range            436
#endif

/* pidfd_open(2): Linux >= 5.3, same number on every architecture. Used only to
 * poll a deadline; a kernel without it waits unbounded, as before. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open             434
#endif

/* ---- Validate a run request ----
 *
 * WHAT: Returns 1 when the request names a command and, if it asks for a
 * capture, gives a usable buffer; returns 0 otherwise.
 *
 * WHY: Keeps the argument-guard branch ladder out of the orchestrator so the
 * top-level function stays a flat, low-complexity sequence of steps.
 *
 * HOW:
 *   1. Reject a NULL request, a NULL argv, or a NULL argv[0].
 *   2. Reject a capture buffer with no room (out != NULL with outsz == 0).
 *   3. Otherwise report the request as valid. out == NULL is legal: the
 *      command then writes to the caller's own stdout.
 */
static int
brix_subprocess_args_ok(const brix_subprocess_req_t *req)
{
    if (req == NULL || req->argv == NULL || req->argv[0] == NULL) {
        return 0;
    }
    if (req->out != NULL && req->outsz == 0) {
        return 0;
    }
    return 1;
}

/* ---- Read exactly one relayed status word ----
 *
 * WHAT: Reads sizeof(int) bytes from fd into *status, retrying on EINTR.
 * Returns 1 on success, 0 on EOF or a non-EINTR error.
 *
 * WHY: The agent's one-shot report is the caller's only source of the child's
 * exit status; a short read means the agent died before reporting.
 *
 * HOW: loop until sizeof(int) bytes have accumulated; EOF or a non-EINTR
 * error → 0; EINTR → retry.
 */
static int
brix_subprocess_read_status(int fd, int *status)
{
    unsigned char *p = (unsigned char *) status;
    size_t         got = 0;

    while (got < sizeof(*status)) {
        ssize_t n = read(fd, p + got, sizeof(*status) - got);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        got += (size_t) n;
    }
    return 1;
}

/* ---- Relay one status word (best effort) ----
 *
 * WHAT: Writes sizeof(int) bytes of status to fd, retrying on EINTR; the
 * outcome is ignored because the agent has nobody left to tell.
 *
 * WHY: Isolates the only write the agent performs; a vanished reader (the
 * caller gave up) must not turn into a signal or an error path in the agent.
 *
 * HOW: loop until all bytes are written; EINTR → retry; any other error → stop.
 */
static void
brix_subprocess_write_status(int fd, int status)
{
    const unsigned char *p = (const unsigned char *) &status;
    size_t               put = 0;

    while (put < sizeof(status)) {
        ssize_t n = write(fd, p + put, sizeof(status) - put);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        put += (size_t) n;
    }
}

/* ---- Close every inherited descriptor the agent does not own ----
 *
 * WHAT: Closes all fds >= 3 except keep, first via close_range(2) and, when the
 * kernel lacks it, by walking the descriptor table up to _SC_OPEN_MAX.
 *
 * WHY: The agent is a fork of a multithreaded process: it holds copies of every
 * pipe end another thread's capture had open at that instant. Left open, that
 * end would withhold the OTHER caller's EOF until this agent's command finished
 * — a wedged endpoint on one transfer would stall every concurrent exchange.
 *
 * HOW: close_range(3, keep-1) and close_range(keep+1, ~0U); if either syscall
 * fails, close(f) for every f in [3, _SC_OPEN_MAX) other than keep.
 */
static void
brix_subprocess_close_others(int keep)
{
    long f, max;
    long rc = 0;

    if (keep > 3) {
        rc = syscall(__NR_close_range, 3U, (unsigned) keep - 1, 0U);
    }
    if (rc == 0) {
        rc = syscall(__NR_close_range, (unsigned) keep + 1, ~0U, 0U);
    }
    if (rc == 0) {
        return;
    }
    max = sysconf(_SC_OPEN_MAX);
    for (f = 3; f < max; f++) {
        if (f != keep) {
            (void) close((int) f);
        }
    }
}

/* ---- Exec the command in the agent's child ----
 *
 * WHAT: Restores the caller's signal mask and execs argv with the capture pipe
 * already on STDOUT_FILENO. Never returns: exec failure → _exit(127).
 *
 * WHY: Only async-signal-safe calls may run between fork and exec in a child of
 * a multithreaded process; keeping the child body to two calls makes that
 * property obvious.
 *
 * HOW:
 *   1. sigprocmask(SIG_SETMASK, old) so the executed program sees the mask the
 *      caller had, not the SIGCHLD block.
 *   2. setsid() so the command leads its own session and process group: a
 *      deadline kill can then reach -pid (the shebang script AND everything it
 *      started), and no operator program shares the host's controlling
 *      terminal. It cannot fail here — a fresh fork is never a group leader.
 *   3. execvp argv; on failure _exit(127) (command not installed), which also
 *      closes stdout so the draining caller sees EOF.
 */
static void
brix_subprocess_child(char *const argv[], const sigset_t *old)
{
    sigprocmask(SIG_SETMASK, old, NULL);
    (void) setsid();
    execvp(argv[0], argv);
    _exit(127);
}

/* ---- Has the deadline expired before the command finished? ----
 *
 * WHAT: Waits up to timeout_ms for pid to exit, without reaping it. Returns 1
 * when the deadline expired first, 0 when the command exited (or when the
 * kernel has no pidfd_open, which means "wait unbounded", the pre-deadline
 * behaviour).
 *
 * WHY: A deadline needs a wait that can time out, and waitpid cannot. A pidfd
 * gives one without SIGALRM and without a waitpid(WNOHANG) spin.
 *
 * HOW: pidfd_open (a failure means no deadline → 0), poll it for timeout_ms
 * (EINTR restarts the window — the agent installs no handlers), close, and
 * report whether poll timed out rather than the child exiting.
 */
static int
brix_subprocess_deadline_expired(pid_t pid, unsigned timeout_ms)
{
    struct pollfd pfd;
    int           pidfd = (int) syscall(__NR_pidfd_open, pid, 0U);
    int           r;

    if (pidfd < 0) {
        return 0;
    }
    pfd.fd = pidfd;
    pfd.events = POLLIN;
    while ((r = poll(&pfd, 1, (int) timeout_ms)) < 0 && errno == EINTR) {
        /* retry */
    }
    (void) close(pidfd);
    return r == 0;
}

/* ---- Reap the command, under the request's deadline ----
 *
 * WHAT: Returns the wait status to relay: the command's raw status, or
 * BRIX_SUBPROCESS_TIMED_OUT when the deadline killed it, or
 * BRIX_SUBPROCESS_NO_STATUS when no status could be obtained.
 *
 * WHY: The deadline must be enforced by the process that owns the command —
 * the agent — because it is the only one that can wait for it at all.
 *
 * HOW: an expired deadline SIGKILLs the command's process group (-pid reaches a
 * shebang script's own children; the command is a session leader, so the group
 * is exactly its subtree) and then the command itself, reaps the zombie and
 * reports the timeout. Otherwise waitpid, retrying on EINTR; any other failure
 * → no status.
 */
static int
brix_subprocess_reap(pid_t child, unsigned timeout_ms)
{
    int status = BRIX_SUBPROCESS_NO_STATUS;

    if (timeout_ms > 0 && brix_subprocess_deadline_expired(child, timeout_ms)) {
        (void) kill(-child, SIGKILL);
        (void) kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            /* retry */
        }
        return BRIX_SUBPROCESS_TIMED_OUT;
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return BRIX_SUBPROCESS_NO_STATUS;
        }
    }
    return status;
}

/* ---- The reparented agent: run the command, relay its wait status ----
 *
 * WHAT: Puts the capture pipe on its own stdout, drops every other inherited
 * fd, forks the command, waits for it, writes the raw wait status (or
 * BRIX_SUBPROCESS_NO_STATUS) to result_fd and _exit(0)s. Never returns.
 *
 * WHY: The agent is the command's parent and the only process that waits for
 * it, so no host SIGCHLD handler can take the status: the host never had the
 * command as a child at all.
 *
 * HOW:
 *   1. SIGCHLD → SIG_DFL: the inherited host handler must not run here (the
 *      mask inherited from the caller keeps it blocked anyway; belt and braces).
 *   2. Move result_fd above 2 (F_DUPFD_CLOEXEC) so step 3 cannot clobber it.
 *   3. With a capture requested, dup2 its write end onto STDOUT_FILENO; a
 *      request without one leaves the caller's stdout in place. Then close
 *      every other fd — the worker's listen sockets, live client connections,
 *      epoll and logs must never reach an operator program.
 *   4. fork; the child execs (brix_subprocess_child).
 *   5. Close our stdout copy so the caller's drain sees EOF when the command
 *      alone exits; reap it under the request's deadline.
 *   6. Relay the status and _exit(0).
 */
static void
brix_subprocess_agent(int result_fd, int capture_fd,
                      const brix_subprocess_req_t *req, const sigset_t *old)
{
    pid_t child;
    int   status;
    int   output_fd = -1;

    (void) signal(SIGCHLD, SIG_DFL);
    result_fd = fcntl(result_fd, F_DUPFD_CLOEXEC, 3);
    if (result_fd < 0) {
        _exit(0);
    }
    if (capture_fd >= 0) {
        output_fd = dup2(capture_fd, STDOUT_FILENO);
        if (output_fd < 0) {
            _exit(0);
        }
    }
    brix_subprocess_close_others(result_fd);
    child = fork();
    if (child == 0) {
        brix_subprocess_child(req->argv, old);   /* never returns */
    }
    if (output_fd >= 0) {
        close(output_fd);
    }
    status = (child > 0) ? brix_subprocess_reap(child, req->timeout_ms)
                         : BRIX_SUBPROCESS_NO_STATUS;
    brix_subprocess_write_status(result_fd, status);
    _exit(0);
}

/* ---- Double-fork the agent and reap the intermediate ----
 *
 * WHAT: Under a SIGCHLD block, forks an intermediate that forks the agent and
 * exits; reaps the intermediate; restores the mask. Returns 0, or -1 (errno
 * set) if the intermediate could not be forked.
 *
 * WHY: The intermediate's immediate exit reparents the agent to init, which is
 * what keeps the command out of the host's waitpid(-1). The intermediate itself
 * is the one child the host MAY reap first (the block is per-thread); its status
 * is unused, so an ECHILD here is harmless and tolerated.
 *
 * HOW:
 *   1. Block SIGCHLD in this thread and remember the previous mask.
 *   2. fork the intermediate; on failure restore the mask and return -1.
 *   3. Intermediate: fork the agent (which closes its unused ends and never
 *      returns), then _exit(0).
 *   4. Parent: waitpid the intermediate (EINTR → retry; anything else → done),
 *      restore the mask, return 0.
 */
static int
brix_subprocess_spawn(const brix_subprocess_req_t *req, const int capture[2],
                      const int result[2])
{
    sigset_t block, old;
    pid_t    inter;

    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old);
    inter = fork();
    if (inter < 0) {
        int e = errno;
        sigprocmask(SIG_SETMASK, &old, NULL);
        errno = e;
        return -1;
    }
    if (inter == 0) {
        if (fork() == 0) {
            close(result[0]);
            close(capture[0]);
            brix_subprocess_agent(result[1], capture[1], req, &old);   /* never returns */
        }
        _exit(0);                                  /* intermediate → reparent */
    }
    while (waitpid(inter, NULL, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    return 0;
}

/* ---- Drain the command's stdout into the output buffer ----
 *
 * WHAT: Reads from fd into out until the buffer is full (leaving room for a
 * trailing NUL), EOF, or a non-EINTR error; NUL-terminates out and returns the
 * number of bytes captured.
 *
 * WHY: The bounded read loop is the caller's only real work and has its own
 * EINTR/EOF handling; keeping it separate isolates that control flow from the
 * spawn/collect plumbing. A writer left behind on a full buffer gets EPIPE when
 * the caller closes the read end, so it cannot wedge the agent's waitpid.
 *
 * HOW: while a byte of space remains before the reserved NUL, read into out at
 * the current offset; EINTR retries, any other error or EOF stops, otherwise
 * the captured-byte count advances. NUL-terminate and return that length.
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

/* ---- Collect the relayed wait status ----
 *
 * WHAT: Reads the agent's status word from result_fd. Returns 0 and stores
 * WEXITSTATUS in *exit_code (when non-NULL) for a normal exit; returns -1 when
 * the agent died before reporting, had no status, or the command was killed by
 * a signal.
 *
 * WHY: This is where "the child exited N" is decided, in one place, from a
 * status only the agent could have obtained — never from a default of 0.
 *
 * HOW:
 *   1. Short read → -1.
 *   2. BRIX_SUBPROCESS_TIMED_OUT → -1 with errno ETIMEDOUT: the deadline
 *      expired and the agent killed the command's process group.
 *   3. BRIX_SUBPROCESS_NO_STATUS or !WIFEXITED → -1.
 *   4. Otherwise publish WEXITSTATUS and return 0.
 */
static int
brix_subprocess_collect(int result_fd, int *exit_code)
{
    int status;

    if (!brix_subprocess_read_status(result_fd, &status)) {
        return -1;   /* agent died before reporting */
    }
    if (status == BRIX_SUBPROCESS_TIMED_OUT) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (status == BRIX_SUBPROCESS_NO_STATUS || !WIFEXITED(status)) {
        return -1;   /* fork failed in the agent, or killed by a signal */
    }
    if (exit_code != NULL) {
        *exit_code = WEXITSTATUS(status);
    }
    return 0;
}

/* ---- Close both ends of two descriptor pairs ----
 *
 * An unopened pair carries -1s (a run with no capture asks for no pipe);
 * close(-1) is a harmless EBADF. */
static void
brix_subprocess_close_pairs(const int a[2], const int b[2])
{
    close(a[0]);
    close(a[1]);
    close(b[0]);
    close(b[1]);
}

/* ---- Run a command under the reparented agent ----
 *
 * WHAT: The general form of brix_subprocess_capture(): runs req->argv under the
 * agent, optionally capturing its stdout and optionally under a deadline.
 * Returns 0 on a normal exit (publishing out_len/exit_code), or -1 — with errno
 * ETIMEDOUT when the deadline killed the command's process group.
 *
 * WHY: Two kinds of caller need this: the token fetches want the output, while
 * the FRM operator programs (the stage command, the purge policy program) want
 * only the exit status and a deadline. Both must stay off the "direct child of
 * an nginx worker" path, whose status the worker's SIGCHLD handler steals.
 *
 * HOW:
 *   1. Zero the caller's out-params and validate the request.
 *   2. Open the status socketpair and, only when a capture was asked for, the
 *      stdout pipe (both CLOEXEC; a run without one keeps -1s so the agent
 *      leaves the caller's stdout alone).
 *   3. Spawn the agent and close the agent-side ends.
 *   4. With a capture, drain stdout to EOF and close the read end.
 *   5. Collect the relayed status, close the result end, publish out_len.
 */
int
brix_subprocess_run(const brix_subprocess_req_t *req, size_t *out_len,
                      int *exit_code)
{
    int     capture[2];
    int     result[2];
    size_t  got = 0;
    int     rc;

    if (out_len != NULL)   { *out_len = 0; }
    if (exit_code != NULL) { *exit_code = -1; }
    if (!brix_subprocess_args_ok(req)) {
        errno = EINVAL;
        return -1;
    }
    capture[0] = capture[1] = -1;
    if (req->out != NULL && pipe2(capture, O_CLOEXEC) != 0) {
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, result) != 0) {
        close(capture[0]);
        close(capture[1]);
        return -1;
    }
    if (brix_subprocess_spawn(req, capture, result) != 0) {
        brix_subprocess_close_pairs(capture, result);
        return -1;
    }
    close(result[1]);
    if (req->out != NULL) {
        close(capture[1]);
        got = brix_subprocess_drain(capture[0], req->out, req->outsz);
        close(capture[0]);
    }
    rc = brix_subprocess_collect(result[0], exit_code);
    close(result[0]);
    if (out_len != NULL) {
        *out_len = got;
    }
    return rc;
}

/* ---- Capture a child command's stdout ----
 *
 * WHAT: brix_subprocess_run() with a capture buffer and no deadline: runs argv
 * under the reparented agent, capturing its stdout into out (up to outsz-1
 * bytes plus a NUL). Returns 0 on a normal child exit (storing the byte count
 * in out_len and the exit status in exit_code when non-NULL), or -1 on any
 * setup failure or abnormal child termination.
 *
 * WHY: Gives ngx-free callers a single, side-effect-honest primitive for running
 * a helper command and reading its output without leaking fds, child processes,
 * a modified signal mask — or, on a thread-pool thread, the exit status.
 *
 * HOW:
 *   1. Reject a NULL buffer here: a capture with nowhere to put the output is a
 *      caller bug, while the general form treats it as "inherit stdout".
 *   2. Delegate to brix_subprocess_run().
 */
int
brix_subprocess_capture(char *const argv[], char *out, size_t outsz,
                          size_t *out_len, int *exit_code)
{
    brix_subprocess_req_t req;

    if (out == NULL) {
        if (out_len != NULL)   { *out_len = 0; }
        if (exit_code != NULL) { *exit_code = -1; }
        errno = EINVAL;
        return -1;
    }
    req.argv = argv;
    req.out = out;
    req.outsz = outsz;
    req.timeout_ms = 0;
    return brix_subprocess_run(&req, out_len, exit_code);
}

/* ---- Strip trailing whitespace from a C string ----
 *
 * WHAT: Removes trailing newline, carriage-return, space, and tab characters
 * from s in place and returns the resulting length; returns 0 for a NULL s.
 *
 * WHY: Command output captured by brix_subprocess_capture routinely carries a
 * trailing newline that callers must not treat as part of a token or value.
 *
 * HOW: a NULL string reports 0; otherwise measure the length, then overwrite
 * each trailing whitespace byte with NUL and shrink the length past it.
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
