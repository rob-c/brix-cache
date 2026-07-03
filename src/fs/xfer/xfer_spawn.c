/*
 * xfer_spawn.c — crash-safe synchronous external-command runner (see xfer_spawn.h).
 *
 * Double-fork so the agent reparents to init (nginx never reaps it); the
 * intermediate is reaped by us under a SIGCHLD block so nginx's handler does not
 * race us for it. The agent forks the actual command, waitpid()s it, and reports
 * the exit status back over a one-shot socketpair; the caller blocks reading it.
 *
 * ngx-free and POSIX-only on purpose: unit-testable without nginx, and the child
 * path is async-signal-safe so it is also safe to call from a thread-pool worker.
 * No goto; early-return.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE          /* execvpe: PATH search + caller-supplied environ */
#endif
#include "xfer_spawn.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* Exit-code sentinels reported by the agent (kept within 0..255 so they never
 * collide with -1 "could not spawn"). */
#define XFER_SPAWN_EXEC_FAILED  127
#define XFER_SPAWN_KILLED       128

/* Read exactly len bytes; 1 on success, 0 on short read/EOF/error. */
static int
xfer_read_exact(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t         got = 0;

    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
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

/* Write exactly len bytes; ignore the outcome (best-effort result reporting). */
static void
xfer_write_exact(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t               put = 0;

    while (put < len) {
        ssize_t n = write(fd, p + put, len - put);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        put += (size_t) n;
    }
}

/* The agent body (runs reparented): fork the command, wait, report exit code. */
static void
xfer_spawn_agent(int result_fd, const char *const argv[], char *const envp[])
{
    pid_t child;
    int   status;
    int   code = XFER_SPAWN_EXEC_FAILED;

    child = fork();
    if (child < 0) {
        xfer_write_exact(result_fd, &code, sizeof(code));
        _exit(0);
    }
    if (child == 0) {
        int f;
        for (f = 3; f < 1024; f++) {
            (void) close(f);     /* drop the socketpair + any inherited fds */
        }
        /* execvpe: PATH search when argv[0] has no '/', matching the prior
         * posix_spawnp; an absolute/relative path skips the search. */
        execvpe(argv[0], (char *const *) argv, envp ? envp : environ);
        _exit(XFER_SPAWN_EXEC_FAILED);
    }

    while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
    code = WIFEXITED(status) ? WEXITSTATUS(status) : XFER_SPAWN_KILLED;
    xfer_write_exact(result_fd, &code, sizeof(code));
    _exit(0);
}

int
brix_xfer_run_reparented(const char *const argv[], char *const envp[])
{
    int      sv[2];
    sigset_t block, prev;
    pid_t    inter;
    int      code = -1;

    if (argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return -1;
    }

    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &prev);

    inter = fork();
    if (inter < 0) {
        int e = errno;
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(sv[0]);
        close(sv[1]);
        errno = e;
        return -1;
    }
    if (inter == 0) {
        pid_t agent = fork();
        if (agent == 0) {
            close(sv[0]);
            xfer_spawn_agent(sv[1], argv, envp);   /* never returns */
            _exit(0);
        }
        _exit(0);                                  /* intermediate → reparent */
    }

    /* parent: reap the intermediate ourselves; nginx never sees it. */
    close(sv[1]);
    while (waitpid(inter, NULL, 0) < 0 && errno == EINTR) { }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    if (!xfer_read_exact(sv[0], &code, sizeof(code))) {
        code = -1;                                 /* agent died before reporting */
    }
    close(sv[0]);
    return code;
}
