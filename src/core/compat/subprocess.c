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

int
brix_subprocess_capture(char *const argv[], char *out, size_t outsz,
                          size_t *out_len, int *exit_code)
{
    int      pfd[2];
    pid_t    pid;
    size_t   got = 0;
    int      status = 0;
    sigset_t block, old;

    if (out_len != NULL)   { *out_len = 0; }
    if (exit_code != NULL) { *exit_code = -1; }
    if (argv == NULL || argv[0] == NULL || out == NULL || outsz == 0) {
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
        close(pfd[0]);
        /* The dup'd stdout MUST stay open across execvp — it IS the capture
         * channel; the kernel reclaims it at _exit. (gcc >= 13 -fanalyzer
         * reports it as an fd leak: it does not model exec/_exit ending the
         * image — known false positive.) */
        if (dup2(pfd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(pfd[1]);
        sigprocmask(SIG_SETMASK, &old, NULL);   /* don't leak the mask to the child */
        execvp(argv[0], argv);
        _exit(127);   /* exec failed (command not installed) */
    }

    close(pfd[1]);
    while (got + 1 < outsz) {
        ssize_t r = read(pfd[0], out + got, outsz - 1 - got);
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
    close(pfd[0]);

    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (out_len != NULL) {
        *out_len = got;
    }
    if (!WIFEXITED(status)) {
        return -1;   /* killed by a signal, etc. */
    }
    if (exit_code != NULL) {
        *exit_code = WEXITSTATUS(status);
    }
    return 0;
}

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
