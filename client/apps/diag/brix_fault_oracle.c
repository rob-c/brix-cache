/*
 * brix_fault_oracle.c — gated external-command oracle.  See brix_fault_oracle.h.
 */
#include "brix_fault_oracle.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

static int g_exec_enabled = 0;

void
fp_oracle_enable(void)
{
    g_exec_enabled = 1;
}

int
fp_oracle_enabled(void)
{
    return g_exec_enabled;
}

int
fp_oracle_run(const char *cmd, int timeout_ms)
{
    if (!g_exec_enabled) {
        return -2;
    }
    if (!cmd || !*cmd) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        setsid();                       /* own process group for a clean timeout kill */
        /* Close every inherited descriptor above stdio so the probe never holds a
         * copy of the proxy's listen/control/relay sockets.  Prefer close_range()
         * (one syscall for the whole range) over a loop to RLIMIT_NOFILE, which on
         * this box is ~500k and would cost half a million syscalls per fork. */
#if defined(SYS_close_range)
        if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
#endif
        {
            for (int fd = 3; fd < 4096; fd++) {
                close(fd);
            }
        }
        execl("/bin/sh", "sh", "-c", cmd, (char *) NULL);
        _exit(127);
    }
    int waited = 0, status = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            break;
        }
        if (r < 0) {
            return -1;
        }
        if (timeout_ms > 0 && waited >= timeout_ms) {
            kill(-pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;                  /* timeout: inconclusive */
        }
        struct timespec ts = { 0, 10 * 1000 * 1000 };   /* 10 ms poll */
        nanosleep(&ts, NULL);
        waited += 10;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}
