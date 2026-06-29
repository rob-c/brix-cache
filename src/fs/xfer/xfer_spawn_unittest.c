/*
 * xfer_spawn_unittest.c — standalone unit test for the reparented command runner.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/xfer_spawn_ut \
 *       src/fs/xfer/xfer_spawn.c src/fs/xfer/xfer_spawn_unittest.c && /tmp/xfer_spawn_ut
 *
 * Exit 0 = all checks pass. Verifies exit-code propagation (0/N), exec failure
 * (127), kill-by-signal (128), env passthrough, and the reparent invariant
 * (no child is left for THIS process to reap — waitpid must report ECHILD).
 */

#include "xfer_spawn.h"

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void
check(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", what, got, want);
        fails++;
    } else {
        printf("ok %s (rc=%d)\n", what, got);
    }
}

int
main(void)
{
    {
        const char *argv[] = { "/bin/sh", "-c", "exit 0", NULL };
        check("exit 0", xrootd_xfer_run_reparented(argv, NULL), 0);
    }
    {
        const char *argv[] = { "/bin/sh", "-c", "exit 7", NULL };
        check("exit 7", xrootd_xfer_run_reparented(argv, NULL), 7);
    }
    {
        const char *argv[] = { "/bin/sh", "-c", "exit 42", NULL };
        check("exit 42", xrootd_xfer_run_reparented(argv, NULL), 42);
    }
    {
        const char *argv[] = { "/no/such/binary/xyzzy", NULL };
        check("exec failure -> 127", xrootd_xfer_run_reparented(argv, NULL), 127);
    }
    {
        const char *argv[] = { "/bin/sh", "-c", "kill -TERM $$", NULL };
        check("killed -> 128", xrootd_xfer_run_reparented(argv, NULL), 128);
    }
    {
        char *envp[] = { (char *) "XFER_UT=yes", NULL };
        const char *argv[] = { "/bin/sh", "-c",
                               "test \"$XFER_UT\" = yes", NULL };
        check("env passthrough", xrootd_xfer_run_reparented(argv, envp), 0);
    }
    {
        /* bare name → PATH search (execvpe), matching the prior posix_spawnp. */
        const char *argv[] = { "sh", "-c", "exit 0", NULL };
        check("PATH search (bare name)",
              xrootd_xfer_run_reparented(argv, NULL), 0);
    }

    /* Reparent invariant: after a run, this process must have NO reapable child
     * (the agent + command reparented to init). waitpid → -1/ECHILD. */
    {
        const char *argv[] = { "/bin/sh", "-c", "exit 0", NULL };
        (void) xrootd_xfer_run_reparented(argv, NULL);
        errno = 0;
        pid_t w = waitpid(-1, NULL, WNOHANG);
        if (!(w == -1 && errno == ECHILD)) {
            printf("FAIL reparent invariant: waitpid=%d errno=%d "
                   "(a child was left for us to reap)\n", (int) w, errno);
            fails++;
        } else {
            printf("ok reparent invariant (no reapable child)\n");
        }
    }

    printf("%d failures\n", fails);
    return fails ? 1 : 0;
}
