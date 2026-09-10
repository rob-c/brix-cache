/*
 * subprocess_unittest.c — standalone unit test for brix_subprocess_capture().
 *
 *   gcc -Wall -Wextra -Werror -pthread -I src -o /tmp/subprocess_ut \
 *       src/core/compat/subprocess.c src/core/compat/subprocess_unittest.c \
 *       && /tmp/subprocess_ut
 *
 * Exit 0 = all checks pass. Verifies stdout capture + exit-code propagation
 * (0/N), exec failure (127), kill-by-signal (-1), NUL-termination + truncation
 * without a hang, the argument guards, and the two properties the rhB42 fast-tier
 * halt was about (history-testing-and-incidents §24.15): under a HOSTILE REAPER —
 * a second thread with SIGCHLD unblocked whose handler waitpid(-1, WNOHANG)s the
 * way nginx's ngx_process_get_status() does, plus a spinning waitpid(-1) loop —
 * the helper still reports the command's real exit code every time, and it leaves
 * no child for THIS process to reap afterwards (waitpid → ECHILD).
 */
#include "subprocess.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REAPER_ROUNDS  300

static int                   fails;
static volatile sig_atomic_t reaper_stop;
static volatile sig_atomic_t reaper_stolen;

static void
check(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", what, got, want);
        fails++;
    } else {
        printf("ok %s (%d)\n", what, got);
    }
}

static void
check_str(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("FAIL %s: got \"%s\" want \"%s\"\n", what, got, want);
        fails++;
    } else {
        printf("ok %s (\"%s\")\n", what, got);
    }
}

/* Run `cmd` under /bin/sh -c; returns the helper's rc, publishes ec/out/len. */
static int
run_sh(const char *cmd, char *out, size_t outsz, size_t *len, int *ec)
{
    char *const argv[] = { (char *) "/bin/sh", (char *) "-c", (char *) cmd, NULL };

    return brix_subprocess_capture(argv, out, outsz, len, ec);
}

/* nginx's shape: ngx_signal_handler → ngx_process_get_status → waitpid(-1, WNOHANG). */
static void
reaper_handler(int signo)
{
    int st;

    (void) signo;
    while (waitpid(-1, &st, WNOHANG) > 0) {
        reaper_stolen++;
    }
}

/* The worker's main thread: SIGCHLD unblocked, and also polling — the worst case. */
static void *
reaper_thread(void *arg)
{
    sigset_t        unblock;
    struct timespec nap = { 0, 50000 };
    int             st;

    (void) arg;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGCHLD);
    pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);
    while (!reaper_stop) {
        while (waitpid(-1, &st, WNOHANG) > 0) {
            reaper_stolen++;
        }
        nanosleep(&nap, NULL);
    }
    return NULL;
}

static void
check_basic_contract(void)
{
    char   out[64];
    size_t len = 99;
    int    ec = 99;

    check("exit 7 + stdout: rc", run_sh("printf hello; exit 7", out, sizeof(out), &len, &ec), 0);
    check("exit 7 + stdout: ec", ec, 7);
    check("exit 7 + stdout: len", (int) len, 5);
    check_str("exit 7 + stdout: out", out, "hello");

    check("exit 0: rc", run_sh("echo ok", out, sizeof(out), &len, &ec), 0);
    check("exit 0: ec", ec, 0);
    check_str("exit 0: out (newline kept for brix_rstrip)", out, "ok\n");
    check("brix_rstrip", (int) brix_rstrip(out), 2);

    check("killed -> rc -1", run_sh("kill -TERM $$", out, sizeof(out), &len, &ec), -1);
    check("killed -> ec untouched (-1)", ec, -1);

    {
        char *const argv[] = { (char *) "/no/such/binary/xyzzy", NULL };
        check("exec failure: rc", brix_subprocess_capture(argv, out, sizeof(out), &len, &ec), 0);
        check("exec failure: ec 127", ec, 127);
        check("exec failure: len 0", (int) len, 0);
    }
    {
        char *const argv[] = { (char *) "sh", (char *) "-c", (char *) "exit 3", NULL };
        check("PATH search (bare name): rc", brix_subprocess_capture(argv, out, sizeof(out), &len, &ec), 0);
        check("PATH search (bare name): ec", ec, 3);
    }
}

static void
check_truncation_and_guards(void)
{
    char   out[16];
    size_t len = 99;
    int    ec = 99;

    /* 200 KiB of output into a 16-byte buffer: the surplus must be discarded so
     * the command finishes (a writer wedged on a full pipe would hang the reap). */
    check("truncation: rc", run_sh("yes | head -c 204800; exit 5", out, sizeof(out), &len, &ec), 0);
    check("truncation: ec after overflow", ec, 5);
    check("truncation: len == outsz-1", (int) len, 15);
    check("truncation: NUL-terminated", out[15], 0);

    check("guard: NULL argv", brix_subprocess_capture(NULL, out, sizeof(out), &len, &ec), -1);
    check("guard: outsz 0", run_sh("true", out, 0, &len, &ec), -1);
    check("guard: NULL out", run_sh("true", NULL, 8, &len, &ec), -1);
    {
        char *const argv[] = { NULL };
        check("guard: empty argv", brix_subprocess_capture(argv, out, sizeof(out), NULL, NULL), -1);
    }
}

static void
check_hostile_reaper(void)
{
    struct sigaction sa;
    pthread_t        th;
    sigset_t         block;
    char             out[16];
    int              ec, wrong = 0, i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = reaper_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);

    /* This thread plays the nginx thread-pool worker: it never handles SIGCHLD.
     * The reaper thread plays the worker's main thread, which does. */
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &block, NULL);
    pthread_create(&th, NULL, reaper_thread, NULL);

    for (i = 0; i < REAPER_ROUNDS; i++) {
        ec = -2;
        if (run_sh("exit 7", out, sizeof(out), NULL, &ec) != 0 || ec != 7) {
            wrong++;
        }
    }
    reaper_stop = 1;
    pthread_join(th, NULL);
    signal(SIGCHLD, SIG_DFL);
    pthread_sigmask(SIG_UNBLOCK, &block, NULL);

    if (wrong != 0) {
        printf("FAIL hostile reaper: %d of %d runs reported the wrong status "
               "(reaper stole %d children)\n", wrong, REAPER_ROUNDS, (int) reaper_stolen);
        fails++;
    } else {
        printf("ok hostile reaper (%d/%d exit 7; reaper collected %d)\n",
               REAPER_ROUNDS, REAPER_ROUNDS, (int) reaper_stolen);
    }

    /* Reparent invariant: nothing is left for THIS process to reap. */
    errno = 0;
    {
        pid_t w = waitpid(-1, NULL, WNOHANG);
        if (!(w == -1 && errno == ECHILD)) {
            printf("FAIL reparent invariant: waitpid=%d errno=%d "
                   "(a child was left for us to reap)\n", (int) w, errno);
            fails++;
        } else {
            printf("ok reparent invariant (no reapable child)\n");
        }
    }
}

int
main(void)
{
    check_basic_contract();
    check_truncation_and_guards();
    check_hostile_reaper();
    printf("%d failures\n", fails);
    return fails ? 1 : 0;
}
