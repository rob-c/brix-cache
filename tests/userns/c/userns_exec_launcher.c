/*
 * userns_exec_launcher.c — generic unprivileged-user-namespace launcher.
 *
 * WHAT: Enters a fresh user+mount namespace with a subuid RANGE map (so the child
 *   is in-ns root over a private band of uids — exactly what is needed to run a
 *   real root-requiring service, e.g. nginx with `xrootd_impersonation map`,
 *   without any real privilege), bind-mounts caller-supplied fake /etc/passwd and
 *   /etc/group over the real ones (so getpwnam/getgrnam resolve the test
 *   identities), then exec()s an arbitrary command INSIDE that namespace.
 *
 * WHY: The phase-40 permissions model must be exercised at the FULL-STACK level —
 *   the real nginx binary, real master/worker/broker processes, real lifecycle
 *   spawn, real auth→identity→dispatch→broker chain — not just the broker in
 *   isolation.  That requires "root" (to spawn the privileged broker and
 *   setfsuid) which an unprivileged user namespace provides for free.  This
 *   launcher is the thin, reusable entry into that namespace; the orchestrator it
 *   exec()s drives the actual red-team scenario.
 *
 * HOW: parent fork()s a child that unshare(CLONE_NEWUSER|CLONE_NEWNS)es and
 *   pauses; the parent runs newuidmap/newgidmap against it (inside-0 -> caller,
 *   inside-1.. -> the /etc/subuid range) then releases it.  The child becomes
 *   in-ns root, makes mounts private, bind-mounts the fake passwd/group, and
 *   execs the command.  Missing userns/newuidmap -> exit SKIP_CODE.
 *
 * Usage:  userns_exec_launcher <fake_passwd> <fake_group> <cmd> [args...]
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>

#define SKIP_CODE 42

/* Run argv[0] to completion; returns its exit status or -1. */
static int
run_cmd(char *const argv[])
{
    pid_t pid = fork();
    int   st;
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) < 0) {
        return -1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* inside-0 -> caller uid; inside-1.. -> the subuid range (100000 + 65536). */
static int
apply_maps(pid_t child)
{
    char pidbuf[32], ru[32], rg[32];

    snprintf(pidbuf, sizeof(pidbuf), "%d", (int) child);
    snprintf(ru, sizeof(ru), "%u", (unsigned) getuid());
    snprintf(rg, sizeof(rg), "%u", (unsigned) getgid());
    {
        char *a[] = { "newuidmap", pidbuf, "0", ru, "1",
                      "1", "100000", "65536", NULL };
        if (run_cmd(a) != 0) {
            return -1;
        }
    }
    {
        char *a[] = { "newgidmap", pidbuf, "0", rg, "1",
                      "1", "100000", "65536", NULL };
        if (run_cmd(a) != 0) {
            return -1;
        }
    }
    return 0;
}

int
main(int argc, char **argv)
{
    int   ready[2], go[2];
    pid_t child;
    char  b;
    int   st;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <passwd> <group> <cmd> [args...]\n", argv[0]);
        return 2;
    }
    if (pipe(ready) != 0 || pipe(go) != 0) {
        printf("SKIP: pipe failed\n");
        return 0;
    }

    child = fork();
    if (child < 0) {
        printf("SKIP: fork failed\n");
        return 0;
    }

    if (child == 0) {
        close(ready[0]);
        close(go[1]);
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
            _exit(SKIP_CODE);            /* unprivileged userns unavailable */
        }
        if (write(ready[1], "R", 1) != 1 || read(go[0], &b, 1) != 1) {
            _exit(SKIP_CODE);
        }
        /* Become a clean in-ns root (real uid already maps to inside-0). */
        if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
            fprintf(stderr, "SKIP: assume in-ns root failed: %s\n", strerror(errno));
            _exit(SKIP_CODE);
        }
        { gid_t z = 0; setgroups(1, &z); }

        if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
            fprintf(stderr, "SKIP: MS_PRIVATE remount failed: %s\n", strerror(errno));
            _exit(SKIP_CODE);
        }
        if (mount(argv[1], "/etc/passwd", NULL, MS_BIND, NULL) != 0
            || mount(argv[2], "/etc/group", NULL, MS_BIND, NULL) != 0)
        {
            fprintf(stderr, "SKIP: bind-mount passwd/group failed: %s\n",
                    strerror(errno));
            _exit(SKIP_CODE);
        }
        execvp(argv[3], &argv[3]);
        fprintf(stderr, "FAIL: exec %s: %s\n", argv[3], strerror(errno));
        _exit(127);
    }

    /* Parent: wait for unshare, install id maps, release. */
    close(ready[1]);
    close(go[0]);
    if (read(ready[0], &b, 1) != 1) {
        waitpid(child, &st, 0);
        printf("SKIP: user namespace unavailable on this host\n");
        return 0;
    }
    if (apply_maps(child) != 0) {
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
        printf("SKIP: newuidmap/newgidmap unavailable or /etc/subuid not set\n");
        return 0;
    }
    if (write(go[1], "G", 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
        printf("SKIP: could not release child\n");
        return 0;
    }
    if (waitpid(child, &st, 0) < 0 || !WIFEXITED(st)) {
        printf("FAIL: child did not exit cleanly\n");
        return 1;
    }
    if (WEXITSTATUS(st) == SKIP_CODE) {
        printf("SKIP: in-namespace prerequisites unmet (see stderr)\n");
        return 0;
    }
    return WEXITSTATUS(st);
}
