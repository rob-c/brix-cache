/*
 * test_seccomp.c — standalone unit test for the D-3 worker syscall filter core
 * (src/core/seccomp/seccomp_core.c). Drives the SHIPPED allowlist/deny tables,
 * not a stand-in, by loading the real filter in a forked child and observing how
 * the child dies (or does not):
 *
 *   success  — under ENFORCE an allowlisted syscall (getpid) runs and the child
 *              exits cleanly; the filter counts a non-empty allow/deny set;
 *   security — under ENFORCE a named-dangerous syscall (execve, ptrace) is
 *              SCMP_ACT_KILL_PROCESS → the child dies by SIGSYS;
 *   error    — under ENFORCE a syscall that is neither allowlisted nor in the
 *              dangerous set (chroot) is EPERM'd, NOT killed (fail-safe default),
 *              and under AUDIT nothing is killed at all (log-only).
 *
 * seccomp is one-way per thread group, so every case runs in its own fork().
 * ngx-free: links libc + libseccomp only, mirroring the core it exercises.
 */
#include "core/seccomp/seccomp_core.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

/* Child exit codes (only meaningful when the child was NOT signalled). */
#define CX_SURVIVED   0   /* body returned normally */
#define CX_EPERM      42  /* body observed EPERM on the probed syscall */
#define CX_UNEXPECTED 43  /* body observed something other than EPERM */
#define CX_APPLYFAIL  44  /* brix_seccomp_core_apply() did not return OK */

/* Outcome of a forked probe. */
struct probe {
    int signalled;   /* 1 if killed by a signal */
    int sig;         /* the terminating signal (valid iff signalled) */
    int code;        /* the exit code (valid iff !signalled) */
};

/*
 * Fork a child, apply the filter for `mode`, then run `body`. `body` returns a
 * child exit code; if the probed syscall killed the process, body never returns.
 * The parent reports how the child terminated.
 */
static struct probe
run_probe(unsigned mode, unsigned allow_exec, int (*body)(void))
{
    struct probe out;
    pid_t pid;
    int status;

    memset(&out, 0, sizeof(out));

    pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        /* Child: load the real filter, then exercise it. */
        if (brix_seccomp_core_apply(mode, allow_exec, NULL, NULL, NULL, NULL)
            != BRIX_SECCOMP_CORE_OK)
        {
            _exit(CX_APPLYFAIL);
        }
        _exit(body());
    }

    assert(waitpid(pid, &status, 0) == pid);
    if (WIFSIGNALED(status)) {
        out.signalled = 1;
        out.sig = WTERMSIG(status);
    } else {
        assert(WIFEXITED(status));
        out.code = WEXITSTATUS(status);
    }
    return out;
}

/* Bodies. All I/O uses allowlisted write/_exit so the report itself survives. */

static int
body_getpid(void)
{
    /* Allowlisted: must run to completion and let the child exit cleanly. */
    return (getpid() > 0) ? CX_SURVIVED : CX_UNEXPECTED;
}

static int
body_execve(void)
{
    char *const argv[] = { (char *) "/bin/true", NULL };
    /* Under enforce this call never returns (killed). Under audit it execs and
     * /bin/true exits 0, so the child exits 0 either way it is *allowed*. */
    execve("/bin/true", argv, NULL);
    execve("/usr/bin/true", argv, NULL);
    return CX_SURVIVED;   /* execve permitted but both paths missing */
}

static int
body_ptrace(void)
{
    /* Under enforce this never returns (killed). */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    return CX_SURVIVED;
}

static int
body_chroot(void)
{
    /* Neither allowlisted nor dangerous: enforce → EPERM (fail-safe), NOT kill.
     * Non-root would get EPERM from chroot anyway, but under enforce the EPERM
     * is delivered by seccomp before the kernel ever sees the call. */
    if (chroot("/") == 0) {
        return CX_UNEXPECTED;   /* somehow succeeded */
    }
    return (errno == EPERM) ? CX_EPERM : CX_UNEXPECTED;
}

/* success: enforce permits an allowlisted syscall; child exits cleanly. */
static void
test_enforce_allows_getpid(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 0, body_getpid);
    assert(!p.signalled);
    assert(p.code == CX_SURVIVED);
    printf("ok enforce_allows_getpid\n");
}

/* security: enforce kills execve (SCMP_ACT_KILL_PROCESS → SIGSYS). */
static void
test_enforce_kills_execve(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 0, body_execve);
    assert(p.signalled);
    assert(p.sig == SIGSYS);
    printf("ok enforce_kills_execve\n");
}

/* security: enforce kills ptrace the same way. */
static void
test_enforce_kills_ptrace(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 0, body_ptrace);
    assert(p.signalled);
    assert(p.sig == SIGSYS);
    printf("ok enforce_kills_ptrace\n");
}

/* allow_exec: enforce + allow_exec lets execve RUN (not killed) — for sites that
 * fork+exec OIDC/TPC/prepare helpers. */
static void
test_enforce_allow_exec_permits_execve(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 1, body_execve);
    assert(!p.signalled);   /* execve was allowlisted, not SIGSYS-killed */
    printf("ok enforce_allow_exec_permits_execve\n");
}

/* allow_exec must NOT relax the HARD set: ptrace is still killed even with
 * allow_exec=1 (the broker stays protected from a worker-code hijack). */
static void
test_allow_exec_still_kills_ptrace(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 1, body_ptrace);
    assert(p.signalled);
    assert(p.sig == SIGSYS);
    printf("ok allow_exec_still_kills_ptrace\n");
}

/* error/fail-safe: a non-allowlisted, non-dangerous syscall is EPERM'd, not
 * killed — a syscall the allowlist forgot degrades one call, never the worker. */
static void
test_enforce_eperms_chroot(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_ENFORCE, 0, body_chroot);
    assert(!p.signalled);
    assert(p.code == CX_EPERM);
    printf("ok enforce_eperms_chroot\n");
}

/* audit: log-only — execve is permitted (not killed); child is never signalled. */
static void
test_audit_never_kills(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_AUDIT, 0, body_execve);
    assert(!p.signalled);
    printf("ok audit_never_kills\n");
}

/* off: no filter installed; every syscall runs; child exits cleanly. */
static void
test_off_is_noop(void)
{
    struct probe p = run_probe(BRIX_SECCOMP_CORE_OFF, 0, body_getpid);
    assert(!p.signalled);
    assert(p.code == CX_SURVIVED);
    printf("ok off_is_noop\n");
}

/* counts: enforce installs a non-empty allow set and the full dangerous set. */
static void
test_counts_reported(void)
{
    unsigned n_allow = 0;
    unsigned n_deny = 0;
    pid_t pid;
    int status;

    /* apply() is one-way, so probe the counts in a child too. Encode "both
     * non-zero and deny>=5" as exit 0. */
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int rc = brix_seccomp_core_apply(BRIX_SECCOMP_CORE_ENFORCE, 0, NULL, NULL,
                                         &n_allow, &n_deny);
        if (rc != BRIX_SECCOMP_CORE_OK) {
            _exit(1);
        }
        _exit((n_allow > 100u && n_deny == 5u) ? 0 : 2);
    }
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    printf("ok counts_reported\n");
}

int
main(void)
{
    test_off_is_noop();
    test_enforce_allows_getpid();
    test_enforce_kills_execve();
    test_enforce_kills_ptrace();
    test_enforce_allow_exec_permits_execve();
    test_allow_exec_still_kills_ptrace();
    test_enforce_eperms_chroot();
    test_audit_never_kills();
    test_counts_reported();
    printf("PASS test_seccomp\n");
    return 0;
}
