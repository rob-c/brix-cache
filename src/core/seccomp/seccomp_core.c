/* ---- File: src/core/seccomp/seccomp_core.c — ngx-free seccomp filter core ----
 *
 * The nginx-free build+load half of the D-3 worker syscall filter (see
 * seccomp_core.h for the contract, seccomp.h for the WHAT/WHY/HOW). No ngx_*
 * dependency, so tests/c/test_seccomp.c links this file directly and drives the
 * SHIPPED allowlist under fork().
 *
 * Filter shape:
 *   - AUDIT   : default action SCMP_ACT_LOG (allow + kernel-audit-log). The
 *               allowlist is added as SCMP_ACT_ALLOW so the steady-state set is
 *               silent and only *unexpected* syscalls surface in the audit log —
 *               exactly what an operator needs to converge the set before
 *               flipping to enforce. Nothing is denied in audit.
 *   - ENFORCE : default action SCMP_ACT_ERRNO(EPERM) (fail-safe: a syscall we
 *               forgot degrades one call, it does not crash the worker). The
 *               allowlist runs; the named-dangerous set is SCMP_ACT_KILL_PROCESS
 *               so an exploit that reaches execve/ptrace/process_vm_* takes the
 *               worker down loudly rather than succeeding.
 *
 * Syscalls are named as STRINGS and resolved at runtime with
 * seccomp_syscall_resolve_name(): a name this arch/kernel/libseccomp does not
 * know resolves to __NR_SCMP_ERROR and is skipped, so one table serves every
 * arch and does not fail to compile against an older libseccomp that predates a
 * newer syscall (e.g. openat2, epoll_pwait2).
 */

#include "core/seccomp/seccomp_core.h"

#include <stddef.h>

#if defined(BRIX_HAVE_SECCOMP)

#include <seccomp.h>
#include <errno.h>

/*
 * The named-dangerous set: under ENFORCE these are killed (not merely EPERM'd)
 * so a worker-code hijack cannot spawn a shell (execve/execveat), attach to or
 * trace another process (ptrace), or read/write the broker's address space
 * (process_vm_readv/writev) — the CAP_SETUID-broker residual that motivates D-3.
 */
static const char *const brix_seccomp_deny[] = {
    "execve", "execveat",
    "ptrace",
    "process_vm_readv", "process_vm_writev",
};

/*
 * The steady-state allowlist. Grouped by purpose; a name this build/arch does
 * not define is skipped at resolve time, so this one table serves every arch
 * libseccomp supports and tolerates 32/64-bit-only variants transparently.
 */
static const char *const brix_seccomp_allow[] = {
    /* ---- process / thread / scheduler ---- */
    "clone", "clone3", "set_tid_address",
    "gettid", "getpid", "getppid",
    "tgkill", "tkill", "kill",
    "exit", "exit_group", "rseq",
    "sched_yield", "sched_getaffinity", "sched_setaffinity",
    "sched_getparam", "sched_getscheduler", "sched_setscheduler",
    "sched_get_priority_max", "sched_get_priority_min",
    "getcpu", "wait4", "waitid",
    "prctl", "arch_prctl", "membarrier", "restart_syscall",

    /* ---- memory ---- */
    "brk", "mmap", "mmap2", "munmap", "mremap", "mprotect", "madvise",
    "mlock", "munlock", "mlockall", "munlockall", "mincore", "memfd_create",

    /* ---- signals ---- */
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend",
    "rt_sigpending", "rt_sigtimedwait", "sigaltstack",
    "signalfd", "signalfd4",

    /* ---- futex / robust lists (thread pool + glibc) ---- */
    "futex", "futex_time64", "set_robust_list", "get_robust_list",

    /* ---- time / entropy ---- */
    "clock_gettime", "clock_gettime64", "clock_getres", "clock_nanosleep",
    "nanosleep", "gettimeofday", "times", "getrandom",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",

    /* ---- resource / info ---- */
    "getrlimit", "setrlimit", "prlimit64", "getrusage", "sysinfo", "uname",

    /* ---- file I/O: data ---- */
    "read", "write", "pread64", "pwrite64",
    "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
    "lseek", "_llseek",
    "sendfile", "sendfile64", "splice", "tee", "copy_file_range",

    /* ---- file I/O: namespace / metadata ---- */
    "open", "openat", "openat2", "close", "close_range",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "statfs", "fstatfs", "statfs64", "fstatfs64",
    "getdents", "getdents64",
    "access", "faccessat", "faccessat2",
    "readlink", "readlinkat",
    "getcwd", "chdir", "fchdir", "umask",
    "fsync", "fdatasync", "sync_file_range", "syncfs",
    "ftruncate", "truncate", "fallocate", "fadvise64",
    "unlink", "unlinkat",
    "rename", "renameat", "renameat2",
    "mkdir", "mkdirat", "rmdir",
    "link", "linkat", "symlink", "symlinkat",
    "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "lchown", "fchownat",
    "utimensat", "futimesat", "utimes",
    "fcntl", "fcntl64", "ioctl", "flock",
    "dup", "dup2", "dup3",
    "pipe", "pipe2", "eventfd", "eventfd2",
    "inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch",

    /* ---- sockets ---- */
    "socket", "socketpair", "connect", "accept", "accept4",
    "bind", "listen", "shutdown",
    "getsockname", "getpeername", "getsockopt", "setsockopt",
    "recvfrom", "sendto", "recvmsg", "sendmsg", "recvmmsg", "sendmmsg",

    /* ---- event loop ---- */
    "epoll_create", "epoll_create1", "epoll_ctl",
    "epoll_wait", "epoll_pwait", "epoll_pwait2",
    "poll", "ppoll", "select", "pselect6",

    /* ---- credentials (identity impersonation: setuid/setgid worker) ---- */
    "setuid", "setgid", "setgroups",
    "setresuid", "setresgid", "setreuid", "setregid",
    "setfsuid", "setfsgid",
    "getuid", "geteuid", "getgid", "getegid",
    "getresuid", "getresgid", "getgroups",
    "capget", "capset",

    /* ---- optional io_uring disk-I/O backend (brix_io_uring on) ---- */
    "io_uring_setup", "io_uring_enter", "io_uring_register",
};

#define BRIX_SECCOMP_N(a) (sizeof(a) / sizeof((a)[0]))

/* Resolve `name` and add one rule, tolerating a name this arch/build does not
 * define (skipped) and a duplicate/permission quirk (-EDOM/-EACCES) without
 * aborting the whole filter. Any other failure is fatal — a filter we cannot
 * construct as intended must not be loaded (fail closed). Returns 0 to continue
 * (and *added incremented when a rule went in), -1 to abort. */
static int
brix_seccomp_core_add(scmp_filter_ctx ctx, uint32_t action, const char *name,
    brix_seccomp_err_fn err_fn, void *ud, unsigned *added)
{
    int sysno;
    int rc;

    sysno = seccomp_syscall_resolve_name(name);
    if (sysno == __NR_SCMP_ERROR) {
        /* Unknown on this arch/kernel/libseccomp — cannot be issued anyway. */
        return 0;
    }

    rc = seccomp_rule_add(ctx, action, sysno, 0);
    if (rc == 0) {
        if (added != NULL) {
            (*added)++;
        }
        return 0;
    }
    if (rc == -EDOM || rc == -EACCES) {
        return 0;
    }

    if (err_fn != NULL) {
        err_fn(ud, name, rc);
    }
    return -1;
}

int
brix_seccomp_core_apply(unsigned mode, brix_seccomp_err_fn err_fn, void *ud,
    unsigned *out_allow, unsigned *out_deny)
{
    scmp_filter_ctx  ctx;
    uint32_t         def_action;
    unsigned         i;
    unsigned         n_allow = 0;
    unsigned         n_deny = 0;
    int              rc;

    if (out_allow != NULL) {
        *out_allow = 0;
    }
    if (out_deny != NULL) {
        *out_deny = 0;
    }

    if (mode == BRIX_SECCOMP_CORE_OFF) {
        return BRIX_SECCOMP_CORE_OK;
    }

    /* AUDIT observes only (log-only default, no denies); ENFORCE fails unknown
     * syscalls with EPERM and hard-kills the named-dangerous set. */
    def_action = (mode == BRIX_SECCOMP_CORE_ENFORCE)
                 ? SCMP_ACT_ERRNO(EPERM)
                 : SCMP_ACT_LOG;

    ctx = seccomp_init(def_action);
    if (ctx == NULL) {
        if (err_fn != NULL) {
            err_fn(ud, NULL, 0);
        }
        return BRIX_SECCOMP_CORE_ERR;
    }

    /* Deny the dangerous set only under enforce; under audit the log-only
     * default already surfaces them without killing the worker. */
    if (mode == BRIX_SECCOMP_CORE_ENFORCE) {
        for (i = 0; i < BRIX_SECCOMP_N(brix_seccomp_deny); i++) {
            if (brix_seccomp_core_add(ctx, SCMP_ACT_KILL_PROCESS,
                                      brix_seccomp_deny[i], err_fn, ud,
                                      &n_deny) != 0)
            {
                seccomp_release(ctx);
                return BRIX_SECCOMP_CORE_ERR;
            }
        }
    }

    for (i = 0; i < BRIX_SECCOMP_N(brix_seccomp_allow); i++) {
        if (brix_seccomp_core_add(ctx, SCMP_ACT_ALLOW, brix_seccomp_allow[i],
                                  err_fn, ud, &n_allow) != 0)
        {
            seccomp_release(ctx);
            return BRIX_SECCOMP_CORE_ERR;
        }
    }

    /* seccomp_load sets PR_SET_NO_NEW_PRIVS itself (SCMP_FLTATR_CTL_NNP defaults
     * on) and installs the BPF program on the calling thread group. */
    rc = seccomp_load(ctx);
    seccomp_release(ctx);

    if (rc != 0) {
        if (err_fn != NULL) {
            err_fn(ud, NULL, rc);
        }
        return BRIX_SECCOMP_CORE_ERR;
    }

    if (out_allow != NULL) {
        *out_allow = n_allow;
    }
    if (out_deny != NULL) {
        *out_deny = n_deny;
    }
    return BRIX_SECCOMP_CORE_OK;
}

#else  /* !BRIX_HAVE_SECCOMP — libseccomp absent at build time */

int
brix_seccomp_core_apply(unsigned mode, brix_seccomp_err_fn err_fn, void *ud,
    unsigned *out_allow, unsigned *out_deny)
{
    (void) err_fn;
    (void) ud;

    if (out_allow != NULL) {
        *out_allow = 0;
    }
    if (out_deny != NULL) {
        *out_deny = 0;
    }

    if (mode == BRIX_SECCOMP_CORE_OFF) {
        return BRIX_SECCOMP_CORE_OK;
    }
    return BRIX_SECCOMP_CORE_UNAVAIL;
}

#endif /* BRIX_HAVE_SECCOMP */
