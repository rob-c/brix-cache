/* ---- File: src/core/seccomp/seccomp_core.h — ngx-free seccomp filter core ----
 *
 * WHAT: The pure, nginx-free half of the D-3 worker syscall filter. Owns the
 *       allowlist / named-dangerous tables and the libseccomp build+load, with
 *       zero dependency on ngx_* types so it links into a standalone C unit test
 *       (tests/c/test_seccomp.c) that forks children and proves execve/ptrace are
 *       killed under enforce, an allowlisted syscall survives, and audit never
 *       kills. seccomp.c is the thin ngx wrapper that logs via the error sink.
 *
 * WHY:  A duplicated mini-filter in the test would not exercise the shipped
 *       allowlist, so the very table that ships must be the table under test —
 *       hence the split (same ngx-free-core convention as wverify / opaque).
 *
 * HOW:  brix_seccomp_core_apply() builds and loads the filter on the CALLING
 *       thread group, matching the shape documented in seccomp.h. Modes mirror
 *       BRIX_SECCOMP_* (0/1/2). Failures are reported through an error sink
 *       callback so the core need not know about ngx logging.
 */
#ifndef BRIX_CORE_SECCOMP_CORE_H
#define BRIX_CORE_SECCOMP_CORE_H

/* Modes — value-identical to BRIX_SECCOMP_OFF/AUDIT/ENFORCE in tunables.h. */
#define BRIX_SECCOMP_CORE_OFF      0
#define BRIX_SECCOMP_CORE_AUDIT    1
#define BRIX_SECCOMP_CORE_ENFORCE  2

/* Return codes for brix_seccomp_core_apply(). */
#define BRIX_SECCOMP_CORE_OK          0   /* filter in force (or mode==off) */
#define BRIX_SECCOMP_CORE_ERR        -1   /* build/load failed (sink called) */
#define BRIX_SECCOMP_CORE_UNAVAIL    -2   /* built without libseccomp */

/*
 * Error sink: invoked with the failing syscall name (NULL for whole-filter
 * failures such as seccomp_init/seccomp_load) and the negative errno-style rc.
 * May be NULL.
 */
typedef void (*brix_seccomp_err_fn)(void *ud, const char *name, int rc);

/*
 * Build and load the worker filter for `mode` on the calling thread group.
 * On success returns BRIX_SECCOMP_CORE_OK and, when non-NULL, sets *out_allow
 * and *out_deny to the number of allow/deny rules actually installed. Returns
 * BRIX_SECCOMP_CORE_ERR (sink invoked) if the filter could not be constructed
 * or loaded, or BRIX_SECCOMP_CORE_UNAVAIL if this binary was built without
 * libseccomp and a non-off mode was requested. mode==off is always OK.
 */
/*
 * `allow_exec` (0/1): when non-zero, execve/execveat are allowlisted (run) instead
 * of killed under ENFORCE — for sites that legitimately fork+exec helpers (OIDC
 * token fetch, native-TPC token-exchange, the kXR_prepare hook). The HARD kills
 * (ptrace/process_vm_*) are unaffected.
 */
int brix_seccomp_core_apply(unsigned mode, unsigned allow_exec,
    brix_seccomp_err_fn err_fn, void *ud, unsigned *out_allow, unsigned *out_deny);

/*
 * Broker filter — a DEFAULT-ALLOW filter that hard-KILLs a small,
 * never-legitimate set (execve/execveat, ptrace, process_vm_readv/writev,
 * mount/umount2/unshare/setns/pivot_root/chroot, module load/unload, kexec,
 * bpf, keyctl/add_key/request_key, mknod/mknodat, reboot). Installed on the
 * root-equivalent impersonation broker AFTER its cap-drop. Default-allow (not an
 * allowlist) so the broker's own openat2/setfsuid/xattr/rename path cannot be
 * broken by a forgotten syscall, while a code-exec exploit still cannot spawn a
 * shell, ptrace the worker, load a module, or read another process's memory.
 * Returns BRIX_SECCOMP_CORE_OK/ERR/UNAVAIL; *out_deny gets the killed-rule count.
 */
int brix_seccomp_broker_apply(brix_seccomp_err_fn err_fn, void *ud,
    unsigned *out_deny);

#endif /* BRIX_CORE_SECCOMP_CORE_H */
