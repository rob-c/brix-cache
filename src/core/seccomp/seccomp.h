/* ---- File: src/core/seccomp/seccomp.h — per-worker seccomp-BPF syscall filter ----
 *
 * WHAT: Declares brix_seccomp_install(), the single entry point that installs a
 *       libseccomp allowlist filter on the calling worker process. Called once
 *       per worker from the tail of ngx_stream_brix_init_process (process.c),
 *       after every setup syscall has run.
 *
 * WHY:  Defence-in-depth (hyper-hardening-plan §D-3). The privilege model is
 *       already strong — unprivileged operation, PR_SET_NO_NEW_PRIVS, full
 *       capability drop — but the impersonation broker necessarily retains
 *       CAP_SETUID, so a worker-code exploit is root-equivalent if the broker is
 *       reached. A syscall allowlist is the most direct mitigation for that
 *       residual: it removes execve/ptrace/process_vm_* from the worker's reach
 *       so a hijacked worker cannot spawn a shell, attach to another process, or
 *       peer into the broker's address space.
 *
 * HOW:  Tri-state, operator opt-in (`brix_seccomp off|audit|enforce`, default
 *       off). AUDIT loads a log-only filter to converge the allowlist without
 *       risk; ENFORCE kills the named-dangerous set and EPERMs any other
 *       non-allowlisted syscall. When the binary was built without libseccomp
 *       (-DBRIX_HAVE_SECCOMP unset) the implementation is a stub that fails
 *       closed for audit/enforce and is a no-op for off — the operator never
 *       silently runs unfiltered while believing otherwise.
 */
#ifndef BRIX_CORE_SECCOMP_H
#define BRIX_CORE_SECCOMP_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Install the seccomp filter for `mode` (BRIX_SECCOMP_OFF/AUDIT/ENFORCE) on the
 * calling process. Returns NGX_OK when the requested policy is in force (OFF is
 * always OK); NGX_ERROR when audit/enforce was requested but the filter could
 * not be built and loaded — the caller MUST fail the worker on NGX_ERROR rather
 * than serve unfiltered.
 */
ngx_int_t brix_seccomp_install(ngx_cycle_t *cycle, ngx_uint_t mode);

#endif /* BRIX_CORE_SECCOMP_H */
