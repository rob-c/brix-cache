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
ngx_int_t brix_seccomp_install(ngx_cycle_t *cycle, ngx_uint_t mode,
    ngx_uint_t allow_exec);

/*
 * Process-global "allow execve under enforce" flag (0/1), set by
 * `brix_seccomp_allow_exec on`.  When 1, an ENFORCE filter allowlists
 * execve/execveat (so OIDC token fetch / native-TPC token-exchange / the
 * kXR_prepare hook can fork+exec) while STILL killing ptrace/process_vm_*.
 */
extern ngx_uint_t brix_seccomp_allow_exec;

/* Custom setter for `brix_seccomp_allow_exec on|off` (stream + http tables). */
char *brix_conf_set_seccomp_allow_exec(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * The process-global effective seccomp mode (strictest across ALL brix servers,
 * stream + http). Set by brix_conf_set_seccomp() at config parse; read by
 * brix_seccomp_install_once().
 */
extern ngx_uint_t brix_seccomp_worker_mode;

/*
 * Custom setter for the `brix_seccomp` directive (registered in BOTH the stream
 * and the shared http directive tables). Parses off|audit|enforce into the
 * per-conf field AND bumps brix_seccomp_worker_mode to the strictest requested.
 */
char *brix_conf_set_seccomp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*
 * Install brix_seccomp_worker_mode on the calling worker, exactly once (idempotent
 * per worker). Called at the end of the brix init_process that runs for this
 * worker — stream for stream/mixed configs, webdav for HTTP-only configs — so
 * WebDAV/S3-only workers are filtered too. Returns NGX_ERROR (fail closed) when an
 * audit/enforce filter was requested but could not be built.
 */
ngx_int_t brix_seccomp_install_once(ngx_cycle_t *cycle);

#endif /* BRIX_CORE_SECCOMP_H */
