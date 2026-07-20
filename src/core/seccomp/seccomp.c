/* ---- File: src/core/seccomp/seccomp.c — ngx wrapper for the seccomp core ----
 *
 * Implements brix_seccomp_install() (see seccomp.h for the WHAT/WHY/HOW) as a
 * thin adapter over the nginx-free seccomp_core.c: it translates the ngx mode,
 * routes libseccomp failures to ngx_log_error through an error sink, and emits
 * the operator-facing NOTICE/EMERG. All the filter tables and the actual
 * libseccomp build+load live in seccomp_core.c so the shipped allowlist is the
 * one exercised by tests/c/test_seccomp.c.
 */

#include "core/seccomp/seccomp.h"
#include "core/seccomp/seccomp_core.h"
#include "core/types/tunables.h"   /* BRIX_SECCOMP_* */

#include <string.h>

/*
 * Process-global effective seccomp mode: the STRICTEST value requested by ANY
 * brix server, stream OR http (WebDAV/S3/cvmfs).  Set at config-parse time by
 * brix_conf_set_seccomp() (which every `brix_seccomp` directive, in either
 * context, routes through) and read once per worker by brix_seccomp_install_once().
 * A single process-wide value is correct because a seccomp filter is per-process
 * and one nginx worker serves every configured server.  It only ever ratchets UP
 * within a master's lifetime (a SIGHUP reload cannot lower it — fail-secure;
 * restart to drop the filter), which is the safe direction for a syscall filter.
 */
ngx_uint_t brix_seccomp_worker_mode = BRIX_SECCOMP_OFF;

/*
 * Process-global "allow execve/execveat under enforce" flag.  DEFAULT ON: brix
 * legitimately fork+execs helpers on common paths (the FRM "exec" MSS adapter,
 * OIDC token fetch, native-TPC token-exchange, WebDAV HTTP-TPC oidc-agent, the
 * kXR_prepare hook), and these are exercised by the E2E suite (test_seccomp_exec_frm.py),
 * so killing exec by default would silently break them the moment an operator turns
 * `brix_seccomp enforce` on.  `brix_seccomp_allow_exec off` on ANY brix server (stream
 * or http) opts back INTO the strict anti-shell posture — execve/execveat KILLED.
 * Fail-secure ratchet: `off` wins and sticks (a later `on`, or a reload dropping the
 * `off`, cannot re-enable exec — restart to reset), the same "ratchet toward secure"
 * direction as the mode.  The HARD kills (ptrace/process_vm_*) are unaffected by this
 * flag and apply regardless.
 */
ngx_uint_t brix_seccomp_allow_exec = 1;

/* Per-worker "already installed" latch so brix_seccomp_install_once() is a no-op
 * after the first call — the install site is whichever brix init_process runs
 * for this worker (stream for stream/mixed, webdav for http-only). */
static ngx_uint_t brix_seccomp_installed = 0;

char *
brix_conf_set_seccomp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t     *field = (ngx_uint_t *) ((char *) conf + cmd->offset);
    ngx_conf_enum_t *e = cmd->post;
    ngx_str_t      *value = cf->args->elts;
    ngx_uint_t      i;

    if (*field != NGX_CONF_UNSET_UINT && *field != BRIX_SECCOMP_OFF) {
        return "is duplicate";
    }
    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len == value[1].len
            && ngx_strcasecmp(e[i].name.data, value[1].data) == 0)
        {
            *field = e[i].value;
            /* Bump the process-global to the strictest requested anywhere. */
            if (e[i].value > brix_seccomp_worker_mode) {
                brix_seccomp_worker_mode = e[i].value;
            }
            return NGX_CONF_OK;
        }
    }
    return "invalid value";
}

ngx_int_t
brix_seccomp_install_once(ngx_cycle_t *cycle)
{
    if (brix_seccomp_installed) {
        return NGX_OK;
    }
    brix_seccomp_installed = 1;
    return brix_seccomp_install(cycle, brix_seccomp_worker_mode,
                                brix_seccomp_allow_exec);
}

char *
brix_conf_set_seccomp_allow_exec(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 3 && ngx_strncasecmp(value[1].data,
                                             (u_char *) "off", 3) == 0)
    {
        brix_seccomp_allow_exec = 0;          /* ratchet toward strict: off wins */
        return NGX_CONF_OK;
    }
    if (value[1].len == 2 && ngx_strncasecmp(value[1].data,
                                             (u_char *) "on", 2) == 0)
    {
        /* on is the default; a no-op that must NOT override a prior `off`
         * (fail-secure — once any server disabled exec, restart to re-enable). */
        return NGX_CONF_OK;
    }
    return "must be \"on\" or \"off\"";
}

/* Sink passed to the core: turns a per-syscall or whole-filter failure into an
 * EMERG line. `name == NULL` denotes a whole-filter failure (init/load). */
static void
brix_seccomp_log_err(void *ud, const char *name, int rc)
{
    ngx_cycle_t *cycle = ud;

    if (name != NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "brix_seccomp: rule add for \"%s\" failed: %s",
                      name, strerror(-rc));
    } else if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "brix_seccomp: filter load failed: %s", strerror(-rc));
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "brix_seccomp: filter init failed");
    }
}

ngx_int_t
brix_seccomp_install(ngx_cycle_t *cycle, ngx_uint_t mode, ngx_uint_t allow_exec)
{
    unsigned n_allow = 0;
    unsigned n_deny = 0;
    int      rc;

    if (mode == BRIX_SECCOMP_OFF) {
        return NGX_OK;
    }

    rc = brix_seccomp_core_apply((unsigned) mode, (unsigned) allow_exec,
                                 brix_seccomp_log_err, cycle, &n_allow, &n_deny);

    if (rc == BRIX_SECCOMP_CORE_UNAVAIL) {
        /* Fail closed: the operator asked for a syscall filter (audit or
         * enforce) but this binary was built without libseccomp. Refusing the
         * worker is the honest outcome — serving while the operator believes a
         * filter is active would be a silent security downgrade. Rebuild with
         * libseccomp-devel or set "brix_seccomp off". */
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "brix_seccomp: mode=%ui requested but this binary was "
                      "built without libseccomp (install libseccomp-devel and "
                      "rebuild, or set \"brix_seccomp off\")", mode);
        return NGX_ERROR;
    }

    if (rc != BRIX_SECCOMP_CORE_OK) {
        /* The sink already logged the specific failure. */
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix_seccomp: worker syscall filter active (mode=%s, exec=%s, "
                  "%ui allowed, %ui denied)",
                  (mode == BRIX_SECCOMP_ENFORCE) ? "enforce" : "audit",
                  allow_exec ? "allowed" : "killed",
                  (ngx_uint_t) n_allow, (ngx_uint_t) n_deny);
    return NGX_OK;
}
