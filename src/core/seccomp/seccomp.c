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
brix_seccomp_install(ngx_cycle_t *cycle, ngx_uint_t mode)
{
    unsigned n_allow = 0;
    unsigned n_deny = 0;
    int      rc;

    if (mode == BRIX_SECCOMP_OFF) {
        return NGX_OK;
    }

    rc = brix_seccomp_core_apply((unsigned) mode, brix_seccomp_log_err, cycle,
                                 &n_allow, &n_deny);

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
                  "brix_seccomp: worker syscall filter active (mode=%s, "
                  "%ui allowed, %ui denied)",
                  (mode == BRIX_SECCOMP_ENFORCE) ? "enforce" : "audit",
                  (ngx_uint_t) n_allow, (ngx_uint_t) n_deny);
    return NGX_OK;
}
