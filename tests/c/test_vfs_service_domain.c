/*
 * test_vfs_service_domain.c — the typed storage-domain assert (phase-107
 * C8/C9, landed in W1).
 *
 * WHAT: drives brix_vfs_domain_mutation and brix_vfs_service_mutation over
 *       hand-built brix_sd_instance_t values covering every domain shape the
 *       assert distinguishes: a correctly-labelled service store, a
 *       mis-composed tier, an export-pointed store, and the zero-initialised
 *       instance an untaught construction site produces.
 * WHY:  the export/service split was prose (phase-105 §0.1) enforced by
 *       nothing; gcas' dedup slots mutated whatever store they were handed.
 *       The assert turns "service code pointed at export storage" into
 *       EINVAL + one crit log line — deliberately NOT the export kernel's
 *       EROFS, because this is a programming error a client cannot provoke
 *       and an EROFS here would be caught by the wrong test.
 * HOW:  links the real vfs_policy_domain.o over the real policy kernel
 *       (vfs_policy.o); the two cross-TU symbols the pair names — the denial
 *       metric and ngx_log_error_core — are counting spies, so both the
 *       refusal and its crit log line are observed directly. No filesystem,
 *       no pool, no driver.
 *
 * Cases:
 *   success:      a CACHE-labelled store passes the narrow form for DEDUP;
 *                 a STAGE-labelled store passes the general form under a
 *                 matching STAGE claim. No log line, no denial sample.
 *   error:        NULL instance, out-of-range op, and out-of-range domain
 *                 are EINVAL before any comparison; an EXPORT-domain
 *                 instance refuses the narrow form with EINVAL and logs at
 *                 crit.
 *   security-neg: a service path cannot launder an export mutation through
 *                 a domain claim — claiming CACHE against an EXPORT
 *                 instance is EINVAL + crit, and claiming EXPORT outright
 *                 routes to the phase-105 kernel fail-closed (EROFS: an
 *                 instance carries no request policy, so no domain claim
 *                 ever authorizes an export mutation); a zero-initialised
 *                 instance is EXPORT, so the untaught site gets the strict
 *                 domain; a mis-composed tier (STAGE store under a CACHE
 *                 claim) is caught, not just the export-pointed shape.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_service_domain").
 */
#include "fs/vfs/vfs_policy_domain.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---- spy state ---------------------------------------------------------- */
static int        g_denials;
static int        g_log_calls;
static ngx_uint_t g_log_level;      /* last level handed to the log core     */

static ngx_log_t  g_log;            /* log_level set in main; zero elsewhere */

static void
reset_spies(void)
{
    g_denials   = 0;
    g_log_calls = 0;
    g_log_level = 0;
}

/* vfs_policy.o's one cross-TU symbol: count the denial samples. */
void
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    (void) proto; (void) op;
    g_denials++;
}

/* vfs_policy_domain.o's one libngx symbol (via the ngx_log_error macro):
 * record the level so "logs at crit" is an assertion, not a hope. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) log; (void) err; (void) fmt;
    g_log_calls++;
    g_log_level = level;
}

/* A labelled instance: only driver-independent fields matter to the assert. */
static void
inst_init(brix_sd_instance_t *inst, brix_vfs_domain_t domain)
{
    memset(inst, 0, sizeof(*inst));
    inst->log    = &g_log;
    inst->domain = domain;
}

/* ---- success ------------------------------------------------------------ */

static void
test_success_cache_store_passes_narrow_form(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_CACHE);
    assert(brix_vfs_service_mutation(&inst, BRIX_VFS_MUTATE_DEDUP) == NGX_OK);
    assert(g_log_calls == 0);
    assert(g_denials == 0);
}

static void
test_success_matching_claim_passes_general_form(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_STAGE);
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_STAGE,
                                    BRIX_VFS_MUTATE_WRITE) == NGX_OK);
    assert(g_log_calls == 0);
}

/* ---- error -------------------------------------------------------------- */

static void
test_error_invalid_arguments_are_einval(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_CACHE);

    errno = 0;
    assert(brix_vfs_service_mutation(NULL, BRIX_VFS_MUTATE_DEDUP)
           == NGX_ERROR);
    assert(errno == EINVAL);

    errno = 0;
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_CACHE,
                                    BRIX_VFS_MUTATE_OP_COUNT) == NGX_ERROR);
    assert(errno == EINVAL);

    errno = 0;
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_COUNT,
                                    BRIX_VFS_MUTATE_WRITE) == NGX_ERROR);
    assert(errno == EINVAL);

    assert(g_log_calls == 0);       /* argument defects are not domain drift  */
}

static void
test_error_export_instance_refuses_narrow_form_and_logs_crit(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_EXPORT);
    errno = 0;
    assert(brix_vfs_service_mutation(&inst, BRIX_VFS_MUTATE_DEDUP)
           == NGX_ERROR);
    assert(errno == EINVAL);        /* programming error, never EROFS         */
    assert(g_log_calls == 1);
    assert(g_log_level == NGX_LOG_CRIT);
}

/* ---- security-negative -------------------------------------------------- */

static void
test_secneg_export_cannot_be_laundered_through_a_cache_claim(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_EXPORT);
    errno = 0;
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_CACHE,
                                    BRIX_VFS_MUTATE_DEDUP) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_log_calls == 1);
    assert(g_log_level == NGX_LOG_CRIT);
}

static void
test_secneg_export_claim_is_fail_closed_erofs(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_EXPORT);
    errno = 0;
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_EXPORT,
                                    BRIX_VFS_MUTATE_WRITE) == NGX_ERROR);
    assert(errno == EROFS);         /* the phase-105 kernel, READ_ONLY policy */
}

static void
test_secneg_zeroed_instance_is_the_strict_export_domain(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    memset(&inst, 0, sizeof(inst)); /* the untaught construction site         */
    errno = 0;
    assert(brix_vfs_service_mutation(&inst, BRIX_VFS_MUTATE_DEDUP)
           == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_log_calls == 0);       /* log == NULL: refusal never needs a log */
}

static void
test_secneg_miscomposed_tier_is_caught(void)
{
    brix_sd_instance_t inst;

    reset_spies();
    inst_init(&inst, BRIX_VFS_DOMAIN_STAGE);
    errno = 0;
    assert(brix_vfs_domain_mutation(&inst, BRIX_VFS_DOMAIN_CACHE,
                                    BRIX_VFS_MUTATE_WRITE) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_log_calls == 1);
    assert(g_log_level == NGX_LOG_CRIT);
}

int
main(void)
{
    g_log.log_level = NGX_LOG_DEBUG;

    test_success_cache_store_passes_narrow_form();
    test_success_matching_claim_passes_general_form();
    test_error_invalid_arguments_are_einval();
    test_error_export_instance_refuses_narrow_form_and_logs_crit();
    test_secneg_export_cannot_be_laundered_through_a_cache_claim();
    test_secneg_export_claim_is_fail_closed_erofs();
    test_secneg_zeroed_instance_is_the_strict_export_domain();
    test_secneg_miscomposed_tier_is_caught();
    printf("vfs_service_domain: 8 cases OK\n");
    return 0;
}
