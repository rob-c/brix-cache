/* test_sd_mkdir_cred_forward.c — unit test for the mkdir credential-forwarding
 * dispatch (brix_sd_mkdir_maybe_cred in src/fs/backend/sd_cred_forward.h).
 *
 * The root:// (xroot) driver previously had plain unlink/rename/stat *_cred slots
 * but NO mkdir_cred slot, so a per-user mkdir dispatched through
 * brix_sd_mkdir_maybe_cred fell back to the plain (service/anonymous-session)
 * mkdir even when the VFS namespace gate had already resolved a per-user
 * credential.  Against a ZTN + SciTokens origin the anonymous session cannot
 * authenticate, so the fallback mkdir failed with EIO (client rc54 "io_error").
 * The fix wires sd_xroot_mkdir_cred into the driver vtable; this test pins the
 * dispatch contract that makes that slot reachable and guards the security
 * property that a DENY-mode request never silently leaks onto the service
 * credential's plain mkdir.
 *
 * Uses a fake driver + instance (no origin, no network) with recording plain and
 * cred mkdir slots.  It proves:
 *   1 (success)      — cred present AND driver has mkdir_cred -> the cred slot is
 *                      called with the exact credential; the plain slot is NOT.
 *   2 (error/fallback) — cred == NULL -> the plain slot is called (legacy path,
 *                      no credential to thread); the cred slot is NOT.  Also: a
 *                      cred present but driver WITHOUT mkdir_cred and NOT in deny
 *                      mode -> plain slot (legitimate allow-mode fallback).
 *   3 (security-neg) — cred with fallback_deny==1 AND driver WITHOUT mkdir_cred
 *                      -> EACCES, and the plain slot is NEVER called (no silent
 *                      service-credential mkdir).
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_mkdir_cred_forward`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/sd.h"

/* ---- ngx link stubs (inert; the forwarder never logs). ------------------- */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* ---- recording fake driver slots ---------------------------------------- */
static int   g_plain_calls;
static int   g_cred_calls;
static char  g_last_path[256];
static mode_t g_last_mode;
static const brix_sd_cred_t *g_last_cred;

static void
reset_counters(void)
{
    g_plain_calls = 0;
    g_cred_calls = 0;
    g_last_path[0] = '\0';
    g_last_mode = 0;
    g_last_cred = NULL;
}

static ngx_int_t
fake_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    (void) inst;
    g_plain_calls++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", path);
    g_last_mode = mode;
    return NGX_OK;
}

static ngx_int_t
fake_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    (void) inst;
    g_cred_calls++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", path);
    g_last_mode = mode;
    g_last_cred = cred;
    return NGX_OK;
}

/* A driver WITH both plain and cred mkdir slots (the fixed xroot shape). */
static const brix_sd_driver_t drv_with_cred = {
    .mkdir      = fake_mkdir,
    .mkdir_cred = fake_mkdir_cred,
};

/* A driver with ONLY the plain slot (the pre-fix xroot shape / any driver that
 * has not yet grown a mkdir_cred slot). */
static const brix_sd_driver_t drv_plain_only = {
    .mkdir      = fake_mkdir,
    .mkdir_cred = NULL,
};

static brix_sd_instance_t
make_inst(const brix_sd_driver_t *drv)
{
    brix_sd_instance_t inst;
    ngx_memzero(&inst, sizeof(inst));
    inst.driver = drv;
    return inst;
}

/* 1 (success): cred + mkdir_cred slot -> cred slot, exact cred, plain untouched. */
static void
test_success_routes_to_cred_slot(void)
{
    brix_sd_instance_t inst = make_inst(&drv_with_cred);
    brix_sd_cred_t     cred;
    ngx_int_t          rc;

    ngx_memzero(&cred, sizeof(cred));
    reset_counters();

    rc = brix_sd_mkdir_maybe_cred(&inst, "/vo/alice/dir", 0755, &cred);

    assert(rc == NGX_OK);
    assert(g_cred_calls == 1);
    assert(g_plain_calls == 0);
    assert(g_last_cred == &cred);            /* exact credential threaded */
    assert(strcmp(g_last_path, "/vo/alice/dir") == 0);
    assert(g_last_mode == 0755);
    printf("ok 1 - cred present + mkdir_cred slot routes to the cred slot\n");
}

/* 2 (error/fallback): cred NULL -> plain slot (no credential to thread). And a
 * cred present on a plain-only driver NOT in deny mode -> plain (allow-mode
 * fallback, unchanged legacy behaviour). */
static void
test_null_and_allow_mode_fall_back_to_plain(void)
{
    brix_sd_instance_t inst_cred = make_inst(&drv_with_cred);
    brix_sd_instance_t inst_plain = make_inst(&drv_plain_only);
    brix_sd_cred_t     cred;
    ngx_int_t          rc;

    ngx_memzero(&cred, sizeof(cred));

    /* cred == NULL: plain slot, never the cred slot. */
    reset_counters();
    rc = brix_sd_mkdir_maybe_cred(&inst_cred, "/pub/x", 0700, NULL);
    assert(rc == NGX_OK);
    assert(g_plain_calls == 1);
    assert(g_cred_calls == 0);

    /* cred present, driver has no mkdir_cred, allow-mode (fallback_deny==0):
     * legitimate fallback to the plain slot. */
    reset_counters();
    cred.fallback_deny = 0;
    rc = brix_sd_mkdir_maybe_cred(&inst_plain, "/pub/y", 0700, &cred);
    assert(rc == NGX_OK);
    assert(g_plain_calls == 1);
    assert(g_cred_calls == 0);
    printf("ok 2 - NULL cred and allow-mode missing-slot both fall back to "
           "the plain slot\n");
}

/* 3 (security-neg): fallback_deny + no mkdir_cred slot -> EACCES, plain NEVER
 * called (no silent service-credential mkdir). */
static void
test_deny_mode_refuses_plain_fallback(void)
{
    brix_sd_instance_t inst = make_inst(&drv_plain_only);
    brix_sd_cred_t     cred;
    ngx_int_t          rc;

    ngx_memzero(&cred, sizeof(cred));
    cred.fallback_deny = 1;
    reset_counters();
    errno = 0;

    rc = brix_sd_mkdir_maybe_cred(&inst, "/vo/alice/secret", 0755, &cred);

    assert(rc == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_plain_calls == 0);              /* service credential NOT used */
    assert(g_cred_calls == 0);
    printf("ok 3 - deny-mode without a mkdir_cred slot refuses (EACCES), never "
           "leaks onto the plain service mkdir\n");
}

int
main(void)
{
    test_success_routes_to_cred_slot();
    test_null_and_allow_mode_fall_back_to_plain();
    test_deny_mode_refuses_plain_fallback();
    printf("PASS test_sd_mkdir_cred_forward (3 tests)\n");
    return 0;
}
