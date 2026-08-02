/*
 * test_cstore_scan_enumerate.c — phase-92 finding #13.
 *
 * WHAT: proves brix_cstore_scan() falls back to the driver's native
 *       object-catalog enumerate (BRIX_SD_CAP_CATALOG) when the cache store has
 *       no opendir/readdir/closedir, so a remote object store (S3/http/rados)
 *       is still scrubbable/inventoriable by the phase-87 G17 background scrub.
 * WHY:  before this, a store lacking directory verbs returned ENOSYS/DECLINED
 *       even when it advertised a native catalog, leaving such caches
 *       un-scanned by eviction/inventory.
 * HOW:  links only the built cstore_scan.o and stubs the one cross-TU symbol it
 *       needs (brix_cstore_cinfo_load) so the scan is fully hermetic. A fake SD
 *       driver exposes enumerate() over a fixed catalog (including a .cinfo
 *       sidecar that must be skipped) and NULL directory verbs, forcing the
 *       fallback path.
 *
 * Cases:
 *   success:      a CAP_CATALOG store with no dir verbs → the visitor sees every
 *                 stored object exactly once, sidecars skipped, per-object size
 *                 carried through from the catalog entry.
 *   edge:         a store with neither dir verbs nor a catalog → NGX_DECLINED
 *                 (errno ENOSYS); an enumerate that fails → NGX_ERROR.
 *   security-neg: a driver that has enumerate() but does NOT advertise
 *                 CAP_CATALOG is NOT enumerated (caps gate honoured); a visitor
 *                 early-abort short-circuits the enumeration and its code wins;
 *                 NULL args are rejected with EINVAL.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("cstore_scan_enumerate").
 */
#include "cstore.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* cstore_scan.o calls brix_cstore_cinfo_load across TUs; stub it so the scan is
 * hermetic — no cinfo record means the visitor simply sees NULL, exactly as it
 * would for an orphan/partial object on a real store. */
ngx_int_t
brix_cstore_cinfo_load(brix_cstore_t *cs, const char *key,
    brix_cache_cinfo_t *ci)
{
    (void) cs;
    (void) key;
    (void) ci;
    return NGX_ERROR;
}

/* ---- fake catalog driver ------------------------------------------------- */

/* fields: key, path, have_stat, size, mtime */
static const brix_sd_catalog_ent_t g_objs[] = {
    { "/a/one.bin",        NULL, 1, 100, 111 },
    { "/a/two.bin",        NULL, 1, 200, 222 },
    { "/a/two.bin.cinfo",  NULL, 1,   8,   0 },  /* sidecar → must be skipped */
    { "/b/three.bin",      NULL, 0,   0,   0 },  /* enumerator captured no stat */
};

static int g_enum_fail = 0;   /* when set, the enumerate verb reports NGX_ERROR */

static ngx_int_t
fake_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    size_t i;

    (void) inst;
    (void) want_stat;

    if (g_enum_fail) {
        errno = EIO;
        return NGX_ERROR;
    }
    for (i = 0; i < sizeof(g_objs) / sizeof(g_objs[0]); i++) {
        if (cb(ctx, &g_objs[i]) != 0) {
            return NGX_OK;   /* cb aborted early; enumerate still reports OK */
        }
    }
    return NGX_OK;
}

static const brix_sd_driver_t catalog_driver = {
    .name      = "fake-catalog",
    .caps      = BRIX_SD_CAP_CATALOG,
    .enumerate = fake_enumerate,
    /* opendir/readdir/closedir intentionally NULL → forces the fallback */
};

/* enumerate present but caps does NOT advertise CAP_CATALOG. */
static const brix_sd_driver_t uncapped_driver = {
    .name      = "fake-uncapped",
    .caps      = 0,
    .enumerate = fake_enumerate,
};

/* no dir verbs, no enumerate at all. */
static const brix_sd_driver_t nodir_driver = {
    .name = "fake-nodir",
    .caps = 0,
};

/* ---- visitor ------------------------------------------------------------- */

typedef struct {
    int  calls;
    int  stop_after;     /* >0: abort (return NGX_ERROR) once calls reaches it */
    long total_size;
    int  saw_sidecar;
} vctx_t;

static ngx_int_t
count_visit(const char *key, const brix_cache_cinfo_t *ci,
    const brix_sd_stat_t *stx, void *ctx)
{
    vctx_t *v = ctx;

    (void) ci;
    v->calls++;
    v->total_size += (long) stx->size;
    if (strstr(key, ".cinfo") != NULL) {
        v->saw_sidecar = 1;
    }
    if (v->stop_after > 0 && v->calls >= v->stop_after) {
        return NGX_ERROR;    /* visitor early-abort — code must propagate */
    }
    return NGX_OK;
}

static brix_cstore_t
make_cstore(brix_sd_instance_t *inst, const brix_sd_driver_t *drv, uint32_t caps)
{
    brix_cstore_t cs;

    memset(inst, 0, sizeof(*inst));
    inst->driver = drv;
    inst->caps   = caps;

    memset(&cs, 0, sizeof(cs));
    cs.store = inst;
    return cs;
}

/* success: catalog store, visitor never stops → every object once, no sidecar. */
static void
test_enumerate_fallback_visits_all(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &catalog_driver,
                                          BRIX_SD_CAP_CATALOG);
    vctx_t             v  = { 0, 0, 0, 0 };

    g_enum_fail = 0;
    assert(brix_cstore_scan(&cs, count_visit, &v) == NGX_OK);
    assert(v.calls == 3);            /* 4 entries − 1 sidecar */
    assert(v.saw_sidecar == 0);      /* sidecar skipped by key suffix */
    assert(v.total_size == 300);     /* 100 + 200 + 0 (three.bin: no stat) */
    printf("  ok: enumerate fallback visits every object, skips sidecars\n");
}

/* edge: no dir verbs AND no catalog → DECLINED / ENOSYS. */
static void
test_no_dirs_no_catalog_declines(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &nodir_driver, 0);
    vctx_t             v  = { 0, 0, 0, 0 };

    errno = 0;
    assert(brix_cstore_scan(&cs, count_visit, &v) == NGX_DECLINED);
    assert(errno == ENOSYS);
    assert(v.calls == 0);
    printf("  ok: store with no dirs and no catalog declines (ENOSYS)\n");
}

/* edge: an enumerate that fails is reported as NGX_ERROR. */
static void
test_enumerate_failure_is_error(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &catalog_driver,
                                          BRIX_SD_CAP_CATALOG);
    vctx_t             v  = { 0, 0, 0, 0 };

    g_enum_fail = 1;
    assert(brix_cstore_scan(&cs, count_visit, &v) == NGX_ERROR);
    g_enum_fail = 0;
    printf("  ok: enumerate failure surfaces as NGX_ERROR\n");
}

/* security-neg: enumerate present but caps lacks CAP_CATALOG → NOT enumerated. */
static void
test_uncapped_driver_not_enumerated(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &uncapped_driver, 0);
    vctx_t             v  = { 0, 0, 0, 0 };

    errno = 0;
    assert(brix_cstore_scan(&cs, count_visit, &v) == NGX_DECLINED);
    assert(errno == ENOSYS);
    assert(v.calls == 0);            /* caps gate: never touched the catalog */
    printf("  ok: enumerate ignored when CAP_CATALOG is not advertised\n");
}

/* security-neg: a visitor early-abort short-circuits and its code propagates. */
static void
test_visitor_abort_propagates(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &catalog_driver,
                                          BRIX_SD_CAP_CATALOG);
    vctx_t             v  = { 0, 1, 0, 0 };   /* stop after the first visit */

    g_enum_fail = 0;
    assert(brix_cstore_scan(&cs, count_visit, &v) == NGX_ERROR);
    assert(v.calls == 1);            /* enumeration aborted, not run to the end */
    printf("  ok: visitor early-abort stops enumeration, code propagates\n");
}

/* security-neg: NULL arguments are rejected. */
static void
test_null_args_rejected(void)
{
    brix_sd_instance_t inst;
    brix_cstore_t      cs = make_cstore(&inst, &catalog_driver,
                                          BRIX_SD_CAP_CATALOG);
    vctx_t             v  = { 0, 0, 0, 0 };

    errno = 0;
    assert(brix_cstore_scan(NULL, count_visit, &v) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(brix_cstore_scan(&cs, NULL, &v) == NGX_ERROR);
    printf("  ok: NULL cstore / NULL visitor rejected (EINVAL)\n");
}

int
main(void)
{
    printf("test_cstore_scan_enumerate:\n");
    test_enumerate_fallback_visits_all();
    test_no_dirs_no_catalog_declines();
    test_enumerate_failure_is_error();
    test_uncapped_driver_not_enumerated();
    test_visitor_abort_propagates();
    test_null_args_rejected();
    printf("test_cstore_scan_enumerate: ALL PASS\n");
    return 0;
}
