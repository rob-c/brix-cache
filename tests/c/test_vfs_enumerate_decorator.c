/*
 * test_vfs_enumerate_decorator.c — the decorator walk in
 * brix_vfs_enumerate_catalog().
 *
 * WHAT: proves the backend-catalog verb descends cache/stage decorators to the
 *       first instance that implements `enumerate`, instead of asking only the
 *       top instance and declining.
 * WHY:  the catalog belongs to the BACKING STORE; a tier decorator holds a
 *       partial local copy of it. Before the walk, putting a cache tier in
 *       front of a catalog-bearing export (rados, pblock, S3) silently demoted
 *       inventory/drift to a full namespace walk — an O(objects) POSIX crawl
 *       over a store whose namespace is synthetic, or nothing at all where the
 *       leaf has no directory verbs either.
 * HOW:  links only the built vfs_walk.o and stubs its cross-TU symbols, so the
 *       enumeration is fully hermetic (no pool, no backend registry, no
 *       filesystem). brix_vfs_decorator_source is one of those stubs: the test
 *       owns the chain, which is the point — the unit under test is the LOOP in
 *       vfs_walk.c, not the two-line accessor it calls. Instances are chained
 *       through a table the stub consults, so a chain of any depth or shape can
 *       be built without a real cache/stage instance.
 *
 * Cases:
 *   success:      leaf-only, decorator→leaf, and decorator→decorator→leaf all
 *                 reach the SAME leaf verb, with want_stat/cb/ctx forwarded
 *                 verbatim and the leaf's own instance (never the decorator's)
 *                 passed as `inst`; the driver's return code is propagated
 *                 unchanged, including a callback early-abort.
 *   error:        a chain whose every link lacks the verb → NGX_DECLINED with
 *                 errno ENOTSUP; a NULL instance likewise; a leaf whose
 *                 enumerate fails → NGX_ERROR with the driver's errno intact.
 *   security-neg: the walk stops at the FIRST implementer — a decorator that
 *                 has the verb answers itself and the leaf is never consulted
 *                 (a tier must not be bypassed when it claims the catalog); an
 *                 instance whose driver pointer is NULL is skipped rather than
 *                 dereferenced, and one at the chain's end declines rather than
 *                 faulting; and the walk descends only — entering at the leaf
 *                 never climbs back into the decorator's partial copy.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_enumerate_decorator").
 */
#include "fs/vfs/vfs.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- cross-TU stubs ------------------------------------------------------
 * vfs_walk.o names these for the namespace-walk half of the TU; the catalog
 * verb under test reaches none of them except decorator_source. */
ngx_int_t brix_vfs_backend_resolve(brix_vfs_ctx_t *ctx, const char *path,
    char *out, size_t outcap);
void brix_vfs_fill_stat(brix_sd_stat_t *out, const struct stat *st);
int brix_fs_is_dot_entry(const char *name);
int brix_open_beneath(int dirfd, const char *rel, int flags, mode_t mode);
int brix_stat_beneath(int dirfd, const char *rel, struct stat *st, int flags);
int brix_unlink_beneath(int dirfd, const char *rel, int flags);
int brix_open_confined_canon(const char *root, const char *path, int flags,
    mode_t mode);
int brix_mkdir_confined_canon(const char *root, const char *path, mode_t mode);
int brix_unlink_confined_canon(const char *root, const char *path, int flags);

ngx_int_t
brix_vfs_backend_resolve(brix_vfs_ctx_t *ctx, const char *path, char *out,
    size_t outcap)
{
    (void) ctx; (void) path; (void) out; (void) outcap;
    return NGX_ERROR;
}

void
brix_vfs_fill_stat(brix_sd_stat_t *out, const struct stat *st)
{
    (void) out; (void) st;
}

int brix_fs_is_dot_entry(const char *name) { (void) name; return 0; }

int
brix_open_beneath(int dirfd, const char *rel, int flags, mode_t mode)
{
    (void) dirfd; (void) rel; (void) flags; (void) mode; return -1;
}

int
brix_stat_beneath(int dirfd, const char *rel, struct stat *st, int flags)
{
    (void) dirfd; (void) rel; (void) st; (void) flags; return -1;
}

int
brix_unlink_beneath(int dirfd, const char *rel, int flags)
{
    (void) dirfd; (void) rel; (void) flags; return -1;
}

int
brix_open_confined_canon(const char *root, const char *path, int flags,
    mode_t mode)
{
    (void) root; (void) path; (void) flags; (void) mode; return -1;
}

int
brix_mkdir_confined_canon(const char *root, const char *path, mode_t mode)
{
    (void) root; (void) path; (void) mode; return -1;
}

int
brix_unlink_confined_canon(const char *root, const char *path, int flags)
{
    (void) root; (void) path; (void) flags; return -1;
}

/* ---- the chain ----------------------------------------------------------
 * A side table maps instance → its decorated source, so the stub can express a
 * chain of any depth (and a deliberately cyclic one) without constructing real
 * cache/stage state. */
#define MAX_LINK 8

static struct {
    const brix_sd_instance_t *from;
    brix_sd_instance_t       *to;
} g_link[MAX_LINK];

static size_t g_links;

static void
link_reset(void)
{
    memset(g_link, 0, sizeof(g_link));
    g_links = 0;
}

static void
link_add(const brix_sd_instance_t *from, brix_sd_instance_t *to)
{
    assert(g_links < MAX_LINK);
    g_link[g_links].from = from;
    g_link[g_links].to = to;
    g_links++;
}

brix_sd_instance_t *
brix_vfs_decorator_source(const brix_sd_instance_t *inst)
{
    size_t i;

    for (i = 0; i < g_links; i++) {
        if (g_link[i].from == inst) {
            return g_link[i].to;
        }
    }
    return NULL;
}

/* ---- fake drivers -------------------------------------------------------- */

static const brix_sd_catalog_ent_t g_objs[] = {
    { "/a/one.bin", NULL, 1, 100, 111 },
    { "/a/two.bin", NULL, 1, 200, 222 },
    { "/b/three.bin", NULL, 0, 0, 0 },
};

typedef struct {
    int                 calls;       /* how often this driver's verb ran */
    brix_sd_instance_t *saw_inst;    /* the instance it was handed */
    int                 saw_want;    /* the want_stat it was handed */
    void               *saw_ctx;
    int                 fail;        /* >0: report NGX_ERROR with this errno */
} drvlog_t;

static drvlog_t g_leaf, g_mid;

static ngx_int_t
enum_impl(drvlog_t *log, brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    size_t i;

    log->calls++;
    log->saw_inst = inst;
    log->saw_want = want_stat;
    log->saw_ctx = ctx;

    if (log->fail) {
        errno = log->fail;
        return NGX_ERROR;
    }
    for (i = 0; i < sizeof(g_objs) / sizeof(g_objs[0]); i++) {
        if (cb(ctx, &g_objs[i]) != 0) {
            return NGX_ABORT;   /* distinct code, so propagation is observable */
        }
    }
    return NGX_OK;
}

static ngx_int_t
leaf_enumerate(brix_sd_instance_t *inst, int want_stat, brix_sd_catalog_cb cb,
    void *ctx)
{
    return enum_impl(&g_leaf, inst, want_stat, cb, ctx);
}

static ngx_int_t
mid_enumerate(brix_sd_instance_t *inst, int want_stat, brix_sd_catalog_cb cb,
    void *ctx)
{
    return enum_impl(&g_mid, inst, want_stat, cb, ctx);
}

static const brix_sd_driver_t leaf_driver = {
    .name = "fake-leaf", .caps = BRIX_SD_CAP_CATALOG,
    .enumerate = leaf_enumerate,
};

static const brix_sd_driver_t mid_driver = {
    .name = "fake-mid", .caps = BRIX_SD_CAP_CATALOG,
    .enumerate = mid_enumerate,
};

/* a decorator with no catalog of its own — the shape cache/stage actually have */
static const brix_sd_driver_t passthru_driver = {
    .name = "fake-passthru", .caps = 0,
};

/* ---- collector ----------------------------------------------------------- */

typedef struct {
    int  seen;
    int  stop_after;   /* >0: abort once `seen` reaches it */
    long total;
} cctx_t;

static int
collect_cb(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    cctx_t *c = ctx;

    c->seen++;
    c->total += (long) ent->size;
    if (c->stop_after > 0 && c->seen >= c->stop_after) {
        return 1;   /* non-zero → the driver stops enumerating */
    }
    return 0;
}

static void
reset(void)
{
    link_reset();
    memset(&g_leaf, 0, sizeof(g_leaf));
    memset(&g_mid, 0, sizeof(g_mid));
    errno = 0;
}

/* ---- cases --------------------------------------------------------------- */

static void
test_success(void)
{
    brix_sd_instance_t leaf, deco, outer;
    cctx_t c;

    memset(&leaf, 0, sizeof(leaf));
    memset(&deco, 0, sizeof(deco));
    memset(&outer, 0, sizeof(outer));
    leaf.driver = &leaf_driver;
    deco.driver = &passthru_driver;
    outer.driver = &passthru_driver;

    /* undecorated export: the verb is found on the instance itself */
    reset();
    memset(&c, 0, sizeof(c));
    assert(brix_vfs_enumerate_catalog(&leaf, 1, collect_cb, &c) == NGX_OK);
    assert(g_leaf.calls == 1);
    assert(g_leaf.saw_inst == &leaf);
    assert(g_leaf.saw_want == 1);
    assert(g_leaf.saw_ctx == &c);
    assert(c.seen == 3);
    assert(c.total == 300);

    /* one decorator in front (cache OR stage) */
    reset();
    memset(&c, 0, sizeof(c));
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&deco, 0, collect_cb, &c) == NGX_OK);
    assert(g_leaf.calls == 1);
    assert(g_leaf.saw_inst == &leaf);   /* the LEAF's instance, not the deco's */
    assert(g_leaf.saw_want == 0);       /* want_stat forwarded verbatim */
    assert(c.seen == 3);

    /* two decorators (stage over cache over origin) */
    reset();
    memset(&c, 0, sizeof(c));
    link_add(&outer, &deco);
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&outer, 1, collect_cb, &c) == NGX_OK);
    assert(g_leaf.calls == 1);
    assert(g_leaf.saw_inst == &leaf);
    assert(c.seen == 3);

    /* the driver's own return code is propagated, not normalised: a callback
     * early-abort through two decorators still surfaces the driver's code */
    reset();
    memset(&c, 0, sizeof(c));
    c.stop_after = 2;
    link_add(&outer, &deco);
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&outer, 1, collect_cb, &c) == NGX_ABORT);
    assert(c.seen == 2);

    printf("ok success\n");
}

static void
test_error(void)
{
    brix_sd_instance_t leaf, deco;
    cctx_t c;

    memset(&leaf, 0, sizeof(leaf));
    memset(&deco, 0, sizeof(deco));
    deco.driver = &passthru_driver;

    /* nothing in the chain implements the verb (POSIX: the namespace IS the
     * catalog) → DECLINED/ENOTSUP so the engine falls back to brix_vfs_walk */
    reset();
    memset(&c, 0, sizeof(c));
    leaf.driver = &passthru_driver;
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&deco, 1, collect_cb, &c) == NGX_DECLINED);
    assert(errno == ENOTSUP);
    assert(c.seen == 0);

    /* NULL instance: same contract, no crash */
    reset();
    memset(&c, 0, sizeof(c));
    assert(brix_vfs_enumerate_catalog(NULL, 1, collect_cb, &c) == NGX_DECLINED);
    assert(errno == ENOTSUP);

    /* a leaf whose enumerate fails reports NGX_ERROR with ITS errno intact —
     * the walk must not overwrite it with its own ENOTSUP */
    reset();
    memset(&c, 0, sizeof(c));
    leaf.driver = &leaf_driver;
    g_leaf.fail = EIO;
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&deco, 1, collect_cb, &c) == NGX_ERROR);
    assert(errno == EIO);
    assert(g_leaf.calls == 1);

    printf("ok error\n");
}

static void
test_security_negative(void)
{
    brix_sd_instance_t leaf, deco, nodrv;
    cctx_t c;

    memset(&leaf, 0, sizeof(leaf));
    memset(&deco, 0, sizeof(deco));
    memset(&nodrv, 0, sizeof(nodrv));
    leaf.driver = &leaf_driver;
    nodrv.driver = NULL;

    /* FIRST implementer wins: a decorator that owns a catalog answers from its
     * own view and the backing store is never enumerated. Descending past a
     * tier that claims the catalog would leak the origin's full object list
     * through an export the tier is there to scope. */
    reset();
    memset(&c, 0, sizeof(c));
    deco.driver = &mid_driver;
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&deco, 1, collect_cb, &c) == NGX_OK);
    assert(g_mid.calls == 1);
    assert(g_mid.saw_inst == &deco);
    assert(g_leaf.calls == 0);

    /* an instance with a NULL driver is skipped, not dereferenced */
    reset();
    memset(&c, 0, sizeof(c));
    link_add(&nodrv, &leaf);
    assert(brix_vfs_enumerate_catalog(&nodrv, 1, collect_cb, &c) == NGX_OK);
    assert(g_leaf.calls == 1);
    assert(c.seen == 3);

    /* a NULL driver at the END of the chain declines rather than faulting */
    reset();
    memset(&c, 0, sizeof(c));
    deco.driver = &passthru_driver;
    link_add(&deco, &nodrv);
    assert(brix_vfs_enumerate_catalog(&deco, 1, collect_cb, &c) == NGX_DECLINED);
    assert(errno == ENOTSUP);

    /* the walk is a descent, never an ascent: entering the stack at the LEAF of
     * a decorated export enumerates the leaf and never climbs back to the
     * decorator that fronts it (a caller holding the backing instance must not
     * be answered from the tier's partial copy). */
    reset();
    memset(&c, 0, sizeof(c));
    deco.driver = &mid_driver;
    link_add(&deco, &leaf);
    assert(brix_vfs_enumerate_catalog(&leaf, 1, collect_cb, &c) == NGX_OK);
    assert(g_leaf.calls == 1);
    assert(g_mid.calls == 0);

    printf("ok security-negative\n");
}

int
main(void)
{
    test_success();
    test_error();
    test_security_negative();
    printf("PASS test_vfs_enumerate_decorator\n");
    return 0;
}
