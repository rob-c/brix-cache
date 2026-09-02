/* test_decorator_cred_forward.c — the cache and stage DECORATORS must carry a
 * per-user credential across themselves, not swallow it.
 *
 * brix_sd_<op>_maybe_cred decides cred-slot vs plain-slot vs deny-refusal by
 * looking at THE INSTANCE IT IS CALLED ON. A decorator therefore answers that
 * question on its own behalf: publishing `.mkdir` while leaving `.mkdir_cred`
 * NULL reads, one tier up, as "this driver has no per-user support" — and a
 * per-user mkdir behind that cache then either refuses outright (deny mode) or
 * runs on the export's service credential (allow mode: the confused deputy),
 * no matter how completely the SOURCE implements the `_cred` slots. Both
 * decorators published exactly that shape for every namespace/xattr/dir op.
 *
 * Links the REAL forwarders (sd_cache_forward.o, sd_stage.o) against a fake
 * source driver, so the vtables and the routing under test are the shipping
 * ones. Only symbols outside the forwarding path are stubbed: the cstore
 * lookups (a forced MISS is what drives sd_cache_stat past its cinfo shortcut
 * to the source), the write-back/staged slots the stage vtable names but this
 * test never dispatches, and ngx_cpystrn (no nginx object is linked here).
 *
 *   1 (success)      — for BOTH decorators, every cred slot routes to the
 *                      source's matching *_cred slot with the exact credential
 *                      pointer, and every plain slot still routes to the plain
 *                      one. The vtable is also checked structurally: no
 *                      published plain namespace slot may lack its cred twin.
 *   2 (error)        — a source with NEITHER slot keeps the pre-existing errno
 *                      contract through the decorator: ENOTSUP for the xattr
 *                      ops, NGX_OK (advisory no-op) for setattr — and unlink's
 *                      eviction fires only when the source actually succeeded.
 *   3 (security-neg) — deny-mode credential + a source with plain slots only:
 *                      EACCES, and the source's plain slot is NEVER entered.
 *                      Not one byte of the request reaches the origin under the
 *                      service credential.
 *   4                — the same forwarder question for `space`, the one
 *                      non-credential slot with the same failure shape: a NULL
 *                      slot on the decorator makes the caller size a write
 *                      against the LOCAL SPOOL instead of the backend. All three
 *                      arms in one function (relay / ENOTSUP / no fabricated
 *                      figures), since there is no credential to vary.
 *
 * Run via `python3 -m cmdscripts.c_regression_units decorator_cred_forward`.
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
#include "fs/backend/cache/sd_cache_internal.h"
#include "fs/backend/stage/sd_stage_internal.h"

/* ---- link stubs: everything OUTSIDE the forwarding path under test ------- */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n && *src) {
        *dst++ = *src++;
    }
    *dst = '\0';
    return dst;
}

/* The cache's stat shortcut: force a MISS so every op reaches the source. */
ngx_int_t
brix_cstore_cinfo_load(brix_cstore_t *cs, const char *key,
    brix_cache_cinfo_t *out)
{
    (void) cs; (void) key; (void) out;
    return NGX_ERROR;
}

static int g_evicts;

ngx_int_t
brix_cstore_evict(brix_cstore_t *cs, const char *key)
{
    (void) cs; (void) key;
    g_evicts++;
    return NGX_OK;
}

/* The stage write/write-back planes (sd_stage_write.o / sd_stage_wb.o) are
 * REAL since phase-107 put the truncate_path/exchange/evict forwarders under
 * test in them; only the async engine below those planes is stubbed — nothing
 * here submits a transfer. */
const char *brix_stage_submit(brix_stage_kind_t k, brix_sd_instance_t *s,
    const char *sk, brix_sd_instance_t *d, const char *dk,
    const brix_stage_opts_t *o)
{ (void) k; (void) s; (void) sk; (void) d; (void) dk; (void) o; abort(); }
ngx_int_t brix_stage_run_inline_cred(brix_stage_kind_t k, brix_sd_instance_t *s,
    const char *sk, brix_sd_instance_t *d, const char *dk,
    const brix_stage_cred_t *c)
{ (void) k; (void) s; (void) sk; (void) d; (void) dk; (void) c; abort(); }

/* ---- the fake source ------------------------------------------------------
 * Records which arm ran and the credential pointer it was handed. `g_fail`
 * makes the source's op fail so eviction-on-success can be pinned. */
static int                    g_plain;
static int                    g_cred;
static const brix_sd_cred_t  *g_last_cred;
static int                    g_fail;

static void
reset(void)
{
    g_plain = 0;
    g_cred = 0;
    g_last_cred = NULL;
    g_fail = 0;
    g_evicts = 0;
    errno = 0;
}

static ngx_int_t
hit_plain(void)
{
    g_plain++;
    return g_fail ? NGX_ERROR : NGX_OK;
}

static ngx_int_t
hit_cred(const brix_sd_cred_t *cred)
{
    g_cred++;
    g_last_cred = cred;
    return g_fail ? NGX_ERROR : NGX_OK;
}

static ngx_int_t
src_stat(brix_sd_instance_t *i, const char *p, brix_sd_stat_t *o)
{ (void) i; (void) p; (void) o; return hit_plain(); }
static ngx_int_t
src_stat_cred(brix_sd_instance_t *i, const char *p, brix_sd_stat_t *o,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) o; return hit_cred(c); }

static ngx_int_t
src_unlink(brix_sd_instance_t *i, const char *p, int d)
{ (void) i; (void) p; (void) d; return hit_plain(); }
static ngx_int_t
src_unlink_cred(brix_sd_instance_t *i, const char *p, int d,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) d; return hit_cred(c); }

static ngx_int_t
src_mkdir(brix_sd_instance_t *i, const char *p, mode_t m)
{ (void) i; (void) p; (void) m; return hit_plain(); }
static ngx_int_t
src_mkdir_cred(brix_sd_instance_t *i, const char *p, mode_t m,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) m; return hit_cred(c); }

static ngx_int_t
src_rename(brix_sd_instance_t *i, const char *a, const char *b, int n)
{ (void) i; (void) a; (void) b; (void) n; return hit_plain(); }
static ngx_int_t
src_rename_cred(brix_sd_instance_t *i, const char *a, const char *b, int n,
    const brix_sd_cred_t *c)
{ (void) i; (void) a; (void) b; (void) n; return hit_cred(c); }

static ngx_int_t
src_truncate_path(brix_sd_instance_t *i, const char *p, off_t l)
{ (void) i; (void) p; (void) l; return hit_plain(); }
static ngx_int_t
src_truncate_path_cred(brix_sd_instance_t *i, const char *p, off_t l,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) l; return hit_cred(c); }

static ngx_int_t
src_setattr(brix_sd_instance_t *i, const char *p, const brix_sd_setattr_t *a)
{ (void) i; (void) p; (void) a; return hit_plain(); }
static ngx_int_t
src_setattr_cred(brix_sd_instance_t *i, const char *p,
    const brix_sd_setattr_t *a, const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) a; return hit_cred(c); }

static ngx_int_t
src_server_copy(brix_sd_instance_t *i, const char *a, const char *b, off_t *n)
{ (void) i; (void) a; (void) b; (void) n; return hit_plain(); }
static ngx_int_t
src_server_copy_cred(brix_sd_instance_t *i, const char *a, const char *b,
    off_t *n, const brix_sd_cred_t *c)
{ (void) i; (void) a; (void) b; (void) n; return hit_cred(c); }

static ssize_t
src_getxattr(brix_sd_instance_t *i, const char *p, const char *n, void *b,
    size_t cap)
{ (void) i; (void) p; (void) n; (void) b; (void) cap; return hit_plain(); }
static ssize_t
src_getxattr_cred(brix_sd_instance_t *i, const char *p, const char *n, void *b,
    size_t cap, const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) n; (void) b; (void) cap; return hit_cred(c); }

static ssize_t
src_listxattr(brix_sd_instance_t *i, const char *p, void *b, size_t cap)
{ (void) i; (void) p; (void) b; (void) cap; return hit_plain(); }
static ssize_t
src_listxattr_cred(brix_sd_instance_t *i, const char *p, void *b, size_t cap,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) b; (void) cap; return hit_cred(c); }

static ngx_int_t
src_setxattr(brix_sd_instance_t *i, const char *p, const char *n,
    const void *v, size_t l, int f)
{ (void) i; (void) p; (void) n; (void) v; (void) l; (void) f;
  return hit_plain(); }
static ngx_int_t
src_setxattr_cred(brix_sd_instance_t *i, const char *p, const char *n,
    const void *v, size_t l, int f, const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) n; (void) v; (void) l; (void) f;
  return hit_cred(c); }

static ngx_int_t
src_removexattr(brix_sd_instance_t *i, const char *p, const char *n)
{ (void) i; (void) p; (void) n; return hit_plain(); }
static ngx_int_t
src_removexattr_cred(brix_sd_instance_t *i, const char *p, const char *n,
    const brix_sd_cred_t *c)
{ (void) i; (void) p; (void) n; return hit_cred(c); }

/* The source's capacity report. Distinctive figures so a decorator that
 * answered from its own spool instead of relaying could not accidentally
 * produce them. */
#define SRC_TOTAL  ((uint64_t) 900000000007ULL)
#define SRC_USED   ((uint64_t) 400000000003ULL)
#define SRC_FREE   ((uint64_t) 500000000004ULL)

static ngx_int_t
src_space(brix_sd_instance_t *i, brix_sd_space_t *o)
{
    (void) i;
    if (g_fail) { g_plain++; errno = EIO; return NGX_ERROR; }
    o->total_bytes = SRC_TOTAL;
    o->used_bytes  = SRC_USED;
    o->free_bytes  = SRC_FREE;
    return hit_plain();
}

static brix_sd_dir_t g_dir;

static brix_sd_dir_t *
src_opendir(brix_sd_instance_t *i, const char *p, int *e)
{ (void) p; (void) e; g_plain++; g_dir.inst = i; return &g_dir; }
static brix_sd_dir_t *
src_opendir_cred(brix_sd_instance_t *i, const char *p, int *e,
    const brix_sd_cred_t *c)
{ (void) p; (void) e; g_cred++; g_last_cred = c; g_dir.inst = i;
  return &g_dir; }

/* Every slot, plain + cred: the source a per-user deployment actually has. */
static const brix_sd_driver_t src_full = {
    .name             = "fake-full",
    .space            = src_space,
    .stat             = src_stat,
    .unlink           = src_unlink,
    .mkdir            = src_mkdir,
    .rename           = src_rename,
    .setattr          = src_setattr,
    .truncate_path    = src_truncate_path,
    .server_copy      = src_server_copy,
    .opendir          = src_opendir,
    .getxattr         = src_getxattr,
    .listxattr        = src_listxattr,
    .setxattr         = src_setxattr,
    .removexattr      = src_removexattr,
    .stat_cred        = src_stat_cred,
    .unlink_cred      = src_unlink_cred,
    .mkdir_cred       = src_mkdir_cred,
    .rename_cred      = src_rename_cred,
    .setattr_cred     = src_setattr_cred,
    .truncate_path_cred = src_truncate_path_cred,
    .server_copy_cred = src_server_copy_cred,
    .opendir_cred     = src_opendir_cred,
    .getxattr_cred    = src_getxattr_cred,
    .listxattr_cred   = src_listxattr_cred,
    .setxattr_cred    = src_setxattr_cred,
    .removexattr_cred = src_removexattr_cred,
};

/* Plain slots only: the shape a deny-mode credential must refuse to ride. */
static const brix_sd_driver_t src_plain_only = {
    .name        = "fake-plain",
    .stat        = src_stat,
    .unlink      = src_unlink,
    .mkdir       = src_mkdir,
    .rename      = src_rename,
    .setattr       = src_setattr,
    .truncate_path = src_truncate_path,
    .server_copy = src_server_copy,
    .opendir     = src_opendir,
    .getxattr    = src_getxattr,
    .listxattr   = src_listxattr,
    .setxattr    = src_setxattr,
    .removexattr = src_removexattr,
};

/* No namespace slots at all: the errno contract of a source that cannot. */
static const brix_sd_driver_t src_empty = { .name = "fake-empty" };

/* ---- decorator instances over a chosen source ---------------------------- */
static brix_sd_instance_t   g_src;
static sd_cache_inst_state  g_cache_state;
static sd_stage_inst_state  g_stage_state;
static brix_sd_instance_t   g_cache;
static brix_sd_instance_t   g_stage;

extern const brix_sd_driver_t brix_sd_stage_driver;

/* The cache decorator's own vtable lives in sd_cache.o, which this test does
 * not link (it drags the whole fill/partial/manifest closure). Its forwarders
 * are non-static, so the routing is exercised by name — and the STAGE half is
 * dispatched through its real vtable, which pins the wiring itself. */
static void
bind_source(const brix_sd_driver_t *drv)
{
    ngx_memzero(&g_src, sizeof(g_src));
    g_src.driver = drv;

    ngx_memzero(&g_cache_state, sizeof(g_cache_state));
    g_cache_state.source = &g_src;
    ngx_memzero(&g_cache, sizeof(g_cache));
    g_cache.state = &g_cache_state;

    ngx_memzero(&g_stage_state, sizeof(g_stage_state));
    g_stage_state.source = &g_src;
    ngx_memzero(&g_stage, sizeof(g_stage));
    g_stage.driver = &brix_sd_stage_driver;
    g_stage.state  = &g_stage_state;
}

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

/* Ran the cred arm exactly once, with the very credential handed in. */
static void
expect_cred(const brix_sd_cred_t *cred, const char *what)
{
    CHECK(g_cred == 1 && g_plain == 0, what);
    CHECK(g_last_cred == cred, what);
}

static void
expect_plain(const char *what)
{
    CHECK(g_plain == 1 && g_cred == 0, what);
}

/* ---- 1: success — the credential survives both decorators ---------------- */
static void
test_cred_reaches_the_source(void)
{
    brix_sd_cred_t     cred;
    brix_sd_stat_t     stt;
    brix_sd_setattr_t  attr;
    const brix_sd_driver_t *sv = &brix_sd_stage_driver;
    off_t              n = 0;
    char               buf[8];

    ngx_memzero(&cred, sizeof(cred));
    ngx_memzero(&attr, sizeof(attr));
    bind_source(&src_full);

    /* --- structural: no published plain namespace slot may lack its twin. A
     * missing twin is precisely the shape that erases the credential, so this
     * is the regression gate, not a style check. */
    CHECK(sv->stat == NULL        || sv->stat_cred != NULL,        "stat twin");
    CHECK(sv->unlink == NULL      || sv->unlink_cred != NULL,      "unlink twin");
    CHECK(sv->mkdir == NULL       || sv->mkdir_cred != NULL,       "mkdir twin");
    CHECK(sv->rename == NULL      || sv->rename_cred != NULL,      "rename twin");
    CHECK(sv->setattr == NULL     || sv->setattr_cred != NULL,     "setattr twin");
    CHECK(sv->server_copy == NULL || sv->server_copy_cred != NULL, "copy twin");
    CHECK(sv->opendir == NULL     || sv->opendir_cred != NULL,     "opendir twin");
    CHECK(sv->getxattr == NULL    || sv->getxattr_cred != NULL,    "getxattr twin");
    CHECK(sv->listxattr == NULL   || sv->listxattr_cred != NULL,   "listxattr twin");
    CHECK(sv->setxattr == NULL    || sv->setxattr_cred != NULL,    "setxattr twin");
    CHECK(sv->removexattr == NULL || sv->removexattr_cred != NULL, "rmxattr twin");
    CHECK(sv->truncate_path == NULL || sv->truncate_path_cred != NULL,
          "truncate_path twin");

    /* --- cache decorator, cred arm */
    reset(); CHECK(sd_cache_stat_cred(&g_cache, "/a", &stt, &cred) == NGX_OK,
                   "cache stat_cred");
    expect_cred(&cred, "cache stat_cred routed");
    reset(); (void) sd_cache_unlink_cred(&g_cache, "/a", 0, &cred);
    expect_cred(&cred, "cache unlink_cred routed");
    CHECK(g_evicts == 1, "cache unlink_cred evicts on success");
    reset(); (void) sd_cache_mkdir_cred(&g_cache, "/a", 0755, &cred);
    expect_cred(&cred, "cache mkdir_cred routed");
    reset(); (void) sd_cache_rename_cred(&g_cache, "/a", "/b", 0, &cred);
    expect_cred(&cred, "cache rename_cred routed");
    reset(); (void) sd_cache_setattr_cred(&g_cache, "/a", &attr, &cred);
    expect_cred(&cred, "cache setattr_cred routed");
    CHECK(g_evicts == 1, "cache setattr_cred evicts (the cinfo holds the mode)");
    reset(); (void) sd_cache_truncate_path_cred(&g_cache, "/a", 4, &cred);
    expect_cred(&cred, "cache truncate_path_cred routed");
    CHECK(g_evicts == 1, "cache truncate_path_cred evicts (length changed)");
    reset(); (void) sd_cache_server_copy_cred(&g_cache, "/a", "/b", &n, &cred);
    expect_cred(&cred, "cache server_copy_cred routed");
    CHECK(g_evicts == 1, "cache server_copy_cred evicts the DESTINATION");
    reset(); CHECK(sd_cache_opendir_cred(&g_cache, "/a", NULL, &cred) == &g_dir,
                   "cache opendir_cred");
    expect_cred(&cred, "cache opendir_cred routed");
    reset(); (void) sd_cache_getxattr_cred(&g_cache, "/a", "n", buf,
                                           sizeof(buf), &cred);
    expect_cred(&cred, "cache getxattr_cred routed");
    reset(); (void) sd_cache_listxattr_cred(&g_cache, "/a", buf, sizeof(buf),
                                            &cred);
    expect_cred(&cred, "cache listxattr_cred routed");
    reset(); (void) sd_cache_setxattr_cred(&g_cache, "/a", "n", "v", 1, 0,
                                           &cred);
    expect_cred(&cred, "cache setxattr_cred routed");
    CHECK(g_evicts == 1, "cache setxattr_cred evicts (the store copy carries "
                         "the attributes, the seeded digest included)");
    reset(); (void) sd_cache_removexattr_cred(&g_cache, "/a", "n", &cred);
    expect_cred(&cred, "cache removexattr_cred routed");
    CHECK(g_evicts == 1, "cache removexattr_cred evicts");

    /* --- cache decorator, plain arm still reaches the plain slot */
    reset(); (void) sd_cache_stat(&g_cache, "/a", &stt);
    expect_plain("cache stat plain");
    reset(); (void) sd_cache_mkdir(&g_cache, "/a", 0755);
    expect_plain("cache mkdir plain");
    reset(); (void) sd_cache_getxattr(&g_cache, "/a", "n", buf, sizeof(buf));
    expect_plain("cache getxattr plain");
    reset(); CHECK(sd_cache_truncate_path(&g_cache, "/a", 4) == NGX_OK,
                   "cache truncate_path plain");
    expect_plain("cache truncate_path plain routed");

    /* An eviction is compensation for a SUCCESSFUL source mutation; a failed one
     * must leave the cached copy alone, or a transient origin error would throw
     * away a valid entry on every retry. */
    reset(); g_fail = 1;
    (void) sd_cache_truncate_path(&g_cache, "/a", 4);
    CHECK(g_evicts == 0, "cache truncate_path does not evict on failure");
    reset(); g_fail = 1;
    (void) sd_cache_setattr(&g_cache, "/a", &attr);
    CHECK(g_evicts == 0, "cache setattr does not evict on failure");
    reset(); g_fail = 1;
    (void) sd_cache_server_copy(&g_cache, "/a", "/b", &n);
    CHECK(g_evicts == 0, "cache server_copy does not evict on failure");
    reset(); g_fail = 1;
    (void) sd_cache_setxattr(&g_cache, "/a", "n", "v", 1, 0);
    CHECK(g_evicts == 0, "cache setxattr does not evict on failure");
    reset(); g_fail = 1;
    (void) sd_cache_removexattr(&g_cache, "/a", "n");
    CHECK(g_evicts == 0, "cache removexattr does not evict on failure");

    /* --- stage decorator, dispatched through its real vtable */
    reset(); (void) sv->stat_cred(&g_stage, "/a", &stt, &cred);
    expect_cred(&cred, "stage stat_cred routed");
    reset(); (void) sv->unlink_cred(&g_stage, "/a", 0, &cred);
    expect_cred(&cred, "stage unlink_cred routed");
    reset(); (void) sv->mkdir_cred(&g_stage, "/a", 0755, &cred);
    expect_cred(&cred, "stage mkdir_cred routed");
    reset(); (void) sv->rename_cred(&g_stage, "/a", "/b", 0, &cred);
    expect_cred(&cred, "stage rename_cred routed");
    reset(); (void) sv->setattr_cred(&g_stage, "/a", &attr, &cred);
    expect_cred(&cred, "stage setattr_cred routed");
    reset(); (void) sv->truncate_path_cred(&g_stage, "/a", 4, &cred);
    expect_cred(&cred, "stage truncate_path_cred routed");
    reset(); (void) sv->server_copy_cred(&g_stage, "/a", "/b", &n, &cred);
    expect_cred(&cred, "stage server_copy_cred routed");
    reset(); (void) sv->opendir_cred(&g_stage, "/a", NULL, &cred);
    expect_cred(&cred, "stage opendir_cred routed");
    reset(); (void) sv->getxattr_cred(&g_stage, "/a", "n", buf, sizeof(buf),
                                      &cred);
    expect_cred(&cred, "stage getxattr_cred routed");
    reset(); (void) sv->listxattr_cred(&g_stage, "/a", buf, sizeof(buf), &cred);
    expect_cred(&cred, "stage listxattr_cred routed");
    reset(); (void) sv->setxattr_cred(&g_stage, "/a", "n", "v", 1, 0, &cred);
    expect_cred(&cred, "stage setxattr_cred routed");
    reset(); (void) sv->removexattr_cred(&g_stage, "/a", "n", &cred);
    expect_cred(&cred, "stage removexattr_cred routed");
    reset(); (void) sv->stat(&g_stage, "/a", &stt);
    expect_plain("stage stat plain");

    printf("  ok   1: every cred slot on both decorators reaches the source's "
           "cred slot with the same credential\n");
}

/* ---- 2: error — the errno / no-op contracts survive the new routing ------ */
static void
test_absent_source_slots(void)
{
    brix_sd_cred_t     cred;
    brix_sd_setattr_t  attr;
    const brix_sd_driver_t *sv = &brix_sd_stage_driver;
    char               buf[8];

    ngx_memzero(&cred, sizeof(cred));
    ngx_memzero(&attr, sizeof(attr));
    bind_source(&src_empty);

    /* xattr: "this source has no extended attributes", not "no such call". */
    reset(); errno = 0;
    CHECK(sd_cache_getxattr_cred(&g_cache, "/a", "n", buf, sizeof(buf), &cred)
              == -1 && errno == ENOTSUP, "cache getxattr ENOTSUP");
    reset(); errno = 0;
    CHECK(sd_cache_listxattr(&g_cache, "/a", buf, sizeof(buf)) == -1
              && errno == ENOTSUP, "cache listxattr ENOTSUP");
    reset(); errno = 0;
    CHECK(sd_cache_setxattr_cred(&g_cache, "/a", "n", "v", 1, 0, &cred)
              == NGX_ERROR && errno == ENOTSUP, "cache setxattr ENOTSUP");
    reset(); errno = 0;
    CHECK(sd_cache_removexattr(&g_cache, "/a", "n") == NGX_ERROR
              && errno == ENOTSUP, "cache removexattr ENOTSUP");
    reset(); errno = 0;
    CHECK(sv->getxattr_cred(&g_stage, "/a", "n", buf, sizeof(buf), &cred) == -1
              && errno == ENOTSUP, "stage getxattr ENOTSUP");
    reset(); errno = 0;
    CHECK(sv->setxattr(&g_stage, "/a", "n", "v", 1, 0) == NGX_ERROR
              && errno == ENOTSUP, "stage setxattr ENOTSUP");

    /* No path-native truncate on the source: ENOTSUP, never the shared relay's
     * ENOSYS and never a bare success. brix_vfs_truncate_path reads "this
     * backend cannot" as "take the open+ftruncate fallback", so a decorator that
     * answered OK here would report a resize the origin never performed. */
    reset(); errno = 0;
    CHECK(sd_cache_truncate_path(&g_cache, "/a", 4) == NGX_ERROR
              && errno == ENOTSUP, "cache truncate_path ENOTSUP");
    reset(); errno = 0;
    CHECK(sv->truncate_path(&g_stage, "/a", 4) == NGX_ERROR
              && errno == ENOTSUP, "stage truncate_path ENOTSUP");

    /* setattr over a source with no mutable metadata stays an advisory no-op —
     * a decorator must not turn "nothing to do" into a client-visible error. */
    reset();
    CHECK(sd_cache_setattr_cred(&g_cache, "/a", &attr, &cred) == NGX_OK,
          "cache setattr no-op OK");
    reset();
    CHECK(sv->setattr_cred(&g_stage, "/a", &attr, &cred) == NGX_OK,
          "stage setattr no-op OK");

    /* A failing source must not have its cached copy dropped as if it had
     * succeeded — the eviction is conditioned on the return, cred or not. */
    bind_source(&src_full);
    reset(); g_fail = 1;
    CHECK(sd_cache_unlink_cred(&g_cache, "/a", 0, &cred) == NGX_ERROR,
          "cache unlink_cred propagates failure");
    CHECK(g_evicts == 0, "no eviction on a failed unlink");
    reset(); g_fail = 1;
    CHECK(sd_cache_rename_cred(&g_cache, "/a", "/b", 0, &cred) == NGX_ERROR,
          "cache rename_cred propagates failure");
    CHECK(g_evicts == 0, "no eviction on a failed rename");

    printf("  ok   2: ENOTSUP, the advisory setattr no-op and evict-on-success "
           "all survive the cred routing\n");
}

/* ---- 3: security-negative — deny mode never rides the service credential -- */
static void
test_deny_mode_never_leaks(void)
{
    brix_sd_cred_t     cred;
    brix_sd_stat_t     stt;
    brix_sd_setattr_t  attr;
    const brix_sd_driver_t *sv = &brix_sd_stage_driver;
    off_t              n = 0;
    char               buf[8];

    ngx_memzero(&cred, sizeof(cred));
    ngx_memzero(&attr, sizeof(attr));
    cred.fallback_deny = 1;
    bind_source(&src_plain_only);

#define DENIED(expr, msg)                                                     \
    do {                                                                      \
        reset();                                                              \
        errno = 0;                                                            \
        (void) (expr);                                                        \
        CHECK(errno == EACCES, msg " sets EACCES");                           \
        CHECK(g_plain == 0 && g_cred == 0, msg " never reached the source");  \
    } while (0)

    DENIED(sd_cache_stat_cred(&g_cache, "/a", &stt, &cred), "cache stat");
    DENIED(sd_cache_unlink_cred(&g_cache, "/a", 0, &cred), "cache unlink");
    DENIED(sd_cache_mkdir_cred(&g_cache, "/a", 0755, &cred), "cache mkdir");
    DENIED(sd_cache_rename_cred(&g_cache, "/a", "/b", 0, &cred), "cache rename");
    DENIED(sd_cache_setattr_cred(&g_cache, "/a", &attr, &cred), "cache setattr");
    DENIED(sd_cache_truncate_path_cred(&g_cache, "/a", 4, &cred),
           "cache truncate_path");
    DENIED(sd_cache_server_copy_cred(&g_cache, "/a", "/b", &n, &cred),
           "cache server_copy");
    DENIED(sd_cache_opendir_cred(&g_cache, "/a", NULL, &cred), "cache opendir");
    DENIED(sd_cache_getxattr_cred(&g_cache, "/a", "n", buf, sizeof(buf), &cred),
           "cache getxattr");
    DENIED(sd_cache_listxattr_cred(&g_cache, "/a", buf, sizeof(buf), &cred),
           "cache listxattr");
    DENIED(sd_cache_setxattr_cred(&g_cache, "/a", "n", "v", 1, 0, &cred),
           "cache setxattr");
    DENIED(sd_cache_removexattr_cred(&g_cache, "/a", "n", &cred),
           "cache removexattr");

    DENIED(sv->stat_cred(&g_stage, "/a", &stt, &cred), "stage stat");
    DENIED(sv->unlink_cred(&g_stage, "/a", 0, &cred), "stage unlink");
    DENIED(sv->mkdir_cred(&g_stage, "/a", 0755, &cred), "stage mkdir");
    DENIED(sv->rename_cred(&g_stage, "/a", "/b", 0, &cred), "stage rename");
    DENIED(sv->setattr_cred(&g_stage, "/a", &attr, &cred), "stage setattr");
    DENIED(sv->truncate_path_cred(&g_stage, "/a", 4, &cred),
           "stage truncate_path");
    DENIED(sv->server_copy_cred(&g_stage, "/a", "/b", &n, &cred),
           "stage server_copy");
    DENIED(sv->opendir_cred(&g_stage, "/a", NULL, &cred), "stage opendir");
    DENIED(sv->getxattr_cred(&g_stage, "/a", "n", buf, sizeof(buf), &cred),
           "stage getxattr");
    DENIED(sv->listxattr_cred(&g_stage, "/a", buf, sizeof(buf), &cred),
           "stage listxattr");
    DENIED(sv->setxattr_cred(&g_stage, "/a", "n", "v", 1, 0, &cred),
           "stage setxattr");
    DENIED(sv->removexattr_cred(&g_stage, "/a", "n", &cred),
           "stage removexattr");
#undef DENIED

    /* And the allow-mode fallback is untouched: a cred with fallback_deny==0
     * over a plain-only source still runs the plain slot, as it always did. */
    cred.fallback_deny = 0;
    reset();
    CHECK(sd_cache_mkdir_cred(&g_cache, "/a", 0755, &cred) == NGX_OK,
          "allow-mode fallback still works");
    expect_plain("allow-mode fallback took the plain slot");

    printf("  ok   3: deny-mode refuses every op at both decorators without "
           "touching the source; allow-mode fallback unchanged\n");
}

/* ---- 4: the space relay — capacity is the SOURCE's, or it is nothing -----
 *
 * `space` is not a credential-scoped op, but it is a decorator forwarder and it
 * fails the same way the cred slots did: a NULL slot on the decorator reads, one
 * tier up, as "this backend has no capacity model", and brix_vfs_space then falls
 * back to statvfs(2) on the export root — which for a cache or stage tier is the
 * LOCAL SPOOL, not the backend the bytes actually live on. A client sizing a
 * write against that answer sizes it against the wrong disk entirely.
 *
 *   success        — both decorators publish the slot and relay the source's own
 *                    three figures byte for byte.
 *   error          — a source with no capacity model is ENOTSUP (so the caller
 *                    takes its documented statvfs fallback), and a source whose
 *                    query fails propagates the failure rather than smoothing it.
 *   security-neg   — on any failure the decorator writes NOTHING into the
 *                    caller's struct: a fabricated capacity is worse than none.
 */
static void
test_space_relayed_from_the_source(void)
{
    const brix_sd_driver_t *sv = &brix_sd_stage_driver;
    brix_sd_space_t         sp;

    CHECK(sv->space != NULL, "the stage vtable publishes space");

    bind_source(&src_full);

    reset();
    ngx_memzero(&sp, sizeof(sp));
    CHECK(sd_cache_space(&g_cache, &sp) == NGX_OK, "cache space ok");
    expect_plain("cache space routed to the source");
    CHECK(sp.total_bytes == SRC_TOTAL && sp.used_bytes == SRC_USED
          && sp.free_bytes == SRC_FREE,
          "cache relays the source's figures, not the spool's");

    reset();
    ngx_memzero(&sp, sizeof(sp));
    CHECK(sv->space(&g_stage, &sp) == NGX_OK, "stage space ok");
    expect_plain("stage space routed to the source");
    CHECK(sp.total_bytes == SRC_TOTAL && sp.used_bytes == SRC_USED
          && sp.free_bytes == SRC_FREE,
          "stage relays the source's figures, not the spool's");

    /* A source with no capacity model: ENOTSUP, which is what tells the caller
     * to fall back — never NGX_OK with a zeroed struct, which reads as a full
     * export, and never the decorator's own local disk. */
    bind_source(&src_empty);
    reset(); errno = 0;
    memset(&sp, 0xee, sizeof(sp));
    CHECK(sd_cache_space(&g_cache, &sp) == NGX_ERROR && errno == ENOTSUP,
          "cache space ENOTSUP with no source slot");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "and leaves the caller's struct untouched");
    reset(); errno = 0;
    memset(&sp, 0xee, sizeof(sp));
    CHECK(sv->space(&g_stage, &sp) == NGX_ERROR && errno == ENOTSUP,
          "stage space ENOTSUP with no source slot");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "and leaves the caller's struct untouched");

    /* A source whose own query fails propagates: the decorator has no second
     * opinion to offer, and inventing one would be a fabricated capacity. */
    bind_source(&src_full);
    reset(); g_fail = 1; errno = 0;
    memset(&sp, 0xee, sizeof(sp));
    CHECK(sd_cache_space(&g_cache, &sp) == NGX_ERROR,
          "cache space propagates a source failure");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "a failed cache space writes no figures");
    reset(); g_fail = 1; errno = 0;
    memset(&sp, 0xee, sizeof(sp));
    CHECK(sv->space(&g_stage, &sp) == NGX_ERROR,
          "stage space propagates a source failure");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "a failed stage space writes no figures");

    printf("  ok   4: both decorators relay the SOURCE's capacity, and report "
           "nothing at all when it has none\n");
}

int
main(void)
{
    test_cred_reaches_the_source();
    test_absent_source_slots();
    test_deny_mode_never_leaks();
    test_space_relayed_from_the_source();
    printf("test_decorator_cred_forward: ALL PASS\n");
    return 0;
}
