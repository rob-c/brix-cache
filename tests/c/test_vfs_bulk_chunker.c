/*
 * test_vfs_bulk_chunker.c — phase-107 C4: the per-level rmtree chunker
 * (brix_vfs_rmtree_dispatch / brix_vfs_rmtree_bulk / the accumulation window)
 * driven hermetically over a fake namespace.
 *
 * WHAT: links the REAL vfs_unlink_many.o against a spy driver whose stat /
 *       opendir / readdir / unlink / unlink_many slots operate on an in-memory
 *       tree, and pins the three things the file's own banner promises and
 *       nothing else in the tree asserts: LEVEL BOUNDARIES (every descendant
 *       key is gone before its directory's own removal), WINDOW FILL (a batch
 *       is never larger than BRIX_SD_BULK_DELETE_WINDOW and the split lands on
 *       the constant, not near it), and SHORT `done` (a transport failure at
 *       key k leaves keys k..n exactly ECANCELED — never "deleted").
 *
 * WHY:  test_vfs_new_mutator_gate.c covers the FLAT entry brix_vfs_delete_many
 *       (policy, ordering, one batch per window, deny-mode). The recursive arm
 *       has no hermetic coverage at all: its correctness content is an
 *       ORDERING property between two different driver slots across recursion
 *       levels, which a wire test cannot see (the client is told "removed"
 *       either way) and which only shows up on a backend with real
 *       collections — i.e. in production, as a half-removed tree. The batch
 *       contract's ECANCELED pre-fill is the difference between a partially
 *       failed DeleteObjects and a caller that believes 997 keys it never
 *       tried are gone.
 *
 * HOW:  every removal stamps a monotonic clock on its node, so the level rule
 *       is asserted UNIVERSALLY — for every node with a parent in the tree,
 *       child.removed_at < parent.removed_at — instead of by reading a tape
 *       for one hand-picked pair. The unlink_many spy asserts on ENTRY that
 *       every result slot it was handed reads ECANCELED, which turns the
 *       pre-fill from an implementation detail into a link-time contract, and
 *       records the batch sizes it saw so the window split is checked against
 *       the constant. Capability probe and batch dispatch each record the
 *       instance they were handed (the R-wave truncate_path lesson: gate and
 *       dispatch must land on the SAME instance).
 *
 * Cases:
 *   success:      children of every directory are removed before it is;
 *                 2 500 keys in one directory split 1000/1000/500 and no batch
 *                 ever exceeds the window; a leaf without CAP_BULK_DELETE, and
 *                 a leaf with the cap but no slot, both fall to the classic
 *                 per-key walk with the batch slot untouched; the capability
 *                 probe and the batch land on the same instance.
 *   error:        a transport failure after k keys returns that errno with
 *                 exactly k keys gone, the untried keys still present and the
 *                 parent directory NOT removed; a per-key failure inside an
 *                 NGX_OK batch fails the walk with that key's errno; a stat
 *                 failure mid-walk aborts with its errno intact across the
 *                 window teardown and removes nothing.
 *   security-neg: deny-mode credential over a batch slot with no _cred twin
 *                 refuses the WHOLE batch (EACCES, zero keys gone, directory
 *                 intact); a driver that scribbles success into result slots
 *                 past the `done` it reported cannot inflate the removed count
 *                 (`done` is the authority, not the vector); every flush is
 *                 verified to have been pre-filled
 *                 with ECANCELED; a directory chain deeper than
 *                 BRIX_FS_TREE_MAX_DEPTH is ELOOP with nothing removed (a
 *                 directory bomb cannot be half-deleted); a spoofed d_type is
 *                 never authority — stat decides file-vs-directory in both
 *                 directions; the bulk metric carries the key count in the
 *                 VALUE with the backend name as the only label (INVARIANT 8).
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_bulk_chunker").
 */
#include "fs/vfs/vfs_internal.h"
#include "fs/backend/sd_accessors.h"
#include "fs/backend/ucred.h"
#include "fs/vfs/vfs_cred_internal.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/fs_walk.h"
#include "observability/metrics/access_log.h"
#include "observability/metrics/unified.h"

#include "vfs_order_spy.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the fake namespace --------------------------------------------------
 * A flat node table; a directory's children are the nodes whose path is the
 * directory's path plus exactly one component. Removal stamps a monotonic
 * clock rather than deleting the row, so the ordering between two different
 * driver slots survives to the assertions. */
#define NODES_MAX 4096

typedef struct {
    char          *path;
    int            is_dir;
    unsigned char  d_type;      /* what readdir CLAIMS — a hint, never truth */
    int            removed_at;  /* 0 = still present                        */
} node_t;

static node_t  g_node[NODES_MAX];
static size_t  g_nodes;
static int     g_clock;

static void
tree_reset(void)
{
    size_t i;

    for (i = 0; i < g_nodes; i++) {
        free(g_node[i].path);
    }
    memset(g_node, 0, sizeof(g_node));
    g_nodes = 0;
    g_clock = 0;
}

static void
tree_add(const char *path, int is_dir)
{
    assert(g_nodes < NODES_MAX);
    g_node[g_nodes].path      = strdup(path);
    assert(g_node[g_nodes].path != NULL);
    g_node[g_nodes].is_dir    = is_dir;
    g_node[g_nodes].d_type    = is_dir ? DT_DIR : DT_REG;
    g_node[g_nodes].removed_at = 0;
    g_nodes++;
}

/* Index of a LIVE node, or -1. */
static int
node_find(const char *path)
{
    size_t i;

    for (i = 0; i < g_nodes; i++) {
        if (g_node[i].removed_at == 0 && strcmp(g_node[i].path, path) == 0) {
            return (int) i;
        }
    }
    return -1;
}

static size_t
tree_live(void)
{
    size_t i, live = 0;

    for (i = 0; i < g_nodes; i++) {
        if (g_node[i].removed_at == 0) {
            live++;
        }
    }
    return live;
}

/* `path` is an immediate child of `parent` (neither is the other). */
static int
is_direct_child(const char *parent, const char *path)
{
    size_t plen = strcmp(parent, "/") == 0 ? 0 : strlen(parent);

    if (strncmp(path, parent, plen) != 0 || path[plen] != '/') {
        return 0;
    }
    return strchr(path + plen + 1, '/') == NULL;
}

/* The universal level rule: nothing may outlive its own parent directory. */
static void
assert_children_before_parents(const char *what)
{
    size_t i, j;

    for (i = 0; i < g_nodes; i++) {
        for (j = 0; j < g_nodes; j++) {
            if (i == j || !g_node[j].is_dir
                || !is_direct_child(g_node[j].path, g_node[i].path))
            {
                continue;
            }
            if (g_node[j].removed_at == 0) {
                continue;                 /* parent still there: nothing owed */
            }
            if (g_node[i].removed_at == 0
                || g_node[i].removed_at > g_node[j].removed_at)
            {
                fprintf(stderr, "LEVEL FAIL (%s): %s (at %d) outlived its "
                        "parent %s (at %d)\n", what, g_node[i].path,
                        g_node[i].removed_at, g_node[j].path,
                        g_node[j].removed_at);
                assert(0);
            }
        }
    }
}

/* ---- spy state ----------------------------------------------------------- */
#define BATCHES_MAX 16

static size_t   g_batch_sz[BATCHES_MAX];
static size_t   g_batches;
static size_t   g_prefill_checked;        /* flushes proven ECANCELED-filled  */
static int      g_unlink_many_calls;
static int      g_unlink_calls;
static int      g_unlink_is_dir_last;
static int      g_classic_calls;          /* the non-bulk fallback walk       */
static const brix_sd_instance_t *g_caps_inst;
static const brix_sd_instance_t *g_batch_inst;

/* injection */
static int      g_batch_stop_at = -1;     /* >=0: attempt only this many keys */
static int      g_batch_stop_errno;
static int      g_batch_lie_beyond_done;  /* zero result slots past `done`    */
static int      g_batch_key_err_at = -1;  /* >=0: this key fails inside NGX_OK*/
static int      g_batch_key_errno;
static const char *g_stat_fail_path;      /* stat this path with ...          */
static int      g_stat_fail_errno;
static uint32_t g_caps = BRIX_SD_CAP_BULK_DELETE;

/* metric observations */
#define METRICS_MAX 16
static const char *g_metric_label[METRICS_MAX];
static size_t      g_metric_keys[METRICS_MAX];
static size_t      g_metrics;

static void
spy_reset(void)
{
    memset(g_batch_sz, 0, sizeof(g_batch_sz));
    memset(g_metric_label, 0, sizeof(g_metric_label));
    memset(g_metric_keys, 0, sizeof(g_metric_keys));
    g_batches = 0;
    g_metrics = 0;
    g_prefill_checked = 0;
    g_unlink_many_calls = 0;
    g_unlink_calls = 0;
    g_unlink_is_dir_last = -1;
    g_classic_calls = 0;
    g_caps_inst = NULL;
    g_batch_inst = NULL;
    g_batch_stop_at = -1;
    g_batch_stop_errno = 0;
    g_batch_lie_beyond_done = 0;
    g_batch_key_err_at = -1;
    g_batch_key_errno = 0;
    g_stat_fail_path = NULL;
    g_stat_fail_errno = 0;
    g_caps = BRIX_SD_CAP_BULK_DELETE;
    ord_reset();
    tree_reset();
}

static size_t
metric_keys_total(void)
{
    size_t i, total = 0;

    for (i = 0; i < g_metrics; i++) {
        total += g_metric_keys[i];
    }
    return total;
}

/* ---- the spy driver ------------------------------------------------------ */
typedef struct {
    char   parent[PATH_MAX];
    size_t cursor;
} fake_dir_t;

static ngx_int_t
spy_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    int idx;

    (void) inst;
    if (g_stat_fail_path != NULL && strcmp(path, g_stat_fail_path) == 0) {
        errno = g_stat_fail_errno;
        return NGX_ERROR;
    }
    idx = node_find(path);
    if (idx < 0) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    memset(out, 0, sizeof(*out));
    out->is_dir = g_node[idx].is_dir ? 1u : 0u;
    out->is_reg = g_node[idx].is_dir ? 0u : 1u;
    return NGX_OK;
}

static brix_sd_dir_t *
spy_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    brix_sd_dir_t *d;
    fake_dir_t      *fd;

    if (node_find(path) < 0) {
        if (err_out != NULL) {
            *err_out = ENOENT;
        }
        return NULL;
    }
    d  = calloc(1, sizeof(*d));
    fd = calloc(1, sizeof(*fd));
    assert(d != NULL && fd != NULL);
    snprintf(fd->parent, sizeof(fd->parent), "%s", path);
    d->inst  = inst;
    d->state = fd;
    return d;
}

static ngx_int_t
spy_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    fake_dir_t *fd = d->state;

    while (fd->cursor < g_nodes) {
        node_t *n = &g_node[fd->cursor++];

        if (n->removed_at != 0 || !is_direct_child(fd->parent, n->path)) {
            continue;
        }
        memset(out, 0, sizeof(*out));
        snprintf(out->name, sizeof(out->name), "%s",
                 strrchr(n->path, '/') + 1);
        out->d_type = n->d_type;
        return NGX_OK;
    }
    return NGX_DONE;
}

static ngx_int_t
spy_closedir(brix_sd_dir_t *d)
{
    free(d->state);
    free(d);
    return NGX_OK;
}

static ngx_int_t
spy_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    int idx;

    (void) inst;
    ord_hit(ORD_BACKEND);
    g_unlink_calls++;
    g_unlink_is_dir_last = is_dir;
    idx = node_find(path);
    if (idx < 0) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    g_node[idx].removed_at = ++g_clock;
    return NGX_OK;
}

static ngx_int_t
spy_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    size_t i, attempt;
    int    all_cancelled = 1;

    ord_hit(ORD_BACKEND);
    g_unlink_many_calls++;
    g_batch_inst = inst;

    /* The pre-fill IS the contract: a key this slot never reaches must read
     * ECANCELED, not 0, whatever the caller does next. */
    for (i = 0; i < b->n; i++) {
        if (b->errs[i] != ECANCELED) {
            all_cancelled = 0;
        }
    }
    assert(all_cancelled
           && "unlink_many was handed a result vector that was not pre-filled "
              "with ECANCELED");
    g_prefill_checked++;

    assert(b->n <= BRIX_SD_BULK_DELETE_WINDOW
           && "a flush larger than the accumulation window");
    if (g_batches < BATCHES_MAX) {
        g_batch_sz[g_batches] = b->n;
    }
    g_batches++;

    attempt = (g_batch_stop_at >= 0 && (size_t) g_batch_stop_at < b->n)
                  ? (size_t) g_batch_stop_at
                  : b->n;
    for (i = 0; i < attempt; i++) {
        int idx;

        if (g_batch_key_err_at >= 0 && i == (size_t) g_batch_key_err_at) {
            b->errs[i] = g_batch_key_errno;
            b->done++;
            continue;
        }
        idx = node_find(b->paths[i]);
        if (idx < 0) {
            b->errs[i] = ENOENT;
            b->done++;
            continue;
        }
        g_node[idx].removed_at = ++g_clock;
        b->errs[i] = 0;
        b->done++;
    }
    if (attempt != b->n) {
        if (g_batch_lie_beyond_done) {
            /* A driver that scribbles success into slots it never attempted,
             * while still reporting the honest `done`. */
            for (i = attempt; i < b->n; i++) {
                b->errs[i] = 0;
            }
        }
        errno = g_batch_stop_errno;
        return NGX_ERROR;               /* errs[attempt..n) stay ECANCELED */
    }
    return NGX_OK;
}

/* _cred twins for the walk's read-side slots, so a deny-mode credential can
 * reach the BATCH slot (the one deliberately left without a twin) instead of
 * being refused at the first stat. */
static ngx_int_t
spy_stat_cred(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    return spy_stat(inst, path, out);
}

static brix_sd_dir_t *
spy_opendir_cred(brix_sd_instance_t *inst, const char *path, int *err_out,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    return spy_opendir(inst, path, err_out);
}

static brix_sd_driver_t  g_drv;
static brix_sd_instance_t g_leaf;

static void
driver_reset(void)
{
    memset(&g_drv, 0, sizeof(g_drv));
    g_drv.stat        = spy_stat;
    g_drv.opendir     = spy_opendir;
    g_drv.readdir     = spy_readdir;
    g_drv.closedir    = spy_closedir;
    g_drv.unlink      = spy_unlink;
    g_drv.unlink_many = spy_unlink_many;

    memset(&g_leaf, 0, sizeof(g_leaf));
    g_leaf.driver = &g_drv;
}

static void
reset_all(void)
{
    spy_reset();
    driver_reset();
}

/* ---- the cross-TU closure ------------------------------------------------ */
uint32_t
brix_sd_caps(const brix_sd_instance_t *inst)
{
    (void) inst;
    return g_caps;
}

ngx_int_t
brix_sd_supports(const brix_sd_instance_t *inst, uint32_t required_caps)
{
    ord_hit(ORD_CAP);
    g_caps_inst = inst;
    return (g_caps & required_caps) == required_caps ? NGX_OK : NGX_ERROR;
}

const char *
brix_sd_backend_name(const brix_sd_instance_t *inst)
{
    (void) inst;
    return "spy-bulk";
}

void
brix_metric_vfs_bulk_delete(const char *driver_name, size_t keys)
{
    assert(g_metrics < METRICS_MAX);
    g_metric_label[g_metrics] = driver_name;
    g_metric_keys[g_metrics]  = keys;
    g_metrics++;
}

/* The classic per-key walk: a spy, so "fell back" is an assertion rather than
 * an absence of evidence. */
ngx_int_t
brix_vfs_driver_rmtree(brix_sd_instance_t *leaf, const brix_sd_driver_t *drv,
    const char *logical, const brix_sd_cred_t *cred, ngx_uint_t depth)
{
    (void) leaf; (void) drv; (void) logical; (void) cred; (void) depth;
    g_classic_calls++;
    return NGX_OK;
}

/* Everything below belongs to brix_vfs_delete_many(), which this unit never
 * calls (test_vfs_new_mutator_gate.c owns that entry point). They abort rather
 * than return, so a future refactor that routes the chunker through any of
 * them fails loudly here instead of silently changing what is under test. */
#define UNREACHED(name)  do {                                                 \
        fprintf(stderr, "unexpected call: %s\n", (name));                     \
        abort();                                                              \
    } while (0)

void
brix_access_log_emit(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result, size_t bytes,
    brix_err_class_t err, ngx_msec_t latency_usec)
{
    (void) ctx; (void) path; (void) op; (void) result; (void) bytes;
    (void) err; (void) latency_usec;
    UNREACHED("brix_access_log_emit");
}

void
brix_metric_backend_bytes(const char *backend_name, brix_metric_op_t op,
    size_t bytes)
{
    (void) backend_name; (void) op; (void) bytes;
    UNREACHED("brix_metric_backend_bytes");
}

void
brix_metric_cache_evicted(brix_proto_t proto, uint64_t bytes)
{
    (void) proto; (void) bytes;
    UNREACHED("brix_metric_cache_evicted");
}

brix_err_class_t
brix_metric_err_from_errno(int sys_errno)
{
    (void) sys_errno;
    UNREACHED("brix_metric_err_from_errno");
}

void
brix_metric_op_done(brix_proto_t proto, brix_metric_op_t op, size_t bytes,
    ngx_msec_t latency_usec, brix_err_class_t err)
{
    (void) proto; (void) op; (void) bytes; (void) latency_usec; (void) err;
    UNREACHED("brix_metric_op_done");
}

brix_ns_result_t
brix_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const brix_ns_delete_opts_t *opts)
{
    (void) log; (void) root_canon; (void) path; (void) opts;
    UNREACHED("brix_ns_delete");
}

brix_ns_result_t
brix_ns_delete_at(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *path, const brix_ns_delete_opts_t *opts)
{
    (void) log; (void) rootfd; (void) root_canon; (void) path; (void) opts;
    UNREACHED("brix_ns_delete_at");
}

ngx_int_t
brix_path_resolved_to_pfn(const brix_vfs_ctx_t *ctx, const char *resolved_path,
    char *pfn, size_t cap)
{
    (void) ctx; (void) resolved_path; (void) pfn; (void) cap;
    UNREACHED("brix_path_resolved_to_pfn");
}

uint64_t
brix_sd_cache_evict(brix_sd_instance_t *inst, const char *key)
{
    (void) inst; (void) key;
    UNREACHED("brix_sd_cache_evict");
}

const brix_sd_driver_t *
brix_sd_default_driver(void)
{
    UNREACHED("brix_sd_default_driver");
}

void
brix_sd_ucred_wipe(brix_sd_ucred_t *cred)
{
    (void) cred;
    UNREACHED("brix_sd_ucred_wipe");
}

int
brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx)
{
    (void) ctx;
    UNREACHED("brix_vfs_cred_gate_active");
}

ngx_int_t
brix_vfs_gate_confined(const brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    (void) ctx; (void) op;
    UNREACHED("brix_vfs_gate_confined");
}

ngx_int_t
brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    (void) ctx; (void) store; (void) cred; (void) use_cred; (void) err_out;
    UNREACHED("brix_vfs_ns_cred");
}

brix_sd_instance_t *
brix_vfs_ns_leaf(brix_sd_instance_t *top)
{
    (void) top;
    UNREACHED("brix_vfs_ns_leaf");
}

ngx_int_t
brix_vfs_require_unlocked_many(brix_vfs_ctx_t *ctx, const char *const *paths,
    size_t n, brix_vfs_mutation_op_t op)
{
    (void) ctx; (void) paths; (void) n; (void) op;
    UNREACHED("brix_vfs_require_unlocked_many");
}

/* ---- fixtures ------------------------------------------------------------ */
/* /t
 *   /t/f1  /t/f2           files, accumulate in the window
 *   /t/sub                 a directory whose boundary must flush them
 *     /t/sub/g1 /t/sub/g2
 *   /t/z9                  a file DECLARED AFTER the subdirectory
 */
static void
build_mixed_tree(void)
{
    tree_add("/t", 1);
    tree_add("/t/f1", 0);
    tree_add("/t/f2", 0);
    tree_add("/t/sub", 1);
    tree_add("/t/sub/g1", 0);
    tree_add("/t/sub/g2", 0);
    tree_add("/t/z9", 0);
}

static void
build_wide_tree(size_t files)
{
    size_t i;

    tree_add("/w", 1);
    for (i = 0; i < files; i++) {
        char p[64];

        snprintf(p, sizeof(p), "/w/f%06zu", i);
        tree_add(p, 0);
    }
}

/* ---- success ------------------------------------------------------------- */
static void
test_success_children_are_gone_before_every_directory(void)
{
    reset_all();
    build_mixed_tree();

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_OK);

    assert(tree_live() == 0 && "the whole tree is gone");
    assert_children_before_parents("mixed tree");

    /* Two flushes: the /t/sub boundary drains f1,f2,g1,g2 (sibling files may
     * flush early — they are deletable any time before their OWN parent's
     * boundary), then /t's boundary drains z9. */
    assert(g_batches == 2 && g_batch_sz[0] == 4 && g_batch_sz[1] == 1);
    assert(g_unlink_calls == 2 && "one rmdir per directory, never per file");
    ord_assert_before(ORD_CAP, ORD_BACKEND,
                      "the capability answer precedes any backend call");
    ord_assert_count(ORD_CAP, 1,
                     "ONE capability decision per rmtree, taken at dispatch — "
                     "not re-probed per level or per flush");
    ord_assert_absent(ORD_POLICY,
                      "the chunker is below the policy gate: its callers own "
                      "the mutation check, and it must not re-answer it");
}

static void
test_success_window_fills_at_exactly_the_constant(void)
{
    size_t files = 2 * BRIX_SD_BULK_DELETE_WINDOW + 500;

    reset_all();
    build_wide_tree(files);

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_OK);

    assert(tree_live() == 0);
    assert(g_batches == 3 && "2 500 keys is three round trips, not 2 500");
    assert(g_batch_sz[0] == BRIX_SD_BULK_DELETE_WINDOW);
    assert(g_batch_sz[1] == BRIX_SD_BULK_DELETE_WINDOW);
    assert(g_batch_sz[2] == 500 && "the split lands ON the constant");
    assert(metric_keys_total() == files);
}

static void
test_success_dispatch_falls_back_without_the_capability(void)
{
    /* no capability, real slot */
    reset_all();
    build_mixed_tree();
    g_caps = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_OK);
    assert(g_classic_calls == 1 && g_unlink_many_calls == 0);
    assert(tree_live() == 7 && "the fallback spy removes nothing here");

    /* capability, no slot — the cap bit alone must never dispatch into NULL */
    reset_all();
    build_mixed_tree();
    g_drv.unlink_many = NULL;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_OK);
    assert(g_classic_calls == 1 && g_unlink_many_calls == 0);
}

static void
test_success_capability_and_batch_land_on_the_same_instance(void)
{
    reset_all();
    build_mixed_tree();

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_OK);

    /* The R-wave truncate_path lesson: a cap probed on one instance and a slot
     * dispatched on another loses the slot behind a decorator. */
    assert(g_caps_inst == &g_leaf && g_batch_inst == &g_leaf);
}

/* ---- error --------------------------------------------------------------- */
static void
test_error_a_transport_failure_leaves_untried_keys_cancelled(void)
{
    reset_all();
    build_wide_tree(10);
    g_batch_stop_at    = 3;
    g_batch_stop_errno = ECONNRESET;

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_ERROR);
    assert(errno == ECONNRESET && "the driver's errno survives the teardown");
    assert(tree_live() == 8 && "exactly the three attempted keys are gone");
    assert(node_find("/w") >= 0
           && "a failed flush aborts before the directory's own removal");
    assert(g_unlink_calls == 0);
    /* The metric counts what was ATTEMPTED AND SUCCEEDED, never the window. */
    assert(g_metrics == 1 && g_metric_keys[0] == 3);
}

static void
test_error_a_per_key_failure_fails_the_walk_with_that_errno(void)
{
    reset_all();
    build_wide_tree(10);
    g_batch_key_err_at = 2;
    g_batch_key_errno  = EPERM;

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_ERROR);
    assert(errno == EPERM
           && "an NGX_OK batch with a failed key still fails the walk — the "
              "classic walk aborts on the first failed unlink and a batch "
              "must not weaken that");
    assert(node_find("/w") >= 0 && node_find("/w/f000002") >= 0);
    assert(g_metrics == 1 && g_metric_keys[0] == 9);
}

static void
test_error_a_stat_failure_aborts_the_walk_with_its_errno(void)
{
    reset_all();
    build_mixed_tree();
    g_stat_fail_path  = "/t/sub/g2";
    g_stat_fail_errno = EIO;

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_ERROR);
    assert(errno == EIO
           && "the window teardown (free of the owned key copies) must not "
              "clobber the errno the caller reports");
    assert(tree_live() == 7 && "an aborted walk flushes nothing");
    assert(g_unlink_many_calls == 0 && g_unlink_calls == 0);
}

/* ---- security-negative --------------------------------------------------- */
static void
test_secneg_deny_mode_refuses_the_whole_batch(void)
{
    brix_sd_cred_t cred;

    reset_all();
    build_wide_tree(10);

    memset(&cred, 0, sizeof(cred));
    cred.fallback_deny = 1;
    /* stat/opendir carry _cred twins so the WALK is allowed to proceed; only
     * the batch slot lacks one, which is the case the forwarding rule exists
     * for — running the batch as the export identity would be the confused
     * deputy this refusal prevents. */
    g_drv.stat_cred        = spy_stat_cred;
    g_drv.opendir_cred     = spy_opendir_cred;
    g_drv.unlink_many_cred = NULL;

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", &cred) == NGX_ERROR);
    assert(errno == EACCES && "no _cred batch twin under deny-mode is EACCES");
    assert(tree_live() == 11 && "zero keys removed, directory intact");
    assert(g_unlink_many_calls == 0
           && "the refusal happens in the forwarding rule, not the driver");
    assert(g_metrics == 1 && g_metric_keys[0] == 0
           && "a refused flush books zero removals, not the window size");
}

static void
test_secneg_a_driver_writing_past_done_cannot_inflate_the_count(void)
{
    reset_all();
    build_wide_tree(10);
    g_batch_stop_at         = 3;
    g_batch_stop_errno      = ECONNRESET;
    g_batch_lie_beyond_done = 1;

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_ERROR);
    assert(errno == ECONNRESET);
    assert(tree_live() == 8 && "the lie is telemetric — nothing extra is gone");
    /* `done` is the authority on what was attempted, NOT the result vector: a
     * driver that overwrites slots past `done` (a bug, or a backend answering
     * for keys it never sent) must not be able to inflate the removed count
     * the operator sees, which is the only evidence a bulk delete leaves. */
    assert(g_metrics == 1 && g_metric_keys[0] == 3
           && "the count is bounded by `done`, never by the window");
}

static void
test_secneg_every_flush_is_prefilled_with_cancelled(void)
{
    reset_all();
    build_wide_tree(2 * BRIX_SD_BULK_DELETE_WINDOW + 500);

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_OK);

    /* The spy asserts the pre-fill on ENTRY; this pins that it actually ran on
     * every flush and was not skipped by an empty-window shortcut. */
    assert(g_prefill_checked == 3 && g_prefill_checked == g_batches);
}

static void
test_secneg_depth_beyond_the_cap_is_eloop_and_removes_nothing(void)
{
    char   p[4096];
    size_t used = 0;
    size_t i, levels = BRIX_FS_TREE_MAX_DEPTH + 8;

    reset_all();
    for (i = 0; i < levels; i++) {
        used += (size_t) snprintf(p + used, sizeof(p) - used, "/d");
        tree_add(p, 1);
    }

    errno = 0;
    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/d", NULL) == NGX_ERROR);
    assert(errno == ELOOP && "a chain past BRIX_FS_TREE_MAX_DEPTH is refused");
    assert(tree_live() == levels
           && "a directory bomb is refused whole — never half-removed");
    assert(g_unlink_calls == 0 && g_unlink_many_calls == 0);
}

static void
test_secneg_dtype_is_a_hint_and_never_authority(void)
{
    reset_all();
    build_mixed_tree();

    /* A backend that classifies from a key listing can be made to claim
     * anything; sd_remote_dir.c says d_type is a hint in as many words. Lie in
     * BOTH directions and require stat to decide: the directory must still be
     * recursed and rmdir'd (never batched as a key, which on a real collection
     * would fail or, worse, succeed against the prefix), and the file must
     * still be batched (never rmdir'd). */
    g_node[3].d_type = DT_REG;            /* /t/sub claims to be a file  */
    g_node[1].d_type = DT_DIR;            /* /t/f1  claims to be a dir   */

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/t", NULL) == NGX_OK);

    assert(tree_live() == 0);
    assert_children_before_parents("spoofed d_type");
    assert(g_batches == 2 && g_batch_sz[0] == 4 && g_batch_sz[1] == 1
           && "the shape is identical to the honest tree");
    assert(g_unlink_calls == 2 && g_unlink_is_dir_last == 1);
}

static void
test_secneg_the_metric_carries_the_count_in_the_value(void)
{
    size_t i;

    reset_all();
    build_wide_tree(2 * BRIX_SD_BULK_DELETE_WINDOW + 500);

    assert(brix_vfs_rmtree_dispatch(&g_leaf, &g_drv, "/w", NULL) == NGX_OK);

    assert(g_metrics == 3);
    for (i = 0; i < g_metrics; i++) {
        assert(strcmp(g_metric_label[i], "spy-bulk") == 0
               && "the only label is the backend name (INVARIANT 8)");
        assert(strpbrk(g_metric_label[i], "0123456789") == NULL
               && "a key count in a label would be unbounded cardinality");
    }
    assert(metric_keys_total() == 2 * BRIX_SD_BULK_DELETE_WINDOW + 500);
}

int
main(void)
{
    test_success_children_are_gone_before_every_directory();
    test_success_window_fills_at_exactly_the_constant();
    test_success_dispatch_falls_back_without_the_capability();
    test_success_capability_and_batch_land_on_the_same_instance();

    test_error_a_transport_failure_leaves_untried_keys_cancelled();
    test_error_a_per_key_failure_fails_the_walk_with_that_errno();
    test_error_a_stat_failure_aborts_the_walk_with_its_errno();

    test_secneg_deny_mode_refuses_the_whole_batch();
    test_secneg_a_driver_writing_past_done_cannot_inflate_the_count();
    test_secneg_every_flush_is_prefilled_with_cancelled();
    test_secneg_depth_beyond_the_cap_is_eloop_and_removes_nothing();
    test_secneg_dtype_is_a_hint_and_never_authority();
    test_secneg_the_metric_carries_the_count_in_the_value();

    tree_reset();
    printf("vfs_bulk_chunker: 13 cases OK\n");
    return 0;
}
