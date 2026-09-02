/*
 * test_vfs_new_mutator_gate.c — the phase-107 W2/W3 verbs (recall, evict,
 * delete_many) behind the real policy kernel, with the §3.4 ordering
 * assertion (W0: vfs_order_spy.h) wired in from this unit on.
 *
 * WHAT: drives brix_vfs_recall, brix_vfs_evict, brix_vfs_delete_many and
 *       brix_vfs_truncate_path — the REAL vfs_recall.o + vfs_unlink_many.o
 *       + vfs_sync.o (+ vfs_unlink.o for the rmtree arm the delete verbs
 *       share) over the REAL vfs_policy.o — and proves, per
 *       verb: the ALLOWED call reaches exactly the expected driver slot in
 *       the canonical order (policy -> leaf -> capability -> credential ->
 *       backend -> invalidation, §3.4); the READ_ONLY call is EROFS with
 *       every sink at zero and only the policy stage on the ordering tape;
 *       and dispatch DIRECTION is what the file banner promises — recall
 *       DESCENDS the decorator chain to the nearline tier while evict
 *       dispatches on the TOP and never descends.
 * WHY:  test_vfs_read_only_spy.c covers the phase-105 verbs; the three verbs
 *       here have dispatch rules a counter alone cannot pin (descend vs top,
 *       one batch call per window, ENOTSUP-books-nothing) and §9.3 requires
 *       the ordering assertion for every NEW mutator. A wire test sees only
 *       the response; only stubs on the sequence tape can see that a refused
 *       recall never probed a capability, selected a credential, or spent a
 *       backend round trip.
 * HOW:  every stub calls ord_hit() at the stage it represents (the W0
 *       contract); the real policy kernel is visible on the tape through its
 *       denial metric (ORD_POLICY fires exactly on refusal, so the refused
 *       tape is [policy] and nothing else — policy-first on the allowed path
 *       is implied by the same kernel refusing with zero sinks). Counting
 *       spies distinguish the chain-top driver's slots from the leaf's, which
 *       is what makes the direction assertions non-vacuous.
 *
 * Cases:
 *   success:      recall reaches the nearline leaf's slot through a non-
 *                 nearline top (descend); evict fires the TOP's slot with the
 *                 leaf's untouched; delete_many makes ONE batch call for n
 *                 keys (C4), falls back to the per-key loop without the slot,
 *                 and runs the namespace arm driverless; the credential gate
 *                 routes each to its _cred twin; invalidation follows the
 *                 backend on the tape; truncate_path's path-native branch
 *                 takes ONE C7 lock read before its slot, and the fallback
 *                 route takes none (brix_vfs_open owns that gate).
 *   error:        an injected driver errno propagates verbatim; a partial
 *                 batch failure leaves untried keys ECANCELED (never
 *                 "deleted"); no nearline tier / no evict slot is ENOTSUP
 *                 under ALLOWED, and recall's ENOTSUP books no recall metric
 *                 and does no credential work; deny-mode over a _cred-less
 *                 vtable is EACCES with zero backend.
 *   security-neg: READ_ONLY answers EROFS for all three verbs — before the
 *                 capability answer (never ENOTSUP), before the identity
 *                 answer (never EACCES), unchanged by an injected backend
 *                 error — with zero sinks, one denial, and an ordering tape
 *                 holding only the policy stage.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_new_mutator_gate").
 */
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_io_core.h"
#include "fs/backend/ucred.h"
#include "fs/vfs/vfs_cred_internal.h"
#include "core/compat/namespace_ops.h"
#include "observability/metrics/access_log.h"

#include "vfs_order_spy.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- spy counters -------------------------------------------------------- */
typedef struct {
    /* backend slots: the leaf/full driver's ... */
    int drv_recall, drv_recall_cred, drv_evict, drv_evict_cred;
    int drv_unlink_many, drv_unlink_many_cred, drv_unlink, drv_unlink_cred;
    int drv_truncate_path, drv_truncate_path_cred;
    /* the open+ftruncate fallback route (stubbed to refuse ENOSYS) */
    int vfs_open_calls;
    /* ... and the chain-top's evict, counted apart so "top, never the leaf"
     * (and its converse for recall) is an assertion, not a hope. */
    int drv_evict_top;
    /* the POSIX namespace arm's delete */
    int ns_delete;
    /* resolution, probing, invalidation */
    int ns_leaf, cred_gate, ns_cred, caps_probe, cache_evict;
    /* observations (not sinks) */
    int denials;
    int metric_recall[BRIX_VFS_RECALL_RESULT_COUNT];
    int metric_evict;
    uint64_t metric_evict_bytes;
    int metric_bulk;
    size_t metric_bulk_keys;
} spy_t;

static spy_t g;

static int g_inject_errno;       /* driver slots fail with this errno        */
static int g_cred_gate_on;       /* the credential gate reports active       */
static int g_cred_fallback_deny; /* materialised cred carries fallback_deny  */
static ngx_int_t g_recall_rc = NGX_AGAIN;  /* queued by default              */
static int g_batch_fail_at = -1; /* >=0: unlink_many fails after this many   */
static int g_lock_refuse;        /* lock gate refuses with EBUSY (C7)        */

static void
spy_reset(void)
{
    memset(&g, 0, sizeof(g));
    g_inject_errno = 0;
    g_recall_rc = NGX_AGAIN;
    g_batch_fail_at = -1;
    g_lock_refuse = 0;
    ord_reset();
}

static int
spy_mutations(void)
{
    return g.drv_recall + g.drv_recall_cred + g.drv_evict + g.drv_evict_cred
        + g.drv_evict_top
        + g.drv_unlink_many + g.drv_unlink_many_cred
        + g.drv_unlink + g.drv_unlink_cred + g.ns_delete
        + g.drv_truncate_path + g.drv_truncate_path_cred;
}

/* Everything a refused verb must leave at zero: the mutations above plus the
 * resolution, capability and credential work that leads to them. */
static int
spy_sinks(void)
{
    return spy_mutations()
        + g.ns_leaf + g.cred_gate + g.ns_cred + g.caps_probe + g.cache_evict;
}

/* ---- resolution / probing / credential stubs ----------------------------- */
brix_sd_instance_t *
brix_vfs_ns_leaf(brix_sd_instance_t *top)
{
    g.ns_leaf++;
    ord_hit(ORD_LEAF);
    return top;
}

/* The chain: decorator_source(chain_top) = the nearline leaf; every other
 * instance is a leaf. Set per test via g_chain_source. */
static brix_sd_instance_t *g_chain_top;
static brix_sd_instance_t *g_chain_source;

brix_sd_instance_t *
brix_vfs_decorator_source(const brix_sd_instance_t *inst)
{
    return (inst == g_chain_top) ? g_chain_source : NULL;
}

uint32_t
brix_sd_caps(const brix_sd_instance_t *inst)
{
    g.caps_probe++;
    ord_hit(ORD_CAP);
    return (inst != NULL) ? inst->caps : 0;
}

ngx_int_t
brix_sd_supports(const brix_sd_instance_t *inst, uint32_t required_caps)
{
    g.caps_probe++;
    ord_hit(ORD_CAP);
    return (inst != NULL && (inst->caps & required_caps) == required_caps)
        ? NGX_OK : NGX_ERROR;
}

int
brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx)
{
    (void) ctx;
    g.cred_gate++;
    return g_cred_gate_on;
}

ngx_int_t
brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    (void) ctx; (void) err_out;
    g.ns_cred++;
    ord_hit(ORD_CRED);
    memset(store, 0, sizeof(*store));
    memset(cred, 0, sizeof(*cred));
    cred->fallback_deny = g_cred_fallback_deny ? 1 : 0;
    *use_cred = 1;
    return NGX_OK;
}

void brix_sd_ucred_wipe(brix_sd_ucred_t *cred) { (void) cred; }

uint64_t
brix_sd_cache_evict(brix_sd_instance_t *inst, const char *key)
{
    (void) inst; (void) key;
    g.cache_evict++;
    ord_hit(ORD_INVALIDATE);
    return 0;
}

/* The C7 lock gate trio. brix_vfs_delete_many gates the whole key window
 * through the _many form BEFORE any arm runs; the stub preserves the real
 * gate's tape contract — one ORD_LOCK per key, refusal at the FIRST key when
 * g_lock_refuse is set (EBUSY, atomic: nothing after it is examined). */
ngx_int_t
brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    (void) ctx; (void) op;
    ord_hit(ORD_LOCK);
    if (g_lock_refuse) {
        errno = EBUSY;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_require_unlocked_at(brix_vfs_ctx_t *ctx, const char *path,
    brix_vfs_mutation_op_t op)
{
    (void) path;
    return brix_vfs_require_unlocked(ctx, op);
}

ngx_int_t
brix_vfs_require_unlocked_many(brix_vfs_ctx_t *ctx, const char *const *paths,
    size_t n, brix_vfs_mutation_op_t op)
{
    size_t i;

    (void) paths;
    for (i = 0; i < n; i++) {
        if (brix_vfs_require_unlocked(ctx, op) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* truncate_path's open+ftruncate fallback (vfs_sync.o). The stub refuses with
 * ENOSYS: none of this unit's cases may complete through the fallback, only
 * prove WHEN it is entered — and that the path-native lock gate is not read
 * on that route (brix_vfs_open carries its own gate; C7 no-double-book). */
brix_vfs_file_t *
brix_vfs_open(brix_vfs_ctx_t *ctx, ngx_uint_t flags, int *err_out)
{
    (void) ctx; (void) flags;
    g.vfs_open_calls++;
    if (err_out != NULL) {
        *err_out = ENOSYS;
    }
    return NULL;
}

ngx_int_t
brix_vfs_close(brix_vfs_file_t *fh, ngx_log_t *log)
{
    (void) fh; (void) log;
    return NGX_OK;
}

void
brix_vfs_io_execute(brix_vfs_job_t *job)
{
    job->io_errno = 0;   /* handle-plane executor: unreached by these verbs */
}

/* ---- the POSIX namespace arm --------------------------------------------- */
brix_ns_result_t
brix_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const brix_ns_delete_opts_t *opts)
{
    brix_ns_result_t res;

    (void) log; (void) root_canon; (void) path; (void) opts;
    g.ns_delete++;
    ord_hit(ORD_BACKEND);
    memset(&res, 0, sizeof(res));
    if (g_inject_errno != 0) {
        res.status = BRIX_NS_IO_ERROR;
        res.sys_errno = g_inject_errno;
        return res;
    }
    res.status = BRIX_NS_OK;
    res.existed = 1;
    return res;
}

brix_ns_result_t
brix_ns_delete_at(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *path, const brix_ns_delete_opts_t *opts)
{
    (void) rootfd;
    return brix_ns_delete(log, root_canon, path, opts);
}

/* ---- path helpers (the real strip shape, as in the read-only spy) -------- */
static const char *
export_relative(const char *path, const char *root_canon)
{
    size_t n = (root_canon != NULL) ? strlen(root_canon) : 0;

    if (n == 0 || strncmp(path, root_canon, n) != 0) {
        return path;
    }
    return (path[n] == '/') ? path + n + 1 : path + n;
}

const char *
brix_vfs_export_relative(const brix_vfs_ctx_t *ctx, const char *path)
{
    return export_relative(path, (ctx != NULL) ? ctx->root_canon : NULL);
}

const char *
brix_vfs_export_relative_root(const char *path, const char *root_canon)
{
    return export_relative(path, root_canon);
}

const brix_sd_driver_t *brix_sd_default_driver(void) { return NULL; }

const char *
brix_sd_backend_name(const brix_sd_instance_t *inst)
{
    (void) inst;
    return "spy";
}

/* ---- metric / log recorders ---------------------------------------------- */
void
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    (void) proto; (void) op;
    g.denials++;
    ord_hit(ORD_POLICY);   /* the kernel's refusal IS the policy stage */
}

void
brix_metric_vfs_recall(brix_vfs_recall_result_t result)
{
    assert((int) result >= 0 && result < BRIX_VFS_RECALL_RESULT_COUNT);
    g.metric_recall[result]++;
}

void
brix_metric_vfs_evict(const char *driver_name, uint64_t bytes)
{
    (void) driver_name;
    g.metric_evict++;
    g.metric_evict_bytes += bytes;
}

void
brix_metric_vfs_bulk_delete(const char *driver_name, size_t keys)
{
    (void) driver_name;
    g.metric_bulk++;
    g.metric_bulk_keys += keys;
}

void
brix_metric_op_done(brix_proto_t proto, brix_metric_op_t op, size_t bytes,
    ngx_msec_t latency_usec, brix_err_class_t err)
{
    (void) proto; (void) op; (void) bytes; (void) latency_usec; (void) err;
}

void
brix_metric_cache_evicted(brix_proto_t proto, uint64_t bytes)
{
    (void) proto; (void) bytes;
}

void
brix_metric_backend_bytes(const char *backend_name, brix_metric_op_t op,
    size_t bytes)
{
    (void) backend_name; (void) op; (void) bytes;
}

brix_err_class_t
brix_metric_err_from_errno(int sys_errno)
{
    (void) sys_errno;
    return (brix_err_class_t) 0;
}

void
brix_access_log_emit(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result, size_t bytes,
    brix_err_class_t err, ngx_msec_t latency_usec)
{
    (void) ctx; (void) path; (void) op; (void) result; (void) bytes;
    (void) err; (void) latency_usec;
}

/* ---- the spy drivers ----------------------------------------------------- */
static ngx_int_t
drv_answer(void)
{
    if (g_inject_errno != 0) {
        errno = g_inject_errno;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
spy_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    (void) inst; (void) key;
    g.drv_recall++;
    ord_hit(ORD_BACKEND);
    if (g_inject_errno != 0) {
        errno = g_inject_errno;
        return NGX_ERROR;
    }
    if (reqid_out != NULL) {
        strcpy(reqid_out, "req-1");
    }
    return g_recall_rc;
}

static ngx_int_t
spy_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    (void) cred;
    g.drv_recall_cred++;
    g.drv_recall--;   /* the plain twin must not also count this call */
    return spy_recall(inst, key, reqid_out);
}

static ngx_int_t
spy_evict(brix_sd_instance_t *inst, const char *path, uint64_t *bytes_out)
{
    (void) inst; (void) path;
    g.drv_evict++;
    ord_hit(ORD_BACKEND);
    if (bytes_out != NULL) {
        *bytes_out = 4096;
    }
    return drv_answer();
}

static ngx_int_t
spy_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_evict_cred++;
    g.drv_evict--;
    return spy_evict(inst, path, bytes_out);
}

/* The chain-top's OWN evict: a separate counter is what turns "evict fired on
 * the top, never the leaf" into an assertion. */
static ngx_int_t
spy_evict_top(brix_sd_instance_t *inst, const char *path, uint64_t *bytes_out)
{
    (void) inst; (void) path;
    g.drv_evict_top++;
    ord_hit(ORD_BACKEND);
    if (bytes_out != NULL) {
        *bytes_out = 512;
    }
    return drv_answer();
}

static ngx_int_t
spy_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    size_t i;

    (void) inst;
    g.drv_unlink_many++;
    ord_hit(ORD_BACKEND);
    for (i = 0; i < b->n; i++) {
        if (g_batch_fail_at >= 0 && i == (size_t) g_batch_fail_at) {
            b->done = i;          /* errs[i..n) stay untouched by contract */
            errno = EIO;
            return NGX_ERROR;
        }
        b->errs[i] = 0;
    }
    b->done = b->n;
    return NGX_OK;
}

static ngx_int_t
spy_unlink_many_cred(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_unlink_many_cred++;
    g.drv_unlink_many--;
    return spy_unlink_many(inst, b);
}

static ngx_int_t
spy_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    (void) inst; (void) path; (void) is_dir;
    g.drv_unlink++;
    ord_hit(ORD_BACKEND);
    return drv_answer();
}

static ngx_int_t
spy_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_unlink_cred++;
    g.drv_unlink--;
    return spy_unlink(inst, path, is_dir);
}

static ngx_int_t
spy_truncate_path(brix_sd_instance_t *inst, const char *path, off_t len)
{
    (void) inst; (void) path; (void) len;
    g.drv_truncate_path++;
    ord_hit(ORD_BACKEND);
    return drv_answer();
}

static ngx_int_t
spy_truncate_path_cred(brix_sd_instance_t *inst, const char *path, off_t len,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_truncate_path_cred++;
    g.drv_truncate_path--;
    return spy_truncate_path(inst, path, len);
}

/* full: a nearline-capable leaf with every slot this unit drives. */
static const brix_sd_driver_t  full_driver = {
    .name = "spy",
    .caps = 0xffffffffu,
    .unlink = spy_unlink,
    .unlink_many = spy_unlink_many,
    .recall = spy_recall,
    .evict = spy_evict,
    .unlink_cred = spy_unlink_cred,
    .unlink_many_cred = spy_unlink_many_cred,
    .recall_cred = spy_recall_cred,
    .evict_cred = spy_evict_cred,
    .truncate_path = spy_truncate_path,
    .truncate_path_cred = spy_truncate_path_cred,
};

/* chain_top: a cache-like tier with NO nearline authority of its own (recall
 * must descend past it) and its OWN evict (evict must stop here). */
static const brix_sd_driver_t  chain_top_driver = {
    .name = "spytop",
    .caps = 0xffffffffu & ~BRIX_SD_CAP_NEARLINE,
    .evict = spy_evict_top,
};

/* plain: every slot present, no _cred twins — the deny-mode EACCES shape. */
static const brix_sd_driver_t  plain_driver = {
    .name = "spyplain",
    .caps = 0xffffffffu,
    .unlink = spy_unlink,
    .unlink_many = spy_unlink_many,
    .recall = spy_recall,
    .evict = spy_evict,
};

/* none: no recall/evict slots, no nearline cap — the ENOTSUP shape. */
static const brix_sd_driver_t  none_driver = {
    .name = "spynone",
    .caps = 0xffffffffu & ~BRIX_SD_CAP_NEARLINE,
    .unlink = spy_unlink,
};

static brix_sd_instance_t  full_inst, chain_top_inst, plain_inst, none_inst;

/* ---- context ------------------------------------------------------------- */
static u_char  src_path[] = "/export/collection/object";

static void
ctx_build(brix_vfs_ctx_t *ctx, brix_vfs_mutation_policy_t policy,
    brix_sd_instance_t *inst)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->metrics_proto = BRIX_PROTO_WEBDAV;
    ctx->root_canon = "/export";
    ctx->mutation_policy = policy;
    ctx->resolved.resolved.data = src_path;
    ctx->resolved.resolved.len = sizeof(src_path) - 1;
    ctx->resolved.is_confined = 1;
    ctx->sd = inst;
}

static const char *const  batch_paths[] = {
    "/export/collection/a", "/export/collection/b", "/export/collection/c",
};
#define BATCH_N  3

/* ---- cases --------------------------------------------------------------- */
static void
test_success(void)
{
    brix_vfs_ctx_t  ctx;
    char            reqid[40];
    uint64_t        bytes;
    int             errs[BATCH_N];
    size_t          done;

    /* recall, single nearline tier: queued, reqid handed through, capability
     * probed BEFORE the slot, exactly one backend call. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_recall(&ctx, reqid) == NGX_AGAIN);
    assert(g.drv_recall == 1 && spy_mutations() == 1);
    assert(strcmp(reqid, "req-1") == 0);
    assert(g.metric_recall[BRIX_VFS_RECALL_QUEUED] == 1);
    assert(g.denials == 0);
    ord_assert_before(ORD_CAP, ORD_BACKEND, "recall: capability before slot");
    ord_assert_count(ORD_BACKEND, 1, "recall: one driver call");

    /* recall DESCENDS: the top tier has no nearline authority, so the leaf's
     * slot answers — the top was probed, never mutated. */
    spy_reset();
    g_chain_top = &chain_top_inst;
    g_chain_source = &full_inst;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &chain_top_inst);
    assert(brix_vfs_recall(&ctx, reqid) == NGX_AGAIN);
    assert(g.drv_recall == 1 && g.drv_evict_top == 0);
    assert(g.caps_probe >= 2);   /* top refused the cap question, leaf took it */

    /* evict dispatches on the TOP of the same chain and never descends. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &chain_top_inst);
    bytes = 0;
    assert(brix_vfs_evict(&ctx, &bytes) == NGX_OK);
    assert(g.drv_evict_top == 1 && g.drv_evict == 0);
    assert(bytes == 512);
    g_chain_top = NULL;
    g_chain_source = NULL;

    /* recall already-online books ONLINE, not QUEUED. */
    spy_reset();
    g_recall_rc = NGX_OK;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_recall(&ctx, NULL) == NGX_OK);
    assert(g.metric_recall[BRIX_VFS_RECALL_ONLINE] == 1);
    assert(g.metric_recall[BRIX_VFS_RECALL_QUEUED] == 0);

    /* the credential gate routes both verbs to the _cred twins, credential
     * selected BEFORE the slot. */
    g_cred_gate_on = 1;
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_recall(&ctx, reqid) == NGX_AGAIN);
    assert(g.drv_recall_cred == 1 && g.drv_recall == 0);
    ord_assert_before(ORD_CRED, ORD_BACKEND, "recall: credential before slot");
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_evict(&ctx, NULL) == NGX_OK);
    assert(g.drv_evict_cred == 1 && g.drv_evict == 0);
    ord_assert_before(ORD_CRED, ORD_BACKEND, "evict: credential before slot");
    g_cred_gate_on = 0;

    /* evict books the reclaimed bytes under the dispatching driver. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    bytes = 0;
    assert(brix_vfs_evict(&ctx, &bytes) == NGX_OK);
    assert(bytes == 4096);
    assert(g.metric_evict == 1 && g.metric_evict_bytes == 4096);

    /* delete_many, batch arm: ONE unlink_many call for the whole window (C4),
     * leaf resolved first, every key invalidated AFTER the batch, key count
     * in the metric VALUE. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    memset(errs, -1, sizeof(errs));
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_OK);
    assert(done == BATCH_N);
    assert(errs[0] == 0 && errs[1] == 0 && errs[2] == 0);
    assert(g.drv_unlink_many == 1 && g.drv_unlink == 0);
    assert(g.cache_evict == BATCH_N);
    assert(g.metric_bulk == 1 && g.metric_bulk_keys == BATCH_N);
    ord_assert_before(ORD_LOCK, ORD_LEAF,
                      "delete_many: lock gate before leaf resolution (C7)");
    ord_assert_before(ORD_LEAF, ORD_BACKEND, "delete_many: leaf before slot");
    ord_assert_before(ORD_BACKEND, ORD_INVALIDATE,
                      "delete_many: invalidation follows the batch");
    ord_assert_count(ORD_LOCK, BATCH_N,
                     "delete_many: one lock read per key (C7)");
    ord_assert_count(ORD_BACKEND, 1, "delete_many: ONE batch call for n keys");

    /* delete_many without the batch slot: the per-key loop, same verdicts. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &none_inst);
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_OK);
    assert(done == BATCH_N && g.drv_unlink == BATCH_N);
    assert(g.drv_unlink_many == 0);

    /* delete_many, namespace arm: no driver, one brix_ns_delete per key. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, NULL);
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_OK);
    assert(done == BATCH_N && g.ns_delete == BATCH_N);

    /* delete_many with the credential gate: ONE credential for the batch. */
    g_cred_gate_on = 1;
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_OK);
    assert(g.drv_unlink_many_cred == 1 && g.ns_cred == 1);
    g_cred_gate_on = 0;

    /* the empty batch mutates nothing and still succeeds. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_delete_many(&ctx, batch_paths, 0, errs, &done) == NGX_OK);
    assert(done == 0 && spy_sinks() == 0);

    /* truncate_path, path-native branch: ONE lock read before the slot (C7),
     * invalidation after it, and the fallback never entered. The leaf is
     * resolved BEFORE the lock gate here — the branch decision needs it, and
     * gating both branches would double-book the advisory metric with
     * brix_vfs_open's own gate — so the pinned order is lock-before-slot,
     * not lock-before-leaf. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_truncate_path(&ctx, 100) == NGX_OK);
    assert(g.drv_truncate_path == 1 && spy_mutations() == 1);
    assert(g.cache_evict == 1 && g.vfs_open_calls == 0);
    ord_assert_before(ORD_LOCK, ORD_BACKEND,
                      "truncate_path: lock gate before the slot (C7)");
    ord_assert_before(ORD_BACKEND, ORD_INVALIDATE,
                      "truncate_path: invalidation follows the slot");
    ord_assert_count(ORD_LOCK, 1, "truncate_path: one lock read");

    /* truncate_path with the credential gate: the _cred twin, lock decided
     * before any credential is selected. */
    g_cred_gate_on = 1;
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    assert(brix_vfs_truncate_path(&ctx, 100) == NGX_OK);
    assert(g.drv_truncate_path_cred == 1 && g.drv_truncate_path == 0);
    ord_assert_before(ORD_LOCK, ORD_CRED,
                      "truncate_path: lock before credential");
    ord_assert_before(ORD_CRED, ORD_BACKEND,
                      "truncate_path: credential before slot");
    g_cred_gate_on = 0;

    printf("ok success\n");
}

static void
test_error(void)
{
    brix_vfs_ctx_t  ctx;
    char            reqid[40];
    int             errs[BATCH_N];
    size_t          done;

    /* an injected driver errno propagates verbatim and books ERROR. */
    spy_reset();
    g_inject_errno = EIO;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_recall(&ctx, reqid) == NGX_ERROR);
    assert(errno == EIO);
    assert(g.metric_recall[BRIX_VFS_RECALL_ERROR] == 1);

    spy_reset();
    g_inject_errno = EIO;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_evict(&ctx, NULL) == NGX_ERROR);
    assert(errno == EIO);
    assert(g.metric_evict == 0);   /* bytes book only on success */

    /* no nearline tier anywhere: ENOTSUP, no recall metric (a capability
     * probe, not a recall attempt), and NO credential work. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &none_inst);
    errno = 0;
    assert(brix_vfs_recall(&ctx, reqid) == NGX_ERROR);
    assert(errno == ENOTSUP);
    assert(reqid[0] == '\0');
    assert(spy_mutations() == 0 && g.ns_cred == 0 && g.cred_gate == 0);
    assert(g.metric_recall[BRIX_VFS_RECALL_ERROR] == 0);

    /* no evict slot on the top: ENOTSUP, zero backend. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &none_inst);
    errno = 0;
    assert(brix_vfs_evict(&ctx, NULL) == NGX_ERROR);
    assert(errno == ENOTSUP && spy_mutations() == 0);

    /* a batch that dies at key 1: done says how far it got, the untried keys
     * stay ECANCELED — an untried key must never read as deleted. */
    spy_reset();
    g_batch_fail_at = 1;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_ERROR);
    assert(errno == EIO);
    assert(done == 1);
    assert(errs[0] == 0 && errs[1] == ECANCELED && errs[2] == ECANCELED);

    /* an over-window batch is refused whole before any key is touched. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    {
        static int  big_errs[BRIX_SD_BULK_DELETE_WINDOW + 1];

        assert(brix_vfs_delete_many(&ctx, batch_paths,
                                    BRIX_SD_BULK_DELETE_WINDOW + 1,
                                    big_errs, &done) == NGX_ERROR);
    }
    assert(errno == EINVAL && spy_sinks() == 0);

    /* deny mode over a _cred-less vtable: EACCES from the forwarder, zero
     * backend for all three verbs (the confused-deputy shape). */
    g_cred_gate_on = 1;
    g_cred_fallback_deny = 1;
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &plain_inst);
    errno = 0;
    assert(brix_vfs_recall(&ctx, reqid) == NGX_ERROR);
    assert(errno == EACCES && spy_mutations() == 0);
    ord_assert_absent(ORD_BACKEND, "deny-mode recall: no backend");

    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &plain_inst);
    errno = 0;
    assert(brix_vfs_evict(&ctx, NULL) == NGX_ERROR);
    assert(errno == EACCES && spy_mutations() == 0);

    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &plain_inst);
    errno = 0;
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_ERROR);
    assert(errno == EACCES && done == 0 && spy_mutations() == 0);
    assert(errs[0] == ECANCELED);   /* refused whole, nothing "deleted" */
    g_cred_gate_on = 0;
    g_cred_fallback_deny = 0;

    /* a negative length is EINVAL before the policy question, zero sinks. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_truncate_path(&ctx, -1) == NGX_ERROR);
    assert(errno == EINVAL && spy_sinks() == 0 && g.denials == 0);

    /* an injected slot errno propagates verbatim and the stale cache copy is
     * NOT evicted — the object was never resized. */
    spy_reset();
    g_inject_errno = EIO;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_truncate_path(&ctx, 100) == NGX_ERROR);
    assert(errno == EIO && g.drv_truncate_path == 1);
    assert(g.cache_evict == 0);
    ord_assert_absent(ORD_INVALIDATE, "failed truncate: no invalidation");
    g_inject_errno = 0;

    /* no path-native slot: the open+ftruncate fallback is entered and the
     * C7 gate is NOT read on the way — brix_vfs_open carries its own gate,
     * and a second read here would double-book the advisory metric. The
     * stubbed open refuses ENOSYS, which is as far as this unit follows. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &none_inst);
    errno = 0;
    assert(brix_vfs_truncate_path(&ctx, 100) == NGX_ERROR);
    assert(errno == ENOSYS && g.vfs_open_calls == 1);
    assert(spy_mutations() == 0);
    ord_assert_absent(ORD_LOCK,
                      "fallback truncate: the open gate owns the lock read");

    printf("ok error\n");
}

typedef ngx_int_t (*verb_fn)(brix_vfs_ctx_t *ctx);

static ngx_int_t
verb_recall(brix_vfs_ctx_t *ctx)
{
    char reqid[40];

    return brix_vfs_recall(ctx, reqid);
}

static ngx_int_t
verb_evict(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_evict(ctx, NULL);
}

static ngx_int_t
verb_delete_many(brix_vfs_ctx_t *ctx)
{
    int    errs[BATCH_N];
    size_t done;

    return brix_vfs_delete_many(ctx, batch_paths, BATCH_N, errs, &done);
}

static ngx_int_t
verb_truncate_path(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_truncate_path(ctx, 100);
}

/* One READ_ONLY call: EROFS, one denial, zero sinks, and an ordering tape
 * holding ONLY the policy stage — the §3.4 policy-first proof by exclusion. */
static void
assert_readonly_refuses(verb_fn fn, brix_sd_instance_t *inst, const char *what)
{
    brix_vfs_ctx_t ctx;

    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, inst);
    errno = 0;
    if (fn(&ctx) != NGX_ERROR || errno != EROFS || spy_sinks() != 0
        || g.denials != 1)
    {
        fprintf(stderr, "read-only %s errno=%d sinks=%d denials=%d\n",
                what, errno, spy_sinks(), g.denials);
        assert(0);
    }
    ord_assert_absent(ORD_LOCK, what);
    ord_assert_absent(ORD_LEAF, what);
    ord_assert_absent(ORD_CAP, what);
    ord_assert_absent(ORD_CRED, what);
    ord_assert_absent(ORD_BACKEND, what);
    ord_assert_absent(ORD_INVALIDATE, what);
    ord_assert_count(ORD_POLICY, 1, what);
}

static void
test_security_negative(void)
{
    brix_vfs_ctx_t  ctx;
    char            reqid[40];
    int             errs[BATCH_N];
    size_t          done;
    int             i;

    /* the core claim, for each verb, with and without the credential gate. */
    for (i = 0; i < 2; i++) {
        g_cred_gate_on = i;
        assert_readonly_refuses(verb_recall, &full_inst, "recall");
        assert_readonly_refuses(verb_evict, &full_inst, "evict");
        assert_readonly_refuses(verb_delete_many, &full_inst, "delete_many");
        assert_readonly_refuses(verb_truncate_path, &full_inst,
                                "truncate_path");
    }
    g_cred_gate_on = 0;

    /* EROFS precedes ENOTSUP: a read-only endpoint with NO nearline tier and
     * NO evict slot still answers EROFS — the driver's shape is not leaked.
     * truncate_path on the slotless driver refuses before the fallback is
     * even chosen (its route decision would disclose the driver's shape). */
    assert_readonly_refuses(verb_recall, &none_inst, "recall/noslot");
    assert_readonly_refuses(verb_evict, &none_inst, "evict/noslot");
    assert_readonly_refuses(verb_truncate_path, &none_inst,
                            "truncate_path/noslot");

    /* EROFS precedes EACCES: deny mode over the _cred-less vtable. */
    g_cred_gate_on = 1;
    g_cred_fallback_deny = 1;
    assert_readonly_refuses(verb_recall, &plain_inst, "recall/deny");
    assert_readonly_refuses(verb_evict, &plain_inst, "evict/deny");
    assert_readonly_refuses(verb_delete_many, &plain_inst,
                            "delete_many/deny");
    g_cred_gate_on = 0;
    g_cred_fallback_deny = 0;

    /* an injected backend error changes nothing — decided before the backend. */
    spy_reset();
    g_inject_errno = EIO;
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, &full_inst);
    errno = 0;
    assert(brix_vfs_recall(&ctx, reqid) == NGX_ERROR);
    assert(errno == EROFS && spy_sinks() == 0);
    assert(reqid[0] == '\0');   /* no parking handle leaks on a refusal */

    /* a refused batch leaves every key ECANCELED and done at zero. */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, &full_inst);
    errno = 0;
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_ERROR);
    assert(errno == EROFS && done == 0);
    assert(errs[0] == ECANCELED && errs[1] == ECANCELED
           && errs[2] == ECANCELED);

    /* C7: a live foreign lock refuses the WHOLE batch atomically — EBUSY,
     * zero sinks (no key was attempted, so no partial delete hides behind
     * the conflict), every key still ECANCELED. The gate ran (LOCK on the
     * tape) but nothing past it did. */
    spy_reset();
    g_lock_refuse = 1;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_ERROR);
    assert(errno == EBUSY && done == 0 && spy_sinks() == 0);
    assert(errs[0] == ECANCELED && errs[1] == ECANCELED
           && errs[2] == ECANCELED);
    ord_assert_count(ORD_LOCK, 1, "locked batch: gate stops at first key");
    ord_assert_absent(ORD_LEAF, "locked batch: no leaf resolution");
    ord_assert_absent(ORD_CRED, "locked batch: no credential work");
    ord_assert_absent(ORD_BACKEND, "locked batch: no backend call");
    ord_assert_absent(ORD_INVALIDATE, "locked batch: no invalidation");

    /* EROFS still precedes EBUSY: read-only + locked refuses on POLICY and
     * never reads a lock record (§3.4 — a read-only endpoint discloses
     * nothing about lock state). */
    spy_reset();
    g_lock_refuse = 1;
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, &full_inst);
    errno = 0;
    assert(brix_vfs_delete_many(&ctx, batch_paths, BATCH_N, errs, &done)
           == NGX_ERROR);
    assert(errno == EROFS && spy_sinks() == 0);
    ord_assert_absent(ORD_LOCK, "read-only batch: lock record never read");
    ord_assert_count(ORD_POLICY, 1, "read-only batch: policy denial booked");
    g_lock_refuse = 0;

    /* C7: a live foreign lock refuses the path-native truncate with EBUSY —
     * no slot call, no invalidation, and CRITICALLY no fallback: falling
     * through to open+ftruncate on a lock refusal would hand the mutation a
     * second door past the gate. */
    spy_reset();
    g_lock_refuse = 1;
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, &full_inst);
    errno = 0;
    assert(brix_vfs_truncate_path(&ctx, 100) == NGX_ERROR);
    assert(errno == EBUSY && spy_mutations() == 0);
    assert(g.cache_evict == 0 && g.vfs_open_calls == 0);
    ord_assert_count(ORD_LOCK, 1, "locked truncate: one lock read");
    ord_assert_absent(ORD_CRED, "locked truncate: no credential work");
    ord_assert_absent(ORD_BACKEND, "locked truncate: no slot call");
    ord_assert_absent(ORD_INVALIDATE, "locked truncate: no invalidation");
    g_lock_refuse = 0;

    printf("ok security-negative\n");
}

int
main(void)
{
    memset(&full_inst, 0, sizeof(full_inst));
    full_inst.driver = &full_driver;
    full_inst.caps = full_driver.caps;

    memset(&chain_top_inst, 0, sizeof(chain_top_inst));
    chain_top_inst.driver = &chain_top_driver;
    chain_top_inst.caps = chain_top_driver.caps;

    memset(&plain_inst, 0, sizeof(plain_inst));
    plain_inst.driver = &plain_driver;
    plain_inst.caps = plain_driver.caps;

    memset(&none_inst, 0, sizeof(none_inst));
    none_inst.driver = &none_driver;
    none_inst.caps = none_driver.caps;

    test_success();
    test_error();
    test_security_negative();
    printf("PASS test_vfs_new_mutator_gate\n");
    return 0;
}
