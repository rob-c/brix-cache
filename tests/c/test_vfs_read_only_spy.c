/*
 * test_vfs_read_only_spy.c — no mutating backend slot is reached on a
 * read-only endpoint (phase-105, Appendix K.4).
 *
 * WHAT: drives the public VFS mutation API — mkdir, rmdir, unlink, rename,
 *       exchange, copy, chmod, setattr, setxattr, removexattr — against a
 *       confined context whose endpoint is READ_ONLY, and proves that every one
 *       fails with EROFS having called NOTHING: no namespace mutation, no
 *       POSIX confined-path syscall, no storage-driver slot (plain OR
 *       credential-scoped), no leaf resolution, no credential resolution, and
 *       no cache invalidation. The identical calls on an ALLOWED endpoint fire
 *       exactly the one expected slot, which is what makes the zeros above
 *       meaningful rather than vacuous.
 * WHY:  a wire test can only observe the RESPONSE. It cannot see that a
 *       refused rename still resolved the leaf, still selected a per-user
 *       credential, or still asked an origin — each of which is a real
 *       information disclosure and, for a credentialed backend, a use of a
 *       secret the request was never entitled to spend. Appendix I.5 also
 *       requires that the read-only refusal precede the capability and
 *       credential answers, so "which gate refused" cannot be probed. Only a
 *       counting spy under the VFS can prove any of that.
 * HOW:  links the real vfs_mkdir/unlink/rename/copy/xattr objects on top of
 *       the real policy kernel, and supplies their entire cross-TU closure as
 *       counting stubs — the namespace layer, the confined-path syscalls, the
 *       leaf/credential resolvers, the cache evictor, and the metric and
 *       access-log recorders. The storage-driver plane is a hand-built
 *       brix_sd_driver_t whose plain and _cred namespace slots each count, so
 *       a gate that a credential path could walk around is visible. Nothing
 *       touches a filesystem, a pool, or a real backend.
 *
 * Cases:
 *   success:      on an ALLOWED endpoint every operation reaches exactly one
 *                 expected sink exactly once, on both the POSIX plane and the
 *                 storage-driver plane; a read (getxattr/listxattr) is never
 *                 gated and works on a READ_ONLY endpoint.
 *   error:        a backend failure injected under an ALLOWED policy
 *                 propagates verbatim with the driver's own errno, so the gate
 *                 is not swallowing or rewriting real backend errors.
 *   security-neg: under READ_ONLY every mutation is EROFS (never EACCES,
 *                 never ENOTSUP — the endpoint's posture, not the caller's
 *                 credentials nor the backend's capabilities) with every spy
 *                 counter at zero; the credential-scoped slots are unreached
 *                 even with the credential gate ACTIVE, which is the
 *                 confused-deputy path; and a driver with every capability
 *                 bit set still refuses.
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_read_only_spy").
 */
#include "fs/vfs/vfs.h"
#include "fs/backend/ucred.h"
#include "fs/vfs/vfs_cred_internal.h"
#include "core/compat/namespace_ops.h"
#include "observability/metrics/access_log.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- spy counters --------------------------------------------------------
 * One counter per sink the VFS can reach past the gate. `total_sinks` is the
 * sum every read-only case asserts to be zero, so a NEW sink added to a
 * mutation path is caught by the existing cases the moment it is stubbed. */
typedef struct {
    /* POSIX namespace + confined-path syscalls */
    int ns_mkdir, ns_delete, ns_rename, ns_local_copy;
    int chmod_canon, setattr_canon, setxattr_canon, removexattr_canon;
    int mkpath;
    /* storage-driver slots, plain and credential-scoped */
    int drv_mkdir, drv_unlink, drv_rename, drv_copy, drv_setxattr;
    int drv_removexattr, drv_setattr, drv_stat;
    int drv_mkdir_cred, drv_unlink_cred, drv_rename_cred, drv_copy_cred;
    int drv_setxattr_cred, drv_removexattr_cred, drv_setattr_cred;
    int drv_stat_cred;
    /* the phase-107 mutation slots (W0/§9.3): every one is a counted sink, so
     * an OLD verb leaking into a NEW slot — or any verb reaching one past the
     * gate — trips the same zero-sink assertions as the original ten. */
    int drv_reserve, drv_unlink_many, drv_sync_publish, drv_exchange;
    int drv_recall, drv_evict;
    int drv_unlink_many_cred, drv_exchange_cred, drv_recall_cred;
    int drv_evict_cred;
    /* resolution and invalidation that must not happen either */
    int ns_leaf, cred_gate, ns_cred, cache_evict, leaf_isdir;
    int publish_dirsync;   /* phase-107 C3 barrier (POSIX arm) */
    int ns_exchange;       /* phase-107 C6 two-name swap (POSIX arm) */
    int rmtree_dispatch;   /* driver-plane recursive delete */
    int precond_refused;   /* C6 refusal observation (expected on refusal) */
    /* reads, which are never gated */
    int getxattr_canon, listxattr_canon;
    /* the policy kernel's own denial observation */
    int denials;
} spy_t;

static spy_t g;

/* Injected backend outcome for the ALLOWED control: 0 = success. */
static int g_inject_errno;
/* Whether the credential gate reports itself active (deny-mode / per-user). */
static int g_cred_gate_on;
/* Whether the stub resolver marks deny-mode fallback: a _cred-less vtable
 * slot then answers EACCES instead of falling back to the plain slot. */
static int g_cred_fallback_deny;

static void
spy_reset(void)
{
    memset(&g, 0, sizeof(g));
    g_inject_errno = 0;
}

/* The sinks that actually CHANGE something. Exactly one kind of these may fire
 * on an allowed mutation; none of them may fire on a refused one. */
static int
spy_mutations(void)
{
    return g.ns_mkdir + g.ns_delete + g.ns_rename + g.ns_local_copy
        + g.ns_exchange
        + g.chmod_canon + g.setattr_canon + g.setxattr_canon
        + g.removexattr_canon + g.mkpath + g.rmtree_dispatch
        + g.drv_mkdir + g.drv_unlink + g.drv_rename + g.drv_copy
        + g.drv_setxattr + g.drv_removexattr + g.drv_setattr
        + g.drv_mkdir_cred + g.drv_unlink_cred + g.drv_rename_cred
        + g.drv_copy_cred + g.drv_setxattr_cred + g.drv_removexattr_cred
        + g.drv_setattr_cred
        + g.drv_reserve + g.drv_unlink_many + g.drv_sync_publish
        + g.drv_exchange + g.drv_recall + g.drv_evict
        + g.drv_unlink_many_cred + g.drv_exchange_cred + g.drv_recall_cred
        + g.drv_evict_cred;
}

/* Every sink a mutation could reach past the gate — the mutations above plus
 * the resolution, probing and invalidation work that leads to them. A refused
 * mutation must leave ALL of it at zero: resolving a leaf, selecting a
 * credential, probing a backend or invalidating a cache entry are each
 * observable, and each is work the request was not entitled to cause. Excludes
 * only the read-only xattr reads (never gated) and the denial observation
 * (expected on refusal). */
static int
spy_sinks(void)
{
    return g.ns_mkdir + g.ns_delete + g.ns_rename + g.ns_local_copy
        + g.chmod_canon + g.setattr_canon + g.setxattr_canon
        + g.removexattr_canon + g.mkpath
        + g.drv_mkdir + g.drv_unlink + g.drv_rename + g.drv_copy
        + g.drv_setxattr + g.drv_removexattr + g.drv_setattr + g.drv_stat
        + g.drv_mkdir_cred + g.drv_unlink_cred + g.drv_rename_cred
        + g.drv_copy_cred + g.drv_setxattr_cred + g.drv_removexattr_cred
        + g.drv_setattr_cred + g.drv_stat_cred
        + g.drv_reserve + g.drv_unlink_many + g.drv_sync_publish
        + g.drv_exchange + g.drv_recall + g.drv_evict
        + g.drv_unlink_many_cred + g.drv_exchange_cred + g.drv_recall_cred
        + g.drv_evict_cred
        + g.ns_leaf + g.cred_gate + g.ns_cred + g.cache_evict + g.leaf_isdir
        + g.publish_dirsync + g.ns_exchange + g.rmtree_dispatch;
}

/* ---- namespace layer (the POSIX plane's mutating dispatch) --------------- */
static brix_ns_result_t
ns_answer(void)
{
    brix_ns_result_t res;

    memset(&res, 0, sizeof(res));
    if (g_inject_errno != 0) {
        res.status = BRIX_NS_IO_ERROR;
        res.sys_errno = g_inject_errno;
        return res;
    }
    res.status = BRIX_NS_OK;
    res.created = 1;
    res.existed = 1;
    return res;
}

brix_ns_result_t
brix_ns_mkdir(ngx_log_t *log, const char *root_canon, const char *path,
    mode_t mode, ngx_flag_t recursive)
{
    (void) log; (void) root_canon; (void) path; (void) mode; (void) recursive;
    g.ns_mkdir++;
    return ns_answer();
}

brix_ns_result_t
brix_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const brix_ns_delete_opts_t *opts)
{
    (void) log; (void) root_canon; (void) path; (void) opts;
    g.ns_delete++;
    return ns_answer();
}

/* The borrowed-rootfd twins are the SAME mutation on the same counter — a
 * read-only export must reach neither the owned nor the borrowed entry. */
brix_ns_result_t
brix_ns_mkdir_at(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *path, mode_t mode, ngx_flag_t recursive)
{
    (void) log; (void) rootfd; (void) root_canon; (void) path;
    (void) mode; (void) recursive;
    g.ns_mkdir++;
    return ns_answer();
}

brix_ns_result_t
brix_ns_delete_at(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *path, const brix_ns_delete_opts_t *opts)
{
    (void) log; (void) rootfd; (void) root_canon; (void) path; (void) opts;
    g.ns_delete++;
    return ns_answer();
}

brix_ns_result_t
brix_ns_rename(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, ngx_flag_t overwrite_dirs)
{
    (void) log; (void) root_canon; (void) src; (void) dst;
    (void) overwrite_dirs;
    g.ns_rename++;
    return ns_answer();
}

brix_ns_result_t
brix_ns_local_copy(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, const brix_ns_copy_opts_t *opts)
{
    (void) log; (void) root_canon; (void) src; (void) dst; (void) opts;
    g.ns_local_copy++;
    return ns_answer();
}

brix_ns_result_t
brix_ns_exchange(ngx_log_t *log, const char *root_canon, const char *a,
    const char *b)
{
    (void) log; (void) root_canon; (void) a; (void) b;
    g.ns_exchange++;
    return ns_answer();
}

/* ---- confined-path syscalls (the POSIX plane's metadata mutations) ------- */
static int
canon_answer(void)
{
    if (g_inject_errno != 0) {
        errno = g_inject_errno;
        return -1;
    }
    return 0;
}

int
brix_chmod_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    (void) log; (void) root_canon; (void) resolved; (void) mode;
    g.chmod_canon++;
    return canon_answer();
}

int
brix_setattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int set_times, const struct timespec times[2],
    int set_owner, uid_t uid, gid_t gid)
{
    (void) log; (void) root_canon; (void) resolved; (void) set_times;
    (void) times; (void) set_owner; (void) uid; (void) gid;
    g.setattr_canon++;
    return canon_answer();
}

int
brix_setxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, const void *value, size_t len,
    int flags)
{
    (void) log; (void) root_canon; (void) resolved; (void) name;
    (void) value; (void) len; (void) flags;
    g.setxattr_canon++;
    return canon_answer();
}

int
brix_removexattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name)
{
    (void) log; (void) root_canon; (void) resolved; (void) name;
    g.removexattr_canon++;
    return canon_answer();
}

ssize_t
brix_getxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, const char *name, void *buf, size_t bufsz)
{
    (void) log; (void) root_canon; (void) resolved; (void) name;
    (void) buf; (void) bufsz;
    g.getxattr_canon++;
    return 0;
}

ssize_t
brix_listxattr_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, void *buf, size_t bufsz)
{
    (void) log; (void) root_canon; (void) resolved; (void) buf; (void) bufsz;
    g.listxattr_canon++;
    return 0;
}

/* ---- resolution, invalidation, observation ------------------------------ */
brix_sd_instance_t *
brix_vfs_ns_leaf(brix_sd_instance_t *top)
{
    g.ns_leaf++;
    return top;
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
    return 0;
}

int
brix_vfs_backend_leaf_isdir(brix_sd_instance_t *leaf, const char *logical,
    const brix_sd_cred_t *cred)
{
    (void) leaf; (void) logical; (void) cred;
    g.leaf_isdir++;
    return 0;
}

int
brix_vfs_backend_mkpath(const char *root_canon, const char *logical,
    mode_t mode, ngx_log_t *log)
{
    (void) root_canon; (void) logical; (void) mode; (void) log;
    g.mkpath++;
    return canon_answer();
}

void
brix_vfs_neg_stat_forget(const char *root_canon, const char *path)
{
    (void) root_canon; (void) path;
}

/* Phase-107 C7: the lock gate also sits AFTER the policy gate. It is a read
 * of lock state, not a mutation sink — "unlocked" keeps every case on its
 * pre-C7 flow, and a refused mutation still must not reach the sinks below. */
ngx_int_t
brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    (void) ctx; (void) op;
    return NGX_OK;
}

ngx_int_t
brix_vfs_require_unlocked_at(brix_vfs_ctx_t *ctx, const char *path,
    brix_vfs_mutation_op_t op)
{
    (void) ctx; (void) path; (void) op;
    return NGX_OK;
}

/* Phase-107 C3: the durable-publish barrier sits AFTER the policy gate, so a
 * refused mutation must never reach it. durable=0 keeps the allowed-control
 * cases on their pre-C3 sink counts (no dirfsync against the fake paths), and
 * the dirsync spy still counts as a sink so a gate leak stays visible. */
ngx_int_t
brix_vfs_backend_durable(const char *root_canon)
{
    (void) root_canon;
    return 0;
}

ngx_int_t
brix_publish_dirsync(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *final_path)
{
    (void) log; (void) rootfd; (void) root_canon; (void) final_path;
    g.publish_dirsync++;
    return NGX_OK;
}

ngx_int_t
brix_vfs_rmtree_dispatch(brix_sd_instance_t *leaf,
    const brix_sd_driver_t *drv, const char *logical,
    const brix_sd_cred_t *cred)
{
    (void) leaf; (void) drv; (void) logical; (void) cred;
    g.rmtree_dispatch++;
    return NGX_OK;
}

/* C6 refusal telemetry — an OBSERVATION, expected on a refusal (like the
 * denial counter), so it is deliberately not a spy sink. */
void
brix_vfs_precond_refused_observe(const brix_sd_precond_t *pre, int err,
    const char *driver_name)
{
    (void) pre; (void) err; (void) driver_name;
    g.precond_refused++;
}

/* The RENAME_NOREPLACE degradation latch: this host never degraded. */
int
brix_renameat_noreplace_degraded(void)
{
    return 0;
}

/* The real helper strips the export root and the separator; the prefix walk in
 * the leaf-aware mkpath depends on that shape, so the stub reproduces it. */
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
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    (void) proto; (void) op;
    g.denials++;
}

void
brix_access_log_emit(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result, size_t bytes,
    brix_err_class_t err, ngx_msec_t latency_usec)
{
    (void) ctx; (void) path; (void) op; (void) result; (void) bytes;
    (void) err; (void) latency_usec;
}

/* ---- the spy storage driver ---------------------------------------------
 * Plain and credential-scoped namespace slots both count, because a gate that
 * a _cred path can walk around is not a gate (the sd_remote `_cred` asymmetry
 * class). Every capability bit is set so a read-only refusal can never be
 * confused with a capability refusal. */
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
spy_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    (void) inst; (void) path;
    g.drv_stat++;
    memset(out, 0, sizeof(*out));
    return NGX_OK;
}

static ngx_int_t
spy_stat_cred(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out,
    const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_stat_cred++;
    return spy_stat(inst, path, out);
}

static ngx_int_t
spy_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    (void) inst; (void) path; (void) mode;
    g.drv_mkdir++;
    return drv_answer();
}

static ngx_int_t
spy_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) mode; (void) cred;
    g.drv_mkdir_cred++;
    return drv_answer();
}

static ngx_int_t
spy_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    (void) inst; (void) path; (void) is_dir;
    g.drv_unlink++;
    return drv_answer();
}

static ngx_int_t
spy_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) is_dir; (void) cred;
    g.drv_unlink_cred++;
    return drv_answer();
}

static ngx_int_t
spy_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    (void) inst; (void) src; (void) dst; (void) noreplace;
    g.drv_rename++;
    return drv_answer();
}

static ngx_int_t
spy_rename_cred(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace, const brix_sd_cred_t *cred)
{
    (void) inst; (void) src; (void) dst; (void) noreplace; (void) cred;
    g.drv_rename_cred++;
    return drv_answer();
}

static ngx_int_t
spy_server_copy(brix_sd_instance_t *inst, const char *src, const char *dst,
    off_t *bytes_out)
{
    (void) inst; (void) src; (void) dst;
    g.drv_copy++;
    if (bytes_out != NULL) {
        *bytes_out = 0;
    }
    return drv_answer();
}

static ngx_int_t
spy_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_copy_cred++;
    g.drv_copy--;   /* the plain twin below must not also count this call */
    return spy_server_copy(inst, src, dst, bytes_out);
}

static ngx_int_t
spy_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    (void) inst; (void) path; (void) name; (void) val; (void) len;
    (void) flags;
    g.drv_setxattr++;
    return drv_answer();
}

static ngx_int_t
spy_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) name; (void) val; (void) len;
    (void) flags; (void) cred;
    g.drv_setxattr_cred++;
    return drv_answer();
}

static ngx_int_t
spy_removexattr(brix_sd_instance_t *inst, const char *path, const char *name)
{
    (void) inst; (void) path; (void) name;
    g.drv_removexattr++;
    return drv_answer();
}

static ngx_int_t
spy_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) name; (void) cred;
    g.drv_removexattr_cred++;
    return drv_answer();
}

static ngx_int_t
spy_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    (void) inst; (void) path; (void) attr;
    g.drv_setattr++;
    return drv_answer();
}

static ngx_int_t
spy_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) attr; (void) cred;
    g.drv_setattr_cred++;
    return drv_answer();
}

/* ---- the phase-107 slots (W0/§9.3) --------------------------------------- */
static ngx_int_t
spy_reserve(brix_sd_obj_t *obj, off_t size)
{
    (void) obj; (void) size;
    g.drv_reserve++;
    return drv_answer();
}

static ngx_int_t
spy_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    size_t i;

    (void) inst;
    g.drv_unlink_many++;
    if (g_inject_errno != 0) {
        errno = g_inject_errno;
        return NGX_ERROR;
    }
    for (i = 0; i < b->n; i++) {
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
    g.drv_unlink_many--;   /* the plain twin must not also count this call */
    return spy_unlink_many(inst, b);
}

static ngx_int_t
spy_sync_publish(brix_sd_instance_t *inst, const char *path)
{
    (void) inst; (void) path;
    g.drv_sync_publish++;
    return drv_answer();
}

static ngx_int_t
spy_exchange(brix_sd_instance_t *inst, const char *a, const char *b)
{
    (void) inst; (void) a; (void) b;
    g.drv_exchange++;
    return drv_answer();
}

static ngx_int_t
spy_exchange_cred(brix_sd_instance_t *inst, const char *a, const char *b,
    const brix_sd_cred_t *cred)
{
    (void) inst; (void) a; (void) b; (void) cred;
    g.drv_exchange_cred++;
    return drv_answer();
}

static ngx_int_t
spy_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    (void) inst; (void) key;
    g.drv_recall++;
    if (reqid_out != NULL) {
        reqid_out[0] = '\0';
    }
    return drv_answer();
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
    if (bytes_out != NULL) {
        *bytes_out = 0;
    }
    return drv_answer();
}

static ngx_int_t
spy_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    (void) cred;
    g.drv_evict_cred++;
    g.drv_evict--;   /* the plain twin must not also count this call */
    return spy_evict(inst, path, bytes_out);
}

static const brix_sd_driver_t  spy_driver = {
    .name = "spy",
    .caps = 0xffffffffu,
    .stat = spy_stat,
    .unlink = spy_unlink,
    .mkdir = spy_mkdir,
    .rename = spy_rename,
    .server_copy = spy_server_copy,
    .setattr = spy_setattr,
    .setxattr = spy_setxattr,
    .removexattr = spy_removexattr,
    .reserve = spy_reserve,
    .unlink_many = spy_unlink_many,
    .sync_publish = spy_sync_publish,
    .exchange = spy_exchange,
    .recall = spy_recall,
    .evict = spy_evict,
    .stat_cred = spy_stat_cred,
    .unlink_cred = spy_unlink_cred,
    .mkdir_cred = spy_mkdir_cred,
    .rename_cred = spy_rename_cred,
    .server_copy_cred = spy_server_copy_cred,
    .setattr_cred = spy_setattr_cred,
    .setxattr_cred = spy_setxattr_cred,
    .removexattr_cred = spy_removexattr_cred,
    .unlink_many_cred = spy_unlink_many_cred,
    .exchange_cred = spy_exchange_cred,
    .recall_cred = spy_recall_cred,
    .evict_cred = spy_evict_cred,
};

static brix_sd_instance_t  spy_instance;

/* Two deliberately-degraded copies of the spy vtable, filled in main():
 * `noxw` withdraws BRIX_SD_CAP_XATTR_WRITE (the phase-71 capability gate
 * answers ENOTSUP), `nocred` withdraws the credential-scoped xattr slots
 * (deny-mode dispatch answers EACCES).  Threat rows N.3: on a read-only
 * endpoint EROFS must precede BOTH of those answers — neither the driver's
 * shape nor the identity plane may leak through the refusal. */
static brix_sd_driver_t    spy_driver_noxw;
static brix_sd_instance_t  spy_instance_noxw;
static brix_sd_driver_t    spy_driver_nocred;
static brix_sd_instance_t  spy_instance_nocred;

/* ---- the operation matrix ----------------------------------------------- */
static u_char  src_path[] = "/export/collection/object";
static u_char  dst_path[] = "/export/collection/other";

static void
ctx_build(brix_vfs_ctx_t *ctx, brix_vfs_mutation_policy_t policy, int use_drv)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->metrics_proto = BRIX_PROTO_WEBDAV;
    ctx->root_canon = "/export";
    ctx->mutation_policy = policy;
    ctx->resolved.resolved.data = src_path;
    ctx->resolved.resolved.len = sizeof(src_path) - 1;
    ctx->resolved.is_confined = 1;
    ctx->sd = use_drv ? &spy_instance : NULL;
}

typedef ngx_int_t (*op_fn)(brix_vfs_ctx_t *ctx);

static ngx_int_t
op_mkdir(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_mkdir(ctx, 0755, 0);
}

static ngx_int_t
op_mkdir_parents(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_mkdir(ctx, 0755, 1);
}

static ngx_int_t op_rmdir(brix_vfs_ctx_t *ctx) { return brix_vfs_rmdir(ctx, 1); }
static ngx_int_t op_unlink(brix_vfs_ctx_t *ctx) { return brix_vfs_unlink(ctx); }

static ngx_int_t
op_rename(brix_vfs_ctx_t *ctx)
{
    brix_path_result_t dst;

    memset(&dst, 0, sizeof(dst));
    dst.resolved.data = dst_path;
    dst.resolved.len = sizeof(dst_path) - 1;
    dst.is_confined = 1;
    return brix_vfs_rename(ctx, &dst, 1);
}

static ngx_int_t
op_exchange(brix_vfs_ctx_t *ctx)
{
    brix_path_result_t other;

    memset(&other, 0, sizeof(other));
    other.resolved.data = dst_path;
    other.resolved.len = sizeof(dst_path) - 1;
    other.is_confined = 1;
    return brix_vfs_exchange(ctx, &other);
}

static ngx_int_t
op_copy(brix_vfs_ctx_t *ctx)
{
    brix_vfs_copy_opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.overwrite = 1;
    return brix_vfs_copy(ctx, (const char *) dst_path, &opts);
}

static ngx_int_t op_chmod(brix_vfs_ctx_t *ctx) { return brix_vfs_chmod(ctx, 0644); }

static ngx_int_t
op_setattr(brix_vfs_ctx_t *ctx)
{
    brix_sd_setattr_t attr;

    /* Times only: the POSIX plane applies mode through a SECOND confined
     * helper, and this matrix asserts one sink per operation. brix_vfs_chmod
     * above already covers the mode half. */
    memset(&attr, 0, sizeof(attr));
    attr.set_times = 1;
    return brix_vfs_setattr(ctx, &attr);
}

static ngx_int_t
op_setxattr(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_setxattr(ctx, "user.brix.test", "v", 1, 0);
}

static ngx_int_t
op_removexattr(brix_vfs_ctx_t *ctx)
{
    return brix_vfs_removexattr(ctx, "user.brix.test");
}

typedef struct {
    const char *name;
    op_fn       fn;
    /* Byte offset into spy_t of the ONE counter this op must bump on an
     * ALLOWED endpoint, per plane. */
    size_t      posix_sink;
    size_t      driver_sink;
    size_t      driver_cred_sink;
} op_case_t;

#define SINK(field)  offsetof(spy_t, field)

static const op_case_t  OPS[] = {
    { "mkdir",       op_mkdir,         SINK(ns_mkdir),           SINK(drv_mkdir),       SINK(drv_mkdir_cred) },
    { "mkdir -p",    op_mkdir_parents, SINK(ns_mkdir),           SINK(mkpath),          SINK(drv_mkdir_cred) },
    /* recursive rmdir routes the driver arm through brix_vfs_rmtree_dispatch
     * (phase-107 C4), which carries the credential itself — one sink for both
     * driver columns. */
    { "rmdir",       op_rmdir,         SINK(ns_delete),          SINK(rmtree_dispatch), SINK(rmtree_dispatch) },
    { "unlink",      op_unlink,        SINK(ns_delete),          SINK(drv_unlink),      SINK(drv_unlink_cred) },
    { "rename",      op_rename,        SINK(ns_rename),          SINK(drv_rename),      SINK(drv_rename_cred) },
    /* phase-107 C6: exchange is a rename-class two-name mutation; the same
     * gate must hold on its POSIX arm, its driver slot, and its _cred twin. */
    { "exchange",    op_exchange,      SINK(ns_exchange),        SINK(drv_exchange),    SINK(drv_exchange_cred) },
    { "copy",        op_copy,          SINK(ns_local_copy),      SINK(drv_copy),        SINK(drv_copy_cred) },
    { "chmod",       op_chmod,         SINK(chmod_canon),        SINK(drv_setattr),     SINK(drv_setattr_cred) },
    { "setattr",     op_setattr,       SINK(setattr_canon),      SINK(drv_setattr),     SINK(drv_setattr_cred) },
    { "setxattr",    op_setxattr,      SINK(setxattr_canon),     SINK(drv_setxattr),    SINK(drv_setxattr_cred) },
    { "removexattr", op_removexattr,   SINK(removexattr_canon),  SINK(drv_removexattr), SINK(drv_removexattr_cred) },
};

#define OP_COUNT  ((int) (sizeof(OPS) / sizeof(OPS[0])))

static int
sink_value(size_t off)
{
    int v;

    memcpy(&v, (const char *) &g + off, sizeof(v));
    return v;
}

/* One ALLOWED call must reach exactly the expected sink, exactly once. */
static void
assert_allowed_reaches(const op_case_t *c, int use_drv, size_t sink)
{
    brix_vfs_ctx_t ctx;

    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, use_drv);
    errno = 0;
    /* The expected sink is reached, and it is the ONLY kind of mutation that
     * happens — a recursive helper may touch its own sink more than once (the
     * leaf-aware mkpath walks a prefix chain), but no second sink may fire. */
    if (c->fn(&ctx) != NGX_OK || sink_value(sink) < 1
        || spy_mutations() != sink_value(sink))
    {
        fprintf(stderr,
                "allowed %s (driver=%d) errno=%d sink=%d mutations=%d\n",
                c->name, use_drv, errno, sink_value(sink), spy_mutations());
        assert(0);
    }
    assert(g.denials == 0);
}

/* One READ_ONLY call must be EROFS with every sink untouched. */
static void
assert_readonly_refuses(const op_case_t *c, int use_drv)
{
    brix_vfs_ctx_t ctx;

    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, use_drv);
    errno = 0;
    if (c->fn(&ctx) != NGX_ERROR || errno != EROFS || spy_sinks() != 0
        || g.denials != 1)
    {
        fprintf(stderr,
                "read-only %s (driver=%d) errno=%d sinks=%d denials=%d\n",
                c->name, use_drv, errno, spy_sinks(), g.denials);
        assert(0);
    }
}

/* One xattr mutation against a degraded vtable must answer exactly
 * `want_errno` and mutate nothing; `want_denials` pins WHICH layer refused
 * (1 = the phase-105 endpoint gate, 0 = a downstream gate).  A downstream
 * refusal legitimately runs resolution work first (leaf, credential gate),
 * but the endpoint gate must leave even that at zero. */
static void
assert_alt_refuses(op_fn fn, brix_sd_instance_t *inst,
    brix_vfs_mutation_policy_t policy, int want_errno, int want_denials)
{
    brix_vfs_ctx_t ctx;
    int            leaked;

    spy_reset();
    ctx_build(&ctx, policy, 1);
    ctx.sd = inst;
    errno = 0;
    if (fn(&ctx) != NGX_ERROR || errno != want_errno
        || g.denials != want_denials)
    {
        leaked = -1;
    } else {
        leaked = (policy == BRIX_VFS_MUTATION_READ_ONLY)
            ? spy_sinks() : spy_mutations();
    }
    if (leaked != 0) {
        fprintf(stderr,
                "alt-vtable errno=%d (want %d) leaked=%d denials=%d (want %d)\n",
                errno, want_errno, leaked, g.denials, want_denials);
        assert(0);
    }
}

static void
test_success(void)
{
    brix_vfs_ctx_t  ctx;
    char            buf[64];
    int             i;

    g_cred_gate_on = 0;
    for (i = 0; i < OP_COUNT; i++) {
        assert_allowed_reaches(&OPS[i], 0, OPS[i].posix_sink);
        assert_allowed_reaches(&OPS[i], 1, OPS[i].driver_sink);
    }

    /* the same matrix with the credential gate active reaches the _cred twin */
    g_cred_gate_on = 1;
    for (i = 0; i < OP_COUNT; i++) {
        assert_allowed_reaches(&OPS[i], 1, OPS[i].driver_cred_sink);
    }
    g_cred_gate_on = 0;

    /* reads are NOT mutations: they work on a read-only endpoint, and they
     * are the control proving the endpoint is otherwise functional */
    spy_reset();
    ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, 0);
    assert(brix_vfs_getxattr(&ctx, "user.brix.test", buf, sizeof(buf)) == 0);
    assert(brix_vfs_listxattr(&ctx, buf, sizeof(buf)) == 0);
    assert(g.getxattr_canon == 1);
    assert(g.listxattr_canon == 1);
    assert(g.denials == 0);

    printf("ok success\n");
}

static void
test_error(void)
{
    brix_vfs_ctx_t ctx;
    int            i;

    /* A real backend failure under an ALLOWED policy propagates verbatim: the
     * gate neither swallows it nor rewrites it into the read-only errno. */
    g_cred_gate_on = 0;
    for (i = 0; i < OP_COUNT; i++) {
        spy_reset();
        g_inject_errno = EIO;
        ctx_build(&ctx, BRIX_VFS_MUTATION_ALLOWED, 0);
        errno = 0;
        assert(OPS[i].fn(&ctx) == NGX_ERROR);
        assert(errno == EIO);
        assert(errno != EROFS);
        assert(g.denials == 0);
    }

    /* Precedence controls (ALLOWED endpoint): these are the answers the
     * read-only endpoint must never leak.  Without CAP_XATTR_WRITE the
     * capability gate answers ENOTSUP; a deny-mode credential gate over a
     * _cred-less vtable answers EACCES.  Zero denials: the phase-105 gate
     * stayed silent, a DOWNSTREAM gate refused. */
    g_cred_gate_on = 0;
    assert_alt_refuses(op_setxattr, &spy_instance_noxw,
                       BRIX_VFS_MUTATION_ALLOWED, ENOTSUP, 0);
    assert_alt_refuses(op_removexattr, &spy_instance_noxw,
                       BRIX_VFS_MUTATION_ALLOWED, ENOTSUP, 0);
    g_cred_gate_on = 1;
    g_cred_fallback_deny = 1;
    assert_alt_refuses(op_setxattr, &spy_instance_nocred,
                       BRIX_VFS_MUTATION_ALLOWED, EACCES, 0);
    assert_alt_refuses(op_removexattr, &spy_instance_nocred,
                       BRIX_VFS_MUTATION_ALLOWED, EACCES, 0);
    g_cred_gate_on = 0;
    g_cred_fallback_deny = 0;

    printf("ok error\n");
}

static void
test_security_negative(void)
{
    brix_vfs_ctx_t ctx;
    int            i;

    /* The core claim: on a read-only endpoint nothing downstream of the gate
     * runs — not on the POSIX plane, not on a fully-capable storage driver,
     * and not on the credential-scoped slots even with the credential gate
     * active (the confused-deputy path a plain-slot-only test would miss). */
    for (i = 0; i < OP_COUNT; i++) {
        g_cred_gate_on = 0;
        assert_readonly_refuses(&OPS[i], 0);
        assert_readonly_refuses(&OPS[i], 1);
        g_cred_gate_on = 1;
        assert_readonly_refuses(&OPS[i], 1);
    }
    g_cred_gate_on = 0;

    /* An injected backend failure changes nothing: the refusal is decided
     * before the backend is consulted, so the answer stays EROFS rather than
     * disclosing what the backend would have said. */
    for (i = 0; i < OP_COUNT; i++) {
        spy_reset();
        g_inject_errno = EIO;
        ctx_build(&ctx, BRIX_VFS_MUTATION_READ_ONLY, 1);
        errno = 0;
        assert(OPS[i].fn(&ctx) == NGX_ERROR);
        assert(errno == EROFS);
        assert(spy_sinks() == 0);
    }

    /* Threat rows N.3 (I.5 ordering): the endpoint's posture precedes both
     * the capability gate and the credential deny — EROFS, never the ENOTSUP
     * that would reveal the driver's shape, never the EACCES that would
     * reveal the identity plane.  One denial each: the phase-105 gate is
     * what refused. */
    g_cred_gate_on = 0;
    assert_alt_refuses(op_setxattr, &spy_instance_noxw,
                       BRIX_VFS_MUTATION_READ_ONLY, EROFS, 1);
    assert_alt_refuses(op_removexattr, &spy_instance_noxw,
                       BRIX_VFS_MUTATION_READ_ONLY, EROFS, 1);
    g_cred_gate_on = 1;
    g_cred_fallback_deny = 1;
    assert_alt_refuses(op_setxattr, &spy_instance_nocred,
                       BRIX_VFS_MUTATION_READ_ONLY, EROFS, 1);
    assert_alt_refuses(op_removexattr, &spy_instance_nocred,
                       BRIX_VFS_MUTATION_READ_ONLY, EROFS, 1);
    g_cred_gate_on = 0;
    g_cred_fallback_deny = 0;

    printf("ok security-negative\n");
}

int
main(void)
{
    memset(&spy_instance, 0, sizeof(spy_instance));
    spy_instance.driver = &spy_driver;
    spy_instance.caps = 0xffffffffu;

    spy_driver_noxw = spy_driver;
    spy_driver_noxw.caps = 0xffffffffu & ~BRIX_SD_CAP_XATTR_WRITE;
    memset(&spy_instance_noxw, 0, sizeof(spy_instance_noxw));
    spy_instance_noxw.driver = &spy_driver_noxw;
    spy_instance_noxw.caps = spy_driver_noxw.caps;

    spy_driver_nocred = spy_driver;
    spy_driver_nocred.setxattr_cred = NULL;
    spy_driver_nocred.removexattr_cred = NULL;
    memset(&spy_instance_nocred, 0, sizeof(spy_instance_nocred));
    spy_instance_nocred.driver = &spy_driver_nocred;
    spy_instance_nocred.caps = 0xffffffffu;

    test_success();
    test_error();
    test_security_negative();
    printf("PASS test_vfs_read_only_spy\n");
    return 0;
}
