#ifndef BRIX_VFS_POLICY_H
#define BRIX_VFS_POLICY_H

/*
 * vfs_policy.h — the VFS mutation-policy contract (phase-105).
 *
 * WHAT: Declares the typed endpoint mutation policy
 *       (brix_vfs_mutation_policy_t), the bounded operation vocabulary
 *       (brix_vfs_mutation_op_t) used for diagnostics and metrics, the policy
 *       kernel every VFS mutation entry point consults
 *       (brix_vfs_require_mutation_policy / _mutation / _confined_mutation),
 *       the config-derivation helper, and the policy-bearing operation context
 *       (brix_vfs_export_op_ctx_t) that carries the same authority into the
 *       ctx-less raw export helpers.
 *
 * WHY:  Before phase-105 "may this request mutate the export?" was a bare
 *       allow_write bit tested in a handful of places, so a mutator that forgot
 *       the test reached a storage driver, and a protocol edge that forgot its
 *       gate was the only thing standing between a read-only export and a
 *       write. Making the authority a typed value that zero-initialises to
 *       READ_ONLY, and routing every mutator through one kernel, turns "the
 *       endpoint is read-only" into a VFS invariant instead of an edge habit.
 *
 * HOW:  The policy is a two-valued enum whose zero is READ_ONLY, so a zeroed or
 *       hand-built object fails closed. The kernel is pure: it validates its
 *       inputs, returns NGX_ERROR with errno = EROFS under a read-only policy,
 *       and performs no allocation, I/O, backend lookup, or credential
 *       selection — which is what lets it run BEFORE leaf resolution, cache
 *       invalidation, and capability probing at every call site.
 *
 * Requires: <ngx_core.h> and observability/metrics/unified.h (brix_proto_t)
 *           before inclusion; included from vfs.h, never directly.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "observability/metrics/unified.h"   /* brix_proto_t, metric recorder */

/* vfs.h defines the struct; the kernel only needs the name, and declaring the
 * typedef here (guarded) lets this header stand alone in a unit test. */
#ifndef BRIX_VFS_CTX_T_DECLARED
#define BRIX_VFS_CTX_T_DECLARED
typedef struct brix_vfs_ctx_s brix_vfs_ctx_t;
#endif

/* Whether this request's endpoint may modify exported storage. READ_ONLY is
 * zero on purpose: a zeroed or partially-built context is read-only, so an
 * omitted policy can never read as "writable". */
typedef enum {
    BRIX_VFS_MUTATION_READ_ONLY = 0,
    BRIX_VFS_MUTATION_ALLOWED   = 1
} brix_vfs_mutation_policy_t;

/* The bounded mutation vocabulary. Values are append-only and exist for
 * diagnostics and low-cardinality metric labels (INVARIANT #8) — never for
 * exempting a backend, a protocol, or a path. It carries no protocol verb, no
 * backend name, and no user data. */
typedef enum {
    BRIX_VFS_MUTATE_OPEN = 0,   /* write/create/truncate/append open        */
    BRIX_VFS_MUTATE_WRITE,      /* byte write, writev, pgwrite, staged write */
    BRIX_VFS_MUTATE_TRUNCATE,   /* handle ftruncate and path-native truncate */
    BRIX_VFS_MUTATE_SYNC,       /* flush/fsync of a writable handle          */
    BRIX_VFS_MUTATE_MKDIR,      /* directory creation, incl. parent chains   */
    BRIX_VFS_MUTATE_REMOVE,     /* unlink and rmdir                          */
    BRIX_VFS_MUTATE_RENAME,     /* rename/move, same- and cross-backend      */
    BRIX_VFS_MUTATE_COPY,       /* copy, recursive copy, server-side copy    */
    BRIX_VFS_MUTATE_SETATTR,    /* chmod/chown/utimes/setattr                */
    BRIX_VFS_MUTATE_XATTR,      /* set/remove xattr, dead props, tags        */
    BRIX_VFS_MUTATE_PUBLISH,    /* staged commit, multipart complete, promote */
    BRIX_VFS_MUTATE_OP_COUNT    /* never a real operation                    */
} brix_vfs_mutation_op_t;

/* The metric mirror of the vocabulary above lives in unified.h so the metrics
 * layer keeps no dependency on the fs layer; vfs_policy.c carries the
 * compile-time equality check between the two. */

/* Map a merged endpoint write-enable flag onto the typed policy. Exactly 1 is
 * ALLOWED; every other value — including an unset ngx_flag_t's NGX_CONF_UNSET —
 * is READ_ONLY. Callers use it only AFTER configuration merge; an intrinsically
 * read-only surface names BRIX_VFS_MUTATION_READ_ONLY directly. It accepts no
 * backend capability, no token scope, and no protocol verb. */
brix_vfs_mutation_policy_t brix_vfs_policy_from_write_enable(
    ngx_flag_t allow_write);

/* The stable lowercase label for `op` ("open", "write", …), or "unknown" for an
 * out-of-range value. One table, shared by metrics and structured logs. */
const char *brix_vfs_mutation_op_name(brix_vfs_mutation_op_t op);

/* ---- the policy kernel ----------------------------------------------------
 * All three return NGX_OK when the operation may proceed, else NGX_ERROR with
 * errno set: EINVAL for a missing context or an out-of-range operation, EINVAL
 * for an unconfined path on the confined form, and EROFS when the endpoint
 * policy is read-only. EROFS is emitted BEFORE any capability, credential, or
 * backend answer, so a read-only endpoint never discloses which of the later
 * gates would also have refused (Appendix I.5). */

/* Pure form: decide from a policy value alone. Used by objects that carry the
 * policy by value (handles, staged sessions, writers, queued jobs) and by the
 * unit tests, which need the decision without a context. */
ngx_int_t brix_vfs_require_mutation_policy(brix_vfs_mutation_policy_t policy,
    brix_vfs_mutation_op_t op);

/* Context form: validate `ctx` and decide from ctx->mutation_policy. Does not
 * require a resolved path — for handle- and fd-based mutations whose target is
 * already open. */
ngx_int_t brix_vfs_require_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

/* Path form: confinement first (EINVAL), then policy (EROFS). Every path-based
 * mutator uses this one. */
ngx_int_t brix_vfs_require_confined_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op);

/* Carried form: decide from a policy an object copied at construction, and
 * attribute the denial to `proto`. This is what an open handle, a staged
 * session, a writer or a queued job uses — it must never re-read a context it
 * may outlive, and it must still be counted the same way a context rejection
 * is. EROFS on refusal, exactly one metric sample. */
ngx_int_t brix_vfs_require_carried_mutation(brix_vfs_mutation_policy_t policy,
    brix_proto_t proto, brix_vfs_mutation_op_t op);

/* ---- policy-bearing raw/export operation context --------------------------
 * The thread-safe raw helpers (vfs_ops.h) take a log + root_canon rather than a
 * ctx, because they run off the event loop where a request context does not
 * exist. This bundle carries the same authority onto them WITHOUT adding a
 * boolean to every signature, so an off-thread export mutation is as gated as
 * an on-thread one. Fields are borrowed; the bundle is a caller-owned value. */
typedef struct {
    ngx_log_t                  *log;
    const char                 *root_canon;
    brix_vfs_mutation_policy_t  mutation_policy;
    brix_proto_t                proto;
} brix_vfs_export_op_ctx_t;

/* Fill *opctx. Zeroes first, so an unset policy is READ_ONLY. No-op on NULL. */
void brix_vfs_export_op_ctx_init(brix_vfs_export_op_ctx_t *opctx,
    ngx_log_t *log, const char *root_canon,
    brix_vfs_mutation_policy_t policy, brix_proto_t proto);

/* Derive an operation context from a request VFS ctx, inheriting its policy,
 * root, log, and metrics protocol verbatim. This is the ONLY sanctioned way to
 * carry request authority onto an off-thread helper: it cannot widen the
 * policy, and a NULL ctx yields a READ_ONLY bundle. */
void brix_vfs_export_op_ctx_from(brix_vfs_export_op_ctx_t *opctx,
    const brix_vfs_ctx_t *ctx);

/* Gate an export mutation described by an operation context. Same contract as
 * brix_vfs_require_mutation: NGX_OK, or NGX_ERROR with EINVAL (no bundle) /
 * EROFS (read-only endpoint). */
ngx_int_t brix_vfs_export_require_mutation(
    const brix_vfs_export_op_ctx_t *opctx, brix_vfs_mutation_op_t op);

/* 1 when raw O_* `flags` describe an operation that can modify the object or
 * the namespace (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND), else 0. A raw
 * read-only open stays legal on a read-only export; anything else takes the
 * kernel first (Appendix C.5). */
int brix_vfs_open_flags_mutate(int flags);

#endif /* BRIX_VFS_POLICY_H */
