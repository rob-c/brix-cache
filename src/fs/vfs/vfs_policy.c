/*
 * vfs_policy.c — the one VFS mutation-policy kernel (phase-105).
 *
 * WHAT: Implements the decision every VFS mutation entry point asks before it
 *       touches anything: may THIS request modify exported storage? Owns the
 *       config-derivation helper (brix_vfs_policy_from_write_enable), the
 *       bounded operation-name table, the three kernel forms, the
 *       policy-bearing operation-context helpers, and the raw-open-flag
 *       classifier.
 *
 * WHY:  The decision used to be spelled out at each call site as
 *       `!ctx->allow_write` -> EACCES, which meant a new mutator inherited the
 *       gate only if its author remembered to write it, and which reported the
 *       same errno as an authorization failure. One kernel makes the gate
 *       inheritable, makes the result distinguishable (EROFS, never EACCES),
 *       and — because it is pure — makes it cheap enough to run BEFORE leaf
 *       resolution, credential selection, cache invalidation, and capability
 *       probing, which is the ordering the security property depends on.
 *
 * HOW:  Every form funnels into brix_vfs_require_mutation_policy(), which
 *       range-checks the operation and returns NGX_ERROR/EROFS for a read-only
 *       policy. The context forms add the object validation (and, for the path
 *       form, confinement) that must precede it, then attribute one denial
 *       observation — only here, so an edge that already refused never
 *       double-counts. No allocation, no I/O, no backend or credential lookup.
 */
#include "vfs_internal.h"
#include "vfs_policy.h"

/* The metrics layer mirrors the operation vocabulary as a plain count so it
 * keeps no dependency on the fs layer; if a value is appended here the mirror
 * must grow with it. */
_Static_assert((int) BRIX_VFS_MUTATE_OP_COUNT
                   == BRIX_VFS_MUTATE_OP_METRIC_COUNT,
    "brix_vfs_mutation_op_t and BRIX_VFS_MUTATE_OP_METRIC_COUNT disagree");

/* ---- Map a merged write-enable flag onto the typed policy ----
 *
 * WHAT: Returns BRIX_VFS_MUTATION_ALLOWED for exactly 1 and
 *       BRIX_VFS_MUTATION_READ_ONLY for every other value.
 *
 * WHY:  ngx_flag_t is a signed integer that is NGX_CONF_UNSET (-1) before a
 *       merge completes, so "non-zero means writable" would read an unmerged
 *       or corrupt flag as permission. Only the exact enabled value opens the
 *       endpoint.
 *
 * HOW:  1. Compare against 1; 2. return the matching enum value.
 */
brix_vfs_mutation_policy_t
brix_vfs_policy_from_write_enable(ngx_flag_t allow_write)
{
    return (allow_write == 1)
        ? BRIX_VFS_MUTATION_ALLOWED : BRIX_VFS_MUTATION_READ_ONLY;
}

/* ---- The stable label for a bounded mutation operation ----
 *
 * WHAT: Returns the lowercase name of `op`, or "unknown" out of range.
 *
 * WHY:  Metrics and structured logs must agree on one closed vocabulary; a
 *       second table would let the two drift and would risk an unbounded label
 *       (INVARIANT #8).
 *
 * HOW:  1. Range-check; 2. index the static table.
 */
const char *
brix_vfs_mutation_op_name(brix_vfs_mutation_op_t op)
{
    static const char *names[BRIX_VFS_MUTATE_OP_COUNT] = {
        "open", "write", "truncate", "sync", "mkdir", "remove",
        "rename", "copy", "setattr", "xattr", "publish", "stage",
        "evict", "lock", "dedup",
    };

    return ((ngx_uint_t) op < BRIX_VFS_MUTATE_OP_COUNT)
        ? names[op] : "unknown";
}

/* ---- Decide a mutation from a policy value alone ----
 *
 * WHAT: NGX_OK when `policy` allows mutation; NGX_ERROR with errno EINVAL for
 *       an out-of-range `op` and EROFS for a read-only endpoint.
 *
 * WHY:  Objects that outlive their request context — file handles, staged
 *       sessions, writer sessions, queued jobs — carry the policy by value and
 *       must be able to re-decide without reaching for a context that may be
 *       gone or for a configuration that may have been reloaded.
 *
 * HOW:  1. Reject an operation outside the closed vocabulary; 2. allow only the
 *       exact ALLOWED value; 3. otherwise fail with EROFS.
 */
ngx_int_t
brix_vfs_require_mutation_policy(brix_vfs_mutation_policy_t policy,
    brix_vfs_mutation_op_t op)
{
    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (policy != BRIX_VFS_MUTATION_ALLOWED) {
        errno = EROFS;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Attribute one read-only denial ----
 *
 * WHAT: Bumps the bounded vfs_mutation_denied counter for (proto, op). No-op
 *       for an out-of-range operation.
 *
 * WHY:  An operator needs to see that an endpoint is refusing writes, and which
 *       family of write, without a path/user/object label ever entering a
 *       metric (INVARIANT #8). Recording it in the kernel and nowhere else is
 *       what keeps an edge rejection and a VFS rejection from both counting.
 *
 * HOW:  1. Range-check the op; 2. hand (proto, op) to the metrics recorder.
 */
void
brix_vfs_mutation_denied_observe(brix_proto_t proto, brix_vfs_mutation_op_t op)
{
    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {
        return;
    }

    brix_metric_vfs_mutation_denied(proto, (ngx_uint_t) op);
}

/* ---- Decide a mutation from a request context ----
 *
 * WHAT: NGX_OK when `ctx` may mutate; NGX_ERROR with EINVAL for a NULL context
 *       or bad operation, EROFS for a read-only endpoint (observed once).
 *
 * WHY:  This is the form every handle-less mutation entry point uses. Keeping
 *       the NULL check here rather than at each call site is what makes a
 *       hand-built or forgotten context fail closed instead of dereferencing.
 *
 * HOW:  1. Reject a NULL context; 2. run the pure kernel on
 *       ctx->mutation_policy; 3. on EROFS record one denial and preserve errno.
 */
ngx_int_t
brix_vfs_require_mutation(const brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_require_mutation_policy(ctx->mutation_policy, op) != NGX_OK) {
        if (errno == EROFS) {
            brix_vfs_mutation_denied_observe(brix_vfs_metrics_proto(ctx), op);
            /* phase-110 W4: the refusal happens BEFORE any VFS op runs, so no
             * observer will record it — stamp the outcome class on the
             * request's/session's monitor here so $brix_status says
             * "forbidden" on every plane (the same class EROFS maps to in
             * brix_metric_err_from_errno). */
            brix_io_monitor_record_err(ctx->io_monitor, BRIX_ERR_FORBIDDEN);
            errno = EROFS;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Decide a path-based mutation from a request context ----
 *
 * WHAT: Confinement first (NGX_ERROR/EINVAL for an unresolved or escaped
 *       path), then the mutation policy (NGX_ERROR/EROFS). NGX_OK otherwise.
 *
 * WHY:  Every path mutator owes both checks, and the order matters: an
 *       unconfined path is a malformed request, not a policy question, so it
 *       must not be answered with the endpoint's write posture.
 *
 * HOW:  1. brix_vfs_require_confined; 2. brix_vfs_require_mutation.
 */
ngx_int_t
brix_vfs_require_confined_mutation(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    return brix_vfs_require_mutation(ctx, op);
}

/* ---- Decide a mutation from a policy an object carries ----
 *
 * WHAT: NGX_OK when the carried policy permits `op`; NGX_ERROR with EROFS
 *       (observed once against `proto`) or EINVAL for a bad operation.
 *
 * WHY:  A handle, staged session, writer or queued job outlives — and may be
 *       used without — the context that created it. Re-reading that context
 *       would be a use-after-free at worst and a policy the request no longer
 *       owns at best, so the object decides from its own copy. Routing that
 *       decision through here rather than an open-coded comparison is what
 *       keeps the counter complete.
 *
 * HOW:  1. run the pure kernel; 2. on EROFS record one denial and preserve
 *       errno.
 */
ngx_int_t
brix_vfs_require_carried_mutation(brix_vfs_mutation_policy_t policy,
    brix_proto_t proto, brix_vfs_mutation_op_t op)
{
    if (brix_vfs_require_mutation_policy(policy, op) != NGX_OK) {
        if (errno == EROFS) {
            brix_vfs_mutation_denied_observe(proto, op);
            errno = EROFS;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Build a policy-bearing operation context ----
 *
 * WHAT: Zero-fills *opctx and stores log, root_canon, policy, and proto. No-op
 *       on NULL.
 *
 * WHY:  The raw export helpers run off the event loop and have no request
 *       context; this bundle is how the request's authority travels with them.
 *       Zeroing first means a partially-filled bundle is READ_ONLY.
 *
 * HOW:  1. NULL-guard; 2. memzero; 3. assign the four borrowed fields.
 */
void
brix_vfs_export_op_ctx_init(brix_vfs_export_op_ctx_t *opctx, ngx_log_t *log,
    const char *root_canon, brix_vfs_mutation_policy_t policy,
    brix_proto_t proto)
{
    if (opctx == NULL) {
        return;
    }

    ngx_memzero(opctx, sizeof(*opctx));
    opctx->log = log;
    opctx->root_canon = root_canon;
    opctx->mutation_policy = (policy == BRIX_VFS_MUTATION_ALLOWED)
        ? BRIX_VFS_MUTATION_ALLOWED : BRIX_VFS_MUTATION_READ_ONLY;
    opctx->proto = proto;
}

/* ---- Derive an operation context from a request VFS context ----
 *
 * WHAT: Copies `ctx`'s log, export root, mutation policy, and metrics protocol
 *       into *opctx. A NULL `ctx` yields a READ_ONLY bundle with no root.
 *
 * WHY:  This is the only sanctioned bridge from a request to an off-thread
 *       helper, and it cannot widen authority: there is no argument with which
 *       a caller could ask for more than the request already had.
 *
 * HOW:  1. NULL-guard opctx; 2. for a NULL ctx build the closed bundle;
 *       3. otherwise forward the four fields through the init helper.
 */
void
brix_vfs_export_op_ctx_from(brix_vfs_export_op_ctx_t *opctx,
    const brix_vfs_ctx_t *ctx)
{
    if (opctx == NULL) {
        return;
    }

    if (ctx == NULL) {
        brix_vfs_export_op_ctx_init(opctx, NULL, NULL,
            BRIX_VFS_MUTATION_READ_ONLY, BRIX_PROTO_ROOT);
        return;
    }

    brix_vfs_export_op_ctx_init(opctx, ctx->log, ctx->root_canon,
        ctx->mutation_policy, brix_vfs_metrics_proto(ctx));
}

/* ---- Decide a mutation from an operation context ----
 *
 * WHAT: NGX_OK when *opctx may mutate; NGX_ERROR with EINVAL for a NULL bundle
 *       or bad operation, EROFS for a read-only endpoint (observed once).
 *
 * WHY:  The off-thread twin of brix_vfs_require_mutation, so a helper reached
 *       from a thread-pool job is gated by exactly the same kernel rather than
 *       by a second, weaker spelling of the rule.
 *
 * HOW:  1. Reject a NULL bundle; 2. run the pure kernel; 3. observe an EROFS
 *       denial against the bundle's protocol.
 */
ngx_int_t
brix_vfs_export_require_mutation(const brix_vfs_export_op_ctx_t *opctx,
    brix_vfs_mutation_op_t op)
{
    if (opctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_require_mutation_policy(opctx->mutation_policy, op) != NGX_OK) {
        if (errno == EROFS) {
            brix_vfs_mutation_denied_observe(opctx->proto, op);
            errno = EROFS;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Classify raw open flags as mutating or not ----
 *
 * WHAT: Returns 1 when `flags` can modify the object or the namespace, 0 for a
 *       provably read-only open.
 *
 * WHY:  brix_vfs_open_fd() takes raw O_* flags, so its policy-bearing wrapper
 *       has to read intent out of the flag word rather than a VFS flag set. A
 *       read-only open must stay free on a read-only export, or the raw helpers
 *       could no longer serve reads.
 *
 * HOW:  1. Mask the access mode and compare against O_RDONLY; 2. test the three
 *       creation/size-changing flags; 3. return the disjunction.
 */
int
brix_vfs_open_flags_mutate(int flags)
{
    if ((flags & O_ACCMODE) != O_RDONLY) {
        return 1;
    }

    return (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0 ? 1 : 0;
}
