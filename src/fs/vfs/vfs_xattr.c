/*
 * vfs_xattr.c — VFS extended-attribute family (get / set / remove / list).
 *
 * WHAT: Implements brix_vfs_getxattr/setxattr/removexattr/listxattr — the
 *       protocol-agnostic surface for the `user.`-namespace xattrs that S3
 *       object tagging, WebDAV dead properties, checksum sidecars, and the
 *       WebDAV lock database all store on export objects.
 *
 * WHY:  Before this unit those callers reached the confined xattr helpers
 *       (brix_*xattr_confined_canon) directly, so the xattr touches were
 *       confined but invisible to metrics/access-logging. Routing them here
 *       gives every xattr op one BRIX_METRIC_OP_XATTR metric + access-log line
 *       and the same guard-then-syscall-then-observe shape as the rest of the
 *       VFS, while still delegating the actual syscall (and impersonation broker
 *       routing) to the confined helpers.
 *
 * HOW:  Each entry point re-verifies confinement (brix_vfs_require_confined),
 *       calls the matching brix_*xattr_confined_canon with ctx->root_canon and
 *       the resolved path, then observes the result as OP_XATTR. set/remove are
 *       mutations of the export and are gated on the endpoint's mutation policy
 *       (phase-105) BEFORE the capability and credential gates, so a read-only
 *       export answers EROFS and never discloses which later gate would also
 *       have refused. get/list propagate the helper byte count (or ERANGE)
 *       unchanged and are never gated — reading an attribute is a read.
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_evict: the leaf
                                          * dispatch bypasses the decorator's
                                          * own cache invalidation */

#include <sys/xattr.h>

/* Shared observe tail for the value-returning ops (get/list): translate a
 * helper return (>=0 ok, -1 errno) into an OP_XATTR metric + access-log line and
 * return the count unchanged (errno preserved on error). ENODATA is observed as
 * a clean zero-byte lookup, not an error: optional-attribute probes (S3
 * usermeta/tagging on GET, WebDAV dead props) routinely miss, and logging each
 * miss as a failed op:"xattr" line put error lines on every served GET. The
 * caller still sees -1/ENODATA unchanged. */
static ssize_t
brix_vfs_xattr_observe_count(const brix_vfs_ctx_t *ctx, const char *path,
    ssize_t n, ngx_msec_t start)
{
    int saved_errno = (n < 0) ? errno : 0;
    int absent_ok = (n >= 0) || saved_errno == ENODATA;

    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_XATTR, NULL,
                              (n > 0) ? (size_t) n : 0,
                              absent_ok ? NGX_OK : NGX_ERROR,
                              absent_ok ? 0 : saved_errno, start);
    if (n < 0) {
        errno = saved_errno;
    }
    return n;
}

/* Unmetered path-parameterized read core: one copy of the credential gate,
 * leaf dispatch, and POSIX fallback, shared by the metered read entry points
 * below and the quiet form the lock gate uses. `path` is an absolute confined
 * path — the ctx's own resolved path, or an ancestor of it inside the same
 * export (the lock-gate walk constructs those, so re-resolution would be
 * redundant). Books NOTHING: the caller owns the observe tail (or its
 * deliberate absence). Returns the byte count, or -1 with errno set. */
static ssize_t
brix_vfs_xattr_read_at(brix_vfs_ctx_t *ctx, const char *path,
    const char *name, void *buf, size_t bufsz)
{
    const brix_sd_driver_t *drv = brix_vfs_ctx_driver(ctx);
    ssize_t                 n;

    if (drv != NULL) {
        brix_sd_ucred_t store;
        brix_sd_cred_t  cred;
        int             use_cred = 0, cred_err = 0;
        char            physical[PATH_MAX];

        /* Zero before the gate: it fills only the active credential kind;
         * an unzeroed cred hands a garbage inactive pointer to the driver
         * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
        ngx_memzero(&cred, sizeof(cred));

        if (brix_path_resolved_to_pfn(ctx, path, physical,
                                      sizeof(physical)) != NGX_OK)
        {
            return -1;
        }

        if (brix_vfs_cred_gate_active(ctx)) {
            if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                != NGX_OK)
            {
                errno = cred_err ? cred_err : EACCES;
                return -1;
            }
        }

        {
            /* Dispatch on the leaf so *_maybe_cred finds the leaf
             * driver's getxattr/listxattr_cred slot (decorators have only
             * plain relays). */
            brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
            brix_sd_cred_t     *cp = use_cred ? &cred : NULL;

            if (name != NULL) {
                n = (drv->getxattr != NULL)
                    ? brix_sd_getxattr_maybe_cred(leaf, physical, name, buf,
                                                  bufsz, cp)
                    : (errno = ENOTSUP, (ssize_t) -1);
            } else {
                n = (drv->listxattr != NULL)
                    ? brix_sd_listxattr_maybe_cred(leaf, physical, buf, bufsz,
                                                   cp)
                    : (errno = ENOTSUP, (ssize_t) -1);
            }
        }
        brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
        return n;
    }

    return (name != NULL)
        ? brix_getxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
                                         buf, bufsz)
        : brix_listxattr_confined_canon(ctx->log, ctx->root_canon, path,
                                          buf, bufsz);
}

/* Shared body for the read-side ops: name != NULL reads that attribute
 * (getxattr), name == NULL lists the attribute names (listxattr). One copy of
 * the confinement check and observe tail around the core above. */
static ssize_t
brix_vfs_xattr_read(brix_vfs_ctx_t *ctx, const char *name, void *buf,
    size_t bufsz)
{
    const char *path = brix_vfs_ctx_path(ctx);
    uint64_t    start = brix_vfs_now_ns();
    ssize_t     n;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, path, -1, start);
    }
    if (brix_vfs_require_authorized_lookup(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, path, -1, start);
    }

    n = brix_vfs_xattr_read_at(ctx, path, name, buf, bufsz);
    return brix_vfs_xattr_observe_count(ctx, path, n, start);
}

/* Quiet attribute read at an explicit confined path (phase-107 C7): the lock
 * gate probes every ancestor between a mutation target and the export root for
 * a lock record, and those probes must not book OP_XATTR metrics — a strict
 * per-request counter delta is part of the metrics conformance contract, and a
 * gate that inflated it per path level would make the xattr counters
 * depth-dependent. Same confinement requirement, credential gate, and leaf
 * dispatch as brix_vfs_getxattr; no observation. Returns the byte count, or -1
 * with errno set (EINVAL for an unconfined ctx). */
ssize_t
brix_vfs_getxattr_quiet_at(brix_vfs_ctx_t *ctx, const char *path,
    const char *name, void *buf, size_t bufsz)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return -1;
    }

    return brix_vfs_xattr_read_at(ctx, path, name, buf, bufsz);
}

/* Read attribute `name` on the resolved ctx path into buf[bufsz] (bufsz==0 asks
 * for the required size). Returns the byte count, or -1 with errno set
 * (ERANGE when the value does not fit). Metered as OP_XATTR. */
ssize_t
brix_vfs_getxattr(brix_vfs_ctx_t *ctx, const char *name,
    void *buf, size_t bufsz)
{
    return brix_vfs_xattr_read(ctx, name, buf, bufsz);
}

/* List the attribute names on the resolved ctx path into buf[bufsz] (NUL-
 * separated; bufsz==0 asks for the required size). Returns the byte count, or
 * -1 with errno set. Metered as OP_XATTR. */
ssize_t
brix_vfs_listxattr(brix_vfs_ctx_t *ctx, void *buf, size_t bufsz)
{
    return brix_vfs_xattr_read(ctx, NULL, buf, bufsz);
}

/* Observe a mutation (set/remove) result: translate an rc (0 ok, non-0 error
 * with errno already set) into an OP_XATTR metric + access-log line, reporting
 * `nbytes` on success and 0 on error, and return NGX_OK/NGX_ERROR. Shared by
 * the set/remove entry points so the observe tail is identical for both. */
static ngx_int_t
brix_vfs_xattr_observe_mut(const brix_vfs_ctx_t *ctx, const char *path,
    int rc, size_t nbytes, ngx_msec_t start)
{
    int saved_errno = (rc != 0) ? errno : 0;

    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_XATTR, NULL,
                              (rc == 0) ? nbytes : 0,
                              (rc != 0) ? NGX_ERROR : NGX_OK, saved_errno,
                              start);
    return (rc != 0) ? NGX_ERROR : NGX_OK;
}

/* Run the shared set/remove driver-path gates: the phase-71 write-capability
 * gate (CAP_XATTR_WRITE required) then the per-user credential gate. On success
 * returns NGX_OK with use_cred/cred populated for the dispatch; on failure
 * sets errno, emits the OP_XATTR error observation, and returns NGX_ERROR so the
 * caller can early-return without duplicating the observe tail. Byte-identical
 * to the inline gates the set/remove paths previously carried. */
static ngx_int_t
brix_vfs_xattr_write_gate(brix_vfs_ctx_t *ctx, const char *path,
    const brix_sd_driver_t *drv, brix_sd_ucred_t *store, brix_sd_cred_t *cred,
    int *use_cred, ngx_msec_t start)
{
    int cred_err = 0;

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver cred slot
     * (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(cred, sizeof(*cred));

    /* phase-71: capability gate — a backend that can read xattrs but not write
     * them (CAP_XATTR without CAP_XATTR_WRITE) rejects set/remove uniformly,
     * regardless of whether the vtable slot is populated. */
    if (!(drv->caps & BRIX_SD_CAP_XATTR_WRITE)) {
        errno = ENOTSUP;
        (void) brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
        return NGX_ERROR;
    }

    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, store, cred, use_cred, &cred_err) != NGX_OK) {
            errno = cred_err ? cred_err : EACCES;
            (void) brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* One mutation request, carried as a unit so the driver path can be a helper
 * without a ten-parameter signature. `is_set` selects set (name = value[len]
 * with raw setxattr(2) `flags`) or remove (value/len/flags ignored). */
typedef struct {
    int          is_set;
    const char  *name;
    const void  *value;
    size_t       len;
    int          flags;
} brix_vfs_xattr_mut_t;

/*
 * brix_vfs_xattr_mutate_driver — driver-backed set/remove.
 *
 * WHAT: Run the write gate, dispatch the mutation on the leaf instance,
 *       invalidate the cached copy it just outdated, and book the observation.
 * WHY:  Split out of brix_vfs_xattr_mutate, which carried the confinement
 *       check, the gate, both dispatch arms, the eviction and two observe tails
 *       in one body and went over the complexity contract when the eviction
 *       landed. Behaviour is identical to the inline branch it replaces.
 * HOW:  On a gate refusal the gate has already observed, so return NGX_ERROR
 *       directly. Otherwise dispatch through brix_sd_{set,remove}xattr_maybe_cred
 *       (ENOTSUP for an absent slot), evict on success, wipe the borrowed
 *       secret, and return through the shared mutation observe tail.
 */
static ngx_int_t
brix_vfs_xattr_mutate_driver(brix_vfs_ctx_t *ctx, const char *path,
    const brix_sd_driver_t *drv, const brix_vfs_xattr_mut_t *m,
    ngx_msec_t start)
{
    brix_sd_instance_t *leaf;
    char                rel[PATH_MAX];
    brix_sd_cred_t     *cp;
    brix_sd_ucred_t     store;
    brix_sd_cred_t      cred;
    int                 use_cred = 0;
    int                 rc;

    if (brix_vfs_xattr_write_gate(ctx, path, drv, &store, &cred, &use_cred,
                                    start) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (brix_path_resolved_to_pfn(ctx, path, rel, sizeof(rel)) != NGX_OK) {
        brix_sd_ucred_wipe(&store);
        return NGX_ERROR;
    }

    /* Dispatch on the leaf so *_maybe_cred finds the leaf driver's
     * setxattr/removexattr_cred slot (decorators have only plain relays). */
    leaf = brix_vfs_ns_leaf(ctx->sd);
    cp   = use_cred ? &cred : NULL;

    if (m->is_set) {
        rc = (drv->setxattr != NULL
              && brix_sd_setxattr_maybe_cred(leaf, rel, m->name, m->value,
                     m->len, m->flags, cp) == NGX_OK)
             ? 0 : (errno = (drv->setxattr ? errno : ENOTSUP), -1);
    } else {
        rc = (drv->removexattr != NULL
              && brix_sd_removexattr_maybe_cred(leaf, rel, m->name, cp)
                 == NGX_OK)
             ? 0 : (errno = (drv->removexattr ? errno : ENOTSUP), -1);
    }

    if (rc == 0) {
        /* The leaf dispatch skipped the cache decorator, so nothing has
         * invalidated the cached copy whose metadata this call just changed at
         * the origin — including the checksum record a cache fill seeds. Same
         * compensation vfs_unlink/vfs_rename make; no-op off a cache. The
         * decorator evicts too when it IS the dispatch instance; this site
         * keeps its own call because only the VFS can label the eviction
         * metric with the protocol (INVARIANT #8). */
        brix_metric_cache_evicted(brix_vfs_metrics_proto(ctx),
                                  brix_sd_cache_evict(ctx->sd, rel));
    }

    brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
    return brix_vfs_xattr_observe_mut(ctx, path, rc,
                                      m->is_set ? m->len : 0, start);
}

/* Shared body for the mutation ops: is_set != 0 sets `name` to value[len]
 * (with raw setxattr(2) flags), is_set == 0 removes `name` (value/len/flags
 * ignored). One copy of the confinement check, the driver-vs-POSIX branch, and
 * the observe tail. */
static ngx_int_t
brix_vfs_xattr_mutate(brix_vfs_ctx_t *ctx, int is_set, const char *name,
    const void *value, size_t len, int flags)
{
    const char             *path = brix_vfs_ctx_path(ctx);
    uint64_t                start = brix_vfs_now_ns();
    const brix_sd_driver_t *drv;
    brix_vfs_xattr_mut_t    m;
    int                     rc;

    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
    }

    /* phase-105: the endpoint gate, ahead of brix_vfs_xattr_write_gate() — that
     * helper answers ENOTSUP for a backend without CAP_XATTR_WRITE and EACCES
     * for a refused credential, and either arriving before EROFS would tell a
     * caller something about a backend it is not allowed to touch. */
    if (brix_vfs_gate_mutation(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK) {
        return brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
    }

    /* phase-107 C7: lock gate after the mutation gate (EROFS precedes EBUSY).
     * The WebDAV lock DB's own writes pass through here too: an initial LOCK
     * finds no covering record, and UNLOCK/refresh present the lock's token
     * (ctx->lock_token), which the gate matches as ownership. */
    if (brix_vfs_require_unlocked(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK) {
        return brix_vfs_xattr_observe_mut(ctx, path, -1, 0, start);
    }

    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        m.is_set = is_set;
        m.name   = name;
        m.value  = value;
        m.len    = len;
        m.flags  = flags;
        return brix_vfs_xattr_mutate_driver(ctx, path, drv, &m, start);
    }

    rc = is_set
         ? brix_setxattr_confined_canon(ctx->log, ctx->root_canon, path,
                                          name, value, len, flags)
         : brix_removexattr_confined_canon(ctx->log, ctx->root_canon, path,
                                             name);
    return brix_vfs_xattr_observe_mut(ctx, path, rc, is_set ? len : 0, start);
}

/* Set attribute `name` to value[len] on the resolved ctx path. `flags` are the
 * raw setxattr(2) flags (XATTR_CREATE / XATTR_REPLACE / 0). Returns NGX_OK or
 * NGX_ERROR with errno set (EROFS on a read-only endpoint). Metered as
 * OP_XATTR. */
ngx_int_t
brix_vfs_setxattr(brix_vfs_ctx_t *ctx, const char *name,
    const void *value, size_t len, int flags)
{
    return brix_vfs_xattr_mutate(ctx, 1, name, value, len, flags);
}

/* Remove attribute `name` from the resolved ctx path. Returns NGX_OK or
 * NGX_ERROR with errno set (ENODATA when the attribute is absent, EROFS on a
 * read-only endpoint). Metered as OP_XATTR. */
ngx_int_t
brix_vfs_removexattr(brix_vfs_ctx_t *ctx, const char *name)
{
    return brix_vfs_xattr_mutate(ctx, 0, name, NULL, 0, 0);
}

/* --- open-handle (fd) variants --------------------------------------------
 * The path variants above re-verify confinement against ctx->resolved before
 * each syscall. The fd variants below operate on an fd that the VFS already
 * opened confined (via brix_vfs_open / brix_vfs_adopt_fd, or a handle-table
 * fd that came from one), so the confinement guarantee travels with the
 * descriptor — there is no path to re-resolve. They exist so that fattr's
 * file-handle mode (and any other open-fd xattr caller) reaches the backend
 * through the VFS instead of calling f*xattr(2) directly.
 *
 * For the READING pair (fget/flist) `ctx` is optional and used only for the
 * OP_XATTR metric + access-log line; it may be NULL (then the op is
 * unobserved). It is NOT required to be confined — passing the request's ctx
 * simply attributes the metric to the right proto.
 *
 * For the MUTATING pair (fset/fremove) `ctx` is REQUIRED (phase-105): an fd
 * carries confinement but not authority, so a mutation with no policy behind it
 * has no way to fail closed and is refused with EINVAL. A service-domain caller
 * that legitimately holds the policy as a value — the checksum-at-rest cache in
 * core/compat/integrity_info.c is the one in-tree case — uses the _carried
 * forms below instead of inventing a context. */

ssize_t
brix_vfs_fgetxattr(const brix_vfs_ctx_t *ctx, int fd, const char *name,
    void *buf, size_t bufsz)
{
    uint64_t start = brix_vfs_now_ns();
    ssize_t  n;

    if (ctx != NULL && brix_vfs_require_authorized_lookup(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, NULL, -1, start);
    }
    n = fgetxattr(fd, name, buf, bufsz);

    return brix_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ssize_t
brix_vfs_flistxattr(const brix_vfs_ctx_t *ctx, int fd, void *buf,
    size_t bufsz)
{
    uint64_t start = brix_vfs_now_ns();
    ssize_t  n;

    if (ctx != NULL && brix_vfs_require_authorized_lookup(ctx) != NGX_OK) {
        return brix_vfs_xattr_observe_count(ctx, NULL, -1, start);
    }
    n = flistxattr(fd, buf, bufsz);

    return brix_vfs_xattr_observe_count(ctx, NULL, n, start);
}

ngx_int_t
brix_vfs_fsetxattr_carried(brix_vfs_mutation_policy_t policy, brix_proto_t proto,
    int fd, const char *name, const void *value, size_t len, int flags)
{
    if (brix_vfs_require_carried_mutation(policy, proto,
            BRIX_VFS_MUTATE_XATTR) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Unmetered, exactly as the NULL-ctx form was: a service-domain metadata
     * touch is not client I/O, and labelling it would misattribute the proto
     * (vfs_internal.h, brix_vfs_observe_ctx_op_ex). The REFUSAL above is
     * counted — that one is an operator-visible policy event. */
    if (fsetxattr(fd, name, value, len, flags) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_vfs_fremovexattr_carried(brix_vfs_mutation_policy_t policy,
    brix_proto_t proto, int fd, const char *name)
{
    if (brix_vfs_require_carried_mutation(policy, proto,
            BRIX_VFS_MUTATE_XATTR) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Unmetered — see brix_vfs_fsetxattr_carried. */
    if (fremovexattr(fd, name) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_vfs_fsetxattr(const brix_vfs_ctx_t *ctx, int fd, const char *name,
    const void *value, size_t len, int flags)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_gate_mutation(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK) {
        return NGX_ERROR;
    }
    return fsetxattr(fd, name, value, len, flags) == 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_vfs_fremovexattr(const brix_vfs_ctx_t *ctx, int fd, const char *name)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_vfs_gate_mutation(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK) {
        return NGX_ERROR;
    }
    return fremovexattr(fd, name) == 0 ? NGX_OK : NGX_ERROR;
}
