/*
 * vfs_stat.c — VFS path stat.
 *
 * WHAT: Implements brix_vfs_stat(), which lstat()s the resolved ctx path and
 *       fills an brix_vfs_stat_t (size/mtime/ctime/mode/ino plus the
 *       is_directory / is_regular flags).
 *
 * WHY:  kXR_stat / kXR_statx, WebDAV PROPFIND on a single resource, and S3 HEAD
 *       all need one confined, metered stat with consistent error mapping
 *       instead of each protocol calling stat(2) directly.
 *
 * HOW:  Re-verifies confinement (and a non-NULL stat_out), uses lstat() so
 *       symlinks are reported rather than followed, converts via
 *       brix_vfs_fill_stat(), and emits an BRIX_METRIC_OP_STAT
 *       metric/access-log line on every path through
 *       brix_vfs_observe_ctx_op().
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/stage/sd_stage.h"
#include "auth/impersonate/impersonate.h"
#include "core/fnv.h"

/* ---- phase-56 C-2: per-worker bounded negative-stat cache ----------------
 *
 * Collapses repeat ENOENT probes of the same absent path (xcache fill races,
 * "does this exist?" namespace browsing) to one syscall per TTL window.
 * Default OFF; BRIX_NEG_STAT_CACHE=1 in the worker environment enables it.
 *
 * Safety envelope (§13 of the phase-56 doc — a negative cache can turn a real
 * file into a false ENOENT, so every mitigation is mandatory):
 *   - per-worker only, never shared cross-worker (plain statics, no SHM);
 *   - short TTL (1 s) bounds staleness from cross-worker creates;
 *   - only a genuine ENOENT is inserted — never EACCES/EIO, never positives
 *     (they carry size/mtime that must be live);
 *   - every same-worker create/mkdir/rename/staged-commit clears the target's
 *     slot via brix_vfs_neg_stat_forget();
 *   - fully disabled while impersonation MAP mode is wired (an ENOENT for one
 *     mapped identity may be an EACCES mask for another);
 *   - the lstat (nofollow) and stat (follow) arms are keyed SEPARATELY: a
 *     follow-stat ENOENT can be a dangling symlink whose lstat legitimately
 *     succeeds, so the two must never share a cached negative — but each arm's
 *     own repeat probes are safely collapsible (the wire's default kXR_stat is
 *     the follow arm, so caching only nofollow would miss the probe storms
 *     this exists for).  Forget clears BOTH arms.
 */
#define BRIX_NEG_STAT_SLOTS   256              /* power of two */
#define BRIX_NEG_STAT_TTL     ((ngx_msec_t) 1000)

typedef struct {
    uint64_t    hash;
    ngx_msec_t  expire;
} brix_neg_stat_ent_t;

static brix_neg_stat_ent_t  brix_neg_stat[BRIX_NEG_STAT_SLOTS];

/* Env knob, resolved once per worker. Identity scoping is checked separately
 * (per call) because MAP mode wires up lazily on first broker contact. */
static int
brix_neg_stat_env_on(void)
{
    static int on = -1;

    if (on < 0) {
        const char *env = getenv("BRIX_NEG_STAT_CACHE");

        on = (env != NULL && env[0] == '1' && env[1] == '\0');
    }
    return on;
}

/* key = FNV1a(root_canon) ⊕ FNV1a(resolved_path), salted per stat arm so a
 * follow negative and a nofollow negative never alias (dangling-symlink
 * hazard).  Canonical basis/prime from core/fnv.h (NOT the frozen
 * pblock/rados variants). */
#define BRIX_NEG_STAT_FOLLOW_SALT  UINT64_C(0x9e3779b97f4a7c15)

static uint64_t
brix_neg_stat_fnv(const char *s)
{
    uint64_t       h = BRIX_FNV1A64_OFFSET_BASIS;
    const u_char  *p;

    for (p = (const u_char *) s; *p != '\0'; p++) {
        h = (h ^ *p) * BRIX_FNV1A64_PRIME;
    }
    return h;
}

static uint64_t
brix_neg_stat_key(const char *root_canon, const char *path, int nofollow)
{
    uint64_t key = brix_neg_stat_fnv(root_canon) ^ brix_neg_stat_fnv(path);

    return nofollow ? key : key ^ BRIX_NEG_STAT_FOLLOW_SALT;
}

/* 1 iff a live cached ENOENT covers (root_canon, path) on this stat arm —
 * lookup and insert are both no-ops under MAP-mode impersonation or with the
 * knob off. */
static int
brix_neg_stat_lookup(const char *root_canon, const char *path, int nofollow)
{
    uint64_t              key;
    brix_neg_stat_ent_t  *ent;

    if (!brix_neg_stat_env_on() || brix_imp_enabled()
        || root_canon == NULL || path == NULL)
    {
        return 0;
    }

    key = brix_neg_stat_key(root_canon, path, nofollow);
    ent = &brix_neg_stat[key & (BRIX_NEG_STAT_SLOTS - 1)];
    return ent->hash == key && ngx_current_msec < ent->expire;
}

static void
brix_neg_stat_insert(const char *root_canon, const char *path, int nofollow)
{
    uint64_t              key;
    brix_neg_stat_ent_t  *ent;

    if (!brix_neg_stat_env_on() || brix_imp_enabled()
        || root_canon == NULL || path == NULL)
    {
        return;
    }

    key = brix_neg_stat_key(root_canon, path, nofollow);
    ent = &brix_neg_stat[key & (BRIX_NEG_STAT_SLOTS - 1)];
    ent->hash = key;
    ent->expire = ngx_current_msec + BRIX_NEG_STAT_TTL;
}

/* Drop any cached negative for (root_canon, path) on BOTH stat arms. Called by
 * every same-worker mutator that can materialise the path (create-open, mkdir,
 * rename target, staged commit). Deliberately NOT gated on impersonation: an
 * impersonated create must still clear an entry inserted by an earlier
 * non-impersonated probe of the same worker. */
void
brix_vfs_neg_stat_forget(const char *root_canon, const char *path)
{
    int                   arm;
    uint64_t              key;
    brix_neg_stat_ent_t  *ent;

    if (!brix_neg_stat_env_on() || root_canon == NULL || path == NULL) {
        return;
    }

    for (arm = 0; arm <= 1; arm++) {
        key = brix_neg_stat_key(root_canon, path, arm);
        ent = &brix_neg_stat[key & (BRIX_NEG_STAT_SLOTS - 1)];
        if (ent->hash == key) {
            ent->hash = 0;
            ent->expire = 0;
        }
    }
}

/*
 * Shared confined-stat body for both the lstat (no-follow) and stat (follow)
 * entrypoints. nofollow!=0 reports a trailing symlink as itself; nofollow=0
 * follows it chroot-style within the export. Both run AS THE MAPPED USER under
 * impersonation (broker-routed) — otherwise a metadata op (WebDAV
 * HEAD/DELETE/PROPFIND-on-file, kXR_stat/statx, S3 HEAD) whose target sits
 * inside a directory the unprivileged worker cannot traverse (a 0700 user-owned
 * subdir, or a group-restricted 0770 dir the mapped user reaches only via a
 * supplementary group) would EACCES and fail (500) for the legitimate
 * owner/group-member. Off impersonation this is the same bare lstat/stat.
 */
static ngx_int_t
brix_vfs_stat_impl(brix_vfs_ctx_t *ctx, brix_vfs_stat_t *stat_out,
    int nofollow)
{
    struct stat               st;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const brix_sd_driver_t *drv;

    start = brix_vfs_now_ns();
    path = brix_vfs_ctx_path(ctx);

    if (stat_out == NULL || brix_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: the namespace lives in the driver, not the export tree.
     * nofollow is moot (an object/block backend has no symlinks). */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        brix_sd_ucred_t   store;
        brix_sd_cred_t    cred;
        brix_sd_stat_t    sd_st;
        int               use_cred = 0, cred_err = 0;
        ngx_int_t         grc;

        /* Zero the cred before the gate: the gate fills only the ACTIVE kind
         * (an x509 proxy path OR a bearer OR an s3/ceph tuple) and leaves the
         * inactive pointers untouched, so an unzeroed struct hands a garbage
         * pointer to the driver's stat_cred slot (a bearer-only PASSTHROUGH
         * cred left a live-stack x509_proxy that sd_xroot dereferenced → SIGSEGV
         * on the two-hop token read). Mirrors the data-plane callers, which all
         * memzero their ucred before brix_vfs_backend_cred. */
        ngx_memzero(&cred, sizeof(cred));

        if (brix_vfs_cred_gate_active(ctx)) {
            grc = brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err);
            if (grc != NGX_OK) {
                saved_errno = cred_err ? cred_err : EACCES;
                errno = saved_errno;
                brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL,
                                          0, NGX_ERROR, saved_errno, start);
                return NGX_ERROR;
            }
        }

        /* Dispatch on the leaf instance so brix_sd_stat_maybe_cred finds the
         * leaf driver's stat_cred slot (decorators have only plain relays). */
        if (drv->stat == NULL
            || brix_sd_stat_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                   brix_vfs_export_relative(ctx, path), &sd_st,
                   use_cred ? &cred : NULL) != NGX_OK)
        {
            saved_errno = errno;
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
            return NGX_ERROR;
        }
        brix_sd_ucred_wipe(&store);       /* secret consumed; erase (A-4/T4) */
        brix_vfs_sd_stat_fill(&sd_st, stat_out);
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    /* C-2: a live cached negative answers the probe without the syscall (or
     * broker IPC). The hit is metered exactly like the real ENOENT it stands
     * in for. Keyed per stat arm — see the safety envelope above. */
    if (brix_neg_stat_lookup(ctx->root_canon, path, nofollow)) {
        errno = ENOENT;
        saved_errno = errno;
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if ((ctx->rootfd >= 0
             ? brix_lstat_confined_canon_at(ctx->log, ctx->rootfd,
                                              ctx->root_canon, path, &st,
                                              nofollow)
             : brix_lstat_confined_canon(ctx->log, ctx->root_canon, path,
                                           &st, nofollow)) != 0)
    {
        saved_errno = errno;
        if (saved_errno == ENOENT) {
            brix_neg_stat_insert(ctx->root_canon, path, nofollow);
        }
        brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    brix_vfs_fill_stat(&st, stat_out);
    brix_vfs_observe_ctx_op(ctx, path, BRIX_METRIC_OP_STAT, NULL, 0,
                              NGX_OK, 0, start);
    return NGX_OK;
}

/* lstat the resolved ctx path into *stat_out (no symlink follow). Confined and
 * metered as OP_STAT; NGX_ERROR with errno set on guard failure or lstat error. */
ngx_int_t
brix_vfs_stat(brix_vfs_ctx_t *ctx, brix_vfs_stat_t *stat_out)
{
    return brix_vfs_stat_impl(ctx, stat_out, 1 /* nofollow */);
}

/* stat the resolved ctx path into *stat_out, FOLLOWING a trailing in-export
 * symlink chroot-style (RESOLVE_IN_ROOT). Confined and metered as OP_STAT;
 * NGX_ERROR with errno set on guard failure or stat error. */
ngx_int_t
brix_vfs_statf(brix_vfs_ctx_t *ctx, brix_vfs_stat_t *stat_out)
{
    return brix_vfs_stat_impl(ctx, stat_out, 0 /* follow */);
}

/* Descend one cache/stage decorator to its wrapped source (NULL at a leaf or a
 * non-decorator instance). Both unwrap helpers self-guard, so this is safe on any
 * instance and lets the residency seam find a nearline driver buried under a
 * read-cache and/or write-stage tier. Shared with the catalog-enumeration seam
 * (vfs_walk.c), which walks the same chain for the same reason. */
brix_sd_instance_t *
brix_vfs_decorator_source(const brix_sd_instance_t *inst)
{
    brix_sd_instance_t *s = brix_sd_cache_source_instance(inst);

    return (s != NULL) ? s : brix_sd_stage_source_instance(inst);
}

/* Classify the resolved ctx path's nearline residency (online/nearline/offline/
 * lost) so protocol handlers can advertise tape state — the HTTP Tape REST API, S3
 * InvalidObjectState / x-amz-storage-class, root:// stat's nearline flag — WITHOUT
 * forcing a recall. Walks any cache/stage decorators down to the CAP_NEARLINE
 * driver and reads its residency model; an export with no nearline tier is always
 * ONLINE (a plain disk/object store is resident). Emits no metric (it is an
 * internal classification the caller's own op accounts for). NGX_OK with *out set,
 * or NGX_ERROR (errno) on a guard failure or a driver error. */
ngx_int_t
brix_vfs_residency(brix_vfs_ctx_t *ctx, brix_sd_residency_t *out,
    int *nearline_export)
{
    brix_sd_instance_t *inst;

    if (nearline_export != NULL) {
        *nearline_export = 0;
    }
    if (out == NULL || brix_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    *out = BRIX_SD_RES_ONLINE;

    for (inst = ctx->sd; inst != NULL;
         inst = brix_vfs_decorator_source(inst))
    {
        if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE) != 0
            && inst->driver->residency != NULL)
        {
            const char *path = brix_vfs_ctx_path(ctx);

            if (nearline_export != NULL) {
                *nearline_export = 1;
            }
            return inst->driver->residency(
                inst, brix_vfs_export_relative(ctx, path), out);
        }
    }
    return NGX_OK;
}

/* 1 iff any tier of the resolved ctx chain declares CAP_NEARLINE — the export
 * fronts tape/archive, whether or not that tier also implements a recall slot.
 * The prepare plane (phase-107 C2) uses this to tell "flat export: staging is
 * advisory" from "nearline export that cannot stage" (the kXR_Unsupported arm),
 * exactly the distinction brix_vfs_recall's single ENOTSUP cannot carry. */
int
brix_vfs_nearline_export(brix_vfs_ctx_t *ctx)
{
    brix_sd_instance_t *inst;

    if (ctx == NULL) {
        return 0;
    }
    for (inst = ctx->sd; inst != NULL;
         inst = brix_vfs_decorator_source(inst))
    {
        if ((brix_sd_caps(inst) & BRIX_SD_CAP_NEARLINE) != 0) {
            return 1;
        }
    }
    return 0;
}

/* Driver-reported export space (phase-83 F5). Same decorator walk as residency:
 * the first tier implementing the optional `space` slot answers with its
 * quota-aware logical view; exports whose drivers have no space model decline so
 * the caller keeps its statvfs(2) fallback. */
ngx_int_t
brix_vfs_space(brix_vfs_ctx_t *ctx, brix_sd_space_t *out)
{
    brix_sd_instance_t *inst;

    if (out == NULL || ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    for (inst = ctx->sd; inst != NULL;
         inst = brix_vfs_decorator_source(inst))
    {
        if (inst->driver->space != NULL) {
            return inst->driver->space(inst, out);
        }
    }
    return NGX_DECLINED;
}

/*
 * brix_vfs_probe — confined existence/type probe for pre-op resolution and
 * ACL gates. Unlike brix_vfs_stat/statf this emits NO OP_STAT metric or
 * access-log line: it is an internal namespace pre-check that the caller's own
 * operation accounts for (routing it through the metered stat would record a
 * phantom STAT for every rm/chmod/mkdir/mv). nofollow selects lstat vs stat
 * semantics. Returns NGX_OK with *stat_out filled when the path is present,
 * NGX_DECLINED when it is absent (errno preserved from the underlying stat), or
 * NGX_ERROR on a confinement-guard failure.
 */
ngx_int_t
brix_vfs_probe(brix_vfs_ctx_t *ctx, int nofollow,
    brix_vfs_stat_t *stat_out)
{
    struct stat               st;
    const brix_sd_driver_t *drv;

    if (stat_out == NULL || brix_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        brix_sd_ucred_t  store;
        brix_sd_cred_t   cred;
        brix_sd_stat_t   sd_st;
        int              use_cred = 0, cred_err = 0;

        /* Zero before the gate: it fills only the active credential kind and
         * leaves the inactive pointers as-is, so an unzeroed cred would pass a
         * garbage x509_proxy/bearer pointer to the driver (see the companion
         * note in brix_vfs_stat_impl). */
        ngx_memzero(&cred, sizeof(cred));

        /* Credential gate for the probe: a denied pre-flight MUST return
         * NGX_ERROR (EACCES), not NGX_DECLINED — a denied probe must not be
         * silently treated as "absent", which would let the caller proceed.
         * The caller maps EACCES → 403. */
        if (brix_vfs_cred_gate_active(ctx)) {
            if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
                != NGX_OK)
            {
                errno = cred_err ? cred_err : EACCES;
                return NGX_ERROR;
            }
        }

        /* Dispatch on the leaf instance so brix_sd_stat_maybe_cred finds the
         * leaf driver's stat_cred slot (decorators have only plain relays). */
        if (drv->stat == NULL
            || brix_sd_stat_maybe_cred(brix_vfs_ns_leaf(ctx->sd),
                   brix_vfs_export_relative(ctx, brix_vfs_ctx_path(ctx)),
                   &sd_st, use_cred ? &cred : NULL) != NGX_OK)
        {
            brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
            return NGX_DECLINED;   /* absent (or unsupported) — caller's errno */
        }
        brix_sd_ucred_wipe(&store);       /* secret consumed; erase (A-4/T4) */
        brix_vfs_sd_stat_fill(&sd_st, stat_out);
        return NGX_OK;
    }

    if ((ctx->rootfd >= 0
             ? brix_lstat_confined_canon_at(ctx->log, ctx->rootfd,
                                              ctx->root_canon,
                                              brix_vfs_ctx_path(ctx), &st,
                                              nofollow)
             : brix_lstat_confined_canon(ctx->log, ctx->root_canon,
                                           brix_vfs_ctx_path(ctx), &st,
                                           nofollow)) != 0)
    {
        return NGX_DECLINED;
    }

    brix_vfs_fill_stat(&st, stat_out);
    return NGX_OK;
}
