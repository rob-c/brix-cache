/*
 * vfs_stat.c — VFS path stat.
 *
 * WHAT: Implements xrootd_vfs_stat(), which lstat()s the resolved ctx path and
 *       fills an xrootd_vfs_stat_t (size/mtime/ctime/mode/ino plus the
 *       is_directory / is_regular flags).
 *
 * WHY:  kXR_stat / kXR_statx, WebDAV PROPFIND on a single resource, and S3 HEAD
 *       all need one confined, metered stat with consistent error mapping
 *       instead of each protocol calling stat(2) directly.
 *
 * HOW:  Re-verifies confinement (and a non-NULL stat_out), uses lstat() so
 *       symlinks are reported rather than followed, converts via
 *       xrootd_vfs_fill_stat(), and emits an XROOTD_METRIC_OP_STAT
 *       metric/access-log line on every path through
 *       xrootd_vfs_observe_ctx_op().
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/stage/sd_stage.h"

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
xrootd_vfs_stat_impl(xrootd_vfs_ctx_t *ctx, xrootd_vfs_stat_t *stat_out,
    int nofollow)
{
    struct stat               st;
    const char               *path;
    uint64_t                  start;
    int                       saved_errno;
    const xrootd_sd_driver_t *drv;

    start = xrootd_vfs_now_ns();
    path = xrootd_vfs_ctx_path(ctx);

    if (stat_out == NULL || xrootd_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    /* Non-POSIX backend: the namespace lives in the driver, not the export tree.
     * nofollow is moot (an object/block backend has no symlinks). */
    drv = xrootd_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        xrootd_sd_stat_t sd_st;

        if (drv->stat == NULL
            || drv->stat(ctx->sd, xrootd_vfs_export_relative(ctx, path), &sd_st)
               != NGX_OK)
        {
            saved_errno = errno;
            xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                      NGX_ERROR, saved_errno, start);
            return NGX_ERROR;
        }
        xrootd_vfs_sd_stat_fill(&sd_st, stat_out);
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                  NGX_OK, 0, start);
        return NGX_OK;
    }

    if (xrootd_lstat_confined_canon(ctx->log, ctx->root_canon, path, &st,
                                    nofollow) != 0)
    {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                                  NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    xrootd_vfs_fill_stat(&st, stat_out);
    xrootd_vfs_observe_ctx_op(ctx, path, XROOTD_METRIC_OP_STAT, NULL, 0,
                              NGX_OK, 0, start);
    return NGX_OK;
}

/* lstat the resolved ctx path into *stat_out (no symlink follow). Confined and
 * metered as OP_STAT; NGX_ERROR with errno set on guard failure or lstat error. */
ngx_int_t
xrootd_vfs_stat(xrootd_vfs_ctx_t *ctx, xrootd_vfs_stat_t *stat_out)
{
    return xrootd_vfs_stat_impl(ctx, stat_out, 1 /* nofollow */);
}

/* stat the resolved ctx path into *stat_out, FOLLOWING a trailing in-export
 * symlink chroot-style (RESOLVE_IN_ROOT). Confined and metered as OP_STAT;
 * NGX_ERROR with errno set on guard failure or stat error. */
ngx_int_t
xrootd_vfs_statf(xrootd_vfs_ctx_t *ctx, xrootd_vfs_stat_t *stat_out)
{
    return xrootd_vfs_stat_impl(ctx, stat_out, 0 /* follow */);
}

/* Descend one cache/stage decorator to its wrapped source (NULL at a leaf or a
 * non-decorator instance). Both unwrap helpers self-guard, so this is safe on any
 * instance and lets the residency seam find a nearline driver buried under a
 * read-cache and/or write-stage tier. */
static xrootd_sd_instance_t *
xrootd_vfs_decorator_source(const xrootd_sd_instance_t *inst)
{
    xrootd_sd_instance_t *s = xrootd_sd_cache_source_instance(inst);

    return (s != NULL) ? s : xrootd_sd_stage_source_instance(inst);
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
xrootd_vfs_residency(xrootd_vfs_ctx_t *ctx, xrootd_sd_residency_t *out,
    int *nearline_export)
{
    xrootd_sd_instance_t *inst;

    if (nearline_export != NULL) {
        *nearline_export = 0;
    }
    if (out == NULL || xrootd_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    *out = XROOTD_SD_RES_ONLINE;

    for (inst = ctx->sd; inst != NULL;
         inst = xrootd_vfs_decorator_source(inst))
    {
        if ((xrootd_sd_caps(inst) & XROOTD_SD_CAP_NEARLINE) != 0
            && inst->driver->residency != NULL)
        {
            const char *path = xrootd_vfs_ctx_path(ctx);

            if (nearline_export != NULL) {
                *nearline_export = 1;
            }
            return inst->driver->residency(
                inst, xrootd_vfs_export_relative(ctx, path), out);
        }
    }
    return NGX_OK;
}

/*
 * xrootd_vfs_probe — confined existence/type probe for pre-op resolution and
 * ACL gates. Unlike xrootd_vfs_stat/statf this emits NO OP_STAT metric or
 * access-log line: it is an internal namespace pre-check that the caller's own
 * operation accounts for (routing it through the metered stat would record a
 * phantom STAT for every rm/chmod/mkdir/mv). nofollow selects lstat vs stat
 * semantics. Returns NGX_OK with *stat_out filled when the path is present,
 * NGX_DECLINED when it is absent (errno preserved from the underlying stat), or
 * NGX_ERROR on a confinement-guard failure.
 */
ngx_int_t
xrootd_vfs_probe(xrootd_vfs_ctx_t *ctx, int nofollow,
    xrootd_vfs_stat_t *stat_out)
{
    struct stat               st;
    const xrootd_sd_driver_t *drv;

    if (stat_out == NULL || xrootd_vfs_require_confined(ctx) != NGX_OK) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    drv = xrootd_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        xrootd_sd_stat_t sd_st;

        if (drv->stat == NULL
            || drv->stat(ctx->sd,
                         xrootd_vfs_export_relative(ctx, xrootd_vfs_ctx_path(ctx)),
                         &sd_st) != NGX_OK)
        {
            return NGX_DECLINED;   /* absent (or unsupported) — caller's errno */
        }
        xrootd_vfs_sd_stat_fill(&sd_st, stat_out);
        return NGX_OK;
    }

    if (xrootd_lstat_confined_canon(ctx->log, ctx->root_canon,
                                    xrootd_vfs_ctx_path(ctx), &st,
                                    nofollow) != 0)
    {
        return NGX_DECLINED;
    }

    xrootd_vfs_fill_stat(&st, stat_out);
    return NGX_OK;
}
