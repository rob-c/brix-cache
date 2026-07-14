/*
 * cms/recv_forward.c — Plane-B forwarded-namespace-op executor for the CMS
 * client-side (manager-connection) receive path.
 *
 * WHAT: Applies a manager-forwarded namespace mutation (kYR_chmod/mkdir/mkpath/
 * mv/rm/rmdir/trunc) to our local storage.  cms_node_exec_forward() decodes the
 * request and routes to one of two storage legs: a non-POSIX export (pblock/
 * object) mutates through its backend driver's namespace slots
 * (cms_forward_via_driver); the default POSIX export takes the kernel-confined
 * *_beneath path (cms_forward_via_posix).  Replies silent-on-success /
 * kYR_error-on-failure, byte-exact with stock cmsd.
 *
 * WHY: Split (Phase-79 file-size split) from recv.c so the storage-mutation
 * machinery — driver slot plumbing and kernel-confined POSIX apply — lives in
 * its own focused, independently reviewable file under the size guideline.  The
 * one entry point the opcode dispatcher calls (cms_node_exec_forward) is
 * declared in recv_internal.h; everything else here is a file-local helper.
 *
 * HOW: cms_drv_* wrap individual driver slots (unlink/setattr/ftruncate);
 * cms_node_exec_driver / cms_posix_apply are the pure per-leg executors;
 * cms_forward_via_driver / cms_forward_via_posix add the shared logging + wire
 * reply tail; cms_node_exec_forward is the decode-then-route orchestrator.  The
 * driver namespace and the POSIX *_beneath helpers are both inherently
 * export-confined, so a hostile manager cannot escape the export root.
 */

#include "cms_internal.h"
#include "recv_internal.h"
#include "fs/vfs/vfs.h"   /* confined open/unlink via the VFS seam */
#include "fs/vfs/vfs_backend_registry.h"   /* non-POSIX backend driver routing */
#include "node_ops.h"               /* Plane B forwarded-op planner */
#include "rrdata.h"                 /* Pup decode of forwarded payloads */
#include "fs/path/beneath.h"

#include <errno.h>
#include <unistd.h>

/*
 * cms_drv_unlink — remove a file (isdir=0) or directory (isdir=1) through a
 * backend driver's unlink slot. Shared by the RM and RMDIR forwarded-op cases so
 * the ENOSYS-on-missing-slot check lives once. Returns 0 / -1+errno.
 */
static int
cms_drv_unlink(brix_sd_instance_t *sd, const char *path, int isdir)
{
    if (sd->driver->unlink == NULL) { errno = ENOSYS; return -1; }
    return sd->driver->unlink(sd, path, isdir) == NGX_OK ? 0 : -1;
}

/*
 * cms_drv_chmod — apply a forwarded chmod through the driver's setattr slot.
 * A driver with no mutable metadata (setattr slot absent) treats chmod as a
 * successful no-op, matching how object catalogs ignore POSIX modes. Returns
 * 0 / -1+errno.
 */
static int
cms_drv_chmod(brix_sd_instance_t *sd, const brix_cms_node_plan_t *plan)
{
    brix_sd_setattr_t attr;

    if (sd->driver->setattr == NULL) { return 0; }   /* no mutable metadata — no-op */
    ngx_memzero(&attr, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = plan->mode;
    return sd->driver->setattr(sd, plan->path, &attr) == NGX_OK ? 0 : -1;
}

/*
 * cms_drv_trunc — truncate an object through the driver's open/ftruncate/close
 * slots. Owns the driver object handle linearly (open → truncate → close) and
 * preserves the truncate errno across the close so the caller reports the real
 * failure cause. Returns 0 / -1+errno.
 */
static int
cms_drv_trunc(brix_sd_instance_t *sd, const brix_cms_node_plan_t *plan)
{
    const brix_sd_driver_t *drv = sd->driver;
    int              err = 0;
    int              rc;
    int              saved;
    brix_sd_obj_t *o;

    if (drv->open == NULL || drv->ftruncate == NULL) { errno = ENOSYS; return -1; }
    o = drv->open(sd, plan->path, BRIX_SD_O_WRITE, 0, &err);
    if (o == NULL) { errno = err ? err : EIO; return -1; }
    rc = drv->ftruncate(o, (off_t) plan->size) == NGX_OK ? 0 : -1;
    saved = errno;
    if (drv->close != NULL) { drv->close(o); }
    errno = saved;
    return rc;
}

/*
 * cms_node_exec_driver — apply a manager-forwarded namespace op through a
 * NON-default backend driver's slots, so a pblock/object data node mutates its
 * catalog instead of the real filesystem (the confined *_beneath helpers the
 * POSIX path uses only touch the real FS). plan->path/path2 are export-relative
 * (leading slash), the format the driver slots expect. Returns 0 / -1+errno; sets
 * *handled=0 only for an action the driver cannot express. The driver namespace
 * is inherently export-confined, so a hostile manager still cannot escape it.
 */
static int
cms_node_exec_driver(brix_sd_instance_t *sd, const char *root_canon,
    const brix_cms_node_plan_t *plan, ngx_log_t *log, int *handled)
{
    const brix_sd_driver_t *drv = sd->driver;

    *handled = 1;

    switch (plan->action) {
    case XRDCMS_NACT_MKDIR:
        if (drv->mkdir == NULL) { errno = ENOSYS; return -1; }
        return drv->mkdir(sd, plan->path, plan->mode) == NGX_OK ? 0 : -1;

    case XRDCMS_NACT_MKPATH:
        /* create the whole path + missing parents in the driver namespace. */
        return brix_vfs_backend_mkpath(root_canon, plan->path, plan->mode, log);

    case XRDCMS_NACT_RMDIR:
        return cms_drv_unlink(sd, plan->path, 1);

    case XRDCMS_NACT_RM:
        return cms_drv_unlink(sd, plan->path, 0);

    case XRDCMS_NACT_MV:
        if (drv->rename == NULL) { errno = ENOSYS; return -1; }
        return drv->rename(sd, plan->path, plan->path2, 0) == NGX_OK ? 0 : -1;

    case XRDCMS_NACT_CHMOD:
        return cms_drv_chmod(sd, plan);

    case XRDCMS_NACT_TRUNC:
        return cms_drv_trunc(sd, plan);

    default:
        *handled = 0;
        return -1;
    }
}

/* cms_forward_via_driver — driver-backend leg of a forwarded namespace op: run
 * the planned mutation through the non-default backend's namespace slots and
 * reply like stock cmsd (silent on success, kYR_error + strerror on failure,
 * "unsupported operation" for an action the driver cannot express). Split from
 * cms_node_exec_forward so each storage leg owns its own logging/reply tail. */
static ngx_int_t
cms_forward_via_driver(ngx_brix_cms_ctx_t *ctx, brix_sd_instance_t *sd,
    u_char code, uint32_t streamid, const brix_cms_node_plan_t *plan)
{
    const char *root_canon = ctx->conf->common.root_canon;
    int         handled;
    int         rc;

    rc = cms_node_exec_driver(sd, root_canon, plan, ctx->cycle->log,
                              &handled);
    if (!handled) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "unsupported operation");
    }
    if (rc != 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
            "brix: CMS node: forwarded op code=%ui path=%s failed: %s",
            (ngx_uint_t) code, plan->path, strerror(errno));
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         strerror(errno));
    }
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
        "brix: CMS node: forwarded op code=%ui path=%s OK (driver)",
        (ngx_uint_t) code, plan->path);
    return NGX_OK;
}

/* cms_posix_apply — POSIX-export leg of a forwarded namespace op: apply the
 * planned mutation to the local filesystem UNDER KERNEL CONFINEMENT
 * (src/fs/path/beneath.h confined helpers / VFS *_at helpers, openat2
 * RESOLVE_BENEATH under the persistent export rootfd). Pure execution — the
 * caller owns logging and the wire reply. Returns 0 / -1+errno; sets
 * *handled=0 only for an action the plan cannot express. */
static int
cms_posix_apply(ngx_brix_cms_ctx_t *ctx, const brix_cms_node_plan_t *plan,
    int *handled)
{
    int         rootfd = ctx->conf->rootfd;
    const char *root_canon = ctx->conf->common.root_canon;

    *handled = 1;

    switch (plan->action) {
    case XRDCMS_NACT_MKDIR:
        return brix_mkdir_beneath(rootfd, plan->path, plan->mode);

    case XRDCMS_NACT_MKPATH: {
        char full[PATH_MAX];
        brix_beneath_full_path(root_canon, plan->path, full, sizeof(full));
        return brix_mkdir_recursive_beneath(ctx->cycle->log, rootfd, root_canon,
                                              full, plan->mode, NULL);
    }
    case XRDCMS_NACT_RMDIR:
        return brix_vfs_unlink_at(rootfd, plan->path, 1);

    case XRDCMS_NACT_RM:
        return brix_vfs_unlink_at(rootfd, plan->path, 0);

    case XRDCMS_NACT_MV:
        return brix_rename_beneath(rootfd, plan->path, plan->path2);

    case XRDCMS_NACT_CHMOD: {
        int rc;
        int fd = brix_vfs_open_fd_at(rootfd, plan->path, O_RDONLY, 0);
        if (fd < 0) { return -1; }
        rc = fchmod(fd, plan->mode);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        close(fd);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        return rc;
    }
    case XRDCMS_NACT_TRUNC: {
        int rc;
        int fd = brix_vfs_open_fd_at(rootfd, plan->path, O_WRONLY, 0);
        if (fd < 0) { return -1; }
        rc = ftruncate(fd, (off_t) plan->size);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        close(fd);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        return rc;
    }
    default:
        *handled = 0;
        return -1;
    }
}

/* cms_forward_via_posix — POSIX-export reply wrapper for a forwarded namespace
 * op: run cms_posix_apply and reply like stock cmsd — silent on success (as
 * cmsd Execute() does on a NULL return from a non-forwarding leaf node),
 * kYR_error (kYR_EINVAL + strerror) on failure, "unsupported operation" for an
 * inexpressible action. A hostile manager cannot make the node mutate outside
 * its export root — an escape fails EXDEV and becomes kYR_error. */
static ngx_int_t
cms_forward_via_posix(ngx_brix_cms_ctx_t *ctx, u_char code, uint32_t streamid,
    const brix_cms_node_plan_t *plan)
{
    int  handled;
    int  rc;

    rc = cms_posix_apply(ctx, plan, &handled);
    if (!handled) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "unsupported operation");
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                      "brix: CMS node: forwarded op code=%ui path=%s failed: %s",
                      (ngx_uint_t) code, plan->path, strerror(errno));
        /* byte-exact: ecode is always kYR_EINVAL; text carries strerror. */
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         strerror(errno));
    }

    /* Success: stay silent — exactly as cmsd Execute() does on a NULL return
     * from a non-forwarding leaf node. */
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS node: forwarded op code=%ui path=%s ok",
                   (ngx_uint_t) code, plan->path);
    return NGX_OK;
}

/* cms_node_exec_forward — execute a manager-forwarded namespace op (Plane B): decode
 * a kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc (the shared request-marshal
 * prologue: rrdata_parse → pure node_plan), then route to the storage leg —
 * a non-POSIX export (pblock/object) mutates through its driver's namespace
 * slots (cms_forward_via_driver); the default POSIX export takes the kernel-
 * confined *_beneath path (cms_forward_via_posix). */
ngx_int_t
cms_node_exec_forward(ngx_brix_cms_ctx_t *ctx, u_char code, uint32_t streamid,
    const u_char *payload, size_t plen)
{
    brix_cms_rrdata_t      d;
    brix_cms_node_plan_t   plan;
    brix_sd_instance_t    *sd;

    if (brix_cms_rrdata_parse(code, payload, plen, &d) != 0
        || brix_cms_node_plan(code, &d, &plan) != 0)
    {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "badly formed request");
    }

    /* A manager-only node (no local export) cannot satisfy a mutation. */
    if (ctx->conf->rootfd < 0) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "no local storage");
    }

    /* A non-POSIX export (pblock/object) routes the mutation through its driver's
     * namespace slots; the default POSIX export keeps the confined *_beneath path
     * unchanged. */
    sd = brix_vfs_backend_resolve(ctx->conf->common.root_canon,
                                  ctx->cycle->log);
    if (sd != NULL && sd->driver != brix_sd_default_driver()) {
        return cms_forward_via_driver(ctx, sd, code, streamid, &plan);
    }

    return cms_forward_via_posix(ctx, code, streamid, &plan);
}
