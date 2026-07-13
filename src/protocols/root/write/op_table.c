/*
 * op_table.c — descriptor table + interpreter for simple namespace ops.
 *
 * Ops that share the pattern: resolve → auth → single syscall → ok/err
 * are expressed as descriptors here; the interpreter handles the boilerplate.
 * Handlers with non-trivial exec paths remain as explicit handlers.
 */
#include "core/ngx_brix_module.h"
#include "op_table.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/error_mapping.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* chmod/rm/rmdir via the VFS seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */

/* Build a stream VFS ctx for a simple namespace op on e->resolved.
 *
 * WHAT: Threads the authenticated session identity (e->ctx->identity) and the
 *       export's per-user backend credential policy onto the ctx (Phase 2
 *       Task 6), mirroring the davs/S3 call sites (Phase 1).
 *
 * WHY:  chmod/rm/rmdir dispatch through brix_vfs_chmod/unlink/rmdir, each of
 *       which runs the brix_vfs_ns_cred gate before reaching a remote-backed
 *       driver; without identity+cred-dir bound here that gate always falls
 *       back to the shared service credential regardless of policy.
 *
 * HOW:  brix_vfs_ctx_bind_backend_cred is a no-op when the export's
 *       brix_storage_credential_dir is unset, so this is safe for every
 *       export (local or remote-backed). */
static void
op_vfs_ctx(const brix_op_exec_t *e, brix_vfs_ctx_t *vctx)
{
    brix_vfs_ctx_init(vctx, e->c->pool, e->c->log, BRIX_PROTO_ROOT,
        e->conf->common.root_canon, NULL, e->conf->common.allow_write,
        0 /* is_tls */, e->ctx->identity, e->resolved);
    brix_vfs_ctx_bind_backend_cred(vctx,
        &e->conf->common.storage_credential_dir,
        e->conf->common.storage_credential_fallback);
    brix_root_vfs_bind_deleg(e->ctx, e->conf, vctx);
}

/* exec functions (one per op) */
static ngx_int_t
exec_chmod(const brix_op_exec_t *e, int *out_errno)
{
    xrdw_chmod_req_t req;
    mode_t mode;

    xrdw_chmod_req_unpack(((ClientRequestHdr *) e->ctx->recv.hdr_buf)->body, &req);
    mode = req.mode & 0777;

    if (mode == 0) {
        mode = 0644;
    }
    /* brix_vfs_chmod delegates to the impersonation-aware confined chmod, so
     * under impersonation it is performed BY THE BROKER as the mapped user (the
     * unprivileged worker is not the owner and a worker-local chmod would EPERM). */
    {
        brix_vfs_ctx_t vctx;

        op_vfs_ctx(e, &vctx);
        if (brix_vfs_chmod(&vctx, mode) == NGX_OK) {
            return NGX_OK;
        }
    }
    *out_errno = errno;
    return NGX_ERROR;
}

static ngx_int_t
exec_rm(const brix_op_exec_t *e, int *out_errno)
{
    brix_vfs_ctx_t vctx;

    /* kXR_rm mirrors osFS->rem: unlink a file, rmdir a directory — NON-recursively
     * (brix_vfs_unlink → brix_vfs_delete(recursive=0): an empty dir is removed,
     * a non-empty dir fails ENOTEMPTY). It must NEVER recurse (recursion here would
     * silently delete whole subtrees on a plain `rm` — data loss). */
    op_vfs_ctx(e, &vctx);
    if (brix_vfs_unlink(&vctx) == NGX_OK) {
        return NGX_OK;
    }
    *out_errno = errno ? errno : EISDIR;
    return NGX_ERROR;
}

static ngx_int_t
exec_rmdir(const brix_op_exec_t *e, int *out_errno)
{
    brix_vfs_ctx_t vctx;

    /* rmdir must reject regular files (brix_vfs_rmdir → vfs_delete with
     * require_directory) and is idempotent for a missing target (stock do_Rmdir
     * tolerates ENOENT), so a not-found dir is treated as success. */
    op_vfs_ctx(e, &vctx);
    if (brix_vfs_rmdir(&vctx, 0 /* non-recursive */) == NGX_OK) {
        return NGX_OK;
    }
    if (errno == ENOENT) {
        return NGX_OK;   /* idempotent_missing */
    }
    *out_errno = errno ? errno : ENOTEMPTY;
    return NGX_ERROR;
}

/* descriptor table */
static const brix_op_desc_t op_table[] = {
    { kXR_chmod,  "CHMOD",  BRIX_OP_CHMOD,  BRIX_AUTH_UPDATE, 1,
      BRIX_PATH_EXISTING, exec_chmod },
    { kXR_rm,     "RM",     BRIX_OP_RM,     BRIX_AUTH_DELETE, 1,
      BRIX_PATH_EXISTING, exec_rm    },
    { kXR_rmdir,  "RMDIR",  BRIX_OP_RMDIR,  BRIX_AUTH_DELETE, 1,
      BRIX_PATH_EITHER,   exec_rmdir },
};
#define N_OPS (sizeof(op_table) / sizeof(op_table[0]))

/* interpreter */
ngx_int_t
brix_dispatch_op(brix_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_brix_srv_conf_t *conf,
                   uint16_t opcode)
{
    char                    reqpath[BRIX_MAX_PATH + 1];
    char                    resolved[PATH_MAX];
    const brix_op_desc_t *d = NULL;
    brix_op_exec_t        ex;
    int                     err = 0;
    size_t                  i;

    for (i = 0; i < N_OPS; i++) {
        if (op_table[i].opcode == opcode) {
            d = &op_table[i];
            break;
        }
    }
    if (d == NULL) {
        return brix_send_error(ctx, c, kXR_InvalidRequest, "unknown opcode");
    }

    if (brix_resolve_op_path(ctx, c, d->op_id, d->name, conf,
                               d->path_mode,
                               reqpath, sizeof(reqpath),
                               resolved, sizeof(resolved)) != NGX_OK) {
        return ctx->write_rc;
    }

    if (brix_auth_gate(ctx, c, d->op_id, d->name,
                         reqpath, resolved, conf,
                         d->auth_level, d->need_write) != NGX_OK) {
        return ctx->write_rc;
    }

    ex.ctx      = ctx;
    ex.c        = c;
    ex.conf     = conf;
    ex.reqpath  = reqpath;
    ex.resolved = resolved;

    if (d->exec(&ex, &err) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, d->op_id, d->name, resolved, "-",
                          brix_kxr_from_errno(err),
                          brix_kxr_err_string(err));
    }

    BRIX_RETURN_OK(ctx, c, d->op_id, d->name, resolved, "-", 0);
}
