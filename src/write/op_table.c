/*
 * op_table.c — descriptor table + interpreter for simple namespace ops.
 *
 * Ops that share the pattern: resolve → auth → single syscall → ok/err
 * are expressed as descriptors here; the interpreter handles the boilerplate.
 * Handlers with non-trivial exec paths remain as explicit handlers.
 */
#include "ngx_xrootd_module.h"
#include "write/op_table.h"
#include "compat/namespace_ops.h"
#include "compat/error_mapping.h"
#include "path/path.h"
#include "fs/vfs.h"   /* chmod/rm/rmdir via the VFS seam */

/* Build a stream VFS ctx for a simple namespace op on e->resolved. */
static void
op_vfs_ctx(const xrootd_op_exec_t *e, xrootd_vfs_ctx_t *vctx)
{
    xrootd_vfs_ctx_init(vctx, e->c->pool, e->c->log, XROOTD_PROTO_STREAM,
        e->conf->common.root_canon, NULL, e->conf->common.allow_write,
        0 /* is_tls */, NULL, e->resolved);
}

/* exec functions (one per op) */
static ngx_int_t
exec_chmod(const xrootd_op_exec_t *e, int *out_errno)
{
    xrdw_chmod_req_t req;
    mode_t mode;

    xrdw_chmod_req_unpack(((ClientRequestHdr *) e->ctx->hdr_buf)->body, &req);
    mode = req.mode & 0777;

    if (mode == 0) {
        mode = 0644;
    }
    /* xrootd_vfs_chmod delegates to the impersonation-aware confined chmod, so
     * under impersonation it is performed BY THE BROKER as the mapped user (the
     * unprivileged worker is not the owner and a worker-local chmod would EPERM). */
    {
        xrootd_vfs_ctx_t vctx;

        op_vfs_ctx(e, &vctx);
        if (xrootd_vfs_chmod(&vctx, mode) == NGX_OK) {
            return NGX_OK;
        }
    }
    *out_errno = errno;
    return NGX_ERROR;
}

static ngx_int_t
exec_rm(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_vfs_ctx_t vctx;

    /* kXR_rm mirrors osFS->rem: unlink a file, rmdir a directory — NON-recursively
     * (xrootd_vfs_unlink → xrootd_vfs_delete(recursive=0): an empty dir is removed,
     * a non-empty dir fails ENOTEMPTY). It must NEVER recurse (recursion here would
     * silently delete whole subtrees on a plain `rm` — data loss). */
    op_vfs_ctx(e, &vctx);
    if (xrootd_vfs_unlink(&vctx) == NGX_OK) {
        return NGX_OK;
    }
    *out_errno = errno ? errno : EISDIR;
    return NGX_ERROR;
}

static ngx_int_t
exec_rmdir(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_vfs_ctx_t vctx;

    /* rmdir must reject regular files (xrootd_vfs_rmdir → vfs_delete with
     * require_directory) and is idempotent for a missing target (stock do_Rmdir
     * tolerates ENOENT), so a not-found dir is treated as success. */
    op_vfs_ctx(e, &vctx);
    if (xrootd_vfs_rmdir(&vctx, 0 /* non-recursive */) == NGX_OK) {
        return NGX_OK;
    }
    if (errno == ENOENT) {
        return NGX_OK;   /* idempotent_missing */
    }
    *out_errno = errno ? errno : ENOTEMPTY;
    return NGX_ERROR;
}

/* descriptor table */
static const xrootd_op_desc_t _ops[] = {
    { kXR_chmod,  "CHMOD",  XROOTD_OP_CHMOD,  XROOTD_AUTH_UPDATE, 1,
      XROOTD_PATH_EXISTING, exec_chmod },
    { kXR_rm,     "RM",     XROOTD_OP_RM,     XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EXISTING, exec_rm    },
    { kXR_rmdir,  "RMDIR",  XROOTD_OP_RMDIR,  XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EITHER,   exec_rmdir },
};
#define N_OPS (sizeof(_ops) / sizeof(_ops[0]))

/* interpreter */
ngx_int_t
xrootd_dispatch_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf,
                   uint16_t opcode)
{
    char                    reqpath[XROOTD_MAX_PATH + 1];
    char                    resolved[PATH_MAX];
    const xrootd_op_desc_t *d = NULL;
    xrootd_op_exec_t        ex;
    int                     err = 0;
    size_t                  i;

    for (i = 0; i < N_OPS; i++) {
        if (_ops[i].opcode == opcode) {
            d = &_ops[i];
            break;
        }
    }
    if (d == NULL) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest, "unknown opcode");
    }

    if (xrootd_resolve_op_path(ctx, c, d->op_id, d->name, conf,
                               d->path_mode,
                               reqpath, sizeof(reqpath),
                               resolved, sizeof(resolved)) != NGX_OK) {
        return ctx->write_rc;
    }

    if (xrootd_auth_gate(ctx, c, d->op_id, d->name,
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
        XROOTD_RETURN_ERR(ctx, c, d->op_id, d->name, resolved, "-",
                          xrootd_kxr_from_errno(err),
                          xrootd_kxr_err_string(err));
    }

    XROOTD_RETURN_OK(ctx, c, d->op_id, d->name, resolved, "-", 0);
}
