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

/* ---- exec functions (one per op) ---------------------------------------- */

static ngx_int_t
exec_chmod(const xrootd_op_exec_t *e, int *out_errno)
{
    ClientChmodRequest *req = (ClientChmodRequest *) e->ctx->hdr_buf;
    mode_t mode = ntohs(req->mode) & 0777;

    if (mode == 0) {
        mode = 0644;
    }
    if (chmod(e->resolved, mode) == 0) {
        return NGX_OK;
    }
    *out_errno = errno;
    return NGX_ERROR;
}

static ngx_int_t
exec_rm(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;

    ngx_memzero(&opts, sizeof(opts));
    res = xrootd_ns_delete(e->c->log, e->conf->common.root_canon,
                           e->resolved, &opts);

    if (res.status == XROOTD_NS_OK) {
        return NGX_OK;
    }

    /* Native kXR_rm retries as rmdir if unlink failed with EISDIR. */
    if (res.was_dir) {
        opts.recursive = 1;
        res = xrootd_ns_delete(e->c->log, e->conf->common.root_canon,
                               e->resolved, &opts);
        if (res.status == XROOTD_NS_OK) {
            return NGX_OK;
        }
    }

    *out_errno = res.sys_errno;
    return NGX_ERROR;
}

static ngx_int_t
exec_rmdir(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;

    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 1;
    opts.require_directory  = 1;   /* rmdir must reject regular files (ENOTDIR) */
    res = xrootd_ns_delete(e->c->log, e->conf->common.root_canon,
                           e->resolved, &opts);
    if (res.status == XROOTD_NS_OK) {
        return NGX_OK;
    }
    *out_errno = res.sys_errno ? res.sys_errno : ENOTEMPTY;
    return NGX_ERROR;
}

/* ---- descriptor table ---------------------------------------------------- */

static const xrootd_op_desc_t _ops[] = {
    { kXR_chmod,  "CHMOD",  XROOTD_OP_CHMOD,  XROOTD_AUTH_UPDATE, 1,
      XROOTD_PATH_EXISTING, exec_chmod },
    { kXR_rm,     "RM",     XROOTD_OP_RM,     XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EXISTING, exec_rm    },
    { kXR_rmdir,  "RMDIR",  XROOTD_OP_RMDIR,  XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EITHER,   exec_rmdir },
};
#define N_OPS (sizeof(_ops) / sizeof(_ops[0]))

/* ---- interpreter --------------------------------------------------------- */

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
