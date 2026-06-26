#ifndef XROOTD_WRITE_OP_TABLE_H
#define XROOTD_WRITE_OP_TABLE_H
#include "ngx_xrootd_module.h"
#include "../path/op_path.h"

/*
 * xrootd_op_exec_t — execution context passed to every op exec function.
 * Populated by the interpreter before calling exec().
 */
typedef struct {
    xrootd_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_xrootd_srv_conf_t  *conf;
    const char                    *reqpath;   /* client-supplied, after extract */
    const char                    *resolved;  /* canonical, after resolve */
} xrootd_op_exec_t;

/*
 * xrootd_op_desc_t — declarative descriptor for a simple namespace op.
 *
 * Simple ops share the same structure:
 *   1. xrootd_resolve_op_path  — extract + resolve
 *   2. xrootd_auth_gate        — three auth tiers
 *   3. exec()                  — single syscall; returns NGX_OK or NGX_ERROR
 *   4. XROOTD_RETURN_OK / XROOTD_RETURN_ERR
 *
 * Ops with non-trivial exec paths (two-mode truncate, atomic mv, TPC sync,
 * stat response formatting, etc.) remain as explicit handlers.
 */
typedef struct {
    uint16_t            opcode;       /* kXR_chmod / kXR_rm / kXR_rmdir ... */
    const char         *name;         /* verb for log lines: "CHMOD", "RM" */
    ngx_uint_t          op_id;        /* XROOTD_OP_* metric slot */
    int                 auth_level;   /* XROOTD_AUTH_* privilege required */
    int                 need_write;   /* 1 = write token scope required */
    xrootd_path_mode_t  path_mode;    /* EXISTING / WRITE / NOEXIST / EITHER */
    /* exec: perform the syscall; on error set *out_errno and return NGX_ERROR */
    ngx_int_t         (*exec)(const xrootd_op_exec_t *e, int *out_errno);
} xrootd_op_desc_t;

/*
 * xrootd_dispatch_op — interpreter entry point.
 *
 * Resolves the path, gates auth, calls exec, and sends the wire response.
 * Handler functions that are reduced to descriptors call this with their opcode.
 *
 * Returns NGX_OK / NGX_ERROR as appropriate for the nginx event loop.
 */
ngx_int_t xrootd_dispatch_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                               ngx_stream_xrootd_srv_conf_t *conf,
                               uint16_t opcode);

#endif /* XROOTD_WRITE_OP_TABLE_H */
