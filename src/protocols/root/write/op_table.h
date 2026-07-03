#ifndef BRIX_WRITE_OP_TABLE_H
#define BRIX_WRITE_OP_TABLE_H
#include "core/ngx_brix_module.h"
#include "protocols/root/path/op_path.h"

/*
 * brix_op_exec_t — execution context passed to every op exec function.
 * Populated by the interpreter before calling exec().
 */
typedef struct {
    brix_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_brix_srv_conf_t  *conf;
    const char                    *reqpath;   /* client-supplied, after extract */
    const char                    *resolved;  /* canonical, after resolve */
} brix_op_exec_t;

/*
 * brix_op_desc_t — declarative descriptor for a simple namespace op.
 *
 * Simple ops share the same structure:
 *   1. brix_resolve_op_path  — extract + resolve
 *   2. brix_auth_gate        — three auth tiers
 *   3. exec()                  — single syscall; returns NGX_OK or NGX_ERROR
 *   4. BRIX_RETURN_OK / BRIX_RETURN_ERR
 *
 * Ops with non-trivial exec paths (two-mode truncate, atomic mv, TPC sync,
 * stat response formatting, etc.) remain as explicit handlers.
 */
typedef struct {
    uint16_t            opcode;       /* kXR_chmod / kXR_rm / kXR_rmdir ... */
    const char         *name;         /* verb for log lines: "CHMOD", "RM" */
    ngx_uint_t          op_id;        /* BRIX_OP_* metric slot */
    int                 auth_level;   /* BRIX_AUTH_* privilege required */
    int                 need_write;   /* 1 = write token scope required */
    brix_path_mode_t  path_mode;    /* EXISTING / WRITE / NOEXIST / EITHER */
    /* exec: perform the syscall; on error set *out_errno and return NGX_ERROR */
    ngx_int_t         (*exec)(const brix_op_exec_t *e, int *out_errno);
} brix_op_desc_t;

/*
 * brix_dispatch_op — interpreter entry point.
 *
 * Resolves the path, gates auth, calls exec, and sends the wire response.
 * Handler functions that are reduced to descriptors call this with their opcode.
 *
 * Returns NGX_OK / NGX_ERROR as appropriate for the nginx event loop.
 */
ngx_int_t brix_dispatch_op(brix_ctx_t *ctx, ngx_connection_t *c,
                               ngx_stream_brix_srv_conf_t *conf,
                               uint16_t opcode);

#endif /* BRIX_WRITE_OP_TABLE_H */
