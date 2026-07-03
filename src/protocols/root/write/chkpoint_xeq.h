#ifndef BRIX_WRITE_CHKPOINT_XEQ_H
#define BRIX_WRITE_CHKPOINT_XEQ_H

#include "core/ngx_brix_module.h"

/* Execute a write sub-operation (write/pgwrite/truncate/writev) under an
 * active checkpoint.  Called from brix_handle_chkpoint for kXR_ckpXeq.
 * idx must be a valid, open, writable file handle with ckp_path != NULL. */
ngx_int_t ckp_xeq(brix_ctx_t *ctx, ngx_connection_t *c, int idx);

#endif /* BRIX_WRITE_CHKPOINT_XEQ_H */
