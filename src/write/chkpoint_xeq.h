#ifndef XROOTD_WRITE_CHKPOINT_XEQ_H
#define XROOTD_WRITE_CHKPOINT_XEQ_H

#include "ngx_xrootd_module.h"

/* Execute a write sub-operation (write/pgwrite/truncate/writev) under an
 * active checkpoint.  Called from xrootd_handle_chkpoint for kXR_ckpXeq.
 * idx must be a valid, open, writable file handle with ckp_path != NULL. */
ngx_int_t ckp_xeq(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx);

#endif /* XROOTD_WRITE_CHKPOINT_XEQ_H */
