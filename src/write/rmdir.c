/*
 * rmdir.c — kXR_rmdir: delegate to op descriptor table.
 */
#include "ngx_xrootd_module.h"
#include "write/op_table.h"

ngx_int_t
xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
					ngx_stream_xrootd_srv_conf_t *conf)
{
	return xrootd_dispatch_op(ctx, c, conf, kXR_rmdir);
}
