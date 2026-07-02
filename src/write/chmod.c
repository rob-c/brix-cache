/*
 * chmod.c — kXR_chmod: delegate to op descriptor table.
 */
#include "ngx_xrootd_module.h"
#include "op_table.h"

ngx_int_t
xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
					ngx_stream_xrootd_srv_conf_t *conf)
{
	return xrootd_dispatch_op(ctx, c, conf, kXR_chmod);
}
