/*
 * chmod.c — kXR_chmod: delegate to op descriptor table.
 */
#include "core/ngx_brix_module.h"
#include "op_table.h"

ngx_int_t
brix_handle_chmod(brix_ctx_t *ctx, ngx_connection_t *c,
					ngx_stream_brix_srv_conf_t *conf)
{
	return brix_dispatch_op(ctx, c, conf, kXR_chmod);
}
