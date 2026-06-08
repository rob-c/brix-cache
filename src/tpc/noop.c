#include "tpc_internal.h"

int
xrootd_tpc_parse_opaque(const char *opaque, xrootd_tpc_params_t *out)
{
    (void) opaque;

    if (out != NULL) {
        ngx_memzero(out, sizeof(*out));
    }

    return -1;
}

ngx_int_t
xrootd_tpc_key_configure_registry(ngx_conf_t *cf)
{
    (void) cf;
    return NGX_OK;
}

void
xrootd_tpc_generate_key(char *buf, size_t buf_sz)
{
    if (buf != NULL && buf_sz > 0) {
        buf[0] = '\0';
    }
}

void
xrootd_tpc_key_register(const char *key, ngx_msec_t ttl_ms)
{
    (void) key;
    (void) ttl_ms;
}

int
xrootd_tpc_key_validate(const char *key)
{
    (void) key;
    return 0;
}

int
xrootd_tpc_key_consume(const char *key)
{
    (void) key;
    return 0;
}

void
xrootd_tpc_key_remove(const char *key)
{
    (void) key;
}

int
xrootd_tpc_check_src_policy(const char *src_host, uint16_t src_port,
    ngx_flag_t allow_local, ngx_flag_t allow_private,
    char *err_msg, size_t err_msg_sz)
{
    (void) src_host;
    (void) src_port;
    (void) allow_local;
    (void) allow_private;

    if (err_msg != NULL && err_msg_sz > 0) {
        ngx_cpystrn((u_char *) err_msg,
                    (u_char *) "native TPC is disabled at build time",
                    err_msg_sz);
    }

    return -1;
}

ngx_int_t
xrootd_tpc_prepare_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    (void) conf;
    (void) tpc;
    (void) dst_path;
    (void) options;
    (void) mode_bits;

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "native TPC is disabled at build time");
}

ngx_int_t
xrootd_tpc_start_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int fhandle_idx)
{
    (void) conf;
    (void) fhandle_idx;

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "native TPC is disabled at build time");
}

ngx_int_t
xrootd_tpc_launch_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    return xrootd_tpc_prepare_pull(ctx, c, conf, tpc, dst_path, options,
                                   mode_bits);
}
