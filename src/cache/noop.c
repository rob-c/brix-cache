#include "cache_internal.h"
#include "writethrough.h"

ngx_int_t
xrootd_cache_open_or_fill(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits)
{
    (void) conf;
    (void) clean_path;
    (void) cache_path;
    (void) options;
    (void) mode_bits;

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "read-through cache is disabled at build time");
}

xrootd_wt_decision_t
xrootd_wt_default_decide(const char *path, uint16_t options, void *user_data)
{
    (void) path;
    (void) options;
    (void) user_data;

    return XROOTD_WT_DECISION_DENY;
}

ngx_int_t
xrootd_wt_config_init_prefixes(ngx_conf_t *cf, ngx_array_t *prefix_list,
    ngx_array_t **out_array, const char *directive_name)
{
    (void) cf;
    (void) directive_name;

    if (out_array != NULL) {
        *out_array = prefix_list;
    }

    return NGX_OK;
}

xrootd_wt_decision_t
xrootd_cache_should_writethrough(const xrootd_vfs_ctx_t *ctx,
    off_t offset, size_t length)
{
    (void) ctx;
    (void) offset;
    (void) length;

    return XROOTD_WT_DECISION_DENY;
}

ngx_int_t
xrootd_wt_flush_on_close(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path)
{
    (void) ctx;
    (void) c;
    (void) conf;
    (void) idx;
    (void) local_path;

    return NGX_DECLINED;
}

ngx_int_t
xrootd_wt_flush_sync_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    uint16_t fail_status)
{
    (void) ctx;
    (void) c;
    (void) conf;
    (void) idx;
    (void) local_path;
    (void) fail_status;

    return NGX_DECLINED;
}

void
xrootd_wt_flush_thread(void *data, ngx_log_t *log)
{
    (void) data;
    (void) log;
}

void
xrootd_wt_flush_done(ngx_event_t *ev)
{
    (void) ev;
}
