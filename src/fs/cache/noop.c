#include "cache_internal.h"
#include "writethrough.h"

/*
 * noop.c — build-time-disabled stub for the read-through / write-through cache.
 *
 * WHAT: Provides the complete public symbol set of the cache subsystem
 *       (brix_cache_open_or_fill, the brix_wt_* write-through API, and the
 *       flush thread/event entry points) as inert no-op implementations.
 *
 * WHY:  The cache is an optional feature. When it is compiled out, the rest of
 *       the module still references these symbols at link time (open/close
 *       handlers call into the write-through hooks unconditionally). This file
 *       satisfies the linker and guarantees graceful degradation rather than a
 *       build break or a runtime crash when caching is absent.
 *
 * HOW:  Each function discards its arguments via (void) casts and returns the
 *       "do nothing / not available" sentinel for its contract:
 *         - brix_cache_open_or_fill() answers the client with
 *           kXR_Unsupported via brix_send_error() (the cache cannot serve).
 *         - brix_wt_default_decide() and brix_cache_should_writethrough()
 *           return BRIX_WT_DECISION_DENY (never write back to origin).
 *         - brix_wt_config_init_prefixes() passes the prefix list through
 *           unchanged and returns NGX_OK so config parsing still succeeds.
 *         - brix_wt_flush_on_close()/brix_wt_flush_sync_handle() return
 *           NGX_DECLINED so callers fall through to their non-cache path.
 *         - the flush thread/done callbacks are empty.
 *       This file is the build-time counterpart to the real implementations in
 *       open_or_fill.c, writethrough_decision.c, and writethrough_flush.c.
 */

ngx_int_t
brix_cache_open_or_fill(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits)
{
    (void) conf;
    (void) clean_path;
    (void) cache_path;
    (void) options;
    (void) mode_bits;

    return brix_send_error(ctx, c, kXR_Unsupported,
                             "read-through cache is disabled at build time");
}

brix_wt_decision_t
brix_wt_default_decide(const char *path, uint16_t options, void *user_data)
{
    (void) path;
    (void) options;
    (void) user_data;

    return BRIX_WT_DECISION_DENY;
}

ngx_int_t
brix_wt_config_init_prefixes(ngx_conf_t *cf, ngx_array_t *prefix_list,
    ngx_array_t **out_array, const char *directive_name)
{
    (void) cf;
    (void) directive_name;

    if (out_array != NULL) {
        *out_array = prefix_list;
    }

    return NGX_OK;
}

brix_wt_decision_t
brix_cache_should_writethrough(const brix_vfs_ctx_t *ctx,
    off_t offset, size_t length)
{
    (void) ctx;
    (void) offset;
    (void) length;

    return BRIX_WT_DECISION_DENY;
}

ngx_int_t
brix_wt_flush_on_close(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int idx, const char *local_path)
{
    (void) ctx;
    (void) c;
    (void) conf;
    (void) idx;
    (void) local_path;

    return NGX_DECLINED;
}

ngx_int_t
brix_wt_flush_sync_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int idx, const char *local_path,
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
brix_wt_flush_thread(void *data, ngx_log_t *log)
{
    (void) data;
    (void) log;
}

void
brix_wt_flush_done(ngx_event_t *ev)
{
    (void) ev;
}
