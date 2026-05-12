#include "open.h"

/*
 * Cache-aware read-open path.
 *
 * Called from xrootd_handle_open when conf->cache is set and the request is a
 * read-mode open.  ACL is checked against the auth root, then the cache root is
 * tried first (cache hit); on miss the file is filled from the configured
 * origin via xrootd_cache_open_or_fill.
 */
ngx_int_t
xrootd_open_cached_read(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_xrootd_srv_conf_t *conf,
                        const char *clean_path,
                        uint16_t options, uint16_t mode_bits)
{
    char  acl_resolved[PATH_MAX];
    char  resolved[PATH_MAX];

    if (!xrootd_resolve_path_noexist(c->log, &conf->root,
                                     clean_path, acl_resolved,
                                     sizeof(acl_resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_ArgInvalid, "invalid path");
    }

    if (xrootd_check_vo_acl(c->log, acl_resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_NotAuthorized, "VO not authorized");
    }

    if (xrootd_resolve_path(c->log, &conf->cache_root,
                            clean_path, resolved, sizeof(resolved))) {
        return xrootd_open_resolved_file(ctx, c, conf, resolved,
                                         options, mode_bits, 0);
    }

    if (!xrootd_resolve_path_noexist(c->log, &conf->cache_root,
                                     clean_path, resolved, sizeof(resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_ArgInvalid, "invalid cache path");
    }

    return xrootd_cache_open_or_fill(ctx, c, conf, clean_path,
                                     resolved, options, mode_bits);
}
