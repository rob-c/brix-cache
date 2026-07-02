#include "open.h"
#include "../cache/cache_storage.h"
#include "../path/beneath.h"

/* Cache-aware read-open (XCache-style).  Checks the VO ACL against the export
 * root first, then resolves the cache path: with slice-caching enabled and an
 * origin configured it serves via per-slice cache files; otherwise it serves a
 * whole-file cache hit directly, or delegates to a background origin fill on
 * miss.  Returns kXR_NotAuthorized on ACL failure, kXR_ArgInvalid on a bad path. */
ngx_int_t
xrootd_open_cached_read(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_xrootd_srv_conf_t *conf,
                        const char *clean_path,
                        uint16_t options, uint16_t mode_bits)
{
    char        acl_path[PATH_MAX];
    char        resolved[PATH_MAX];
    struct stat cst;
    int         n;

    xrootd_beneath_full_path(conf->common.root_canon, clean_path,
                             acl_path, sizeof(acl_path));

    if (xrootd_check_vo_acl_identity(c->log, acl_path, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_NotAuthorized, "VO not authorized");
    }

    /* Build the absolute cache path: cache_root + "/" + rel_clean_path */
    n = snprintf(resolved, sizeof(resolved), "%s/%s",
                 (char *) conf->cache_root.data,
                 xrootd_beneath_rel(clean_path));
    if (n < 0 || (size_t) n >= sizeof(resolved)) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_ArgInvalid, "path too long");
    }

    /* vfs-seam-allow: separate storage domain. `resolved` is under the
     * server-managed cache root (svc-owned, a different root than the export);
     * this existence check runs as the worker, not through the export-confined,
     * impersonation-aware VFS. */
    if (stat(resolved, &cst) == 0) {  /* vfs-seam-allow: separate server-managed cache-root domain */
        /* Cache-served reads stay plaintext (read_codec=0); inline read
         * compression (phase-42 W4) is only negotiated on the direct path. */
        return xrootd_open_resolved_file(ctx, c, conf, resolved,
                                         options, mode_bits, 0, 0);
    }

    return xrootd_cache_open_or_fill(ctx, c, conf, clean_path,
                                     resolved, options, mode_bits);
}
