#include "open.h"
#include "fs/cache/cache_storage.h"
#include "fs/path/beneath.h"

/* Cache-aware read-open (XCache-style).  Checks the VO ACL against the export
 * root first, then resolves the cache path: with slice-caching enabled and an
 * origin configured it serves via per-slice cache files; otherwise it serves a
 * whole-file cache hit directly, or delegates to a background origin fill on
 * miss.  Returns kXR_NotAuthorized on ACL failure, kXR_ArgInvalid on a bad path. */
ngx_int_t
brix_open_cached_read(brix_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_brix_srv_conf_t *conf,
                        const char *clean_path,
                        uint16_t options, uint16_t mode_bits)
{
    char        acl_path[PATH_MAX];
    char        resolved[PATH_MAX];
    struct stat cst;
    int         n;

    brix_beneath_full_path(conf->common.root_canon, clean_path,
                             acl_path, sizeof(acl_path));

    /* SECURITY (cache transparency): the cache serve path — both the HIT branch
     * below and the async fill on MISS — MUST run the SAME full three-tier gate
     * the direct/non-cache path runs (open_request.c, brix_auth_gate at
     * BRIX_AUTH_READ): authdb (tier 1), VO ACL (tier 2), AND token scope
     * (tier 3), evaluated against the EXPORT-root namespace path (acl_path), not
     * the cache-root path. The old VO-ACL-only check let a principal denied by
     * authdb or token scope be served bytes that another principal's request had
     * already pulled into the shared, path-only-keyed cache — a cross-user /
     * cross-group leak. The fill worker performs no auth, so this open-time gate
     * is the sole enforcement point. It runs BEFORE the stat() below, so a denied
     * principal never even probes cache residency (no cache-hit timing oracle),
     * and returns ctx->write_rc exactly as the direct path does. The decision is
     * L1/L2 identity-cached, so an authorized principal's repeat hits stay cheap. */
    if (brix_auth_gate(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
                         clean_path, acl_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    /* Build the absolute cache path: cache_root + "/" + rel_clean_path */
    n = snprintf(resolved, sizeof(resolved), "%s/%s",
                 (char *) conf->cache_root.data,
                 brix_beneath_rel(clean_path));
    if (n < 0 || (size_t) n >= sizeof(resolved)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN",
                          clean_path, "cache", kXR_ArgInvalid, "path too long");
    }

    /* vfs-seam-allow: separate storage domain. `resolved` is under the
     * server-managed cache root (svc-owned, a different root than the export);
     * this existence check runs as the worker, not through the export-confined,
     * impersonation-aware VFS. */
    if (stat(resolved, &cst) == 0) {  /* vfs-seam-allow: separate server-managed cache-root domain */
        /* Cache-served reads stay plaintext (read_codec=0); inline read
         * compression (phase-42 W4) is only negotiated on the direct path. */
        return brix_open_resolved_file(ctx, c, conf, resolved,
                                         options, mode_bits, 0, 0);
    }

    return brix_cache_open_or_fill(ctx, c, conf, clean_path,
                                     resolved, options, mode_bits);
}
