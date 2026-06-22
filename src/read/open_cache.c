#include "open.h"
#include "slice_read.h"
#include "../path/beneath.h"

/* ------------------------------------------------------------------ */
/* Cache-Aware Read-Open — open_cached_read for cached content serving   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the cache-aware read-open path that serves files from local cache when available, falling back to origin fill on cache miss. Called from xrootd_handle_open when conf->cache is set and the request is a read-mode open. The flow resolves the path against auth root for ACL check, then tries cache root first (cache hit → direct serve), on miss triggers background fill via xrootd_cache_open_or_fill. */

/* ------------------------------------------------------------------ */
/* Section: Cache Hit vs Miss Decision                                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Two-step resolution — resolve against conf->cache_root first (if path exists, cache hit → open directly), if not found resolve against conf->cache_root with noexist flag (cache miss → trigger fill from origin). The cached content serves identical bytes to origin but at reduced latency for repeated access patterns across sessions. */

/* ---- Function: xrootd_open_cached_read() — cache-aware read-open with two-step resolution ----
 *
 * WHAT: Cache-aware read-open handler that implements XCache-style caching for read operations. First resolves path against auth root (conf->common.root) via xrootd_resolve_path_noexist() to verify ACL permissions using VO rules and ctx->vo_list. If ACL check fails, returns kXR_NotAuthorized error immediately. On ACL pass attempts cache root resolution (conf->cache_root) — if path exists at cache root (xrootd_resolve_path succeeds), serves content directly via xrootd_open_resolved_file() with zero flags indicating cached source. If cache miss (path not found at cache root), uses noexist flag to probe and then triggers background origin fill via xrootd_cache_open_or_fill() which fetches from upstream/origin while serving the request. Two distinct output paths: cache hit serves immediately; cache miss initiates async fill with client served during fetch.
 *
 * WHY: XCache-style caching reduces latency for repeated access patterns across sessions by storing frequently accessed content locally. The two-step resolution (auth root first, then cache root) ensures cached content is only served when the user has proper VO authorization — preventing unauthorized users from accessing cached files through cache hits alone. Cache-miss fill trigger uses background operations so client requests are not blocked waiting for origin fetch — concurrent requests during fill can be served once cache population completes. Thread safety: operates on local stack variables (acl_resolved, resolved) and provided connection/ctx; no shared state modification during resolution phase.
 *
 * HOW: Declares two PATH_MAX buffers for separate resolution paths. Step 1: resolve against auth root with noexist flag — if this fails (invalid path), returns kXR_ArgInvalid error. Step 2: check VO ACL via xrootd_check_vo_acl() using conf->vo_rules and ctx->vo_list — if unauthorized, returns kXR_NotAuthorized. Step 3: attempt cache root resolution without noexist flag — if path found at cache (NGX_OK), delegates to xrootd_open_resolved_file() with flags=0 indicating cached source. Step 4: on cache miss, resolve against cache root with noexist flag again — if this fails (invalid cache path), returns kXR_ArgInvalid. Step 5: on successful noexist probe, delegate to xrootd_cache_open_or_fill() for background origin fetch. */

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

    /*
     * Phase 26 slice caching: when enabled and an origin is configured, serve
     * this read handle from per-slice cache files instead of fetching the whole
     * file at open.  Falls through to the whole-file path when slicing is off.
     */
    if (conf->cache_slice_size > 0 && conf->cache_origin_host.len > 0) {
        return xrootd_open_slice_handle(ctx, c, conf, clean_path, resolved,
                                        options);
    }

    if (stat(resolved, &cst) == 0) {
        /* Cache-served reads stay plaintext (read_codec=0); inline read
         * compression (phase-42 W4) is only negotiated on the direct path. */
        return xrootd_open_resolved_file(ctx, c, conf, resolved,
                                         options, mode_bits, 0, 0);
    }

    return xrootd_cache_open_or_fill(ctx, c, conf, clean_path,
                                     resolved, options, mode_bits);
}
