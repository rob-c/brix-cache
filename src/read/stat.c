#include "../ngx_xrootd_module.h"
#include "stat.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* File Stat — kXR_stat and kXR_statx metadata query handlers            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_stat opcode — querying file metadata (inode, size, flags, mtime). The handler supports two modes:
 *      path-based stat (stat(2) syscall on filesystem path) and handle-based stat (fstat(2) syscall on open file descriptor). Both modes
 *      return identical ASCII-formatted body containing inode number, file size in bytes, permission flags (readable/writable/cachersp),
 *      and modification time. In VFS mode (kXR_vfs flag), the format expands to include additional filesystem statistics.
 *
 * WHY: Stat is one of the most frequently called opcodes — clients query metadata before opening files, during directory listing iterations,
 *      and for cache-hit validation. Handle-based stat provides fast metadata access without re-resolving paths (uses cached canonical path).
 *      Cache flag detection helps clients distinguish between local cached content vs origin content for prefetch optimization.
 *
 * HOW: Two-mode flow → parse options (kXR_vfs flag) → if dlen > 0: extract/clean/resolve path + authdb/VO ACL/token scope check + stat(2) + cache flag detection,
 *      else: validate handle + fstat(2) on cached FD + from_cache flag → format body via xrootd_make_stat_body() → return kXR_ok with ASCII body payload. */

/* ------------------------------------------------------------------ */
/* Section: Cache Flag Detection (kXR_cachersp)                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Helper function that checks whether a requested path exists in the local cache (conf->cache_root). Returns kXR_cachersp flag if found, 0 otherwise.
 *      This flag tells clients the file is served from cache rather than origin — useful for prefetch optimization and caching metrics.
 *
 * WHY: Clients can optimize read patterns when they know content is cached locally. The cachersp flag in stat body enables downstream logic to skip origin fetches
 *      for repeated access patterns, reducing latency across session boundaries. This is particularly valuable for large files accessed by multiple clients.
 *
 * HOW: Three-step validation → cache enabled check (skip if disabled or cache_root empty) → build cache_path = conf->cache_root + reqpath → stat(2) on cache path →
 *      return kXR_cachersp if regular file exists, 0 otherwise. Uses PATH_MAX buffer to prevent overflow. */

/* Return kXR_cachersp if reqpath (client's clean path) exists in cache_root. */
int
xrootd_cache_path_flag(const ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath)
{
    char        cache_path[PATH_MAX];
    struct stat cst;
    int         n;

    if (!conf->cache || conf->cache_root.len == 0 || reqpath == NULL) {
        return 0;
    }

    n = snprintf(cache_path, sizeof(cache_path), "%s%s",
                 (char *) conf->cache_root.data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(cache_path)) {
        return 0;
    }

    return (stat(cache_path, &cst) == 0 && S_ISREG(cst.st_mode))
           ? kXR_cachersp : 0;
}

/* ---- Function: xrootd_handle_stat() ----
 *
 * WHAT: Handles the kXR_stat opcode — queries file metadata in two modes: path-based stat (stat(2) syscall on filesystem path) and handle-based stat (fstat(2)
 *      syscall on open file descriptor). Returns ASCII-formatted body containing inode number, file size, permission flags (readable/writable/cachersp), and mtime.
 *      Supports VFS mode expansion via kXR_vfs flag. Both modes require authdb/VO ACL/token scope checks before returning metadata.
 *
 * WHY: Stat is one of the most frequently called opcodes — clients query metadata before opening files, during directory listing iterations, and for cache-hit validation. Handle-based stat provides fast metadata access without re-resolving paths (uses cached canonical path). Cache flag detection helps clients distinguish between local cached content vs origin content for prefetch optimization.
 *
 * HOW: Two-mode flow → parse options (kXR_vfs flag) — if dlen > 0: extract/clean/resolve path + authdb/VO ACL/token scope check + stat(2) + cache flag detection via xrootd_cache_path_flag(), else: validate handle + fstat(2) on cached FD + from_cache flag → format body via xrootd_make_stat_body() — return kXR_ok with ASCII body payload. Logging uses resolved path for handle-based stats.
 *
 * Parameters:
 *   ctx  - stream session context (payload, hdr_buf, cur_dlen, files[])
 *   c    - nginx connection (log, ssl state)
 *   conf - server config (root, cache, vo_rules)
 */

ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               reqpath_buf[XROOTD_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;
    ngx_int_t          validate_rc;
    int                extra_flags = 0;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 0)) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", "-", "-",
                              kXR_ArgInvalid, "invalid path payload");
        }
        reqpath = reqpath_buf;

        if (!xrootd_resolve_path(c->log, &conf->common.root,
                                 reqpath, resolved, sizeof(resolved))) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotFound, "file not found");
        }

        if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_LOOKUP) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_NotAuthorized, "authdb denied");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_NotAuthorized, "VO not authorized");
        }

        if (xrootd_check_token_scope(ctx, reqpath, 0) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotAuthorized, "token scope denied");
        }

        if (stat(resolved, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", reqpath, "-",
                              kXR_NotFound, "file not found");
        }

        extra_flags = xrootd_cache_path_flag(conf, reqpath);

    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (!xrootd_validate_file_handle(ctx, c, idx, "STAT",
                                         XROOTD_OP_STAT, &validate_rc)) {
            return validate_rc;
        }

        resolved[0] = '\0';
        ngx_cpystrn((u_char *) resolved,
                    (u_char *) (ctx->files[idx].path != NULL
                                ? ctx->files[idx].path : "-"),
                    sizeof(resolved));

        if (fstat(ctx->files[idx].fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "STAT", resolved, "-",
                              kXR_IOError, strerror(errno));
        }

        extra_flags = ctx->files[idx].from_cache ? kXR_cachersp : 0;
    }

    /* Convert the host stat struct into the exact ASCII body the client expects. */
    xrootd_make_stat_body(&st, is_vfs, extra_flags, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    /* Log the stat - use resolved path for handle-based stats */
    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : resolved,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}
